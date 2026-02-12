use clap::{Parser, Subcommand};
use pem2jks::keystore::{self, JKS};
use std::fs;
use std::process;

#[derive(Parser)]
#[command(
    name = "pem2jks",
    about = "Convert PEM certificates and keys to JKS keystore"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Certificate with optional key and alias (cert.pem[:key.pem[:alias]])
    #[arg(short = 'c', long = "cert", value_name = "CERT")]
    cert: Vec<String>,

    /// CA certificate with optional alias (ca.pem[:alias])
    #[arg(long = "ca", value_name = "CA")]
    ca: Vec<String>,

    /// Output file path
    #[arg(short = 'o', long = "output", default_value = "keystore.jks")]
    output: String,

    /// Keystore password
    #[arg(short = 'p', long = "password")]
    password: Option<String>,

    /// File containing the keystore password
    #[arg(long = "password-file")]
    password_file: Option<String>,

    /// Password for input keystore
    #[arg(long = "input-password")]
    input_password: Option<String>,

    /// Existing JKS file to append to
    #[arg(short = 'i', long = "input")]
    input: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Print version information
    Version,
}

fn get_version() -> String {
    option_env!("VERSION").unwrap_or("dev").to_string()
}

fn get_commit() -> String {
    option_env!("GIT_COMMIT").unwrap_or("unknown").to_string()
}

fn get_build_date() -> String {
    option_env!("BUILD_DATE").unwrap_or("unknown").to_string()
}

fn resolve_password(cli: &Cli) -> Result<String, String> {
    if let Some(ref pw) = cli.password {
        return Ok(pw.clone());
    }
    if let Some(ref pw_file) = cli.password_file {
        let content = fs::read_to_string(pw_file)
            .map_err(|e| format!("failed to read password file '{}': {}", pw_file, e))?;
        return Ok(content.trim().to_string());
    }
    if let Ok(pw) = std::env::var("KEYSTORE_PASSWORD") {
        return Ok(pw);
    }
    Err(
        "no password provided: use --password, --password-file, or KEYSTORE_PASSWORD env"
            .to_string(),
    )
}

struct CertSpec {
    cert_file: String,
    key_file: Option<String>,
    alias: Option<String>,
}

struct CaSpec {
    ca_file: String,
    alias: Option<String>,
}

fn parse_cert_spec(s: &str) -> CertSpec {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    match parts.len() {
        1 => CertSpec {
            cert_file: parts[0].to_string(),
            key_file: None,
            alias: None,
        },
        2 => CertSpec {
            cert_file: parts[0].to_string(),
            key_file: if parts[1].is_empty() {
                None
            } else {
                Some(parts[1].to_string())
            },
            alias: None,
        },
        3 => CertSpec {
            cert_file: parts[0].to_string(),
            key_file: if parts[1].is_empty() {
                None
            } else {
                Some(parts[1].to_string())
            },
            alias: if parts[2].is_empty() {
                None
            } else {
                Some(parts[2].to_string())
            },
        },
        _ => unreachable!(),
    }
}

fn parse_ca_spec(s: &str) -> CaSpec {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    match parts.len() {
        1 => CaSpec {
            ca_file: parts[0].to_string(),
            alias: None,
        },
        2 => CaSpec {
            ca_file: parts[0].to_string(),
            alias: if parts[1].is_empty() {
                None
            } else {
                Some(parts[1].to_string())
            },
        },
        _ => unreachable!(),
    }
}

fn default_cert_alias(index: usize) -> String {
    if index == 0 {
        "server".to_string()
    } else {
        format!("server-{}", index)
    }
}

fn default_ca_alias(index: usize) -> String {
    if index == 0 {
        "ca".to_string()
    } else {
        format!("ca-{}", index)
    }
}

fn create_jks_keystore(
    certs: &[CertSpec],
    cas: &[CaSpec],
    password: &str,
    input_jks: Option<(&[u8], &str)>,
) -> Result<Vec<u8>, String> {
    let mut jks = if let Some((data, input_pw)) = input_jks {
        JKS::unmarshal(data, input_pw)
            .map_err(|e| format!("failed to read input keystore: {}", e))?
    } else {
        JKS::new()
    };

    for (i, spec) in certs.iter().enumerate() {
        let cert_pem = fs::read(&spec.cert_file)
            .map_err(|e| format!("failed to read cert file '{}': {}", spec.cert_file, e))?;
        let cert_chain = keystore::parse_pem_certificates(&cert_pem)
            .map_err(|e| format!("failed to parse cert '{}': {}", spec.cert_file, e))?;

        let alias = spec.alias.clone().unwrap_or_else(|| default_cert_alias(i));

        if let Some(ref key_file) = spec.key_file {
            let key_pem = fs::read(key_file)
                .map_err(|e| format!("failed to read key file '{}': {}", key_file, e))?;
            let pkcs8_key = keystore::parse_pem_private_key(&key_pem)
                .map_err(|e| format!("failed to parse key '{}': {}", key_file, e))?;
            jks.add_private_key(&alias, &pkcs8_key, cert_chain)
                .map_err(|e| e.to_string())?;
        } else {
            // No key, add certs as trusted certs
            for (j, cert_der) in cert_chain.into_iter().enumerate() {
                let cert_alias = if j == 0 {
                    alias.clone()
                } else {
                    format!("{}-{}", alias, j)
                };
                jks.add_trusted_cert(&cert_alias, &cert_der)
                    .map_err(|e| e.to_string())?;
            }
        }
    }

    for (i, spec) in cas.iter().enumerate() {
        let ca_pem = fs::read(&spec.ca_file)
            .map_err(|e| format!("failed to read CA file '{}': {}", spec.ca_file, e))?;
        let ca_certs = keystore::parse_pem_certificates(&ca_pem)
            .map_err(|e| format!("failed to parse CA cert '{}': {}", spec.ca_file, e))?;

        let base_alias = spec.alias.clone().unwrap_or_else(|| default_ca_alias(i));

        for (j, cert_der) in ca_certs.into_iter().enumerate() {
            let cert_alias = if j == 0 {
                base_alias.clone()
            } else {
                format!("{}-{}", base_alias, j)
            };
            jks.add_trusted_cert(&cert_alias, &cert_der)
                .map_err(|e| e.to_string())?;
        }
    }

    jks.marshal(password).map_err(|e| e.to_string())
}

fn main() {
    let cli = Cli::parse();

    if let Some(Commands::Version) = cli.command {
        println!(
            "pem2jks {} (commit: {}, built: {})",
            get_version(),
            get_commit(),
            get_build_date()
        );
        return;
    }

    if cli.cert.is_empty() && cli.ca.is_empty() && cli.input.is_none() {
        eprintln!("error: at least one --cert, --ca, or --input is required");
        process::exit(1);
    }

    let password = match resolve_password(&cli) {
        Ok(pw) => pw,
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    };

    let cert_specs: Vec<CertSpec> = cli.cert.iter().map(|s| parse_cert_spec(s)).collect();
    let ca_specs: Vec<CaSpec> = cli.ca.iter().map(|s| parse_ca_spec(s)).collect();

    let input_data = cli.input.as_ref().map(|input_path| {
        fs::read(input_path).unwrap_or_else(|e| {
            eprintln!(
                "error: failed to read input keystore '{}': {}",
                input_path, e
            );
            process::exit(1);
        })
    });

    let input_pw = cli.input_password.as_deref().unwrap_or(&password);

    let input_jks = input_data.as_ref().map(|data| (data.as_slice(), input_pw));

    match create_jks_keystore(&cert_specs, &ca_specs, &password, input_jks) {
        Ok(data) => {
            if let Err(e) = fs::write(&cli.output, data) {
                eprintln!("error: failed to write output file '{}': {}", cli.output, e);
                process::exit(1);
            }
            println!("Created keystore: {}", cli.output);
        }
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cert_spec_one_part() {
        let spec = parse_cert_spec("cert.pem");
        assert_eq!(spec.cert_file, "cert.pem");
        assert!(spec.key_file.is_none());
        assert!(spec.alias.is_none());
    }

    #[test]
    fn test_parse_cert_spec_two_parts() {
        let spec = parse_cert_spec("cert.pem:key.pem");
        assert_eq!(spec.cert_file, "cert.pem");
        assert_eq!(spec.key_file.as_deref(), Some("key.pem"));
        assert!(spec.alias.is_none());
    }

    #[test]
    fn test_parse_cert_spec_three_parts() {
        let spec = parse_cert_spec("cert.pem:key.pem:myalias");
        assert_eq!(spec.cert_file, "cert.pem");
        assert_eq!(spec.key_file.as_deref(), Some("key.pem"));
        assert_eq!(spec.alias.as_deref(), Some("myalias"));
    }

    #[test]
    fn test_parse_cert_spec_empty_key() {
        let spec = parse_cert_spec("cert.pem::myalias");
        assert_eq!(spec.cert_file, "cert.pem");
        assert!(spec.key_file.is_none());
        assert_eq!(spec.alias.as_deref(), Some("myalias"));
    }

    #[test]
    fn test_parse_ca_spec_one_part() {
        let spec = parse_ca_spec("ca.pem");
        assert_eq!(spec.ca_file, "ca.pem");
        assert!(spec.alias.is_none());
    }

    #[test]
    fn test_parse_ca_spec_two_parts() {
        let spec = parse_ca_spec("ca.pem:myca");
        assert_eq!(spec.ca_file, "ca.pem");
        assert_eq!(spec.alias.as_deref(), Some("myca"));
    }

    #[test]
    fn test_default_cert_alias() {
        assert_eq!(default_cert_alias(0), "server");
        assert_eq!(default_cert_alias(1), "server-1");
        assert_eq!(default_cert_alias(2), "server-2");
    }

    #[test]
    fn test_default_ca_alias() {
        assert_eq!(default_ca_alias(0), "ca");
        assert_eq!(default_ca_alias(1), "ca-1");
        assert_eq!(default_ca_alias(2), "ca-2");
    }
}
