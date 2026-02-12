//! Integration tests that verify JKS keystores using Java keytool via testcontainers.
//!
//! These tests create JKS keystores using the library, then verify them with
//! Java's keytool inside a Docker container (eclipse-temurin JDK).
//!
//! Run with: cargo test --test integration_test -- --ignored
//! Requires Docker.

use pem2jks::keystore::{self, JKS};
use testcontainers::core::{ExecCommand, WaitFor};
use testcontainers::runners::SyncRunner;
use testcontainers::{GenericImage, ImageExt};

fn generate_ca_cert() -> (Vec<u8>, Vec<u8>) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test CA");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Test Org");

    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();
    (cert_pem, key_pem)
}

fn generate_server_cert(ca_cert_pem: &[u8], ca_key_pem: &[u8], cn: &str) -> (Vec<u8>, Vec<u8>) {
    let ca_key_pair = rcgen::KeyPair::from_pem(&String::from_utf8_lossy(ca_key_pem)).unwrap();
    let issuer =
        rcgen::Issuer::from_ca_cert_pem(&String::from_utf8_lossy(ca_cert_pem), &ca_key_pair)
            .unwrap();

    let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Test Org");

    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key_pair, &issuer).unwrap();

    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();
    (cert_pem, key_pem)
}

/// Helper to verify a keystore using Java keytool via testcontainers.
/// Creates a fresh container with the keystore data pre-loaded via with_copy_to.
/// Returns the entry count reported by keytool.
fn verify_keystore_with_keytool(name: &str, keystore_data: &[u8], password: &str) -> usize {
    let container_path = format!("/tmp/{}", name);

    let container = GenericImage::new("eclipse-temurin", "21-jdk-alpine")
        .with_wait_for(WaitFor::seconds(2))
        .with_copy_to(container_path.clone(), keystore_data.to_vec())
        .with_cmd(vec!["sleep", "infinity"])
        .start()
        .expect("Failed to start Java container");

    // Run keytool to list entries
    let keytool_cmd = format!(
        "keytool -list -keystore {} -storepass {}",
        container_path, password
    );
    let mut result = container
        .exec(ExecCommand::new(vec![
            "sh".to_string(),
            "-c".to_string(),
            keytool_cmd,
        ]))
        .expect("exec failed");

    let stdout = result.stdout_to_vec().expect("read stdout");
    let stdout_str = String::from_utf8_lossy(&stdout);

    let exit_code = result.exit_code().expect("exit code");
    if exit_code != Some(0) {
        let stderr = result.stderr_to_vec().expect("read stderr");
        panic!(
            "keytool failed with exit code {:?}\nstdout: {}\nstderr: {}",
            exit_code,
            stdout_str,
            String::from_utf8_lossy(&stderr)
        );
    }

    // Parse entry count from "Your keystore contains N entries"
    let mut entry_count = 0;
    for line in stdout_str.lines() {
        if line.contains("Your keystore contains") {
            let digits: String = line.chars().filter(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = digits.parse::<usize>() {
                entry_count = n;
            }
            break;
        }
    }

    entry_count
}

// All integration tests are ignored by default (require Docker)
// Run with: cargo test --test integration_test -- --ignored

#[test]
#[ignore]
fn integration_jks_with_private_key() {
    let (ca_cert_pem, ca_key_pem) = generate_ca_cert();
    let (tls_cert_pem, tls_key_pem) = generate_server_cert(&ca_cert_pem, &ca_key_pem, "localhost");

    let cert_chain = keystore::parse_pem_certificates(&tls_cert_pem).expect("parse cert");
    let pkcs8_key = keystore::parse_pem_private_key(&tls_key_pem).expect("parse key");

    let mut jks = JKS::new();
    jks.add_private_key("server", &pkcs8_key, cert_chain)
        .expect("add private key");

    let data = jks.marshal("changeit").expect("marshal");
    let count = verify_keystore_with_keytool("test-pk.jks", &data, "changeit");
    assert!(count >= 1, "Expected at least 1 entry, got {}", count);
}

#[test]
#[ignore]
fn integration_jks_with_ca() {
    let (ca_cert_pem, ca_key_pem) = generate_ca_cert();
    let (tls_cert_pem, tls_key_pem) = generate_server_cert(&ca_cert_pem, &ca_key_pem, "localhost");

    let cert_chain = keystore::parse_pem_certificates(&tls_cert_pem).expect("parse cert");
    let pkcs8_key = keystore::parse_pem_private_key(&tls_key_pem).expect("parse key");
    let ca_certs = keystore::parse_pem_certificates(&ca_cert_pem).expect("parse CA");

    let mut jks = JKS::new();
    jks.add_private_key("server", &pkcs8_key, cert_chain)
        .expect("add private key");
    for (i, cert) in ca_certs.into_iter().enumerate() {
        let alias = if i == 0 {
            "ca".to_string()
        } else {
            format!("ca-{}", i)
        };
        jks.add_trusted_cert(&alias, &cert).expect("add CA");
    }

    let data = jks.marshal("changeit").expect("marshal");
    let count = verify_keystore_with_keytool("test-ca.jks", &data, "changeit");
    assert_eq!(count, 2, "Expected 2 entries (1 key + 1 CA)");
}

#[test]
#[ignore]
fn integration_jks_truststore() {
    let (ca_cert_pem, _) = generate_ca_cert();
    let ca_certs = keystore::parse_pem_certificates(&ca_cert_pem).expect("parse CA");

    let mut jks = JKS::new();
    for (i, cert) in ca_certs.into_iter().enumerate() {
        let alias = if i == 0 {
            "ca".to_string()
        } else {
            format!("ca-{}", i)
        };
        jks.add_trusted_cert(&alias, &cert).expect("add CA");
    }

    let data = jks.marshal("changeit").expect("marshal");
    let count = verify_keystore_with_keytool("truststore.jks", &data, "changeit");
    assert_eq!(count, 1, "Expected 1 CA entry");
}

#[test]
#[ignore]
fn integration_jks_multiple_keys() {
    let (ca_cert_pem, ca_key_pem) = generate_ca_cert();
    let (cert1_pem, key1_pem) = generate_server_cert(&ca_cert_pem, &ca_key_pem, "app1.example.com");
    let (cert2_pem, key2_pem) = generate_server_cert(&ca_cert_pem, &ca_key_pem, "app2.example.com");

    let chain1 = keystore::parse_pem_certificates(&cert1_pem).expect("parse cert1");
    let key1 = keystore::parse_pem_private_key(&key1_pem).expect("parse key1");
    let chain2 = keystore::parse_pem_certificates(&cert2_pem).expect("parse cert2");
    let key2 = keystore::parse_pem_private_key(&key2_pem).expect("parse key2");

    let mut jks = JKS::new();
    jks.add_private_key("server1", &key1, chain1)
        .expect("add key1");
    jks.add_private_key("server2", &key2, chain2)
        .expect("add key2");

    let data = jks.marshal("changeit").expect("marshal");
    let count = verify_keystore_with_keytool("multi-keys.jks", &data, "changeit");
    assert_eq!(count, 2, "Expected 2 entries");
}

#[test]
#[ignore]
fn integration_jks_multiple_cas() {
    let (ca1_pem, _) = generate_ca_cert();
    let (ca2_pem, _) = generate_ca_cert();

    let ca1_certs = keystore::parse_pem_certificates(&ca1_pem).expect("parse CA1");
    let ca2_certs = keystore::parse_pem_certificates(&ca2_pem).expect("parse CA2");

    let mut jks = JKS::new();
    jks.add_trusted_cert("ca1", &ca1_certs[0]).expect("add CA1");
    jks.add_trusted_cert("ca2", &ca2_certs[0]).expect("add CA2");

    let data = jks.marshal("changeit").expect("marshal");
    let count = verify_keystore_with_keytool("multi-ca.jks", &data, "changeit");
    assert_eq!(count, 2, "Expected 2 CA entries");
}

#[test]
#[ignore]
fn integration_jks_append_private_key() {
    let (ca_cert_pem, ca_key_pem) = generate_ca_cert();
    let (cert_pem, key_pem) = generate_server_cert(&ca_cert_pem, &ca_key_pem, "localhost");

    let chain = keystore::parse_pem_certificates(&cert_pem).expect("parse cert");
    let key = keystore::parse_pem_private_key(&key_pem).expect("parse key");

    // Create initial JKS
    let mut jks1 = JKS::new();
    jks1.add_private_key("initial-key", &key, chain)
        .expect("add initial key");
    let data1 = jks1.marshal("changeit").expect("marshal");

    let count1 = verify_keystore_with_keytool("append-initial.jks", &data1, "changeit");
    assert_eq!(count1, 1, "Expected 1 entry initially");

    // Append another key
    let mut jks2 = JKS::unmarshal(&data1, "changeit").expect("unmarshal");
    let (cert2_pem, key2_pem) = generate_server_cert(&ca_cert_pem, &ca_key_pem, "app2.example.com");
    let chain2 = keystore::parse_pem_certificates(&cert2_pem).expect("parse cert2");
    let key2 = keystore::parse_pem_private_key(&key2_pem).expect("parse key2");
    jks2.add_private_key("appended-key", &key2, chain2)
        .expect("add appended key");
    let data2 = jks2.marshal("changeit").expect("marshal");

    let count2 = verify_keystore_with_keytool("append-final.jks", &data2, "changeit");
    assert_eq!(count2, 2, "Expected 2 entries after append");
}

#[test]
#[ignore]
fn integration_jks_append_ca() {
    let (ca_cert_pem, ca_key_pem) = generate_ca_cert();
    let (cert_pem, key_pem) = generate_server_cert(&ca_cert_pem, &ca_key_pem, "localhost");

    let chain = keystore::parse_pem_certificates(&cert_pem).expect("parse cert");
    let key = keystore::parse_pem_private_key(&key_pem).expect("parse key");

    // Create initial JKS with private key
    let mut jks1 = JKS::new();
    jks1.add_private_key("server", &key, chain)
        .expect("add key");
    let data1 = jks1.marshal("changeit").expect("marshal");

    // Append CA
    let mut jks2 = JKS::unmarshal(&data1, "changeit").expect("unmarshal");
    let ca_certs = keystore::parse_pem_certificates(&ca_cert_pem).expect("parse CA");
    jks2.add_trusted_cert("ca", &ca_certs[0]).expect("add CA");
    let data2 = jks2.marshal("changeit").expect("marshal");

    let count = verify_keystore_with_keytool("append-ca.jks", &data2, "changeit");
    assert_eq!(count, 2, "Expected 2 entries (1 key + 1 CA)");
}
