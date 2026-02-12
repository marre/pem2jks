use der::asn1::{Null, ObjectIdentifier, OctetStringRef};
use der::{Decode, Encode, Reader, Sequence, SliceReader};
use digest::Digest;
use rand::Rng;
use sha1::Sha1;
use std::fmt;
use std::io::{self, Read, Write};

// JKS constants
const JKS_MAGIC: u32 = 0xFEEDFEED;
const JKS_VERSION: u32 = 2;
const TAG_PRIVATE_KEY: u32 = 1;
const TAG_TRUSTED_CERT: u32 = 2;
const SIGNATURE_WHITENER: &[u8] = b"Mighty Aphrodite";

/// Sun JKS proprietary algorithm OID: 1.3.6.1.4.1.42.2.17.1.1
const SUN_JKS_ALGO_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.42.2.17.1.1");

// ASN.1 structures for EncryptedPrivateKeyInfo
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier,
    parameters: Null,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct EncryptedPrivateKeyInfoAsn1<'a> {
    algorithm: AlgorithmIdentifier,
    encrypted_data: OctetStringRef<'a>,
}

/// Error type for JKS operations.
#[derive(Debug)]
pub enum JksError {
    InvalidMagic,
    InvalidVersion,
    IntegrityCheckFailed,
    DecryptionCheckFailed,
    InvalidAlgorithm,
    EmptyAlias,
    EmptyPrivateKey,
    EmptyCertChain,
    DuplicateAlias(String),
    InvalidCertificate(String),
    InvalidPem(String),
    UnsupportedKeyType(String),
    Io(io::Error),
    Asn1(String),
    Other(String),
}

impl fmt::Display for JksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JksError::InvalidMagic => write!(f, "invalid JKS magic number"),
            JksError::InvalidVersion => write!(f, "invalid JKS version"),
            JksError::IntegrityCheckFailed => write!(f, "integrity check failed (wrong password?)"),
            JksError::DecryptionCheckFailed => {
                write!(f, "private key decryption check failed (wrong password?)")
            }
            JksError::InvalidAlgorithm => write!(f, "invalid encryption algorithm"),
            JksError::EmptyAlias => write!(f, "alias cannot be empty"),
            JksError::EmptyPrivateKey => write!(f, "private key cannot be empty"),
            JksError::EmptyCertChain => write!(f, "certificate chain cannot be empty"),
            JksError::DuplicateAlias(a) => write!(f, "duplicate alias: {}", a),
            JksError::InvalidCertificate(msg) => write!(f, "invalid certificate: {}", msg),
            JksError::InvalidPem(msg) => write!(f, "invalid PEM: {}", msg),
            JksError::UnsupportedKeyType(msg) => write!(f, "unsupported key type: {}", msg),
            JksError::Io(e) => write!(f, "I/O error: {}", e),
            JksError::Asn1(msg) => write!(f, "ASN.1 error: {}", msg),
            JksError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for JksError {}

impl From<io::Error> for JksError {
    fn from(e: io::Error) -> Self {
        JksError::Io(e)
    }
}

impl From<der::Error> for JksError {
    fn from(e: der::Error) -> Self {
        JksError::Asn1(e.to_string())
    }
}

impl From<pem::PemError> for JksError {
    fn from(e: pem::PemError) -> Self {
        JksError::InvalidPem(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, JksError>;

/// A JKS keystore entry.
pub enum Entry {
    PrivateKey(PrivateKeyEntry),
    TrustedCert(TrustedCertEntry),
}

/// A private key entry in a JKS keystore.
pub struct PrivateKeyEntry {
    pub alias: String,
    pub timestamp: i64,           // milliseconds since epoch
    pub priv_key: Vec<u8>,        // PKCS#8 DER
    pub cert_chain: Vec<Vec<u8>>, // DER-encoded certs
}

/// A trusted certificate entry in a JKS keystore.
pub struct TrustedCertEntry {
    pub alias: String,
    pub timestamp: i64,
    pub cert: Vec<u8>, // DER-encoded cert
}

/// A Java KeyStore (JKS format).
pub struct JKS {
    pub entries: Vec<Entry>,
}

impl JKS {
    /// Create a new empty JKS keystore.
    pub fn new() -> Self {
        JKS {
            entries: Vec::new(),
        }
    }

    /// Check if an alias already exists (case-insensitive).
    pub fn has_alias(&self, alias: &str) -> bool {
        let lower = alias.to_lowercase();
        self.entries.iter().any(|e| {
            let a = match e {
                Entry::PrivateKey(pk) => &pk.alias,
                Entry::TrustedCert(tc) => &tc.alias,
            };
            a.to_lowercase() == lower
        })
    }

    /// Add a private key entry with current timestamp.
    pub fn add_private_key(
        &mut self,
        alias: &str,
        pkcs8_key: &[u8],
        cert_chain: Vec<Vec<u8>>,
    ) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        self.add_private_key_with_timestamp(alias, pkcs8_key, cert_chain, timestamp)
    }

    /// Add a private key entry with a specific timestamp.
    pub fn add_private_key_with_timestamp(
        &mut self,
        alias: &str,
        pkcs8_key: &[u8],
        cert_chain: Vec<Vec<u8>>,
        timestamp: i64,
    ) -> Result<()> {
        if alias.is_empty() {
            return Err(JksError::EmptyAlias);
        }
        if pkcs8_key.is_empty() {
            return Err(JksError::EmptyPrivateKey);
        }
        if cert_chain.is_empty() {
            return Err(JksError::EmptyCertChain);
        }
        if self.has_alias(alias) {
            return Err(JksError::DuplicateAlias(alias.to_string()));
        }
        // Validate each cert in the chain
        for (i, cert_der) in cert_chain.iter().enumerate() {
            validate_certificate(cert_der)
                .map_err(|e| JksError::InvalidCertificate(format!("cert chain[{}]: {}", i, e)))?;
        }

        self.entries.push(Entry::PrivateKey(PrivateKeyEntry {
            alias: alias.to_string(),
            timestamp,
            priv_key: pkcs8_key.to_vec(),
            cert_chain,
        }));
        Ok(())
    }

    /// Add a trusted certificate entry with current timestamp.
    pub fn add_trusted_cert(&mut self, alias: &str, cert_der: &[u8]) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        self.add_trusted_cert_with_timestamp(alias, cert_der, timestamp)
    }

    /// Add a trusted certificate entry with a specific timestamp.
    pub fn add_trusted_cert_with_timestamp(
        &mut self,
        alias: &str,
        cert_der: &[u8],
        timestamp: i64,
    ) -> Result<()> {
        if alias.is_empty() {
            return Err(JksError::EmptyAlias);
        }
        if self.has_alias(alias) {
            return Err(JksError::DuplicateAlias(alias.to_string()));
        }
        validate_certificate(cert_der)?;

        self.entries.push(Entry::TrustedCert(TrustedCertEntry {
            alias: alias.to_string(),
            timestamp,
            cert: cert_der.to_vec(),
        }));
        Ok(())
    }

    /// Serialize the keystore to JKS binary format.
    pub fn marshal(&self, password: &str) -> Result<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::new();

        // Header
        write_u32(&mut buf, JKS_MAGIC)?;
        write_u32(&mut buf, JKS_VERSION)?;
        write_u32(&mut buf, self.entries.len() as u32)?;

        for entry in &self.entries {
            match entry {
                Entry::PrivateKey(pk) => {
                    write_u32(&mut buf, TAG_PRIVATE_KEY)?;
                    write_utf(&mut buf, &pk.alias)?;
                    write_i64(&mut buf, pk.timestamp)?;

                    // Encrypt the private key
                    let encrypted = encrypt_private_key(&pk.priv_key, password)?;
                    let encapsulated = encapsulate_private_key(&encrypted)?;
                    write_byte_array(&mut buf, &encapsulated)?;

                    // Cert chain
                    write_u32(&mut buf, pk.cert_chain.len() as u32)?;
                    for cert in &pk.cert_chain {
                        write_utf(&mut buf, "X.509")?;
                        write_byte_array(&mut buf, cert)?;
                    }
                }
                Entry::TrustedCert(tc) => {
                    write_u32(&mut buf, TAG_TRUSTED_CERT)?;
                    write_utf(&mut buf, &tc.alias)?;
                    write_i64(&mut buf, tc.timestamp)?;
                    write_utf(&mut buf, "X.509")?;
                    write_byte_array(&mut buf, &tc.cert)?;
                }
            }
        }

        // Integrity hash
        let hash = compute_integrity_hash(password, &buf);
        buf.extend_from_slice(&hash);

        Ok(buf)
    }

    /// Deserialize a JKS keystore from binary data.
    pub fn unmarshal(data: &[u8], password: &str) -> Result<JKS> {
        if data.len() < 12 {
            return Err(JksError::Other("data too short".to_string()));
        }

        // Verify integrity hash (last 20 bytes)
        if data.len() < 20 {
            return Err(JksError::IntegrityCheckFailed);
        }
        let (keystore_data, stored_hash) = data.split_at(data.len() - 20);
        let computed_hash = compute_integrity_hash(password, keystore_data);
        if computed_hash != stored_hash {
            return Err(JksError::IntegrityCheckFailed);
        }

        let mut cursor = keystore_data as &[u8];

        let magic = read_u32(&mut cursor)?;
        if magic != JKS_MAGIC {
            return Err(JksError::InvalidMagic);
        }

        let version = read_u32(&mut cursor)?;
        if version != JKS_VERSION {
            return Err(JksError::InvalidVersion);
        }

        let entry_count = read_u32(&mut cursor)?;
        let mut entries = Vec::with_capacity(entry_count as usize);

        for _ in 0..entry_count {
            let tag = read_u32(&mut cursor)?;
            match tag {
                TAG_PRIVATE_KEY => {
                    let alias = read_utf(&mut cursor)?;
                    let timestamp = read_i64(&mut cursor)?;

                    let encapsulated = read_byte_array(&mut cursor)?;
                    let encrypted = decapsulate_private_key(&encapsulated)?;
                    let priv_key = decrypt_private_key(&encrypted, password)?;

                    let chain_len = read_u32(&mut cursor)?;
                    let mut cert_chain = Vec::with_capacity(chain_len as usize);
                    for _ in 0..chain_len {
                        let _cert_type = read_utf(&mut cursor)?;
                        let cert_data = read_byte_array(&mut cursor)?;
                        cert_chain.push(cert_data);
                    }

                    entries.push(Entry::PrivateKey(PrivateKeyEntry {
                        alias,
                        timestamp,
                        priv_key,
                        cert_chain,
                    }));
                }
                TAG_TRUSTED_CERT => {
                    let alias = read_utf(&mut cursor)?;
                    let timestamp = read_i64(&mut cursor)?;
                    let _cert_type = read_utf(&mut cursor)?;
                    let cert = read_byte_array(&mut cursor)?;

                    entries.push(Entry::TrustedCert(TrustedCertEntry {
                        alias,
                        timestamp,
                        cert,
                    }));
                }
                _ => {
                    return Err(JksError::Other(format!("unknown entry tag: {}", tag)));
                }
            }
        }

        Ok(JKS { entries })
    }
}

impl Default for JKS {
    fn default() -> Self {
        Self::new()
    }
}

// --- Binary I/O helpers (big-endian) ---

fn write_u32(w: &mut Vec<u8>, v: u32) -> Result<()> {
    w.write_all(&v.to_be_bytes())?;
    Ok(())
}

fn write_i64(w: &mut Vec<u8>, v: i64) -> Result<()> {
    w.write_all(&v.to_be_bytes())?;
    Ok(())
}

fn write_utf(w: &mut Vec<u8>, s: &str) -> Result<()> {
    let bytes = s.as_bytes();
    let len = bytes.len() as u16;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(bytes)?;
    Ok(())
}

fn write_byte_array(w: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(data)?;
    Ok(())
}

fn read_u32(r: &mut &[u8]) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn read_i64(r: &mut &[u8]) -> Result<i64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(i64::from_be_bytes(buf))
}

fn read_utf(r: &mut &[u8]) -> Result<String> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|e| JksError::Other(format!("invalid UTF-8: {}", e)))
}

fn read_byte_array(r: &mut &[u8]) -> Result<Vec<u8>> {
    let len = read_u32(r)? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

// --- UTF-16BE conversion ---

fn password_to_utf16be(password: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for c in password.chars() {
        let cp = c as u32;
        if cp <= 0xFFFF {
            result.push((cp >> 8) as u8);
            result.push(cp as u8);
        } else {
            // Surrogate pair
            let adjusted = cp - 0x10000;
            let high = 0xD800 + (adjusted >> 10);
            let low = 0xDC00 + (adjusted & 0x3FF);
            result.push((high >> 8) as u8);
            result.push(high as u8);
            result.push((low >> 8) as u8);
            result.push(low as u8);
        }
    }
    result
}

// --- Integrity hash ---

fn compute_integrity_hash(password: &str, data: &[u8]) -> Vec<u8> {
    let password_bytes = password_to_utf16be(password);
    let mut hasher = Sha1::new();
    hasher.update(&password_bytes);
    hasher.update(SIGNATURE_WHITENER);
    hasher.update(data);
    hasher.finalize().to_vec()
}

// --- Private key encryption/decryption (Sun JKS proprietary) ---

fn encrypt_private_key(plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
    let password_bytes = password_to_utf16be(password);

    // Generate 20-byte random IV
    let mut rng = rand::thread_rng();
    let mut iv = [0u8; 20];
    rng.fill(&mut iv);

    // Generate keystream and XOR
    let encrypted = jks_crypt(&password_bytes, &iv, plaintext);

    // Check hash: SHA1(password_utf16be + plaintext)
    let mut check_hasher = Sha1::new();
    check_hasher.update(&password_bytes);
    check_hasher.update(plaintext);
    let check = check_hasher.finalize();

    // Result: IV + encrypted + check
    let mut result = Vec::with_capacity(20 + encrypted.len() + 20);
    result.extend_from_slice(&iv);
    result.extend_from_slice(&encrypted);
    result.extend_from_slice(&check);
    Ok(result)
}

fn decrypt_private_key(data: &[u8], password: &str) -> Result<Vec<u8>> {
    if data.len() < 40 {
        return Err(JksError::Other("encrypted key data too short".to_string()));
    }

    let password_bytes = password_to_utf16be(password);
    let iv = &data[..20];
    let encrypted = &data[20..data.len() - 20];
    let stored_check = &data[data.len() - 20..];

    // Decrypt
    let plaintext = jks_crypt(&password_bytes, iv, encrypted);

    // Verify check
    let mut check_hasher = Sha1::new();
    check_hasher.update(&password_bytes);
    check_hasher.update(&plaintext);
    let computed_check = check_hasher.finalize();

    if computed_check[..] != stored_check[..] {
        return Err(JksError::DecryptionCheckFailed);
    }

    Ok(plaintext)
}

/// XOR plaintext/ciphertext with iterative SHA1 keystream.
fn jks_crypt(password_bytes: &[u8], iv: &[u8], input: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; input.len()];
    let mut prev_hash = iv.to_vec();
    let mut pos = 0;

    while pos < input.len() {
        let mut hasher = Sha1::new();
        hasher.update(password_bytes);
        hasher.update(&prev_hash);
        let hash = hasher.finalize();
        let hash_bytes = &hash[..];

        for &hash_byte in hash_bytes.iter().take(20) {
            if pos >= input.len() {
                break;
            }
            output[pos] = input[pos] ^ hash_byte;
            pos += 1;
        }

        prev_hash = hash_bytes.to_vec();
    }

    output
}

// --- ASN.1 EncryptedPrivateKeyInfo encapsulation ---

fn encapsulate_private_key(encrypted_data: &[u8]) -> Result<Vec<u8>> {
    let octet_string =
        OctetStringRef::new(encrypted_data).map_err(|e| JksError::Asn1(e.to_string()))?;
    let epki = EncryptedPrivateKeyInfoAsn1 {
        algorithm: AlgorithmIdentifier {
            algorithm: SUN_JKS_ALGO_OID,
            parameters: Null,
        },
        encrypted_data: octet_string,
    };
    epki.to_der().map_err(|e| JksError::Asn1(e.to_string()))
}

fn decapsulate_private_key(data: &[u8]) -> Result<Vec<u8>> {
    let reader = SliceReader::new(data).map_err(|e| JksError::Asn1(e.to_string()))?;

    // Read outer SEQUENCE
    let header = reader
        .peek_header()
        .map_err(|e| JksError::Asn1(e.to_string()))?;
    if header.tag != der::Tag::Sequence {
        return Err(JksError::Asn1("expected SEQUENCE".to_string()));
    }

    let epki =
        EncryptedPrivateKeyInfoAsn1::from_der(data).map_err(|e| JksError::Asn1(e.to_string()))?;

    if epki.algorithm.algorithm != SUN_JKS_ALGO_OID {
        return Err(JksError::InvalidAlgorithm);
    }

    Ok(epki.encrypted_data.as_bytes().to_vec())
}

// --- Certificate validation ---

fn validate_certificate(cert_der: &[u8]) -> Result<()> {
    x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| JksError::InvalidCertificate(e.to_string()))?;
    Ok(())
}

// --- PEM parsing ---

/// Parse PEM-encoded certificates, returning DER bytes for each.
pub fn parse_pem_certificates(pem_data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let pems = pem::parse_many(pem_data)?;
    if pems.is_empty() {
        return Err(JksError::InvalidPem("no PEM blocks found".to_string()));
    }

    let mut certs = Vec::new();
    for p in &pems {
        if p.tag() != "CERTIFICATE" {
            return Err(JksError::InvalidPem(format!(
                "expected CERTIFICATE, got {}",
                p.tag()
            )));
        }
        let der_bytes = p.contents().to_vec();
        validate_certificate(&der_bytes)?;
        certs.push(der_bytes);
    }
    Ok(certs)
}

/// Parse a PEM-encoded private key, returning PKCS#8 DER bytes.
/// Supports PRIVATE KEY (PKCS#8), RSA PRIVATE KEY (PKCS#1), EC PRIVATE KEY (SEC1).
pub fn parse_pem_private_key(pem_data: &[u8]) -> Result<Vec<u8>> {
    let p = pem::parse(pem_data)?;
    match p.tag() {
        "PRIVATE KEY" => {
            // Already PKCS#8
            Ok(p.contents().to_vec())
        }
        "RSA PRIVATE KEY" => {
            // PKCS#1 → PKCS#8
            use rsa::pkcs1::DecodeRsaPrivateKey;
            use rsa::RsaPrivateKey;
            let rsa_key = RsaPrivateKey::from_pkcs1_der(p.contents())
                .map_err(|e| JksError::InvalidPem(format!("invalid PKCS#1 RSA key: {}", e)))?;
            use rsa::pkcs8::EncodePrivateKey;
            let pkcs8 = rsa_key
                .to_pkcs8_der()
                .map_err(|e| JksError::InvalidPem(format!("PKCS#1→PKCS#8 conversion: {}", e)))?;
            Ok(pkcs8.as_bytes().to_vec())
        }
        "EC PRIVATE KEY" => {
            // SEC1 → PKCS#8
            let secret_key = p256::SecretKey::from_sec1_der(p.contents())
                .map_err(|e| JksError::InvalidPem(format!("invalid SEC1 EC key: {}", e)))?;
            use p256::pkcs8::EncodePrivateKey;
            let pkcs8 = secret_key
                .to_pkcs8_der()
                .map_err(|e| JksError::InvalidPem(format!("SEC1→PKCS#8 conversion: {}", e)))?;
            Ok(pkcs8.as_bytes().to_vec())
        }
        other => Err(JksError::UnsupportedKeyType(format!(
            "unsupported PEM tag: {}",
            other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    fn generate_rsa_cert_and_key() -> (Vec<u8>, Vec<u8>) {
        use rsa::pkcs8::EncodePrivateKey;
        let mut rng = rand::thread_rng();
        let rsa_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pkcs8_der = rsa_key.to_pkcs8_der().unwrap();
        let pkcs8_bytes = pkcs8_der.as_bytes();
        let private_key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8_bytes.to_vec()),
        );
        let key_pair =
            KeyPair::from_der_and_sign_algo(&private_key_der, &rcgen::PKCS_RSA_SHA256).unwrap();
        let params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.der().to_vec(), key_pair.serialize_der())
    }

    fn generate_ec_cert_and_key() -> (Vec<u8>, Vec<u8>) {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.der().to_vec(), key_pair.serialize_der())
    }

    fn generate_cert_and_key() -> (Vec<u8>, Vec<u8>) {
        let key_pair = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.der().to_vec(), key_pair.serialize_der())
    }

    #[test]
    fn test_create_jks_with_rsa_key() {
        let (cert_der, key_der) = generate_rsa_cert_and_key();
        let mut jks = JKS::new();
        jks.add_private_key("server", &key_der, vec![cert_der])
            .unwrap();
        let data = jks.marshal("changeit").unwrap();
        // Verify magic number
        assert_eq!(data[0], 0xFE);
        assert_eq!(data[1], 0xED);
        assert_eq!(data[2], 0xFE);
        assert_eq!(data[3], 0xED);
    }

    #[test]
    fn test_create_jks_with_ec_key() {
        let (cert_der, key_der) = generate_ec_cert_and_key();
        let mut jks = JKS::new();
        jks.add_private_key("server", &key_der, vec![cert_der])
            .unwrap();
        let data = jks.marshal("changeit").unwrap();
        assert_eq!(&data[0..4], &[0xFE, 0xED, 0xFE, 0xED]);
    }

    #[test]
    fn test_create_jks_truststore() {
        let (cert_der, _) = generate_cert_and_key();
        let mut jks = JKS::new();
        jks.add_trusted_cert("ca", &cert_der).unwrap();
        let data = jks.marshal("changeit").unwrap();
        assert_eq!(&data[0..4], &[0xFE, 0xED, 0xFE, 0xED]);
    }

    #[test]
    fn test_parse_pkcs1_rsa_key() {
        let mut rng = rand::thread_rng();
        let rsa_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        use rsa::pkcs1::EncodeRsaPrivateKey;
        let pkcs1_der = rsa_key.to_pkcs1_der().unwrap();
        let pem_str = pem::encode(&pem::Pem::new("RSA PRIVATE KEY", pkcs1_der.as_bytes()));
        let result = parse_pem_private_key(pem_str.as_bytes()).unwrap();
        assert!(!result.is_empty());
        // Verify it's valid PKCS#8
        pkcs8::PrivateKeyInfo::from_der(&result).unwrap();
    }

    #[test]
    fn test_parse_ec_key() {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let pkcs8_der = key_pair.serialize_der();
        // Convert to SEC1 for testing
        use p256::pkcs8::DecodePrivateKey as _;
        let secret = p256::SecretKey::from_pkcs8_der(&pkcs8_der).unwrap();
        let sec1_der = secret.to_sec1_der().unwrap();
        let sec1_bytes: &[u8] = &sec1_der;
        let pem_str = pem::encode(&pem::Pem::new("EC PRIVATE KEY", sec1_bytes));
        let result = parse_pem_private_key(pem_str.as_bytes()).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_integrity_hash_determinism() {
        let hash1 = compute_integrity_hash("password", b"test data");
        let hash2 = compute_integrity_hash("password", b"test data");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_integrity_hash_password_sensitivity() {
        let hash1 = compute_integrity_hash("password1", b"test data");
        let hash2 = compute_integrity_hash("password2", b"test data");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_utf16be_encoding() {
        // ASCII
        let result = password_to_utf16be("AB");
        assert_eq!(result, vec![0x00, 0x41, 0x00, 0x42]);

        // Empty
        let result = password_to_utf16be("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_utf16be_encoding_supplementary() {
        // Character outside BMP (U+1F600 😀)
        let result = password_to_utf16be("\u{1F600}");
        // Surrogate pair: D83D DE00
        assert_eq!(result, vec![0xD8, 0x3D, 0xDE, 0x00]);
    }

    #[test]
    fn test_private_key_encryption_roundtrip() {
        let plaintext = b"test private key data for encryption roundtrip";
        let encrypted = encrypt_private_key(plaintext, "mypassword").unwrap();
        let decrypted = decrypt_private_key(&encrypted, "mypassword").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_marshal_unmarshal_private_key() {
        let (cert_der, key_der) = generate_cert_and_key();
        let mut jks = JKS::new();
        jks.add_private_key_with_timestamp("server", &key_der, vec![cert_der.clone()], 1000000)
            .unwrap();
        let data = jks.marshal("changeit").unwrap();
        let jks2 = JKS::unmarshal(&data, "changeit").unwrap();
        assert_eq!(jks2.entries.len(), 1);
        match &jks2.entries[0] {
            Entry::PrivateKey(pk) => {
                assert_eq!(pk.alias, "server");
                assert_eq!(pk.timestamp, 1000000);
                assert_eq!(pk.priv_key, key_der);
                assert_eq!(pk.cert_chain.len(), 1);
                assert_eq!(pk.cert_chain[0], cert_der);
            }
            _ => panic!("expected PrivateKey entry"),
        }
    }

    #[test]
    fn test_marshal_unmarshal_trusted_cert() {
        let (cert_der, _) = generate_cert_and_key();
        let mut jks = JKS::new();
        jks.add_trusted_cert_with_timestamp("ca", &cert_der, 2000000)
            .unwrap();
        let data = jks.marshal("changeit").unwrap();
        let jks2 = JKS::unmarshal(&data, "changeit").unwrap();
        assert_eq!(jks2.entries.len(), 1);
        match &jks2.entries[0] {
            Entry::TrustedCert(tc) => {
                assert_eq!(tc.alias, "ca");
                assert_eq!(tc.timestamp, 2000000);
                assert_eq!(tc.cert, cert_der);
            }
            _ => panic!("expected TrustedCert entry"),
        }
    }

    #[test]
    fn test_marshal_unmarshal_multiple_entries() {
        let (cert1, key1) = generate_cert_and_key();
        let (cert2, _) = generate_cert_and_key();
        let mut jks = JKS::new();
        jks.add_private_key_with_timestamp("server", &key1, vec![cert1], 1000)
            .unwrap();
        jks.add_trusted_cert_with_timestamp("ca", &cert2, 2000)
            .unwrap();
        let data = jks.marshal("changeit").unwrap();
        let jks2 = JKS::unmarshal(&data, "changeit").unwrap();
        assert_eq!(jks2.entries.len(), 2);
        assert!(matches!(&jks2.entries[0], Entry::PrivateKey(_)));
        assert!(matches!(&jks2.entries[1], Entry::TrustedCert(_)));
    }

    #[test]
    fn test_unmarshal_wrong_password() {
        let (cert_der, key_der) = generate_cert_and_key();
        let mut jks = JKS::new();
        jks.add_private_key("server", &key_der, vec![cert_der])
            .unwrap();
        let data = jks.marshal("correct").unwrap();
        let result = JKS::unmarshal(&data, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_add_private_key_empty_alias() {
        let (cert_der, key_der) = generate_cert_and_key();
        let mut jks = JKS::new();
        let result = jks.add_private_key("", &key_der, vec![cert_der]);
        assert!(matches!(result, Err(JksError::EmptyAlias)));
    }

    #[test]
    fn test_add_private_key_empty_key() {
        let (cert_der, _) = generate_cert_and_key();
        let mut jks = JKS::new();
        let result = jks.add_private_key("server", &[], vec![cert_der]);
        assert!(matches!(result, Err(JksError::EmptyPrivateKey)));
    }

    #[test]
    fn test_add_private_key_empty_chain() {
        let (_, key_der) = generate_cert_and_key();
        let mut jks = JKS::new();
        let result = jks.add_private_key("server", &key_der, vec![]);
        assert!(matches!(result, Err(JksError::EmptyCertChain)));
    }

    #[test]
    fn test_add_private_key_invalid_cert() {
        let (_, key_der) = generate_cert_and_key();
        let mut jks = JKS::new();
        let result = jks.add_private_key("server", &key_der, vec![vec![0x00, 0x01, 0x02]]);
        assert!(matches!(result, Err(JksError::InvalidCertificate(_))));
    }

    #[test]
    fn test_add_private_key_duplicate_alias() {
        let (cert1, key1) = generate_cert_and_key();
        let (cert2, key2) = generate_cert_and_key();
        let mut jks = JKS::new();
        jks.add_private_key("server", &key1, vec![cert1]).unwrap();
        let result = jks.add_private_key("server", &key2, vec![cert2]);
        assert!(matches!(result, Err(JksError::DuplicateAlias(_))));
    }

    #[test]
    fn test_add_private_key_case_insensitive_collision() {
        let (cert1, key1) = generate_cert_and_key();
        let (cert2, key2) = generate_cert_and_key();
        let mut jks = JKS::new();
        jks.add_private_key("Server", &key1, vec![cert1]).unwrap();
        let result = jks.add_private_key("SERVER", &key2, vec![cert2]);
        assert!(matches!(result, Err(JksError::DuplicateAlias(_))));
    }

    #[test]
    fn test_add_trusted_cert_empty_alias() {
        let (cert_der, _) = generate_cert_and_key();
        let mut jks = JKS::new();
        let result = jks.add_trusted_cert("", &cert_der);
        assert!(matches!(result, Err(JksError::EmptyAlias)));
    }

    #[test]
    fn test_add_trusted_cert_duplicate_alias() {
        let (cert1, _) = generate_cert_and_key();
        let (cert2, _) = generate_cert_and_key();
        let mut jks = JKS::new();
        jks.add_trusted_cert("ca", &cert1).unwrap();
        let result = jks.add_trusted_cert("ca", &cert2);
        assert!(matches!(result, Err(JksError::DuplicateAlias(_))));
    }

    #[test]
    fn test_add_trusted_cert_invalid_cert() {
        let mut jks = JKS::new();
        let result = jks.add_trusted_cert("ca", &[0xFF, 0xFF]);
        assert!(matches!(result, Err(JksError::InvalidCertificate(_))));
    }

    #[test]
    fn test_invalid_pem_no_blocks() {
        let result = parse_pem_certificates(b"not a pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pem_wrong_tag() {
        let pem_str = pem::encode(&pem::Pem::new("FOOBAR", vec![1, 2, 3]));
        let result = parse_pem_certificates(pem_str.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pem_private_key_wrong_tag() {
        let pem_str = pem::encode(&pem::Pem::new("FOOBAR", vec![1, 2, 3]));
        let result = parse_pem_private_key(pem_str.as_bytes());
        assert!(matches!(result, Err(JksError::UnsupportedKeyType(_))));
    }

    #[test]
    fn test_corrupted_data_unmarshal() {
        let result = JKS::unmarshal(&[0x00, 0x01, 0x02], "password");
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_data_unmarshal_bad_magic() {
        // Build a fake keystore with wrong magic but correct hash
        let mut buf: Vec<u8> = Vec::new();
        write_u32(&mut buf, 0xDEADBEEF).unwrap(); // wrong magic
        write_u32(&mut buf, JKS_VERSION).unwrap();
        write_u32(&mut buf, 0).unwrap(); // 0 entries
        let hash = compute_integrity_hash("password", &buf);
        buf.extend_from_slice(&hash);
        // Integrity passes but magic is wrong
        let result = JKS::unmarshal(&buf, "password");
        assert!(matches!(result, Err(JksError::InvalidMagic)));
    }

    #[test]
    fn test_certificate_chain_three_levels() {
        use rcgen::CertifiedIssuer;

        // Generate root CA
        let root_kp = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::new(vec![]).unwrap();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Root CA");
        let root_issuer = CertifiedIssuer::self_signed(root_params, &root_kp).unwrap();

        // Generate intermediate CA
        let inter_kp = KeyPair::generate().unwrap();
        let mut inter_params = CertificateParams::new(vec![]).unwrap();
        inter_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        inter_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Intermediate CA");
        let inter_issuer =
            CertifiedIssuer::signed_by(inter_params, &inter_kp, &root_issuer).unwrap();

        // Generate leaf cert
        let leaf_kp = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["leaf.example.com".to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_kp, &inter_issuer).unwrap();

        let chain = vec![
            leaf_cert.der().to_vec(),
            inter_issuer.der().to_vec(),
            root_issuer.der().to_vec(),
        ];

        let mut jks = JKS::new();
        jks.add_private_key_with_timestamp("server", &leaf_kp.serialize_der(), chain.clone(), 1234)
            .unwrap();

        let data = jks.marshal("changeit").unwrap();
        let jks2 = JKS::unmarshal(&data, "changeit").unwrap();
        match &jks2.entries[0] {
            Entry::PrivateKey(pk) => {
                assert_eq!(pk.cert_chain.len(), 3);
                assert_eq!(pk.cert_chain, chain);
            }
            _ => panic!("expected PrivateKey"),
        }
    }

    #[test]
    fn test_parse_pem_certificates_multiple() {
        let kp1 = KeyPair::generate().unwrap();
        let params1 = CertificateParams::new(vec!["a.example.com".to_string()]).unwrap();
        let cert1 = params1.self_signed(&kp1).unwrap();

        let kp2 = KeyPair::generate().unwrap();
        let params2 = CertificateParams::new(vec!["b.example.com".to_string()]).unwrap();
        let cert2 = params2.self_signed(&kp2).unwrap();

        let pem1 = pem::encode(&pem::Pem::new("CERTIFICATE", cert1.der().to_vec()));
        let pem2 = pem::encode(&pem::Pem::new("CERTIFICATE", cert2.der().to_vec()));
        let combined = format!("{}{}", pem1, pem2);

        let result = parse_pem_certificates(combined.as_bytes()).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], cert1.der().to_vec());
        assert_eq!(result[1], cert2.der().to_vec());
    }

    #[test]
    fn test_has_alias_case_insensitive() {
        let (cert, key) = generate_cert_and_key();
        let mut jks = JKS::new();
        jks.add_private_key("MyAlias", &key, vec![cert]).unwrap();
        assert!(jks.has_alias("myalias"));
        assert!(jks.has_alias("MYALIAS"));
        assert!(jks.has_alias("MyAlias"));
        assert!(!jks.has_alias("other"));
    }

    #[test]
    fn test_encapsulate_decapsulate_roundtrip() {
        let data = b"some encrypted data for testing ASN.1 roundtrip";
        let encapsulated = encapsulate_private_key(data).unwrap();
        let decapsulated = decapsulate_private_key(&encapsulated).unwrap();
        assert_eq!(decapsulated, data);
    }
}
