package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

const jksMagic = 0xFEEDFEED

func TestCreateJKSWithRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	cert, certDER := generateTestCert(t, &key.PublicKey)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal key to PKCS#8: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	jksData, err := CreateJKSFromPEM(certPEM, keyPEM, nil, "changeit", "test")
	if err != nil {
		t.Fatalf("Failed to create JKS: %v", err)
	}

	if len(jksData) < 4 {
		t.Fatal("JKS data too short")
	}
	magic := uint32(jksData[0])<<24 | uint32(jksData[1])<<16 | uint32(jksData[2])<<8 | uint32(jksData[3])
	if magic != jksMagic {
		t.Errorf("Wrong magic number: got 0x%X, want 0x%X", magic, jksMagic)
	}

	t.Logf("Generated JKS size: %d bytes", len(jksData))
	t.Logf("Certificate subject: %s", cert.Subject)
}

func TestCreateJKSWithECKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate EC key: %v", err)
	}

	_, certDER := generateTestCert(t, &key.PublicKey)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal key to PKCS#8: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	jksData, err := CreateJKSFromPEM(certPEM, keyPEM, nil, "changeit", "test")
	if err != nil {
		t.Fatalf("Failed to create JKS: %v", err)
	}

	t.Logf("Generated JKS with EC key, size: %d bytes", len(jksData))
}

func TestCreateJKSTruststore(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	_, certDER := generateTestCert(t, &key.PublicKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	jksData, err := CreateJKSFromPEM(nil, nil, certPEM, "changeit", "ca")
	if err != nil {
		t.Fatalf("Failed to create truststore: %v", err)
	}

	t.Logf("Generated JKS truststore size: %d bytes", len(jksData))
}

func TestCreatePKCS12WithRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	_, certDER := generateTestCert(t, &key.PublicKey)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal key to PKCS#8: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	p12Data, err := CreatePKCS12FromPEM(certPEM, keyPEM, nil, "changeit", "test")
	if err != nil {
		t.Fatalf("Failed to create PKCS#12: %v", err)
	}

	t.Logf("Generated PKCS#12 size: %d bytes", len(p12Data))
}

func TestCreatePKCS12Truststore(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	_, certDER := generateTestCert(t, &key.PublicKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	p12Data, err := CreatePKCS12FromPEM(nil, nil, certPEM, "changeit", "ca")
	if err != nil {
		t.Fatalf("Failed to create PKCS#12 truststore: %v", err)
	}

	t.Logf("Generated PKCS#12 truststore size: %d bytes", len(p12Data))
}

func TestCreatePKCS12Legacy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	_, certDER := generateTestCert(t, &key.PublicKey)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal key to PKCS#8: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	p12Data, err := CreatePKCS12FromPEMLegacy(certPEM, keyPEM, nil, "changeit", "test")
	if err != nil {
		t.Fatalf("Failed to create legacy PKCS#12: %v", err)
	}

	t.Logf("Generated legacy PKCS#12 size: %d bytes", len(p12Data))
}

func TestParsePKCS1Key(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	pkcs1 := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1})

	pkcs8, err := ParsePEMPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#1 key: %v", err)
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		t.Fatalf("Failed to parse resulting PKCS#8: %v", err)
	}

	if _, ok := parsedKey.(*rsa.PrivateKey); !ok {
		t.Error("Parsed key is not RSA")
	}
}

func TestParseECKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate EC key: %v", err)
	}

	ecDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal EC key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})

	pkcs8, err := ParsePEMPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("Failed to parse EC key: %v", err)
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		t.Fatalf("Failed to parse resulting PKCS#8: %v", err)
	}

	if _, ok := parsedKey.(*ecdsa.PrivateKey); !ok {
		t.Error("Parsed key is not ECDSA")
	}
}

func TestIntegrityHash(t *testing.T) {
	data := []byte("test data")
	password := "changeit"

	hash := computeJKSIntegrityHash(data, password)
	if len(hash) != 20 {
		t.Errorf("Wrong hash length: got %d, want 20", len(hash))
	}

	hash2 := computeJKSIntegrityHash(data, password)
	for i := range hash {
		if hash[i] != hash2[i] {
			t.Error("Hash is not deterministic")
			break
		}
	}

	hash3 := computeJKSIntegrityHash(data, "different")
	same := true
	for i := range hash {
		if hash[i] != hash3[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("Different passwords produced same hash")
	}
}

func TestUTF16BEEncoding(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"A", []byte{0x00, 0x41}},
		{"AB", []byte{0x00, 0x41, 0x00, 0x42}},
		{"", []byte{}},
	}

	for _, tc := range tests {
		result := stringToUTF16BE(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("Wrong length for %q: got %d, want %d", tc.input, len(result), len(tc.expected))
			continue
		}
		for i := range result {
			if result[i] != tc.expected[i] {
				t.Errorf("Wrong byte at %d for %q: got 0x%X, want 0x%X", i, tc.input, result[i], tc.expected[i])
			}
		}
	}
}

func TestEncapsulatePrivateKeyASN1Format(t *testing.T) {
	// Test that encapsulatePrivateKey produces properly formatted PKCS#8 EncryptedPrivateKeyInfo
	// with ASN.1 NULL parameters (matching Java keytool and minijks)
	testData := []byte("test encrypted key data")

	encapsulated, err := encapsulatePrivateKey(testData)
	if err != nil {
		t.Fatalf("encapsulatePrivateKey failed: %v", err)
	}

	// Parse the encapsulated data to verify structure
	var epki struct {
		Algo struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		EncryptedData []byte
	}

	rest, err := asn1.Unmarshal(encapsulated, &epki)
	if err != nil {
		t.Fatalf("Failed to unmarshal encapsulated key: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("Unexpected trailing data: %d bytes", len(rest))
	}

	// Verify the OID is correct (Sun JKS algorithm OID)
	expectedOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1}
	if !epki.Algo.Algorithm.Equal(expectedOID) {
		t.Errorf("Wrong algorithm OID: got %v, want %v", epki.Algo.Algorithm, expectedOID)
	}

	// Verify parameters is ASN.1 NULL (0x05, 0x00)
	expectedNull := []byte{0x05, 0x00}
	if !bytes.Equal(epki.Algo.Parameters.FullBytes, expectedNull) {
		t.Errorf("Wrong algorithm parameters: got %x, want %x (ASN.1 NULL)", epki.Algo.Parameters.FullBytes, expectedNull)
	}

	// Verify the encrypted data matches
	if !bytes.Equal(epki.EncryptedData, testData) {
		t.Errorf("Wrong encrypted data: got %x, want %x", epki.EncryptedData, testData)
	}
}

func TestJKSPrivateKeyRoundtrip(t *testing.T) {
	// Test that we can encrypt a private key and the format is valid
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	password := "testpassword"
	encrypted, err := encryptJKSPrivateKey(pkcs8Key, password)
	if err != nil {
		t.Fatalf("encryptJKSPrivateKey failed: %v", err)
	}

	// Verify encrypted data has correct structure: 20 bytes IV + encrypted + 20 bytes hash
	if len(encrypted) < 40 {
		t.Errorf("Encrypted data too short: %d bytes", len(encrypted))
	}

	// Encapsulate and verify ASN.1 structure
	encapsulated, err := encapsulatePrivateKey(encrypted)
	if err != nil {
		t.Fatalf("encapsulatePrivateKey failed: %v", err)
	}

	// Ensure it can be parsed as valid ASN.1
	var epki struct {
		Algo struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		EncryptedData []byte
	}

	_, err = asn1.Unmarshal(encapsulated, &epki)
	if err != nil {
		t.Fatalf("Failed to unmarshal encapsulated key: %v", err)
	}
}

func generateTestCert(t *testing.T, pub interface{}) (*x509.Certificate, []byte) {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate signing key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, signingKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, certDER
}
