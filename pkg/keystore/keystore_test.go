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

func TestJKSPrivateKeyEncryption(t *testing.T) {
	// Helper function to verify ASN.1 structure
	verifyASN1Structure := func(t *testing.T, encapsulated []byte, expectedData []byte) {
		t.Helper()
		
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
		if !epki.Algo.Algorithm.Equal(sunJKSAlgoOID) {
			t.Errorf("Wrong algorithm OID: got %v, want %v", epki.Algo.Algorithm, sunJKSAlgoOID)
		}

		// Verify parameters is ASN.1 NULL (0x05, 0x00)
		if !bytes.Equal(epki.Algo.Parameters.FullBytes, asn1NULL.FullBytes) {
			t.Errorf("Wrong algorithm parameters: got %x, want %x (ASN.1 NULL)", epki.Algo.Parameters.FullBytes, asn1NULL.FullBytes)
		}

		// Verify the encrypted data matches
		if !bytes.Equal(epki.EncryptedData, expectedData) {
			t.Errorf("Wrong encrypted data")
		}
	}

	t.Run("encapsulation format", func(t *testing.T) {
		// Test that encapsulatePrivateKey produces properly formatted PKCS#8 EncryptedPrivateKeyInfo
		// with ASN.1 NULL parameters (matching Java keytool and minijks)
		testData := []byte("test encrypted key data")

		encapsulated, err := encapsulatePrivateKey(testData)
		if err != nil {
			t.Fatalf("encapsulatePrivateKey failed: %v", err)
		}

		verifyASN1Structure(t, encapsulated, testData)
	})

	t.Run("full encryption flow", func(t *testing.T) {
		// Test encryption of real private key
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
			t.Fatalf("Encrypted data too short: %d bytes", len(encrypted))
		}

		// Encapsulate and verify ASN.1 structure
		encapsulated, err := encapsulatePrivateKey(encrypted)
		if err != nil {
			t.Fatalf("encapsulatePrivateKey failed: %v", err)
		}

		verifyASN1Structure(t, encapsulated, encrypted)
	})
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

func TestJKSUnmarshalPrivateKey(t *testing.T) {
	// Create a JKS with a private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	_, certDER := generateTestCert(t, &key.PublicKey)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal key to PKCS#8: %v", err)
	}

	// Test with mixed-case alias to verify casing preservation
	ks := NewJKS()
	mixedCaseAlias := "MyTestKey"
	if err := ks.AddPrivateKey(mixedCaseAlias, pkcs8, [][]byte{certDER}); err != nil {
		t.Fatalf("Failed to add private key: %v", err)
	}

	// Marshal the JKS
	jksData, err := ks.Marshal("changeit")
	if err != nil {
		t.Fatalf("Failed to marshal JKS: %v", err)
	}

	// Unmarshal the JKS
	ks2 := NewJKS()
	if err := ks2.Unmarshal(jksData, "changeit"); err != nil {
		t.Fatalf("Failed to unmarshal JKS: %v", err)
	}

	// Verify entry count
	if len(ks2.Entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(ks2.Entries))
	}

	// Verify entry type and content
	entry, ok := ks2.Entries[0].(PrivateKeyEntry)
	if !ok {
		t.Fatalf("Expected PrivateKeyEntry, got %T", ks2.Entries[0])
	}

	// Verify alias casing is preserved
	if entry.Alias != mixedCaseAlias {
		t.Errorf("Expected alias %q, got %q", mixedCaseAlias, entry.Alias)
	}

	if !bytes.Equal(entry.PrivKey, pkcs8) {
		t.Error("Private key mismatch after unmarshal")
	}

	if len(entry.CertChain) != 1 {
		t.Errorf("Expected 1 cert in chain, got %d", len(entry.CertChain))
	}

	if !bytes.Equal(entry.CertChain[0], certDER) {
		t.Error("Certificate mismatch after unmarshal")
	}

	t.Logf("Successfully unmarshaled JKS with private key entry")
}

func TestJKSUnmarshalTrustedCert(t *testing.T) {
	// Create a JKS with a trusted certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	_, certDER := generateTestCert(t, &key.PublicKey)

	// Test with mixed-case alias to verify casing preservation
	ks := NewJKS()
	mixedCaseAlias := "MyTrustedCA"
	if err := ks.AddTrustedCert(mixedCaseAlias, certDER); err != nil {
		t.Fatalf("Failed to add trusted cert: %v", err)
	}

	// Marshal the JKS
	jksData, err := ks.Marshal("changeit")
	if err != nil {
		t.Fatalf("Failed to marshal JKS: %v", err)
	}

	// Unmarshal the JKS
	ks2 := NewJKS()
	if err := ks2.Unmarshal(jksData, "changeit"); err != nil {
		t.Fatalf("Failed to unmarshal JKS: %v", err)
	}

	// Verify entry count
	if len(ks2.Entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(ks2.Entries))
	}

	// Verify entry type and content
	entry, ok := ks2.Entries[0].(TrustedCertEntry)
	if !ok {
		t.Fatalf("Expected TrustedCertEntry, got %T", ks2.Entries[0])
	}

	// Verify alias casing is preserved
	if entry.Alias != mixedCaseAlias {
		t.Errorf("Expected alias %q, got %q", mixedCaseAlias, entry.Alias)
	}

	if !bytes.Equal(entry.Cert, certDER) {
		t.Error("Certificate mismatch after unmarshal")
	}

	t.Logf("Successfully unmarshaled JKS with trusted cert entry")
}

func TestJKSUnmarshalMultipleEntries(t *testing.T) {
	// Create a JKS with multiple entries
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 1: %v", err)
	}
	_, cert1DER := generateTestCert(t, &key1.PublicKey)
	pkcs8_1, err := x509.MarshalPKCS8PrivateKey(key1)
	if err != nil {
		t.Fatalf("Failed to marshal key 1 to PKCS#8: %v", err)
	}

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 2: %v", err)
	}
	_, cert2DER := generateTestCert(t, &key2.PublicKey)
	pkcs8_2, err := x509.MarshalPKCS8PrivateKey(key2)
	if err != nil {
		t.Fatalf("Failed to marshal key 2 to PKCS#8: %v", err)
	}

	key3, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key 3: %v", err)
	}
	_, cert3DER := generateTestCert(t, &key3.PublicKey)

	ks := NewJKS()
	if err := ks.AddPrivateKey("key1", pkcs8_1, [][]byte{cert1DER}); err != nil {
		t.Fatalf("Failed to add private key 1: %v", err)
	}
	if err := ks.AddPrivateKey("key2", pkcs8_2, [][]byte{cert2DER}); err != nil {
		t.Fatalf("Failed to add private key 2: %v", err)
	}
	if err := ks.AddTrustedCert("ca-cert", cert3DER); err != nil {
		t.Fatalf("Failed to add trusted cert: %v", err)
	}

	// Marshal the JKS
	jksData, err := ks.Marshal("changeit")
	if err != nil {
		t.Fatalf("Failed to marshal JKS: %v", err)
	}

	// Unmarshal the JKS
	ks2 := NewJKS()
	if err := ks2.Unmarshal(jksData, "changeit"); err != nil {
		t.Fatalf("Failed to unmarshal JKS: %v", err)
	}

	// Verify entry count
	if len(ks2.Entries) != 3 {
		t.Fatalf("Expected 3 entries, got %d", len(ks2.Entries))
	}

	// Verify first private key entry
	entry1, ok := ks2.Entries[0].(PrivateKeyEntry)
	if !ok {
		t.Fatalf("Expected entry 0 to be PrivateKeyEntry, got %T", ks2.Entries[0])
	}
	if entry1.Alias != "key1" {
		t.Errorf("Expected alias 'key1', got %q", entry1.Alias)
	}

	// Verify second private key entry
	entry2, ok := ks2.Entries[1].(PrivateKeyEntry)
	if !ok {
		t.Fatalf("Expected entry 1 to be PrivateKeyEntry, got %T", ks2.Entries[1])
	}
	if entry2.Alias != "key2" {
		t.Errorf("Expected alias 'key2', got %q", entry2.Alias)
	}

	// Verify trusted cert entry
	entry3, ok := ks2.Entries[2].(TrustedCertEntry)
	if !ok {
		t.Fatalf("Expected entry 2 to be TrustedCertEntry, got %T", ks2.Entries[2])
	}
	if entry3.Alias != "ca-cert" {
		t.Errorf("Expected alias 'ca-cert', got %q", entry3.Alias)
	}

	t.Logf("Successfully unmarshaled JKS with 2 private keys and 1 trusted cert")
}

func TestJKSUnmarshalWrongPassword(t *testing.T) {
	// Create a JKS
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	_, certDER := generateTestCert(t, &key.PublicKey)

	ks := NewJKS()
	if err := ks.AddTrustedCert("test", certDER); err != nil {
		t.Fatalf("Failed to add trusted cert: %v", err)
	}

	// Marshal with one password
	jksData, err := ks.Marshal("correctpassword")
	if err != nil {
		t.Fatalf("Failed to marshal JKS: %v", err)
	}

	// Try to unmarshal with wrong password
	ks2 := NewJKS()
	err = ks2.Unmarshal(jksData, "wrongpassword")
	if err == nil {
		t.Error("Expected error when unmarshaling with wrong password, got nil")
	}
	if err != nil && !bytes.Contains([]byte(err.Error()), []byte("integrity check failed")) {
		t.Fatalf("Expected error containing %q, got: %v", "integrity check failed", err)
	}
}

// TestAddPrivateKeyValidation tests validation in AddPrivateKey
func TestAddPrivateKeyValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	_, certDER := generateTestCert(t, &key.PublicKey)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	tests := []struct {
		name      string
		alias     string
		key       []byte
		certChain [][]byte
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "empty alias",
			alias:     "",
			key:       pkcs8,
			certChain: [][]byte{certDER},
			wantErr:   true,
			errMsg:    "alias cannot be empty",
		},
		{
			name:      "empty private key",
			alias:     "test",
			key:       []byte{},
			certChain: [][]byte{certDER},
			wantErr:   true,
			errMsg:    "private key cannot be empty",
		},
		{
			name:      "nil private key",
			alias:     "test",
			key:       nil,
			certChain: [][]byte{certDER},
			wantErr:   true,
			errMsg:    "private key cannot be empty",
		},
		{
			name:      "empty cert chain",
			alias:     "test",
			key:       pkcs8,
			certChain: [][]byte{},
			wantErr:   true,
			errMsg:    "certificate chain cannot be empty",
		},
		{
			name:      "nil cert chain",
			alias:     "test",
			key:       pkcs8,
			certChain: nil,
			wantErr:   true,
			errMsg:    "certificate chain cannot be empty",
		},
		{
			name:      "invalid certificate",
			alias:     "test",
			key:       pkcs8,
			certChain: [][]byte{[]byte("invalid cert data")},
			wantErr:   true,
			errMsg:    "invalid certificate",
		},
		{
			name:      "valid input",
			alias:     "test",
			key:       pkcs8,
			certChain: [][]byte{certDER},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := NewJKS()
			err := ks.AddPrivateKey(tt.alias, tt.key, tt.certChain)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !bytes.Contains([]byte(err.Error()), []byte(tt.errMsg)) {
				t.Errorf("AddPrivateKey() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

// TestAddTrustedCertValidation tests validation in AddTrustedCert
func TestAddTrustedCertValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	_, certDER := generateTestCert(t, &key.PublicKey)

	tests := []struct {
		name    string
		alias   string
		cert    []byte
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty alias",
			alias:   "",
			cert:    certDER,
			wantErr: true,
			errMsg:  "alias cannot be empty",
		},
		{
			name:    "empty certificate",
			alias:   "test",
			cert:    []byte{},
			wantErr: true,
			errMsg:  "certificate cannot be empty",
		},
		{
			name:    "nil certificate",
			alias:   "test",
			cert:    nil,
			wantErr: true,
			errMsg:  "certificate cannot be empty",
		},
		{
			name:    "invalid certificate",
			alias:   "test",
			cert:    []byte("invalid cert data"),
			wantErr: true,
			errMsg:  "invalid certificate",
		},
		{
			name:    "valid input",
			alias:   "test",
			cert:    certDER,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := NewJKS()
			err := ks.AddTrustedCert(tt.alias, tt.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddTrustedCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !bytes.Contains([]byte(err.Error()), []byte(tt.errMsg)) {
				t.Errorf("AddTrustedCert() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

// TestParsePEMInvalidFormats tests error handling in PEM parsing
func TestParsePEMInvalidFormats(t *testing.T) {
	tests := []struct {
		name    string
		pemData []byte
		wantErr bool
	}{
		{
			name:    "empty input",
			pemData: []byte{},
			wantErr: true,
		},
		{
			name:    "nil input",
			pemData: nil,
			wantErr: true,
		},
		{
			name:    "invalid PEM format",
			pemData: []byte("not a PEM block"),
			wantErr: true,
		},
		{
			name:    "PEM with no data",
			pemData: []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"),
			wantErr: true,
		},
		{
			name:    "truncated PEM",
			pemData: []byte("-----BEGIN CERTIFICATE-----\nYWJjZGVm"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePEMCertificates(tt.pemData)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePEMCertificates() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestUnmarshalCorruptedData tests Unmarshal with various corrupted inputs
func TestUnmarshalCorruptedData(t *testing.T) {
	// First create a valid JKS to work with
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	_, certDER := generateTestCert(t, &key.PublicKey)

	ks := NewJKS()
	if err := ks.AddTrustedCert("test", certDER); err != nil {
		t.Fatalf("Failed to add trusted cert: %v", err)
	}

	validData, err := ks.Marshal("changeit")
	if err != nil {
		t.Fatalf("Failed to marshal JKS: %v", err)
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "truncated data",
			data:    validData[:10],
			wantErr: true,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "invalid magic number",
			data:    append([]byte{0x00, 0x00, 0x00, 0x00}, validData[4:]...),
			wantErr: true,
		},
		{
			name:    "corrupted integrity hash",
			data:    append(validData[:len(validData)-20], make([]byte, 20)...),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks2 := NewJKS()
			err := ks2.Unmarshal(tt.data, "changeit")
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCertificateChain tests JKS with multi-certificate chains
func TestCertificateChain(t *testing.T) {
	// Generate a certificate chain: root CA -> intermediate CA -> end entity
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	// Create root CA certificate
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	// Create intermediate CA certificate
	intermKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate intermediate key: %v", err)
	}

	intermTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCert, _ := x509.ParseCertificate(rootCertDER)
	intermCertDER, err := x509.CreateCertificate(rand.Reader, intermTemplate, rootCert, &intermKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}

	// Create end entity certificate
	endKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate end entity key: %v", err)
	}

	endTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "End Entity",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	intermCert, _ := x509.ParseCertificate(intermCertDER)
	endCertDER, err := x509.CreateCertificate(rand.Reader, endTemplate, intermCert, &endKey.PublicKey, intermKey)
	if err != nil {
		t.Fatalf("Failed to create end entity certificate: %v", err)
	}

	// Create keystore with full chain
	pkcs8, err := x509.MarshalPKCS8PrivateKey(endKey)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	ks := NewJKS()
	certChain := [][]byte{endCertDER, intermCertDER, rootCertDER}
	if err := ks.AddPrivateKey("server", pkcs8, certChain); err != nil {
		t.Fatalf("Failed to add private key with chain: %v", err)
	}

	// Marshal and unmarshal
	jksData, err := ks.Marshal("changeit")
	if err != nil {
		t.Fatalf("Failed to marshal JKS: %v", err)
	}

	ks2 := NewJKS()
	if err := ks2.Unmarshal(jksData, "changeit"); err != nil {
		t.Fatalf("Failed to unmarshal JKS: %v", err)
	}

	// Verify chain length
	entry := ks2.Entries[0].(PrivateKeyEntry)
	if len(entry.CertChain) != 3 {
		t.Errorf("Expected chain length 3, got %d", len(entry.CertChain))
	}

	// Verify certificate order
	if !bytes.Equal(entry.CertChain[0], endCertDER) {
		t.Error("First certificate in chain doesn't match end entity cert")
	}
	if !bytes.Equal(entry.CertChain[1], intermCertDER) {
		t.Error("Second certificate in chain doesn't match intermediate cert")
	}
	if !bytes.Equal(entry.CertChain[2], rootCertDER) {
		t.Error("Third certificate in chain doesn't match root cert")
	}

	t.Logf("Successfully handled certificate chain with %d certificates", len(entry.CertChain))
}
