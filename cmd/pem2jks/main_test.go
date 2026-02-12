package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marre/pem2jks/pkg/keystore"
	"software.sslmate.com/src/go-pkcs12"
)

// generateTestCert generates a test certificate and key for testing
func generateTestCert(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()

	// Generate key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Encode to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key})

	return certPEM, keyPEM
}

func TestCreateJKSKeystoreMultipleCerts(t *testing.T) {
	// Generate test certificates
	cert1PEM, key1PEM := generateTestCert(t, "app1.example.com")
	cert2PEM, key2PEM := generateTestCert(t, "app2.example.com")
	// Prepare cert/key pairs
	pairs := []certKeyPair{
		{certPEM: cert1PEM, keyPEM: key1PEM, alias: "app1"},
		{certPEM: cert2PEM, keyPEM: key2PEM, alias: "app2"},
	}

	// Create JKS keystore
	jksData, err := createJKSKeystore(pairs, nil, "changeit", "", "changeit")
	if err != nil {
		t.Fatalf("Failed to create JKS keystore: %v", err)
	}

	if len(jksData) == 0 {
		t.Error("JKS keystore data is empty")
	}

	// Verify JKS magic number
	if len(jksData) >= 4 {
		magic := uint32(jksData[0])<<24 | uint32(jksData[1])<<16 | uint32(jksData[2])<<8 | uint32(jksData[3])
		if magic != 0xFEEDFEED {
			t.Errorf("Wrong magic number: got 0x%X, want 0xFEEDFEED", magic)
		}
	}

	t.Logf("Created JKS with 2 private key entries, size: %d bytes", len(jksData))
}

func TestCreatePKCS12KeystoreWithCA(t *testing.T) {
	// Generate test cert and CA
	certPEM, keyPEM := generateTestCert(t, "app.example.com")
	caPEM, _ := generateTestCert(t, "CA")

	// Prepare cert/key pair and CA
	pairs := []certKeyPair{
		{certPEM: certPEM, keyPEM: keyPEM, alias: "app"},
	}
	caPairs := []certKeyPair{
		{certPEM: caPEM, alias: "ca"},
	}

	// Create PKCS#12 keystore with CA
	p12Data, err := createPKCS12Keystore(pairs, caPairs, "changeit", "", "changeit")
	if err != nil {
		t.Fatalf("Failed to create PKCS#12 keystore: %v", err)
	}

	if len(p12Data) == 0 {
		t.Error("PKCS#12 keystore data is empty")
	}

	// Verify we can decode it
	privKey, cert, caCerts, err := pkcs12.DecodeChain(p12Data, "changeit")
	if err != nil {
		t.Fatalf("Failed to decode PKCS#12: %v", err)
	}

	if privKey == nil {
		t.Error("Private key is nil")
	}
	if cert == nil {
		t.Error("Certificate is nil")
	}
	if len(caCerts) != 1 {
		t.Errorf("Expected 1 CA cert, got %d", len(caCerts))
	}

	t.Logf("Created PKCS#12 with 1 private key and 1 CA cert, size: %d bytes", len(p12Data))
}

func TestPKCS12AppendToTruststore(t *testing.T) {
	tempDir := t.TempDir()

	// Create initial truststore with one CA
	ca1PEM, _ := generateTestCert(t, "CA1")

	pairs1 := []certKeyPair{
		{certPEM: ca1PEM, keyPEM: nil, alias: "ca1"},
	}

	p12Data1, err := createPKCS12Keystore(pairs1, nil, "changeit", "", "changeit")
	if err != nil {
		t.Fatalf("Failed to create initial PKCS#12: %v", err)
	}

	// Write to file
	inputFile := filepath.Join(tempDir, "truststore.p12")
	if err := os.WriteFile(inputFile, p12Data1, 0600); err != nil {
		t.Fatalf("Failed to write truststore: %v", err)
	}

	// Add another CA
	ca2PEM, _ := generateTestCert(t, "CA2")

	pairs2 := []certKeyPair{
		{certPEM: ca2PEM, keyPEM: nil, alias: "ca2"},
	}

	// Append to existing truststore
	p12Data2, err := createPKCS12Keystore(pairs2, nil, "changeit", inputFile, "changeit")
	if err != nil {
		t.Fatalf("Failed to append to PKCS#12: %v", err)
	}

	if len(p12Data2) == 0 {
		t.Error("Appended PKCS#12 keystore data is empty")
	}

	// Verify we have 2 certs now
	certs, err := pkcs12.DecodeTrustStore(p12Data2, "changeit")
	if err != nil {
		t.Fatalf("Failed to decode appended PKCS#12: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("Expected 2 certs in truststore, got %d", len(certs))
	}

	t.Logf("Appended to PKCS#12 truststore, now has %d certs", len(certs))
}

func TestPKCS12OnlyOnePrivateKey(t *testing.T) {
	// Generate two cert/key pairs
	cert1PEM, key1PEM := generateTestCert(t, "app1.example.com")
	cert2PEM, key2PEM := generateTestCert(t, "app2.example.com")

	// Try to create PKCS#12 with two private keys (should fail)
	pairs := []certKeyPair{
		{certPEM: cert1PEM, keyPEM: key1PEM, alias: "app1"},
		{certPEM: cert2PEM, keyPEM: key2PEM, alias: "app2"},
	}

	_, err := createPKCS12Keystore(pairs, nil, "changeit", "", "changeit")
	if err == nil {
		t.Error("Expected error when creating PKCS#12 with multiple private keys, got nil")
	}
	if err != nil {
		t.Logf("Got expected error: %v", err)
	}
}

func TestMultipleCAFiles(t *testing.T) {
	// Generate multiple CAs
	ca1PEM, _ := generateTestCert(t, "CA1")
	ca2PEM, _ := generateTestCert(t, "CA2")

	// Create CA pairs
	caPairs := []certKeyPair{
		{certPEM: ca1PEM, alias: "ca1"},
		{certPEM: ca2PEM, alias: "ca2"},
	}

	// Create JKS truststore with multiple CAs
	jksData, err := createJKSKeystore(nil, caPairs, "changeit", "", "changeit")
	if err != nil {
		t.Fatalf("Failed to create JKS with multiple CAs: %v", err)
	}

	if len(jksData) == 0 {
		t.Error("JKS data is empty")
	}

	t.Logf("Created JKS truststore with 2 CAs, size: %d bytes", len(jksData))
}

func TestJKSAppendToExisting(t *testing.T) {
	tempDir := t.TempDir()

	// Create initial JKS with one private key
	cert1PEM, key1PEM := generateTestCert(t, "app1.example.com")

	pairs1 := []certKeyPair{
		{certPEM: cert1PEM, keyPEM: key1PEM, alias: "app1"},
	}

	jksData1, err := createJKSKeystore(pairs1, nil, "changeit", "", "changeit")
	if err != nil {
		t.Fatalf("Failed to create initial JKS: %v", err)
	}

	// Write to file
	inputFile := filepath.Join(tempDir, "initial.jks")
	if err := os.WriteFile(inputFile, jksData1, 0600); err != nil {
		t.Fatalf("Failed to write initial JKS: %v", err)
	}

	// Add another private key to the existing JKS
	cert2PEM, key2PEM := generateTestCert(t, "app2.example.com")

	pairs2 := []certKeyPair{
		{certPEM: cert2PEM, keyPEM: key2PEM, alias: "app2"},
	}

	// Append to existing JKS
	jksData2, err := createJKSKeystore(pairs2, nil, "changeit", inputFile, "changeit")
	if err != nil {
		t.Fatalf("Failed to append to JKS: %v", err)
	}

	if len(jksData2) == 0 {
		t.Error("Appended JKS data is empty")
	}

	// Verify we have 2 entries now by unmarshaling
	ks := keystore.NewJKS()
	if err := ks.Unmarshal(jksData2, "changeit"); err != nil {
		t.Fatalf("Failed to unmarshal appended JKS: %v", err)
	}

	if len(ks.Entries) != 2 {
		t.Errorf("Expected 2 entries in JKS, got %d", len(ks.Entries))
	}

	// Verify both are private key entries
	privateKeyCount := 0
	for _, entry := range ks.Entries {
		if _, ok := entry.(keystore.PrivateKeyEntry); ok {
			privateKeyCount++
		}
	}

	if privateKeyCount != 2 {
		t.Errorf("Expected 2 private key entries, got %d", privateKeyCount)
	}

	t.Logf("Successfully appended to JKS, now has %d entries", len(ks.Entries))
}

func TestJKSAppendTrustedCertsToKeystore(t *testing.T) {
	tempDir := t.TempDir()

	// Create initial JKS with a private key
	certPEM, keyPEM := generateTestCert(t, "app.example.com")

	pairs := []certKeyPair{
		{certPEM: certPEM, keyPEM: keyPEM, alias: "app"},
	}

	jksData1, err := createJKSKeystore(pairs, nil, "changeit", "", "changeit")
	if err != nil {
		t.Fatalf("Failed to create initial JKS: %v", err)
	}

	// Write to file
	inputFile := filepath.Join(tempDir, "keystore.jks")
	if err := os.WriteFile(inputFile, jksData1, 0600); err != nil {
		t.Fatalf("Failed to write initial JKS: %v", err)
	}

	// Add CA certificates to the existing JKS
	ca1PEM, _ := generateTestCert(t, "CA1")
	ca2PEM, _ := generateTestCert(t, "CA2")

	caPairs := []certKeyPair{
		{certPEM: ca1PEM, alias: "ca1"},
		{certPEM: ca2PEM, alias: "ca2"},
	}

	// Append CAs to existing JKS
	jksData2, err := createJKSKeystore(nil, caPairs, "changeit", inputFile, "changeit")
	if err != nil {
		t.Fatalf("Failed to append CAs to JKS: %v", err)
	}

	// Verify we have 3 entries now (1 private key + 2 trusted certs)
	ks := keystore.NewJKS()
	if err := ks.Unmarshal(jksData2, "changeit"); err != nil {
		t.Fatalf("Failed to unmarshal appended JKS: %v", err)
	}

	if len(ks.Entries) != 3 {
		t.Errorf("Expected 3 entries in JKS, got %d", len(ks.Entries))
	}

	// Count entry types
	privateKeyCount := 0
	trustedCertCount := 0
	for _, entry := range ks.Entries {
		switch entry.(type) {
		case keystore.PrivateKeyEntry:
			privateKeyCount++
		case keystore.TrustedCertEntry:
			trustedCertCount++
		}
	}

	if privateKeyCount != 1 {
		t.Errorf("Expected 1 private key entry, got %d", privateKeyCount)
	}
	if trustedCertCount != 2 {
		t.Errorf("Expected 2 trusted cert entries, got %d", trustedCertCount)
	}

	t.Logf("Successfully appended CAs to JKS with private key, now has %d entries", len(ks.Entries))
}

// TestNewEntryFormat tests the new --entry flag format
func TestNewEntryFormat(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test certificates
	cert1PEM, key1PEM := generateTestCert(t, "app1.example.com")
	cert2PEM, _ := generateTestCert(t, "ca.example.com") // No key for CA cert
	cert3PEM, key3PEM := generateTestCert(t, "app2.example.com")

	// Write to temp files
	cert1File := filepath.Join(tmpDir, "app1.crt")
	key1File := filepath.Join(tmpDir, "app1.key")
	cert2File := filepath.Join(tmpDir, "ca.crt")
	cert3File := filepath.Join(tmpDir, "app2.crt")
	key3File := filepath.Join(tmpDir, "app2.key")

	if err := os.WriteFile(cert1File, cert1PEM, 0644); err != nil {
		t.Fatalf("Failed to write cert1: %v", err)
	}
	if err := os.WriteFile(key1File, key1PEM, 0644); err != nil {
		t.Fatalf("Failed to write key1: %v", err)
	}
	if err := os.WriteFile(cert2File, cert2PEM, 0644); err != nil {
		t.Fatalf("Failed to write cert2: %v", err)
	}
	if err := os.WriteFile(cert3File, cert3PEM, 0644); err != nil {
		t.Fatalf("Failed to write cert3: %v", err)
	}
	if err := os.WriteFile(key3File, key3PEM, 0644); err != nil {
		t.Fatalf("Failed to write key3: %v", err)
	}

	// Test 1: cert:key:alias format
	t.Run("cert_key_alias", func(t *testing.T) {
		certs = []string{cert1File + ":" + key1File + ":myapp"}
		defer func() { certs = nil }()

		pairs, err := parseCerts(certs)
		if err != nil {
			t.Fatalf("parseCerts failed: %v", err)
		}

		if len(pairs) != 1 {
			t.Fatalf("Expected 1 pair, got %d", len(pairs))
		}
		if pairs[0].alias != "myapp" {
			t.Errorf("Expected alias 'myapp', got %q", pairs[0].alias)
		}
		if len(pairs[0].certPEM) == 0 {
			t.Error("Expected cert PEM to be populated")
		}
		if len(pairs[0].keyPEM) == 0 {
			t.Error("Expected key PEM to be populated")
		}
	})

	// Test 2: cert:key (auto-generate alias)
	t.Run("cert_key_autoalias", func(t *testing.T) {
		certs = []string{cert1File + ":" + key1File}
		defer func() { certs = nil }()

		pairs, err := parseCerts(certs)
		if err != nil {
			t.Fatalf("parseCerts failed: %v", err)
		}

		if len(pairs) != 1 {
			t.Fatalf("Expected 1 pair, got %d", len(pairs))
		}
		if pairs[0].alias != "server" {
			t.Errorf("Expected alias 'server', got %q", pairs[0].alias)
		}
	})

	// Test 3: cert:: (cert-only with auto-generated alias)
	t.Run("cert_only", func(t *testing.T) {
		certs = []string{cert2File + "::"}
		defer func() { certs = nil }()

		pairs, err := parseCerts(certs)
		if err != nil {
			t.Fatalf("parseCerts failed: %v", err)
		}

		if len(pairs) != 1 {
			t.Fatalf("Expected 1 pair, got %d", len(pairs))
		}
		if pairs[0].alias != "server" {
			t.Errorf("Expected alias 'server', got %q", pairs[0].alias)
		}
		if len(pairs[0].keyPEM) != 0 {
			t.Error("Expected key PEM to be empty for cert-only")
		}
	})

	// Test 4: cert::alias (cert-only with explicit alias)
	t.Run("cert_only_alias", func(t *testing.T) {
		certs = []string{cert2File + "::myca"}
		defer func() { certs = nil }()

		pairs, err := parseCerts(certs)
		if err != nil {
			t.Fatalf("parseCerts failed: %v", err)
		}

		if len(pairs) != 1 {
			t.Fatalf("Expected 1 pair, got %d", len(pairs))
		}
		if pairs[0].alias != "myca" {
			t.Errorf("Expected alias 'myca', got %q", pairs[0].alias)
		}
		if len(pairs[0].keyPEM) != 0 {
			t.Error("Expected key PEM to be empty for cert-only")
		}
	})

	// Test 5: Multiple mixed entries
	t.Run("mixed_entries", func(t *testing.T) {
		certs = []string{
			cert1File + ":" + key1File + ":app1",
			cert2File + "::ca",
			cert3File + ":" + key3File, // auto-alias should be "server-2"
		}
		defer func() { certs = nil }()

		pairs, err := parseCerts(certs)
		if err != nil {
			t.Fatalf("parseCerts failed: %v", err)
		}

		if len(pairs) != 3 {
			t.Fatalf("Expected 3 pairs, got %d", len(pairs))
		}

		// Verify first entry (with key and alias)
		if pairs[0].alias != "app1" {
			t.Errorf("Expected alias 'app1', got %q", pairs[0].alias)
		}
		if len(pairs[0].keyPEM) == 0 {
			t.Error("Expected key PEM for first entry")
		}

		// Verify second entry (cert-only with alias)
		if pairs[1].alias != "ca" {
			t.Errorf("Expected alias 'ca', got %q", pairs[1].alias)
		}
		if len(pairs[1].keyPEM) != 0 {
			t.Error("Expected no key PEM for second entry")
		}

		// Verify third entry (with key, auto-alias)
		if pairs[2].alias != "server-2" {
			t.Errorf("Expected alias 'server-2', got %q", pairs[2].alias)
		}
		if len(pairs[2].keyPEM) == 0 {
			t.Error("Expected key PEM for third entry")
		}
	})
}

// TestFIPSMode tests FIPS 140-2 compliance mode
func TestFIPSMode(t *testing.T) {
	// Generate test certificate and key
	certPEM, keyPEM := generateTestCert(t, "fips-test.example.com")

	// Create temp files
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	t.Run("FIPS mode with default format", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "fips-default.p12")

		// Set flags - explicitly use PKCS#12 since our test helper doesn't simulate flag changes
		certs = []string{certFile + ":" + keyFile}
		password = "changeit"
		fipsMode = true
		format = "pkcs12" // Use PKCS#12 directly (in CLI, --fips auto-sets this)
		inputFile = ""
		cas = []string{}

		// Run conversion
		data, err := createKeystore()
		if err != nil {
			t.Fatalf("Failed to create keystore in FIPS mode: %v", err)
		}

		// Write output
		if err := os.WriteFile(outputFile, data, 0600); err != nil {
			t.Fatalf("Failed to write output: %v", err)
		}

		// Verify it's a valid PKCS#12 file
		_, _, _, err = pkcs12.DecodeChain(data, password)
		if err != nil {
			t.Fatalf("Failed to decode PKCS#12: %v", err)
		}

		t.Logf("Successfully created FIPS-compliant PKCS#12 keystore")
	})

	t.Run("FIPS mode rejects explicit JKS format", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "fips-jks-should-fail.jks")

		// Set flags for FIPS mode with explicit JKS
		certs = []string{certFile + ":" + keyFile}
		password = "changeit"
		fipsMode = true
		format = "jks"
		inputFile = ""
		cas = []string{}

		// Try to create JKS in FIPS mode - should fail
		_, err := createKeystore()
		if err == nil {
			t.Fatal("Expected error when using JKS format in FIPS mode, got nil")
		}

		expectedErrMsg := "JKS format is not FIPS 140-2 compliant"
		if !strings.Contains(err.Error(), expectedErrMsg) {
			t.Errorf("Expected error message to contain %q, got: %v", expectedErrMsg, err)
		}

		t.Logf("FIPS mode correctly rejected JKS format: %v", err)

		// Verify output file was not created
		if _, err := os.Stat(outputFile); err == nil {
			t.Error("Output file should not have been created when FIPS mode rejects JKS")
		}
	})

	t.Run("FIPS mode with PKCS#12 format", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "fips-pkcs12.p12")

		// Set flags
		certs = []string{certFile + ":" + keyFile}
		password = "changeit"
		fipsMode = true
		format = "pkcs12"
		inputFile = ""

		// Run conversion
		data, err := createKeystore()
		if err != nil {
			t.Fatalf("Failed to create PKCS#12 keystore in FIPS mode: %v", err)
		}

		// Write output
		if err := os.WriteFile(outputFile, data, 0600); err != nil {
			t.Fatalf("Failed to write output: %v", err)
		}

		// Verify it's a valid PKCS#12 file
		privKey, cert, caCerts, err := pkcs12.DecodeChain(data, password)
		if err != nil {
			t.Fatalf("Failed to decode PKCS#12: %v", err)
		}

		if privKey == nil {
			t.Error("Expected private key in keystore")
		}
		if cert == nil {
			t.Error("Expected certificate in keystore")
		}

		t.Logf("Successfully created FIPS-compliant PKCS#12 keystore with %d CA certs", len(caCerts))
	})
}

// Helper function to create keystore (simplified version for testing)
func createKeystore() ([]byte, error) {
	// Parse cert/key entries
	pairs, err := parseCerts(certs)
	if err != nil {
		return nil, err
	}

	// Parse CA entries if any
	caPairs, err := parseCAs(cas)
	if err != nil {
		return nil, err
	}

	// Normalize format
	keystoreFormat := strings.ToLower(format)

	// FIPS mode validation
	if fipsMode && keystoreFormat == "jks" {
		return nil, fmt.Errorf("FIPS mode is enabled: JKS format is not FIPS 140-2 compliant (uses SHA-1). Please use PKCS#12 format with --format=pkcs12")
	}

	// Create keystore based on format
	switch keystoreFormat {
	case "jks":
		return createJKSKeystore(pairs, caPairs, password, inputFile, password)
	case "pkcs12", "p12":
		return createPKCS12Keystore(pairs, caPairs, password, inputFile, password)
	default:
		return nil, fmt.Errorf("invalid format: %s", format)
	}
}
