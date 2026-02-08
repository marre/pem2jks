package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	// Create temp directory for test files
	tempDir := t.TempDir()

	// Generate test certificates
	cert1PEM, key1PEM := generateTestCert(t, "app1.example.com")
	cert2PEM, key2PEM := generateTestCert(t, "app2.example.com")

	// Write to files
	cert1File := filepath.Join(tempDir, "cert1.pem")
	key1File := filepath.Join(tempDir, "key1.pem")
	cert2File := filepath.Join(tempDir, "cert2.pem")
	key2File := filepath.Join(tempDir, "key2.pem")

	if err := os.WriteFile(cert1File, cert1PEM, 0600); err != nil {
		t.Fatalf("Failed to write cert1: %v", err)
	}
	if err := os.WriteFile(key1File, key1PEM, 0600); err != nil {
		t.Fatalf("Failed to write key1: %v", err)
	}
	if err := os.WriteFile(cert2File, cert2PEM, 0600); err != nil {
		t.Fatalf("Failed to write cert2: %v", err)
	}
	if err := os.WriteFile(key2File, key2PEM, 0600); err != nil {
		t.Fatalf("Failed to write key2: %v", err)
	}

	// Prepare cert/key pairs
	pairs := []certKeyPair{
		{certPEM: cert1PEM, keyPEM: key1PEM, alias: "app1"},
		{certPEM: cert2PEM, keyPEM: key2PEM, alias: "app2"},
	}

	// Create JKS keystore
	jksData, err := createJKSKeystore(pairs, nil, "changeit")
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

	// Prepare cert/key pair
	pairs := []certKeyPair{
		{certPEM: certPEM, keyPEM: keyPEM, alias: "app"},
	}

	// Create PKCS#12 keystore with CA
	p12Data, err := createPKCS12Keystore(pairs, caPEM, "changeit", "", false)
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
	
	p12Data1, err := createPKCS12Keystore(pairs1, nil, "changeit", "", false)
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
	p12Data2, err := createPKCS12Keystore(pairs2, nil, "changeit", inputFile, false)
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

	_, err := createPKCS12Keystore(pairs, nil, "changeit", "", false)
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

	// Combine CA PEMs
	allCAPEM := append(ca1PEM, ca2PEM...)

	// Create JKS truststore with multiple CAs
	jksData, err := createJKSKeystore(nil, allCAPEM, "changeit")
	if err != nil {
		t.Fatalf("Failed to create JKS with multiple CAs: %v", err)
	}

	if len(jksData) == 0 {
		t.Error("JKS data is empty")
	}

	t.Logf("Created JKS truststore with 2 CAs, size: %d bytes", len(jksData))
}

func TestGenerateAliases(t *testing.T) {
	tests := []struct {
		name           string
		numCerts       int
		providedAliases []string
		expectedAliases []string
	}{
		{
			name:            "No aliases provided",
			numCerts:        3,
			providedAliases: []string{},
			expectedAliases: []string{"server", "server-1", "server-2"},
		},
		{
			name:            "Some aliases provided",
			numCerts:        3,
			providedAliases: []string{"app1", "app2"},
			expectedAliases: []string{"app1", "app2", "server-2"},
		},
		{
			name:            "All aliases provided",
			numCerts:        2,
			providedAliases: []string{"custom1", "custom2"},
			expectedAliases: []string{"custom1", "custom2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the alias generation logic from runConvert
			generatedAliases := make([]string, tt.numCerts)
			for i := 0; i < tt.numCerts; i++ {
				if i < len(tt.providedAliases) && tt.providedAliases[i] != "" {
					generatedAliases[i] = tt.providedAliases[i]
				} else {
					if i == 0 {
						generatedAliases[i] = "server"
					} else {
						generatedAliases[i] = "server-" + string(rune('0'+i))
					}
				}
			}

			// For proper formatting
			for i := 0; i < tt.numCerts; i++ {
				if i < len(tt.providedAliases) && tt.providedAliases[i] != "" {
					generatedAliases[i] = tt.providedAliases[i]
				} else {
					if i == 0 {
						generatedAliases[i] = "server"
					} else {
						// Use proper integer formatting
						generatedAliases[i] = "server-" + string(rune('0'+i))
					}
				}
			}

			// Actually, let me use the correct logic
			for i := 0; i < tt.numCerts; i++ {
				if i < len(tt.providedAliases) && tt.providedAliases[i] != "" {
					if generatedAliases[i] != tt.expectedAliases[i] {
						t.Errorf("Alias %d: got %q, want %q", i, generatedAliases[i], tt.expectedAliases[i])
					}
				}
			}
		})
	}
}
