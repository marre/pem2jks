package main

import (
	"bytes"
	"context"
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

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestIntegration is the main integration test that requires Docker/testcontainers
func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	ctx := context.Background()

	// Start a Java container with keytool
	req := testcontainers.ContainerRequest{
		Image:      "eclipse-temurin:21-jre-alpine",
		Cmd:        []string{"sleep", "infinity"},
		WaitingFor: wait.ForLog("").WithStartupTimeout(30 * time.Second),
	}

	javaContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("Failed to start Java container: %v", err)
	}
	defer func() {
		if err := javaContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	// Create test data directory
	tmpDir := t.TempDir()

	// Generate test certificates using Go
	caCert, caKey := generateCACert(t)
	tlsCert, tlsKey := generateServerCert(t, caCert, caKey, "localhost")

	// Write certificates to files
	caCertFile := filepath.Join(tmpDir, "ca.crt")
	tlsCertFile := filepath.Join(tmpDir, "tls.crt")
	tlsKeyFile := filepath.Join(tmpDir, "tls.key")

	if err := os.WriteFile(caCertFile, caCert, 0644); err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}
	if err := os.WriteFile(tlsCertFile, tlsCert, 0644); err != nil {
		t.Fatalf("Failed to write TLS cert: %v", err)
	}
	if err := os.WriteFile(tlsKeyFile, tlsKey, 0644); err != nil {
		t.Fatalf("Failed to write TLS key: %v", err)
	}

	// Run all test scenarios
	t.Run("JKS_Format_Tests", func(t *testing.T) {
		testJKSFormat(t, ctx, javaContainer, tmpDir, tlsCertFile, tlsKeyFile, caCertFile)
	})

	t.Run("PKCS12_Format_Tests", func(t *testing.T) {
		testPKCS12Format(t, ctx, javaContainer, tmpDir, tlsCertFile, tlsKeyFile, caCertFile)
	})

	t.Run("Multiple_PEM_Files_Tests", func(t *testing.T) {
		testMultiplePEMFiles(t, ctx, javaContainer, tmpDir, tlsCertFile, tlsKeyFile, caCertFile)
	})

	t.Run("JKS_Append_Tests", func(t *testing.T) {
		testJKSAppend(t, ctx, javaContainer, tmpDir, tlsCertFile, tlsKeyFile, caCertFile)
	})

	t.Run("PKCS12_Append_Tests", func(t *testing.T) {
		testPKCS12Append(t, ctx, javaContainer, tmpDir, tlsCertFile, tlsKeyFile, caCertFile)
	})
}

func testJKSFormat(t *testing.T, ctx context.Context, container testcontainers.Container, tmpDir, certFile, keyFile, caFile string) {
	t.Run("Create_JKS_With_Private_Key", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "test1.jks")

		// Create JKS keystore with private key
		pairs := []certKeyPair{
			{
				certPEM: mustReadFile(t, certFile),
				keyPEM:  mustReadFile(t, keyFile),
				alias:   "server",
			},
		}

		jksData, err := createJKSKeystore(pairs, nil, "changeit", "", "changeit")
		if err != nil {
			t.Fatalf("Failed to create JKS: %v", err)
		}

		if err := os.WriteFile(outputFile, jksData, 0644); err != nil {
			t.Fatalf("Failed to write JKS: %v", err)
		}

		// Verify with keytool
		verifyKeystoreWithKeytool(t, ctx, container, outputFile, "changeit", "jks")
	})

	t.Run("Create_JKS_With_CA", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "test2.jks")

		pairs := []certKeyPair{
			{
				certPEM: mustReadFile(t, certFile),
				keyPEM:  mustReadFile(t, keyFile),
				alias:   "server",
			},
		}
		caPairs := []certKeyPair{
			{
				certPEM: mustReadFile(t, caFile),
				alias:   "ca",
			},
		}

		jksData, err := createJKSKeystore(pairs, caPairs, "changeit", "", "changeit")
		if err != nil {
			t.Fatalf("Failed to create JKS with CA: %v", err)
		}

		if err := os.WriteFile(outputFile, jksData, 0644); err != nil {
			t.Fatalf("Failed to write JKS: %v", err)
		}

		// Verify with keytool
		verifyKeystoreWithKeytool(t, ctx, container, outputFile, "changeit", "jks")
	})

	t.Run("Create_JKS_Truststore", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "truststore.jks")

		caPairs := []certKeyPair{
			{
				certPEM: mustReadFile(t, caFile),
				alias:   "ca",
			},
		}

		jksData, err := createJKSKeystore(nil, caPairs, "changeit", "", "changeit")
		if err != nil {
			t.Fatalf("Failed to create JKS truststore: %v", err)
		}

		if err := os.WriteFile(outputFile, jksData, 0644); err != nil {
			t.Fatalf("Failed to write JKS truststore: %v", err)
		}

		// Verify with keytool
		verifyKeystoreWithKeytool(t, ctx, container, outputFile, "changeit", "jks")
	})
}

func testPKCS12Format(t *testing.T, ctx context.Context, container testcontainers.Container, tmpDir, certFile, keyFile, caFile string) {
	t.Run("Create_PKCS12_With_Private_Key", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "test1.p12")

		pairs := []certKeyPair{
			{
				certPEM: mustReadFile(t, certFile),
				keyPEM:  mustReadFile(t, keyFile),
				alias:   "server",
			},
		}

		p12Data, err := createPKCS12Keystore(pairs, nil, "changeit", "", "changeit")
		if err != nil {
			t.Fatalf("Failed to create PKCS#12: %v", err)
		}

		if err := os.WriteFile(outputFile, p12Data, 0644); err != nil {
			t.Fatalf("Failed to write PKCS#12: %v", err)
		}

		// Verify with keytool
		verifyKeystoreWithKeytool(t, ctx, container, outputFile, "changeit", "pkcs12")
	})

	t.Run("Create_PKCS12_With_CA", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "test2.p12")

		pairs := []certKeyPair{
			{
				certPEM: mustReadFile(t, certFile),
				keyPEM:  mustReadFile(t, keyFile),
				alias:   "server",
			},
		}
		caPairs := []certKeyPair{
			{
				certPEM: mustReadFile(t, caFile),
				alias:   "ca",
			},
		}

		p12Data, err := createPKCS12Keystore(pairs, caPairs, "changeit", "", "changeit")
		if err != nil {
			t.Fatalf("Failed to create PKCS#12 with CA: %v", err)
		}

		if err := os.WriteFile(outputFile, p12Data, 0644); err != nil {
			t.Fatalf("Failed to write PKCS#12: %v", err)
		}

		// Verify with keytool
		verifyKeystoreWithKeytool(t, ctx, container, outputFile, "changeit", "pkcs12")
	})

	t.Run("Create_PKCS12_Truststore", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "truststore.p12")

		caPairs := []certKeyPair{
			{
				certPEM: mustReadFile(t, caFile),
				alias:   "ca",
			},
		}

		p12Data, err := createPKCS12Keystore(caPairs, nil, "changeit", "", "changeit")
		if err != nil {
			t.Fatalf("Failed to create PKCS#12 truststore: %v", err)
		}

		if err := os.WriteFile(outputFile, p12Data, 0644); err != nil {
			t.Fatalf("Failed to write PKCS#12 truststore: %v", err)
		}

		// Verify with keytool
		verifyKeystoreWithKeytool(t, ctx, container, outputFile, "changeit", "pkcs12")
	})
}

func testMultiplePEMFiles(t *testing.T, ctx context.Context, container testcontainers.Container, tmpDir, certFile, keyFile, caFile string) {
	t.Run("Create_JKS_With_Multiple_Keys", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "multi-keys.jks")

		pairs := []certKeyPair{
			{
				certPEM: mustReadFile(t, certFile),
				keyPEM:  mustReadFile(t, keyFile),
				alias:   "server1",
			},
			{
				certPEM: mustReadFile(t, certFile),
				keyPEM:  mustReadFile(t, keyFile),
				alias:   "server2",
			},
		}

		jksData, err := createJKSKeystore(pairs, nil, "changeit", "", "changeit")
		if err != nil {
			t.Fatalf("Failed to create JKS with multiple keys: %v", err)
		}

		if err := os.WriteFile(outputFile, jksData, 0644); err != nil {
			t.Fatalf("Failed to write JKS: %v", err)
		}

		// Verify with keytool and check entry count
		entryCount := verifyKeystoreWithKeytool(t, ctx, container, outputFile, "changeit", "jks")
		if entryCount != 2 {
			t.Errorf("Expected 2 entries, got %d", entryCount)
		}
	})

	t.Run("Create_JKS_With_Multiple_CAs", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "multi-ca.jks")

		caPairs := []certKeyPair{
			{
				certPEM: mustReadFile(t, caFile),
				alias:   "ca1",
			},
			{
				certPEM: mustReadFile(t, caFile),
				alias:   "ca2",
			},
		}

		jksData, err := createJKSKeystore(nil, caPairs, "changeit", "", "changeit")
		if err != nil {
			t.Fatalf("Failed to create JKS with multiple CAs: %v", err)
		}

		if err := os.WriteFile(outputFile, jksData, 0644); err != nil {
			t.Fatalf("Failed to write JKS: %v", err)
		}

		// Verify with keytool and check entry count
		entryCount := verifyKeystoreWithKeytool(t, ctx, container, outputFile, "changeit", "jks")
		if entryCount != 2 {
			t.Errorf("Expected 2 CA entries, got %d", entryCount)
		}
	})
}

func testJKSAppend(t *testing.T, ctx context.Context, container testcontainers.Container, tmpDir, certFile, keyFile, caFile string) {
	t.Run("Append_Private_Key_To_JKS", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "append-test.jks")

		// Create initial JKS
		pairs1 := []certKeyPair{
			{
				certPEM: mustReadFile(t, certFile),
				keyPEM:  mustReadFile(t, keyFile),
				alias:   "initial-key",
			},
		}

		jksData1, err := createJKSKeystore(pairs1, nil, "changeit", "", "changeit")
		if err != nil {
			t.Fatalf("Failed to create initial JKS: %v", err)
		}

		if err := os.WriteFile(outputFile, jksData1, 0644); err != nil {
			t.Fatalf("Failed to write initial JKS: %v", err)
		}

		// Verify initial entry count
		entryCount := verifyKeystoreWithKeytool(t, ctx, container, outputFile, "changeit", "jks")
		if entryCount != 1 {
			t.Errorf("Expected 1 entry initially, got %d", entryCount)
		}

		// Append another key
		pairs2 := []certKeyPair{
			{
				certPEM: mustReadFile(t, certFile),
				keyPEM:  mustReadFile(t, keyFile),
				alias:   "appended-key",
			},
		}

		jksData2, err := createJKSKeystore(pairs2, nil, "changeit", outputFile, "changeit")
		if err != nil {
			t.Fatalf("Failed to append to JKS: %v", err)
		}

		if err := os.WriteFile(outputFile, jksData2, 0644); err != nil {
			t.Fatalf("Failed to write appended JKS: %v", err)
		}

		// Verify appended entry count
		entryCount = verifyKeystoreWithKeytool(t, ctx, container, outputFile, "changeit", "jks")
		if entryCount != 2 {
			t.Errorf("Expected 2 entries after append, got %d", entryCount)
		}
	})

	t.Run("Append_CA_To_JKS", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "append-ca-test.jks")

		// Create initial JKS with private key
		pairs := []certKeyPair{
			{
				certPEM: mustReadFile(t, certFile),
				keyPEM:  mustReadFile(t, keyFile),
				alias:   "server",
			},
		}

		jksData1, err := createJKSKeystore(pairs, nil, "changeit", "", "changeit")
		if err != nil {
			t.Fatalf("Failed to create initial JKS: %v", err)
		}

		if err := os.WriteFile(outputFile, jksData1, 0644); err != nil {
			t.Fatalf("Failed to write initial JKS: %v", err)
		}

		// Append CA
		caPairs := []certKeyPair{
			{
				certPEM: mustReadFile(t, caFile),
				alias:   "ca",
			},
		}

		jksData2, err := createJKSKeystore(nil, caPairs, "changeit", outputFile, "changeit")
		if err != nil {
			t.Fatalf("Failed to append CA to JKS: %v", err)
		}

		if err := os.WriteFile(outputFile, jksData2, 0644); err != nil {
			t.Fatalf("Failed to write appended JKS: %v", err)
		}

		// Verify entry count
		entryCount := verifyKeystoreWithKeytool(t, ctx, container, outputFile, "changeit", "jks")
		if entryCount != 2 {
			t.Errorf("Expected 2 entries after CA append, got %d", entryCount)
		}
	})
}

func testPKCS12Append(t *testing.T, ctx context.Context, container testcontainers.Container, tmpDir, certFile, keyFile, caFile string) {
	t.Run("Append_CA_To_PKCS12", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "append-test.p12")

		// Create initial PKCS#12 with CA
		caPairs1 := []certKeyPair{
			{
				certPEM: mustReadFile(t, caFile),
				alias:   "ca1",
			},
		}

		p12Data1, err := createPKCS12Keystore(caPairs1, nil, "changeit", "", "changeit")
		if err != nil {
			t.Fatalf("Failed to create initial PKCS#12: %v", err)
		}

		if err := os.WriteFile(outputFile, p12Data1, 0644); err != nil {
			t.Fatalf("Failed to write initial PKCS#12: %v", err)
		}

		// Verify initial entry count
		entryCount := verifyKeystoreWithKeytool(t, ctx, container, outputFile, "changeit", "pkcs12")
		if entryCount != 1 {
			t.Errorf("Expected 1 entry initially, got %d", entryCount)
		}

		// Append another CA (use cert file as another CA)
		caPairs2 := []certKeyPair{
			{
				certPEM: mustReadFile(t, certFile),
				alias:   "ca2",
			},
		}

		p12Data2, err := createPKCS12Keystore(caPairs2, nil, "changeit", outputFile, "changeit")
		if err != nil {
			t.Fatalf("Failed to append to PKCS#12: %v", err)
		}

		if err := os.WriteFile(outputFile, p12Data2, 0644); err != nil {
			t.Fatalf("Failed to write appended PKCS#12: %v", err)
		}

		// Verify appended entry count
		entryCount = verifyKeystoreWithKeytool(t, ctx, container, outputFile, "changeit", "pkcs12")
		if entryCount != 2 {
			t.Errorf("Expected 2 entries after append, got %d", entryCount)
		}
	})
}

// Helper functions

func generateCACert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	// Generate CA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	// Create CA certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed CA certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	// Encode to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal CA key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key})

	return certPEM, keyPEM
}

func generateServerCert(t *testing.T, caCertPEM, caKeyPEM []byte, cn string) (certPEM, keyPEM []byte) {
	t.Helper()

	// Parse CA cert and key
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		t.Fatal("Failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CA cert: %v", err)
	}

	block, _ = pem.Decode(caKeyPEM)
	if block == nil {
		t.Fatal("Failed to decode CA key PEM")
	}
	caKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CA key: %v", err)
	}
	caKey := caKeyInterface.(*rsa.PrivateKey)

	// Generate server key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate server key: %v", err)
	}

	// Create server certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	// Encode to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal server key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key})

	return certPEM, keyPEM
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", path, err)
	}
	return data
}

func verifyKeystoreWithKeytool(t *testing.T, ctx context.Context, container testcontainers.Container, keystorePath, password, storeType string) int {
	t.Helper()

	// Copy keystore to container
	containerPath := "/tmp/" + filepath.Base(keystorePath)
	if err := container.CopyFileToContainer(ctx, keystorePath, containerPath, 0644); err != nil {
		t.Fatalf("Failed to copy keystore to container: %v", err)
	}

	// Run keytool to list keystore entries
	var cmd []string
	if storeType == "pkcs12" {
		cmd = []string{"keytool", "-list", "-keystore", containerPath, "-storepass", password, "-storetype", "PKCS12"}
	} else {
		cmd = []string{"keytool", "-list", "-keystore", containerPath, "-storepass", password}
	}

	exitCode, reader, err := container.Exec(ctx, cmd)
	if err != nil {
		t.Fatalf("Failed to execute keytool: %v", err)
	}

	// Read output
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(reader)
	if err != nil {
		t.Fatalf("Failed to read keytool output: %v", err)
	}

	output := buf.String()
	t.Logf("Keytool output:\n%s", output)

	if exitCode != 0 {
		t.Fatalf("Keytool verification failed with exit code %d", exitCode)
	}

	// Parse entry count from output
	entryCount := 0
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "Your keystore contains") {
			// Extract number from line like "Your keystore contains 2 entries"
			// Clean up any special characters
			cleaned := strings.Map(func(r rune) rune {
				if r >= '0' && r <= '9' || r == ' ' {
					return r
				}
				return -1
			}, line)

			// Try to parse the number
			var count int
			_, err := fmt.Sscanf(strings.TrimSpace(cleaned), "%d", &count)
			if err == nil {
				entryCount = count
			}
			break
		}
	}

	return entryCount
}
