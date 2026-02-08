// Package main provides the pem2jks CLI tool.
package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/marre/pem2jks/pkg/keystore"
	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
)

// Version information (set by ldflags)
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

// certKeyPair represents a certificate and key pair with alias
type certKeyPair struct {
	certPEM []byte
	keyPEM  []byte
	alias   string
}

// CLI flags
var (
	certFiles    []string
	keyFiles     []string
	caFiles      []string
	outputFile   string
	password     string
	passwordFile string
	aliases      []string
	format       string
	legacy       bool
	inputFile    string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "pem2jks",
	Short: "Convert PEM certificates to Java KeyStore format",
	Long: `pem2jks is a tool for converting PEM-encoded certificates and private keys
into Java KeyStore (JKS) or PKCS#12 format.

It is designed for use in Kubernetes environments where certificates are
typically provided in PEM format (e.g., from cert-manager) but Java
applications require JKS or PKCS#12 keystores.`,
	Example: `  # Create JKS keystore with private key and certificate
  pem2jks -c tls.crt -k tls.key -p changeit -o keystore.jks

  # Create PKCS#12 keystore (modern format)
  pem2jks -c tls.crt -k tls.key -p changeit -f pkcs12

  # Create PKCS#12 with legacy algorithms for older Java
  pem2jks -c tls.crt -k tls.key -p changeit -f pkcs12 --legacy

  # Create keystore with multiple cert/key pairs
  pem2jks -c app1.crt -k app1.key -a app1 -c app2.crt -k app2.key -a app2 -p changeit

  # Add certificates to existing PKCS#12 keystore
  pem2jks --input existing.p12 -c new.crt -k new.key -a newcert -p changeit

  # Create keystore with certificate chain and CAs
  pem2jks -c tls.crt -k tls.key --ca ca1.crt --ca ca2.crt -p changeit

  # Create truststore (CA certs only, no private key)
  pem2jks --ca ca.crt -p changeit -f pkcs12 -o truststore.p12

  # Use environment variable for password
  export KEYSTORE_PASSWORD=changeit
  pem2jks -c tls.crt -k tls.key`,
	RunE:          runConvert,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("pem2jks %s (commit: %s, built: %s)\n", Version, GitCommit, BuildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)

	// Define flags
	rootCmd.Flags().StringArrayVarP(&certFiles, "cert", "c", []string{}, "path to certificate PEM file (repeatable)")
	rootCmd.Flags().StringArrayVarP(&keyFiles, "key", "k", []string{}, "path to private key PEM file (repeatable)")
	rootCmd.Flags().StringArrayVar(&caFiles, "ca", []string{}, "path to CA certificate PEM file (repeatable)")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output keystore file path (default based on format)")
	rootCmd.Flags().StringVarP(&password, "password", "p", "", "keystore password (or use KEYSTORE_PASSWORD env)")
	rootCmd.Flags().StringVar(&passwordFile, "password-file", "", "file containing keystore password")
	rootCmd.Flags().StringArrayVarP(&aliases, "alias", "a", []string{}, "alias for the private key entry (repeatable, default: server, server-1, ...)")
	rootCmd.Flags().StringVarP(&format, "format", "f", "jks", "keystore format: jks, pkcs12, or p12")
	rootCmd.Flags().BoolVar(&legacy, "legacy", false, "use legacy algorithms for PKCS#12 (for older Java)")
	rootCmd.Flags().StringVarP(&inputFile, "input", "i", "", "existing keystore file to append to (supports both JKS and PKCS#12)")
}

func runConvert(cmd *cobra.Command, args []string) error {
	// Normalize and validate format
	keystoreFormat := strings.ToLower(format)
	switch keystoreFormat {
	case "jks", "pkcs12", "p12":
		// valid
	default:
		return fmt.Errorf("invalid format %q (use jks, pkcs12, or p12)", format)
	}

	// Set default output filename based on format
	outputPath := outputFile
	if outputPath == "" {
		switch keystoreFormat {
		case "jks":
			outputPath = "keystore.jks"
		case "pkcs12", "p12":
			outputPath = "keystore.p12"
		}
	}

	// Get password
	keystorePassword := getPassword()
	if keystorePassword == "" {
		return fmt.Errorf("password is required (use -p/--password, --password-file, or KEYSTORE_PASSWORD env)")
	}

	// Validate cert/key pairs match
	if len(certFiles) != len(keyFiles) && len(keyFiles) > 0 {
		return fmt.Errorf("number of --cert flags (%d) must match number of --key flags (%d)", len(certFiles), len(keyFiles))
	}

	// Generate aliases if not provided
	generatedAliases := make([]string, len(certFiles))
	for i := range certFiles {
		if i < len(aliases) && aliases[i] != "" {
			generatedAliases[i] = aliases[i]
		} else {
			if i == 0 {
				generatedAliases[i] = "server"
			} else {
				generatedAliases[i] = fmt.Sprintf("server-%d", i)
			}
		}
	}

	// Read cert/key pairs
	var pairs []certKeyPair

	for i := range certFiles {
		certPEM, err := os.ReadFile(certFiles[i])
		if err != nil {
			return fmt.Errorf("reading certificate file %s: %w", certFiles[i], err)
		}

		var keyPEM []byte
		if i < len(keyFiles) && keyFiles[i] != "" {
			keyPEM, err = os.ReadFile(keyFiles[i])
			if err != nil {
				return fmt.Errorf("reading private key file %s: %w", keyFiles[i], err)
			}
		}

		pairs = append(pairs, certKeyPair{
			certPEM: certPEM,
			keyPEM:  keyPEM,
			alias:   generatedAliases[i],
		})
	}

	// Read CA certificates
	var allCAPEM []byte
	for _, caFile := range caFiles {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return fmt.Errorf("reading CA certificate file %s: %w", caFile, err)
		}
		allCAPEM = append(allCAPEM, caPEM...)
	}

	// Validate we have something to do
	if len(pairs) == 0 && len(allCAPEM) == 0 {
		if inputFile == "" {
			return fmt.Errorf("at least one of --cert or --ca is required")
		}
	}

	// Create keystore based on format
	var keystoreData []byte
	var err error

	switch keystoreFormat {
	case "jks":
		keystoreData, err = createJKSKeystore(pairs, allCAPEM, keystorePassword, inputFile)
	case "pkcs12", "p12":
		keystoreData, err = createPKCS12Keystore(pairs, allCAPEM, keystorePassword, inputFile, legacy)
	}

	if err != nil {
		return fmt.Errorf("creating keystore: %w", err)
	}

	// Write output file
	if err := os.WriteFile(outputPath, keystoreData, 0600); err != nil {
		return fmt.Errorf("writing keystore file: %w", err)
	}

	fmt.Printf("Created keystore: %s\n", outputPath)
	return nil
}

func createJKSKeystore(pairs []certKeyPair, caPEM []byte, password string, inputFile string) ([]byte, error) {
	var ks *keystore.JKS

	// Load existing keystore if provided
	if inputFile != "" {
		existingData, err := os.ReadFile(inputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read input file: %w", err)
		}

		ks = keystore.NewJKS()
		if err := ks.Unmarshal(existingData, password); err != nil {
			return nil, fmt.Errorf("failed to load existing JKS keystore: %w", err)
		}
	} else {
		ks = keystore.NewJKS()
	}

	// Add each cert/key pair
	for _, pair := range pairs {
		// Parse certificate(s)
		var certChain [][]byte
		if len(pair.certPEM) > 0 {
			var err error
			certChain, err = keystore.ParsePEMCertificates(pair.certPEM)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate for alias %s: %w", pair.alias, err)
			}
		}

		// If we have a private key, add as private key entry
		if len(pair.keyPEM) > 0 {
			if len(certChain) == 0 {
				return nil, fmt.Errorf("private key provided but no certificate for alias %s", pair.alias)
			}
			pkcs8Key, err := keystore.ParsePEMPrivateKey(pair.keyPEM)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key for alias %s: %w", pair.alias, err)
			}
			if err := ks.AddPrivateKey(pair.alias, pkcs8Key, certChain); err != nil {
				return nil, fmt.Errorf("failed to add private key entry for alias %s: %w", pair.alias, err)
			}
		} else if len(certChain) > 0 {
			// No private key, add as trusted cert(s)
			for i, cert := range certChain {
				certAlias := pair.alias
				if i > 0 {
					certAlias = fmt.Sprintf("%s-%d", pair.alias, i)
				}
				if err := ks.AddTrustedCert(certAlias, cert); err != nil {
					return nil, fmt.Errorf("failed to add trusted cert for alias %s: %w", certAlias, err)
				}
			}
		}
	}

	// Add CA certificates as trusted certs
	if len(caPEM) > 0 {
		caCerts, err := keystore.ParsePEMCertificates(caPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificates: %w", err)
		}
		for i, caCert := range caCerts {
			caAlias := "ca"
			if i > 0 {
				caAlias = fmt.Sprintf("ca-%d", i)
			}
			if err := ks.AddTrustedCert(caAlias, caCert); err != nil {
				return nil, fmt.Errorf("failed to add CA certificate: %w", err)
			}
		}
	}

	if len(ks.Entries) == 0 {
		return nil, errors.New("no entries to add to keystore")
	}

	return ks.Marshal(password)
}

func createPKCS12Keystore(pairs []certKeyPair, caPEM []byte, password string, inputFile string, useLegacy bool) ([]byte, error) {
	ks := keystore.NewPKCS12()

	// Load existing keystore if provided
	if inputFile != "" {
		existingData, err := os.ReadFile(inputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read input file: %w", err)
		}

		// Try to decode as keystore with private key
		privKey, cert, caCerts, err := pkcs12.DecodeChain(existingData, password)
		if err == nil && privKey != nil {
			// Has private key
			ks.SetPrivateKey(privKey, cert)
			for _, caCert := range caCerts {
				ks.AddCACert(caCert)
			}
		} else {
			// Try as truststore
			certs, err := pkcs12.DecodeTrustStore(existingData, password)
			if err != nil {
				return nil, fmt.Errorf("failed to decode existing keystore: %w", err)
			}
			for _, cert := range certs {
				ks.AddTrustedCert(cert)
			}
		}
	}

	// Add new cert/key pairs
	for _, pair := range pairs {
		var certChain []*x509.Certificate
		if len(pair.certPEM) > 0 {
			certs, err := keystore.ParsePEMCertificates(pair.certPEM)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate for alias %s: %w", pair.alias, err)
			}
			for _, certDER := range certs {
				cert, err := x509.ParseCertificate(certDER)
				if err != nil {
					return nil, fmt.Errorf("failed to parse certificate for alias %s: %w", pair.alias, err)
				}
				certChain = append(certChain, cert)
			}
		}

		if len(pair.keyPEM) > 0 {
			if len(certChain) == 0 {
				return nil, fmt.Errorf("private key provided but no certificate for alias %s", pair.alias)
			}

			pkcs8Data, err := keystore.ParsePEMPrivateKey(pair.keyPEM)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key for alias %s: %w", pair.alias, err)
			}
			key, err := x509.ParsePKCS8PrivateKey(pkcs8Data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PKCS8 private key for alias %s: %w", pair.alias, err)
			}

			// For PKCS12, we can only have one private key entry
			if ks.PrivateKey != nil {
				return nil, fmt.Errorf("PKCS#12 format only supports one private key entry (alias %s conflicts with existing)", pair.alias)
			}

			ks.SetPrivateKey(key, certChain[0])
			for _, caCert := range certChain[1:] {
				ks.AddCACert(caCert)
			}
		} else if len(certChain) > 0 {
			for _, cert := range certChain {
				ks.AddTrustedCert(cert)
			}
		}
	}

	// Add CA certificates
	if len(caPEM) > 0 {
		caCerts, err := keystore.ParsePEMCertificates(caPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificates: %w", err)
		}
		for _, certDER := range caCerts {
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
			}
			if ks.PrivateKey != nil {
				ks.AddCACert(cert)
			} else {
				ks.AddTrustedCert(cert)
			}
		}
	}

	if useLegacy {
		return ks.MarshalLegacy(password)
	}
	return ks.Marshal(password)
}

func getPassword() string {
	// Priority: --password > --password-file > KEYSTORE_PASSWORD env
	if password != "" {
		return password
	}
	if passwordFile != "" {
		data, err := os.ReadFile(passwordFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password file: %v\n", err)
			os.Exit(2)
		}
		return strings.TrimSpace(string(data))
	}
	return os.Getenv("KEYSTORE_PASSWORD")
}
