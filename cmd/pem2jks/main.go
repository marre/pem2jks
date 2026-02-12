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
	certs         []string // cert:key:alias format
	cas           []string // ca:alias format
	outputFile    string
	password      string
	passwordFile  string
	inputPassword string
	format        string
	inputFile     string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "pem2jks",
	Short: "Convert PEM certificates to Java KeyStore format",
	Long: getBuildSpecificLongDescription(),
	Example: getBuildSpecificExamples(),
	RunE:          runConvert,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// getBuildSpecificLongDescription returns the long description based on build type
func getBuildSpecificLongDescription() string {
	base := `pem2jks is a tool for converting PEM-encoded certificates and private keys
into Java KeyStore (JKS) or PKCS#12 format.

It is designed for use in Kubernetes environments where certificates are
typically provided in PEM format (e.g., from cert-manager) but Java
applications require JKS or PKCS#12 keystores.`

	if fipsBuild {
		return base + `

FIPS 140-2 Build:
  This is a FIPS 140-2 compliant build. Only PKCS#12 format is supported.
  PKCS#12 output uses PBES2 with PBKDF2-HMAC-SHA-256 and AES-256-CBC, which are
  FIPS-approved algorithms. JKS format is not available in FIPS builds.`
	}

	return base + `

FIPS 140-2 Compliance:
  For FIPS-compliant keystores, use PKCS#12 format (--format=pkcs12).
  PKCS#12 output uses PBES2 with PBKDF2-HMAC-SHA-256 and AES-256-CBC, which are
  FIPS-approved algorithms. JKS format uses SHA-1 and is not FIPS-compliant.
  For a FIPS-only build, use the pem2jks-fips binary.`
}

// getBuildSpecificExamples returns examples based on build type
func getBuildSpecificExamples() string {
	if fipsBuild {
		return `  # Create PKCS#12 keystore (FIPS-compliant)
  pem2jks -c tls.crt:tls.key -p changeit

  # Create PKCS#12 keystore with explicit format
  pem2jks -c tls.crt:tls.key -p changeit -f pkcs12

  # Create keystore with multiple cert/key pairs (not supported in PKCS#12)
  # Note: PKCS#12 only supports one private key entry

  # Mix private key entry with cert-only entries
  pem2jks -c tls.crt:tls.key:server --ca ca1.crt:ca1 --ca ca2.crt:ca2 -p changeit

  # Create keystore with certificate chain and CAs
  pem2jks -c tls.crt:tls.key --ca ca1.crt:root-ca --ca ca2.crt:intermediate -p changeit

  # Create truststore (CA certs only, no private key)
  pem2jks --ca ca.crt:my-ca -p changeit -o truststore.p12

  # Use environment variable for password
  export KEYSTORE_PASSWORD=changeit
  pem2jks -c tls.crt:tls.key`
	}

	return `  # Create JKS keystore with private key and certificate
  pem2jks -c tls.crt:tls.key -p changeit -o keystore.jks

  # Create PKCS#12 keystore (FIPS-compliant)
  pem2jks -c tls.crt:tls.key -p changeit -f pkcs12

  # Create keystore with multiple cert/key pairs and custom aliases
  pem2jks -c app1.crt:app1.key:app1 -c app2.crt:app2.key:app2 -p changeit

  # Mix private key entry with cert-only entries
  pem2jks -c tls.crt:tls.key:server -c ca1.crt::ca1 -c ca2.crt::ca2 -p changeit

  # Add certificates to existing keystore with different passwords
  pem2jks --input existing.jks --input-password oldpass \
          -c new.crt:new.key:newcert -p newpass

  # Create keystore with certificate chain and CAs with aliases
  pem2jks -c tls.crt:tls.key --ca ca1.crt:root-ca --ca ca2.crt:intermediate -p changeit

  # Create truststore (CA certs only, no private key)
  pem2jks --ca ca.crt:my-ca -p changeit -f pkcs12 -o truststore.p12

  # Use environment variable for password
  export KEYSTORE_PASSWORD=changeit
  pem2jks -c tls.crt:tls.key`
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fipsTag := ""
		if fipsBuild {
			fipsTag = " (FIPS 140-2)"
		}
		fmt.Printf("pem2jks %s%s (commit: %s, built: %s)\n", Version, fipsTag, GitCommit, BuildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)

	// Define flags
	rootCmd.Flags().StringArrayVarP(&certs, "cert", "c", []string{}, "certificate and key entry in format cert.pem[:key.pem[:alias]] (repeatable)")
	rootCmd.Flags().StringArrayVar(&cas, "ca", []string{}, "CA certificate in format ca.pem[:alias] (repeatable)")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output keystore file path (default based on format)")
	rootCmd.Flags().StringVarP(&password, "password", "p", "", "keystore password (or use KEYSTORE_PASSWORD env)")
	rootCmd.Flags().StringVar(&passwordFile, "password-file", "", "file containing keystore password")
	rootCmd.Flags().StringVar(&inputPassword, "input-password", "", "password for input keystore (defaults to --password if not specified)")
	
	if fipsBuild {
		// In FIPS build, default to pkcs12 and hide JKS option
		rootCmd.Flags().StringVarP(&format, "format", "f", "pkcs12", "keystore format: pkcs12 or p12 (JKS not available in FIPS builds)")
	} else {
		rootCmd.Flags().StringVarP(&format, "format", "f", "jks", "keystore format: jks, pkcs12, or p12")
	}
	
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

	// FIPS build validation
	if fipsBuild {
		if keystoreFormat == "jks" {
			return fmt.Errorf("JKS format is not available in FIPS builds. This is a FIPS 140-2 compliant build that only supports PKCS#12 format")
		}
		fmt.Fprintln(os.Stderr, "INFO: FIPS 140-2 build - using PKCS#12 with PBES2 and SHA-256")
	} else {
		// Warn when using JKS in non-FIPS builds
		if keystoreFormat == "jks" {
			fmt.Fprintln(os.Stderr, "WARNING: JKS format uses SHA-1 and is not FIPS 140-2 compliant. For FIPS compliance, use --format=pkcs12 or the pem2jks-fips binary")
		}
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

	// Get output password
	keystorePassword := getPassword()
	if keystorePassword == "" {
		return fmt.Errorf("password is required (use -p/--password, --password-file, or KEYSTORE_PASSWORD env)")
	}

	// Get input password (defaults to output password if not specified)
	inputKeystorePassword := inputPassword
	if inputKeystorePassword == "" {
		inputKeystorePassword = keystorePassword
	}

	// Parse cert/key entries
	pairs, err := parseCerts(certs)
	if err != nil {
		return err
	}

	// Parse CA certificates
	caPairs, err := parseCAs(cas)
	if err != nil {
		return err
	}

	// Validate we have something to do
	if len(pairs) == 0 && len(caPairs) == 0 {
		if inputFile == "" {
			return fmt.Errorf("at least one of --cert or --ca is required")
		}
	}

	// Create keystore based on format
	var keystoreData []byte

	switch keystoreFormat {
	case "jks":
		keystoreData, err = createJKSKeystore(pairs, caPairs, keystorePassword, inputFile, inputKeystorePassword)
	case "pkcs12", "p12":
		keystoreData, err = createPKCS12Keystore(pairs, caPairs, keystorePassword, inputFile, inputKeystorePassword)
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

func createJKSKeystore(pairs []certKeyPair, caPairs []certKeyPair, password string, inputFile string, inputPassword string) ([]byte, error) {
	var ks *keystore.JKS

	// Load existing keystore if provided
	if inputFile != "" {
		existingData, err := os.ReadFile(inputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read input file: %w", err)
		}

		ks = keystore.NewJKS()
		if err := ks.Unmarshal(existingData, inputPassword); err != nil {
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
	for _, caPair := range caPairs {
		caCerts, err := keystore.ParsePEMCertificates(caPair.certPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate for alias %s: %w", caPair.alias, err)
		}
		for i, caCert := range caCerts {
			caAlias := caPair.alias
			if i > 0 {
				caAlias = fmt.Sprintf("%s-%d", caPair.alias, i)
			}
			if err := ks.AddTrustedCert(caAlias, caCert); err != nil {
				return nil, fmt.Errorf("failed to add CA certificate for alias %s: %w", caAlias, err)
			}
		}
	}

	if len(ks.Entries) == 0 {
		return nil, errors.New("no entries to add to keystore")
	}

	return ks.Marshal(password)
}

func createPKCS12Keystore(pairs []certKeyPair, caPairs []certKeyPair, password string, inputFile string, inputPassword string) ([]byte, error) {
	ks := keystore.NewPKCS12()

	// Load existing keystore if provided
	if inputFile != "" {
		existingData, err := os.ReadFile(inputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read input file: %w", err)
		}

		// Try to decode as keystore with private key
		privKey, cert, caCerts, err := pkcs12.DecodeChain(existingData, inputPassword)
		if err == nil && privKey != nil {
			// Has private key
			ks.SetPrivateKey(privKey, cert)
			for _, caCert := range caCerts {
				ks.AddCACert(caCert)
			}
		} else {
			// Try as truststore
			certs, err := pkcs12.DecodeTrustStore(existingData, inputPassword)
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
				if ks.PrivateKey != nil {
					ks.AddCACert(cert)
				} else {
					ks.AddTrustedCert(cert)
				}
			}
		}
	}

	// Add CA certificates
	for _, caPair := range caPairs {
		caCerts, err := keystore.ParsePEMCertificates(caPair.certPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate for alias %s: %w", caPair.alias, err)
		}
		for _, certDER := range caCerts {
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				return nil, fmt.Errorf("failed to parse CA certificate for alias %s: %w", caPair.alias, err)
			}
			if ks.PrivateKey != nil {
				ks.AddCACert(cert)
			} else {
				ks.AddTrustedCert(cert)
			}
		}
	}

	return ks.Marshal(password)
}

// parseCerts parses the --cert flag format: cert.pem[:key.pem[:alias]]
func parseCerts(certs []string) ([]certKeyPair, error) {
	var pairs []certKeyPair

	for i, cert := range certs {
		parts := strings.Split(cert, ":")
		if len(parts) < 1 || len(parts) > 3 {
			return nil, fmt.Errorf("invalid cert format %q (expected cert.pem[:key.pem[:alias]])", cert)
		}

		certFile := parts[0]
		if certFile == "" {
			return nil, fmt.Errorf("certificate file cannot be empty in cert %q", cert)
		}

		// Read certificate
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("reading certificate file %s: %w", certFile, err)
		}

		// Read key if provided
		var keyPEM []byte
		if len(parts) > 1 && parts[1] != "" {
			keyPEM, err = os.ReadFile(parts[1])
			if err != nil {
				return nil, fmt.Errorf("reading private key file %s: %w", parts[1], err)
			}
		}

		// Get alias or generate default
		alias := ""
		if len(parts) > 2 && parts[2] != "" {
			alias = parts[2]
		} else {
			if i == 0 {
				alias = "server"
			} else {
				alias = fmt.Sprintf("server-%d", i)
			}
		}

		pairs = append(pairs, certKeyPair{
			certPEM: certPEM,
			keyPEM:  keyPEM,
			alias:   alias,
		})
	}

	return pairs, nil
}

// parseCAs parses the --ca flag format: ca.pem[:alias]
func parseCAs(cas []string) ([]certKeyPair, error) {
	var pairs []certKeyPair

	for i, ca := range cas {
		parts := strings.Split(ca, ":")
		if len(parts) < 1 || len(parts) > 2 {
			return nil, fmt.Errorf("invalid CA format %q (expected ca.pem[:alias])", ca)
		}

		caFile := parts[0]
		if caFile == "" {
			return nil, fmt.Errorf("CA certificate file cannot be empty in ca %q", ca)
		}

		// Read CA certificate
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA certificate file %s: %w", caFile, err)
		}

		// Get alias or generate default
		alias := ""
		if len(parts) > 1 && parts[1] != "" {
			alias = parts[1]
		} else {
			if i == 0 {
				alias = "ca"
			} else {
				alias = fmt.Sprintf("ca-%d", i)
			}
		}

		pairs = append(pairs, certKeyPair{
			certPEM: caPEM,
			keyPEM:  nil, // CAs don't have private keys
			alias:   alias,
		})
	}

	return pairs, nil
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
