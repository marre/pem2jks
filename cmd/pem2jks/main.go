// Package main provides the pem2jks CLI tool.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/marre/pem2jks/pkg/keystore"
	"github.com/spf13/cobra"
)

// Version information (set by ldflags)
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

// CLI flags
var (
	certFile     string
	keyFile      string
	caFile       string
	outputFile   string
	password     string
	passwordFile string
	alias        string
	format       string
	legacy       bool
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

  # Create keystore with certificate chain and CA
  pem2jks -c tls.crt -k tls.key --ca ca.crt -p changeit

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
	rootCmd.Flags().StringVarP(&certFile, "cert", "c", "", "path to certificate PEM file")
	rootCmd.Flags().StringVarP(&keyFile, "key", "k", "", "path to private key PEM file")
	rootCmd.Flags().StringVar(&caFile, "ca", "", "path to CA certificate PEM file")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output keystore file path (default based on format)")
	rootCmd.Flags().StringVarP(&password, "password", "p", "", "keystore password (or use KEYSTORE_PASSWORD env)")
	rootCmd.Flags().StringVar(&passwordFile, "password-file", "", "file containing keystore password")
	rootCmd.Flags().StringVarP(&alias, "alias", "a", "server", "alias for the private key entry")
	rootCmd.Flags().StringVarP(&format, "format", "f", "jks", "keystore format: jks, pkcs12, or p12")
	rootCmd.Flags().BoolVar(&legacy, "legacy", false, "use legacy algorithms for PKCS#12 (for older Java)")
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

	// Read certificate
	var certPEM []byte
	var err error
	if certFile != "" {
		certPEM, err = os.ReadFile(certFile)
		if err != nil {
			return fmt.Errorf("reading certificate file: %w", err)
		}
	}

	// Read private key
	var keyPEM []byte
	if keyFile != "" {
		keyPEM, err = os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("reading private key file: %w", err)
		}
	}

	// Read CA certificate
	var caPEM []byte
	if caFile != "" {
		caPEM, err = os.ReadFile(caFile)
		if err != nil {
			return fmt.Errorf("reading CA certificate file: %w", err)
		}
	}

	// Validate we have something to do
	if len(certPEM) == 0 && len(caPEM) == 0 {
		return fmt.Errorf("at least one of --cert or --ca is required")
	}

	// Create keystore based on format
	var keystoreData []byte

	switch keystoreFormat {
	case "jks":
		keystoreData, err = keystore.CreateJKSFromPEM(certPEM, keyPEM, caPEM, keystorePassword, alias)
	case "pkcs12", "p12":
		if legacy {
			keystoreData, err = keystore.CreatePKCS12FromPEMLegacy(certPEM, keyPEM, caPEM, keystorePassword, alias)
		} else {
			keystoreData, err = keystore.CreatePKCS12FromPEM(certPEM, keyPEM, caPEM, keystorePassword, alias)
		}
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
