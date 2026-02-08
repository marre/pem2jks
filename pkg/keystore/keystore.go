// Package keystore provides functionality to create Java KeyStore (JKS) and PKCS#12 keystores.
package keystore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

const (
	// JKS constants
	jksMagicNumber       = 0xFEEDFEED
	jksVersion           = 2
	jksTagPrivateKey     = 1
	jksTagTrustedCert    = 2
	jksSignatureWhitener = "Mighty Aphrodite"
)

// Sun's proprietary key protection algorithm OID: 1.3.6.1.4.1.42.2.17.1.1
// This algorithm has no meaningful parameters, but for compatibility Java keytool
// and minijks expect the AlgorithmIdentifier parameters field to be encoded as
// an explicit ASN.1 NULL.
var sunJKSAlgoOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1}

// Entry represents a keystore entry
type Entry interface {
	isEntry()
}

// PrivateKeyEntry represents a private key with its certificate chain
type PrivateKeyEntry struct {
	Alias     string
	Timestamp time.Time
	PrivKey   []byte   // PKCS#8 encoded private key
	CertChain [][]byte // DER encoded certificates
}

func (PrivateKeyEntry) isEntry() {}

// TrustedCertEntry represents a trusted certificate
type TrustedCertEntry struct {
	Alias     string
	Timestamp time.Time
	Cert      []byte // DER encoded certificate
}

func (TrustedCertEntry) isEntry() {}

// JKS represents a JKS keystore
type JKS struct {
	Entries []Entry
}

// NewJKS creates a new empty JKS keystore
func NewJKS() *JKS {
	return &JKS{
		Entries: make([]Entry, 0),
	}
}

// AddPrivateKey adds a private key entry with its certificate chain
func (ks *JKS) AddPrivateKey(alias string, pkcs8Key []byte, certChain [][]byte) error {
	return ks.AddPrivateKeyWithTimestamp(alias, pkcs8Key, certChain, time.Now())
}

// AddPrivateKeyWithTimestamp adds a private key entry with its certificate chain and a specific timestamp
func (ks *JKS) AddPrivateKeyWithTimestamp(alias string, pkcs8Key []byte, certChain [][]byte, timestamp time.Time) error {
	if alias == "" {
		return errors.New("alias cannot be empty")
	}
	if len(pkcs8Key) == 0 {
		return errors.New("private key cannot be empty")
	}
	if len(certChain) == 0 {
		return errors.New("certificate chain cannot be empty")
	}

	// Validate certificates
	for i, certDER := range certChain {
		if _, err := x509.ParseCertificate(certDER); err != nil {
			return fmt.Errorf("invalid certificate at index %d: %w", i, err)
		}
	}

	ks.Entries = append(ks.Entries, PrivateKeyEntry{
		Alias:     alias, // Preserve original casing - JKS is case-insensitive but we keep user's preference
		Timestamp: timestamp,
		PrivKey:   pkcs8Key,
		CertChain: certChain,
	})
	return nil
}

// AddTrustedCert adds a trusted certificate entry
func (ks *JKS) AddTrustedCert(alias string, certDER []byte) error {
	return ks.AddTrustedCertWithTimestamp(alias, certDER, time.Now())
}

// AddTrustedCertWithTimestamp adds a trusted certificate entry with a specific timestamp
func (ks *JKS) AddTrustedCertWithTimestamp(alias string, certDER []byte, timestamp time.Time) error {
	if alias == "" {
		return errors.New("alias cannot be empty")
	}
	if len(certDER) == 0 {
		return errors.New("certificate cannot be empty")
	}

	// Validate certificate
	if _, err := x509.ParseCertificate(certDER); err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}

	ks.Entries = append(ks.Entries, TrustedCertEntry{
		Alias:     alias, // Preserve original casing
		Timestamp: timestamp,
		Cert:      certDER,
	})
	return nil
}

// Marshal serializes the keystore to JKS format
func (ks *JKS) Marshal(password string) ([]byte, error) {
	var buf bytes.Buffer

	// Write header
	if err := binary.Write(&buf, binary.BigEndian, uint32(jksMagicNumber)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint32(jksVersion)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(ks.Entries))); err != nil {
		return nil, err
	}

	// Write entries
	for _, entry := range ks.Entries {
		switch e := entry.(type) {
		case PrivateKeyEntry:
			if err := ks.writePrivateKeyEntry(&buf, e, password); err != nil {
				return nil, err
			}
		case TrustedCertEntry:
			if err := ks.writeTrustedCertEntry(&buf, e); err != nil {
				return nil, err
			}
		}
	}

	// Calculate and append integrity hash
	data := buf.Bytes()
	hash := computeJKSIntegrityHash(data, password)
	buf.Write(hash)

	return buf.Bytes(), nil
}

// Unmarshal deserializes a JKS keystore from bytes
func (ks *JKS) Unmarshal(data []byte, password string) error {
	// Last 20 bytes are the SHA1 integrity hash
	if len(data) < 20 {
		return errors.New("JKS file too short for integrity hash")
	}
	keystoreData := data[:len(data)-20]
	storedHash := data[len(data)-20:]

	// Verify integrity hash
	computedHash := computeJKSIntegrityHash(keystoreData, password)
	if !bytes.Equal(storedHash, computedHash) {
		return errors.New("JKS integrity check failed - incorrect password or corrupted file")
	}

	r := bytes.NewReader(keystoreData)

	// Read header
	var magic, version, entryCount uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return fmt.Errorf("failed to read magic number: %w", err)
	}
	if magic != jksMagicNumber {
		return fmt.Errorf("invalid JKS magic number: 0x%X", magic)
	}

	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return fmt.Errorf("failed to read version: %w", err)
	}
	if version != jksVersion {
		return fmt.Errorf("unsupported JKS version: %d", version)
	}

	if err := binary.Read(r, binary.BigEndian, &entryCount); err != nil {
		return fmt.Errorf("failed to read entry count: %w", err)
	}

	// Read entries
	ks.Entries = make([]Entry, 0, entryCount)
	for i := uint32(0); i < entryCount; i++ {
		var tag uint32
		if err := binary.Read(r, binary.BigEndian, &tag); err != nil {
			return fmt.Errorf("failed to read entry tag: %w", err)
		}

		switch tag {
		case jksTagPrivateKey:
			entry, err := readPrivateKeyEntry(r, password)
			if err != nil {
				return fmt.Errorf("failed to read private key entry %d: %w", i, err)
			}
			ks.Entries = append(ks.Entries, entry)
		case jksTagTrustedCert:
			entry, err := readTrustedCertEntry(r)
			if err != nil {
				return fmt.Errorf("failed to read trusted cert entry %d: %w", i, err)
			}
			ks.Entries = append(ks.Entries, entry)
		default:
			return fmt.Errorf("unknown entry tag: %d", tag)
		}
	}

	return nil
}

func readPrivateKeyEntry(r io.Reader, password string) (PrivateKeyEntry, error) {
	var entry PrivateKeyEntry

	// Read alias
	alias, err := readUTF(r)
	if err != nil {
		return entry, fmt.Errorf("failed to read alias: %w", err)
	}
	entry.Alias = alias

	// Read timestamp
	var timestampMillis int64
	if err := binary.Read(r, binary.BigEndian, &timestampMillis); err != nil {
		return entry, fmt.Errorf("failed to read timestamp: %w", err)
	}
	entry.Timestamp = time.UnixMilli(timestampMillis)

	// Read encrypted private key
	encryptedKeyData, err := readBytes(r)
	if err != nil {
		return entry, fmt.Errorf("failed to read encrypted key: %w", err)
	}

	// Decrypt private key
	privKey, err := decryptJKSPrivateKey(encryptedKeyData, password)
	if err != nil {
		return entry, fmt.Errorf("failed to decrypt private key: %w", err)
	}
	entry.PrivKey = privKey

	// Read certificate chain count
	var chainLen uint32
	if err := binary.Read(r, binary.BigEndian, &chainLen); err != nil {
		return entry, fmt.Errorf("failed to read chain length: %w", err)
	}

	// Read certificate chain
	entry.CertChain = make([][]byte, 0, chainLen)
	for j := uint32(0); j < chainLen; j++ {
		// Read certificate type
		certType, err := readUTF(r)
		if err != nil {
			return entry, fmt.Errorf("failed to read cert type: %w", err)
		}
		if certType != "X.509" {
			return entry, fmt.Errorf("unsupported certificate type: %s", certType)
		}

		// Read certificate data
		certData, err := readBytes(r)
		if err != nil {
			return entry, fmt.Errorf("failed to read cert data: %w", err)
		}
		entry.CertChain = append(entry.CertChain, certData)
	}

	return entry, nil
}

func readTrustedCertEntry(r io.Reader) (TrustedCertEntry, error) {
	var entry TrustedCertEntry

	// Read alias
	alias, err := readUTF(r)
	if err != nil {
		return entry, fmt.Errorf("failed to read alias: %w", err)
	}
	entry.Alias = alias

	// Read timestamp
	var timestampMillis int64
	if err := binary.Read(r, binary.BigEndian, &timestampMillis); err != nil {
		return entry, fmt.Errorf("failed to read timestamp: %w", err)
	}
	entry.Timestamp = time.UnixMilli(timestampMillis)

	// Read certificate type
	certType, err := readUTF(r)
	if err != nil {
		return entry, fmt.Errorf("failed to read cert type: %w", err)
	}
	if certType != "X.509" {
		return entry, fmt.Errorf("unsupported certificate type: %s", certType)
	}

	// Read certificate data
	certData, err := readBytes(r)
	if err != nil {
		return entry, fmt.Errorf("failed to read cert data: %w", err)
	}
	entry.Cert = certData

	return entry, nil
}

// readUTF reads a string in Java's modified UTF-8 format
func readUTF(r io.Reader) (string, error) {
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return "", err
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", err
	}
	return string(data), nil
}

// readBytes reads a length-prefixed byte array
func readBytes(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}

// decryptJKSPrivateKey decrypts a PKCS#8 private key using JKS proprietary algorithm
func decryptJKSPrivateKey(encapsulatedData []byte, password string) ([]byte, error) {
	// Parse the PKCS#8 EncryptedPrivateKeyInfo structure
	var epki encryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(encapsulatedData, &epki)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted private key info: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("unexpected trailing data after encrypted private key info")
	}

	// Verify algorithm OID
	if !epki.Algo.Algorithm.Equal(sunJKSAlgoOID) {
		return nil, fmt.Errorf("unsupported private key encryption algorithm: %v", epki.Algo.Algorithm)
	}

	encryptedData := epki.EncryptedData

	// Encrypted data format: IV (20 bytes) + encrypted key + check (20 bytes)
	if len(encryptedData) < 40 {
		return nil, errors.New("encrypted key data too short")
	}

	passwordBytes := stringToUTF16BE(password)
	iv := encryptedData[:20]
	encrypted := encryptedData[20 : len(encryptedData)-20]
	storedCheck := encryptedData[len(encryptedData)-20:]

	// Decrypt the key
	keystream := jksKeystream(iv, passwordBytes)
	plaintext := make([]byte, len(encrypted))
	for i, b := range encrypted {
		plaintext[i] = b ^ keystream[i]
	}

	// Verify integrity check: SHA1(password + plaintext)
	h := sha1.New()
	h.Write(passwordBytes)
	h.Write(plaintext)
	computedCheck := h.Sum(nil)

	if !bytes.Equal(storedCheck, computedCheck) {
		return nil, errors.New("private key integrity check failed - incorrect password")
	}

	return plaintext, nil
}

func (ks *JKS) writePrivateKeyEntry(w io.Writer, entry PrivateKeyEntry, password string) error {
	// Tag
	if err := binary.Write(w, binary.BigEndian, uint32(jksTagPrivateKey)); err != nil {
		return err
	}

	// Alias
	if err := writeUTF(w, entry.Alias); err != nil {
		return err
	}

	// Timestamp (milliseconds since epoch)
	if err := binary.Write(w, binary.BigEndian, entry.Timestamp.UnixMilli()); err != nil {
		return err
	}

	// Encrypt and write private key
	encryptedKey, err := encryptJKSPrivateKey(entry.PrivKey, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}
	encapsulated, err := encapsulatePrivateKey(encryptedKey)
	if err != nil {
		return fmt.Errorf("failed to encapsulate private key: %w", err)
	}
	if err := writeBytes(w, encapsulated); err != nil {
		return err
	}

	// Certificate chain
	if err := binary.Write(w, binary.BigEndian, uint32(len(entry.CertChain))); err != nil {
		return err
	}
	for _, cert := range entry.CertChain {
		if err := writeUTF(w, "X.509"); err != nil {
			return err
		}
		if err := writeBytes(w, cert); err != nil {
			return err
		}
	}

	return nil
}

func (ks *JKS) writeTrustedCertEntry(w io.Writer, entry TrustedCertEntry) error {
	// Tag
	if err := binary.Write(w, binary.BigEndian, uint32(jksTagTrustedCert)); err != nil {
		return err
	}

	// Alias
	if err := writeUTF(w, entry.Alias); err != nil {
		return err
	}

	// Timestamp
	if err := binary.Write(w, binary.BigEndian, entry.Timestamp.UnixMilli()); err != nil {
		return err
	}

	// Certificate type
	if err := writeUTF(w, "X.509"); err != nil {
		return err
	}

	// Certificate data
	if err := writeBytes(w, entry.Cert); err != nil {
		return err
	}

	return nil
}

// writeUTF writes a string in Java's modified UTF-8 format
func writeUTF(w io.Writer, s string) error {
	data := []byte(s)
	if err := binary.Write(w, binary.BigEndian, uint16(len(data))); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// writeBytes writes a length-prefixed byte array
func writeBytes(w io.Writer, data []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// computeJKSIntegrityHash computes the SHA1 hash for keystore integrity
func computeJKSIntegrityHash(data []byte, password string) []byte {
	passwordUTF16 := stringToUTF16BE(password)

	h := sha1.New()
	h.Write(passwordUTF16)
	h.Write([]byte(jksSignatureWhitener)) // UTF-8, not UTF-16BE!
	h.Write(data)
	return h.Sum(nil)
}

// stringToUTF16BE converts a string to UTF-16 big-endian bytes
// This correctly handles Unicode characters outside the BMP (> U+FFFF)
// by encoding them as surrogate pairs.
func stringToUTF16BE(s string) []byte {
	var result []byte
	for _, r := range s {
		if r <= 0xFFFF {
			result = append(result, byte(r>>8), byte(r))
		} else {
			// Characters outside BMP need surrogate pair encoding
			r -= 0x10000
			high := uint16(0xD800 + (r >> 10))
			low := uint16(0xDC00 + (r & 0x3FF))
			result = append(result, byte(high>>8), byte(high))
			result = append(result, byte(low>>8), byte(low))
		}
	}
	return result
}

// encryptJKSPrivateKey encrypts a PKCS#8 private key using JKS proprietary algorithm
func encryptJKSPrivateKey(pkcs8Key []byte, password string) ([]byte, error) {
	passwordBytes := stringToUTF16BE(password)

	// Generate random 20-byte IV
	iv := make([]byte, 20)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// XOR key with keystream
	keystream := jksKeystream(iv, passwordBytes)
	encrypted := make([]byte, len(pkcs8Key))
	for i, b := range pkcs8Key {
		encrypted[i] = b ^ keystream[i]
	}

	// Calculate integrity check: SHA1(password + plaintext)
	h := sha1.New()
	h.Write(passwordBytes)
	h.Write(pkcs8Key)
	check := h.Sum(nil)

	// Result: IV + encrypted_data + check
	result := make([]byte, 0, 20+len(encrypted)+20)
	result = append(result, iv...)
	result = append(result, encrypted...)
	result = append(result, check...)

	return result, nil
}

// jksKeystream generates a keystream for JKS private key encryption
func jksKeystream(iv, password []byte) []byte {
	var keystream []byte
	cur := iv
	for len(keystream) < 10000 {
		h := sha1.New()
		h.Write(password)
		h.Write(cur)
		cur = h.Sum(nil)
		keystream = append(keystream, cur...)
	}
	return keystream
}

// asn1NULL represents an ASN.1 NULL value used in AlgorithmIdentifier.
// Java keytool and minijks encode unused algorithm parameters as ASN.1 NULL.
var asn1NULL = asn1.RawValue{FullBytes: []byte{0x05, 0x00}}

// encryptedPrivateKeyInfo is the PKCS#8 EncryptedPrivateKeyInfo ASN.1 structure.
// Defined in RFC 5208 § 6: https://tools.ietf.org/html/rfc5208#section-6
type encryptedPrivateKeyInfo struct {
	Algo          algorithmIdentifier
	EncryptedData []byte
}

// algorithmIdentifier is the AlgorithmIdentifier ASN.1 structure.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// encapsulatePrivateKey wraps the encrypted key in PKCS#8 EncryptedPrivateKeyInfo.
// The Sun JKS algorithm OID (1.3.6.1.4.1.42.2.17.1.1) uses ASN.1 NULL for parameters,
// matching the behavior of Java keytool and the minijks implementation.
func encapsulatePrivateKey(encryptedKey []byte) ([]byte, error) {
	epki := encryptedPrivateKeyInfo{
		Algo: algorithmIdentifier{
			Algorithm:  sunJKSAlgoOID,
			Parameters: asn1NULL,
		},
		EncryptedData: encryptedKey,
	}

	return asn1.Marshal(epki)
}

// ParsePEMCertificates parses one or more PEM-encoded certificates.
func ParsePEMCertificates(pemData []byte) ([][]byte, error) {
	var certs [][]byte
	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("invalid certificate: %w", err)
		}
		certs = append(certs, block.Bytes)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found in PEM data")
	}
	return certs, nil
}

// ParsePEMPrivateKey parses a PEM-encoded private key and returns PKCS#8 DER.
func ParsePEMPrivateKey(pemData []byte) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM data found")
	}

	switch block.Type {
	case "PRIVATE KEY":
		return block.Bytes, nil

	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal to PKCS#8: %w", err)
		}
		return pkcs8, nil

	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal to PKCS#8: %w", err)
		}
		return pkcs8, nil

	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

// parsePEMPrivateKeyRaw parses a PEM private key and returns the raw key object.
func parsePEMPrivateKeyRaw(pemData []byte) (interface{}, error) {
	pkcs8Data, err := ParsePEMPrivateKey(pemData)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS8PrivateKey(pkcs8Data)
}

// CreateJKSFromPEM creates a JKS keystore from PEM data.
func CreateJKSFromPEM(certPEM, keyPEM, caPEM []byte, password, alias string) ([]byte, error) {
	ks := NewJKS()

	// Parse main certificate(s)
	var certChain [][]byte
	if len(certPEM) > 0 {
		var err error
		certChain, err = ParsePEMCertificates(certPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
	}

	// If we have a private key, add as private key entry
	if len(keyPEM) > 0 {
		if len(certChain) == 0 {
			return nil, errors.New("private key provided but no certificate")
		}
		pkcs8Key, err := ParsePEMPrivateKey(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		if err := ks.AddPrivateKey(alias, pkcs8Key, certChain); err != nil {
			return nil, fmt.Errorf("failed to add private key entry: %w", err)
		}
	} else if len(certChain) > 0 {
		for i, cert := range certChain {
			certAlias := alias
			if i > 0 {
				certAlias = fmt.Sprintf("%s-%d", alias, i)
			}
			if err := ks.AddTrustedCert(certAlias, cert); err != nil {
				return nil, fmt.Errorf("failed to add trusted cert: %w", err)
			}
		}
	}

	// Add CA certificates as trusted certs
	if len(caPEM) > 0 {
		caCerts, err := ParsePEMCertificates(caPEM)
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

// PKCS12KeyStore represents a PKCS#12 keystore.
type PKCS12KeyStore struct {
	PrivateKey   interface{}
	Certificate  *x509.Certificate
	CACerts      []*x509.Certificate
	TrustedCerts []*x509.Certificate
}

// NewPKCS12 creates a new empty PKCS12KeyStore.
func NewPKCS12() *PKCS12KeyStore {
	return &PKCS12KeyStore{}
}

// SetPrivateKey sets the private key and its certificate.
func (ks *PKCS12KeyStore) SetPrivateKey(key interface{}, cert *x509.Certificate) {
	ks.PrivateKey = key
	ks.Certificate = cert
}

// AddCACert adds a CA certificate to the chain.
func (ks *PKCS12KeyStore) AddCACert(cert *x509.Certificate) {
	ks.CACerts = append(ks.CACerts, cert)
}

// AddTrustedCert adds a trusted certificate (for truststores).
func (ks *PKCS12KeyStore) AddTrustedCert(cert *x509.Certificate) {
	ks.TrustedCerts = append(ks.TrustedCerts, cert)
}

// Marshal serializes the keystore to PKCS#12 format.
func (ks *PKCS12KeyStore) Marshal(password string) ([]byte, error) {
	if ks.PrivateKey != nil {
		return pkcs12.Modern.Encode(ks.PrivateKey, ks.Certificate, ks.CACerts, password)
	}

	if len(ks.TrustedCerts) == 0 && len(ks.CACerts) == 0 {
		return nil, errors.New("no certificates to encode")
	}

	allCerts := append(ks.TrustedCerts, ks.CACerts...)
	return pkcs12.Modern.EncodeTrustStore(allCerts, password)
}

// MarshalLegacy serializes the keystore to PKCS#12 format using legacy algorithms.
func (ks *PKCS12KeyStore) MarshalLegacy(password string) ([]byte, error) {
	if ks.PrivateKey != nil {
		return pkcs12.Legacy.Encode(ks.PrivateKey, ks.Certificate, ks.CACerts, password)
	}

	if len(ks.TrustedCerts) == 0 && len(ks.CACerts) == 0 {
		return nil, errors.New("no certificates to encode")
	}

	allCerts := append(ks.TrustedCerts, ks.CACerts...)
	return pkcs12.Legacy.EncodeTrustStore(allCerts, password)
}

// CreatePKCS12FromPEM creates a PKCS#12 keystore from PEM data.
func CreatePKCS12FromPEM(certPEM, keyPEM, caPEM []byte, password, alias string) ([]byte, error) {
	ks := NewPKCS12()

	var certChain []*x509.Certificate
	if len(certPEM) > 0 {
		certs, err := ParsePEMCertificates(certPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		for _, certDER := range certs {
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certChain = append(certChain, cert)
		}
	}

	if len(keyPEM) > 0 {
		if len(certChain) == 0 {
			return nil, errors.New("private key provided but no certificate")
		}

		key, err := parsePEMPrivateKeyRaw(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
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

	if len(caPEM) > 0 {
		caCerts, err := ParsePEMCertificates(caPEM)
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

	return ks.Marshal(password)
}

// CreatePKCS12FromPEMLegacy creates a PKCS#12 keystore using legacy algorithms.
func CreatePKCS12FromPEMLegacy(certPEM, keyPEM, caPEM []byte, password, alias string) ([]byte, error) {
	ks := NewPKCS12()

	var certChain []*x509.Certificate
	if len(certPEM) > 0 {
		certs, err := ParsePEMCertificates(certPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		for _, certDER := range certs {
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certChain = append(certChain, cert)
		}
	}

	if len(keyPEM) > 0 {
		if len(certChain) == 0 {
			return nil, errors.New("private key provided but no certificate")
		}

		key, err := parsePEMPrivateKeyRaw(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
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

	if len(caPEM) > 0 {
		caCerts, err := ParsePEMCertificates(caPEM)
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

	return ks.MarshalLegacy(password)
}
