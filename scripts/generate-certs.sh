#!/bin/bash
# Generate test certificates for pem2jks testing
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TESTDATA_DIR="$PROJECT_ROOT/testdata"

# Create testdata directory if it doesn't exist
mkdir -p "$TESTDATA_DIR"
cd "$TESTDATA_DIR"

echo "Generating test certificates in $TESTDATA_DIR..."

# Generate CA key and certificate
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt \
    -subj "/CN=Test CA/O=Test Org" 2>/dev/null

# Generate server key and certificate
openssl genrsa -out tls.key 2048 2>/dev/null
openssl req -new -key tls.key -out tls.csr \
    -subj "/CN=localhost/O=Test Org" 2>/dev/null
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out tls.crt -days 365 -sha256 2>/dev/null

# Clean up CSR
rm -f tls.csr ca.srl

echo "Generated:"
echo "  ca.key   - CA private key"
echo "  ca.crt   - CA certificate"
echo "  tls.key  - Server private key"
echo "  tls.crt  - Server certificate"
