#!/bin/bash
# Integration test runner for pem2jks
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TESTDATA_DIR="$PROJECT_ROOT/testdata"
BINARY="$PROJECT_ROOT/bin/pem2jks"

echo "=== pem2jks Integration Tests ==="
echo ""

# Create testdata directory if needed
mkdir -p "$TESTDATA_DIR"
cd "$TESTDATA_DIR"

# Generate test certificates if needed
if [ ! -f ca.crt ] || [ ! -f tls.key ]; then
    echo "Generating test certificates..."
    "$PROJECT_ROOT/scripts/generate-certs.sh"
fi

# Build if needed
if [ ! -f "$BINARY" ]; then
    echo "Building pem2jks..."
    cd "$PROJECT_ROOT"
    make build
    cd "$TESTDATA_DIR"
fi

echo ""
echo "====== JKS Format Tests ======"
echo ""

echo "Test 1: Create JKS keystore with private key"
"$BINARY" -c tls.crt -k tls.key -p changeit -a server -o test1.jks -f jks
echo "  Created test1.jks"

echo ""
echo "Test 2: Create JKS keystore with private key and CA"
"$BINARY" -c tls.crt -k tls.key --ca ca.crt -p changeit -a server -o test2.jks -f jks
echo "  Created test2.jks"

echo ""
echo "Test 3: Create JKS truststore (CA only)"
"$BINARY" --ca ca.crt -p changeit -a ca -o truststore.jks -f jks
echo "  Created truststore.jks"

echo ""
echo "Test 4: Verify JKS with keytool"
if command -v keytool &> /dev/null; then
    echo "  Verifying test1.jks (basic):"
    keytool -list -keystore test1.jks -storepass changeit || { echo "  ERROR: keytool verification failed"; exit 1; }
    
    echo ""
    echo "  Verifying test2.jks (with CA, verbose):"
    keytool -list -v -keystore test2.jks -storepass changeit || { echo "  ERROR: keytool verification failed"; exit 1; }
    
    echo ""
    echo "  Verifying truststore.jks (basic):"
    keytool -list -keystore truststore.jks -storepass changeit || { echo "  ERROR: keytool verification failed"; exit 1; }
else
    echo "  ERROR: keytool not found - it is required for validation"
    exit 1
fi

echo ""
echo "====== PKCS#12 Format Tests ======"
echo ""

echo "Test 5: Create PKCS#12 keystore with private key"
"$BINARY" -c tls.crt -k tls.key -p changeit -a server -o test1.p12 -f pkcs12
echo "  Created test1.p12"

echo ""
echo "Test 6: Create PKCS#12 keystore with private key and CA"
"$BINARY" -c tls.crt -k tls.key --ca ca.crt -p changeit -a server -o test2.p12 -f pkcs12
echo "  Created test2.p12"

echo ""
echo "Test 7: Create PKCS#12 truststore (CA only)"
"$BINARY" --ca ca.crt -p changeit -a ca -o truststore.p12 -f pkcs12
echo "  Created truststore.p12"

echo ""
echo "Test 8: Verify PKCS#12 with keytool"
if command -v keytool &> /dev/null; then
    echo "  Verifying test1.p12 (basic):"
    keytool -list -keystore test1.p12 -storepass changeit -storetype PKCS12 || { echo "  ERROR: keytool verification failed"; exit 1; }
    
    echo ""
    echo "  Verifying test2.p12 (with CA, verbose):"
    keytool -list -v -keystore test2.p12 -storepass changeit -storetype PKCS12 || { echo "  ERROR: keytool verification failed"; exit 1; }
    
    echo ""
    echo "  Verifying truststore.p12 (basic):"
    keytool -list -keystore truststore.p12 -storepass changeit -storetype PKCS12 || { echo "  ERROR: keytool verification failed"; exit 1; }
else
    echo "  ERROR: keytool not found - it is required for validation"
    exit 1
fi

echo ""
echo "====== PKCS#12 Legacy Format Tests ======"
echo ""

echo "Test 9: Create PKCS#12 keystore with legacy algorithms"
"$BINARY" -c tls.crt -k tls.key -p changeit -a server -o test-legacy.p12 -f pkcs12 --legacy
echo "  Created test-legacy.p12"

echo ""
echo "Test 10: Verify legacy PKCS#12 with keytool"
if command -v keytool &> /dev/null; then
    echo "  Verifying test-legacy.p12 (verbose):"
    keytool -list -v -keystore test-legacy.p12 -storepass changeit -storetype PKCS12 || { echo "  ERROR: keytool verification failed"; exit 1; }
else
    echo "  ERROR: keytool not found - it is required for validation"
    exit 1
fi

# Cleanup
echo ""
echo "Cleaning up test files..."
rm -f test1.jks test2.jks truststore.jks
rm -f test1.p12 test2.p12 truststore.p12 test-legacy.p12

echo ""
echo "=== All tests completed ==="
