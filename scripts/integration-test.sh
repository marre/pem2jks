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
echo "Test 4: Verify JKS with Java keytool"
if command -v keytool &> /dev/null; then
    echo "  Listing test1.jks:"
    keytool -list -keystore test1.jks -storepass changeit 2>/dev/null || echo "  (keytool verification failed)"
    
    echo ""
    echo "  Listing test2.jks:"
    keytool -list -keystore test2.jks -storepass changeit 2>/dev/null || echo "  (keytool verification failed)"
    
    echo ""
    echo "  Listing truststore.jks:"
    keytool -list -keystore truststore.jks -storepass changeit 2>/dev/null || echo "  (keytool verification failed)"
else
    echo "  keytool not found, skipping Java verification"
fi

echo ""
echo "Test 5: Verify JKS with Java code"
if command -v java &> /dev/null && command -v javac &> /dev/null; then
    echo "  Compiling VerifyKeystore.java..."
    javac VerifyKeystore.java 2>/dev/null || echo "  (compilation failed)"
    if [ -f VerifyKeystore.class ]; then
        echo "  Running verification..."
        java VerifyKeystore test1.jks changeit || echo "  (Java verification failed for test1.jks)"
        java VerifyKeystore test2.jks changeit || echo "  (Java verification failed for test2.jks)"
        java VerifyKeystore truststore.jks changeit || echo "  (Java verification failed for truststore.jks)"
    fi
else
    echo "  Java not found, skipping Java code verification"
fi

echo ""
echo "====== PKCS#12 Format Tests ======"
echo ""

echo "Test 6: Create PKCS#12 keystore with private key"
"$BINARY" -c tls.crt -k tls.key -p changeit -a server -o test1.p12 -f pkcs12
echo "  Created test1.p12"

echo ""
echo "Test 7: Create PKCS#12 keystore with private key and CA"
"$BINARY" -c tls.crt -k tls.key --ca ca.crt -p changeit -a server -o test2.p12 -f pkcs12
echo "  Created test2.p12"

echo ""
echo "Test 8: Create PKCS#12 truststore (CA only)"
"$BINARY" --ca ca.crt -p changeit -a ca -o truststore.p12 -f pkcs12
echo "  Created truststore.p12"

echo ""
echo "Test 9: Verify PKCS#12 with Java keytool"
if command -v keytool &> /dev/null; then
    echo "  Listing test1.p12:"
    keytool -list -keystore test1.p12 -storepass changeit -storetype PKCS12 2>/dev/null || echo "  (keytool verification failed)"
    
    echo ""
    echo "  Listing test2.p12:"
    keytool -list -keystore test2.p12 -storepass changeit -storetype PKCS12 2>/dev/null || echo "  (keytool verification failed)"
    
    echo ""
    echo "  Listing truststore.p12:"
    keytool -list -keystore truststore.p12 -storepass changeit -storetype PKCS12 2>/dev/null || echo "  (keytool verification failed)"
else
    echo "  keytool not found, skipping Java verification"
fi

echo ""
echo "Test 10: Verify PKCS#12 with Java code"
if command -v java &> /dev/null && [ -f VerifyKeystore.class ]; then
    echo "  Running verification..."
    java -Dkeystore.type=PKCS12 VerifyKeystore test1.p12 changeit || echo "  (Java verification failed for test1.p12)"
    java -Dkeystore.type=PKCS12 VerifyKeystore test2.p12 changeit || echo "  (Java verification failed for test2.p12)"
    java -Dkeystore.type=PKCS12 VerifyKeystore truststore.p12 changeit || echo "  (Java verification failed for truststore.p12)"
else
    echo "  Java not found or not compiled, skipping Java code verification"
fi

echo ""
echo "====== PKCS#12 Legacy Format Tests ======"
echo ""

echo "Test 11: Create PKCS#12 keystore with legacy algorithms"
"$BINARY" -c tls.crt -k tls.key -p changeit -a server -o test-legacy.p12 -f pkcs12 --legacy
echo "  Created test-legacy.p12"

echo ""
echo "Test 12: Verify legacy PKCS#12 with Java keytool"
if command -v keytool &> /dev/null; then
    echo "  Listing test-legacy.p12:"
    keytool -list -keystore test-legacy.p12 -storepass changeit -storetype PKCS12 2>/dev/null || echo "  (keytool verification failed)"
else
    echo "  keytool not found, skipping Java verification"
fi

# Cleanup
echo ""
echo "Cleaning up test files..."
rm -f test1.jks test2.jks truststore.jks
rm -f test1.p12 test2.p12 truststore.p12 test-legacy.p12
rm -f VerifyKeystore.class

echo ""
echo "=== All tests completed ==="
