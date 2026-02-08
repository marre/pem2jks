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
"$BINARY" -c tls.crt:tls.key:server -p changeit -o test1.jks -f jks
echo "  Created test1.jks"

echo ""
echo "Test 2: Create JKS keystore with private key and CA"
"$BINARY" -c tls.crt:tls.key:server --ca ca.crt -p changeit -o test2.jks -f jks
echo "  Created test2.jks"

echo ""
echo "Test 3: Create JKS truststore (CA only)"
"$BINARY" --ca ca.crt:ca -p changeit -o truststore.jks -f jks
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
"$BINARY" -c tls.crt:tls.key:server -p changeit -o test1.p12 -f pkcs12
echo "  Created test1.p12"

echo ""
echo "Test 6: Create PKCS#12 keystore with private key and CA"
"$BINARY" -c tls.crt:tls.key:server --ca ca.crt -p changeit -o test2.p12 -f pkcs12
echo "  Created test2.p12"

echo ""
echo "Test 7: Create PKCS#12 truststore (CA only)"
"$BINARY" --ca ca.crt:ca -p changeit -o truststore.p12 -f pkcs12
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
"$BINARY" -c tls.crt:tls.key:server -p changeit -o test-legacy.p12 -f pkcs12 --legacy
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

echo ""
echo "====== Multiple PEM Files Tests ======"
echo ""

echo "Test 11: Create JKS with multiple cert/key pairs"
"$BINARY" -c tls.crt:tls.key:server1 \
          -c tls.crt:tls.key:server2 \
          -p changeit -o multi-keys.jks -f jks
echo "  Created multi-keys.jks"

echo ""
echo "Test 12: Verify JKS with multiple entries"
if command -v keytool &> /dev/null; then
    echo "  Verifying multi-keys.jks:"
    ENTRY_COUNT=$(keytool -list -keystore multi-keys.jks -storepass changeit 2>&1 | grep "Your keystore contains" | grep -o '[0-9]\+' || echo "0")
    if [ "$ENTRY_COUNT" -eq "2" ]; then
        echo "  ✓ Contains 2 entries as expected"
    else
        echo "  ERROR: Expected 2 entries, found $ENTRY_COUNT"
        exit 1
    fi
    keytool -list -keystore multi-keys.jks -storepass changeit || { echo "  ERROR: keytool verification failed"; exit 1; }
else
    echo "  ERROR: keytool not found"
    exit 1
fi

echo ""
echo "Test 13: Create keystore with multiple CA certificates"
"$BINARY" --ca ca.crt --ca ca.crt -p changeit -o multi-ca.jks -f jks
echo "  Created multi-ca.jks"

echo ""
echo "Test 14: Verify keystore with multiple CAs"
if command -v keytool &> /dev/null; then
    echo "  Verifying multi-ca.jks:"
    ENTRY_COUNT=$(keytool -list -keystore multi-ca.jks -storepass changeit 2>&1 | grep "Your keystore contains" | grep -o '[0-9]\+' || echo "0")
    if [ "$ENTRY_COUNT" -eq "2" ]; then
        echo "  ✓ Contains 2 CA entries as expected"
    else
        echo "  ERROR: Expected 2 entries, found $ENTRY_COUNT"
        exit 1
    fi
    keytool -list -keystore multi-ca.jks -storepass changeit || { echo "  ERROR: keytool verification failed"; exit 1; }
else
    echo "  ERROR: keytool not found"
    exit 1
fi

echo ""
echo "====== JKS Append Tests ======"
echo ""

echo "Test 15: Create initial JKS with one private key"
"$BINARY" -c tls.crt:tls.key:initial-key -p changeit -o append-test.jks -f jks
echo "  Created append-test.jks with 1 entry"

echo ""
echo "Test 16: Append another private key to existing JKS"
"$BINARY" --input append-test.jks -c tls.crt:tls.key:appended-key -p changeit -o append-test.jks -f jks
echo "  Appended to append-test.jks"

echo ""
echo "Test 17: Verify JKS after append"
if command -v keytool &> /dev/null; then
    echo "  Verifying append-test.jks:"
    ENTRY_COUNT=$(keytool -list -keystore append-test.jks -storepass changeit 2>&1 | grep "Your keystore contains" | grep -o '[0-9]\+' || echo "0")
    if [ "$ENTRY_COUNT" -eq "2" ]; then
        echo "  ✓ Contains 2 entries after append (as expected)"
    else
        echo "  ERROR: Expected 2 entries after append, found $ENTRY_COUNT"
        exit 1
    fi
    keytool -list -keystore append-test.jks -storepass changeit || { echo "  ERROR: keytool verification failed"; exit 1; }
else
    echo "  ERROR: keytool not found"
    exit 1
fi

echo ""
echo "Test 18: Append CA certificates to existing JKS"
"$BINARY" --input append-test.jks --ca ca.crt -p changeit -o append-test.jks -f jks
echo "  Appended CA to append-test.jks"

echo ""
echo "Test 19: Verify JKS after CA append"
if command -v keytool &> /dev/null; then
    echo "  Verifying append-test.jks after CA append:"
    ENTRY_COUNT=$(keytool -list -keystore append-test.jks -storepass changeit 2>&1 | grep "Your keystore contains" | grep -o '[0-9]\+' || echo "0")
    if [ "$ENTRY_COUNT" -eq "3" ]; then
        echo "  ✓ Contains 3 entries after CA append (as expected)"
    else
        echo "  ERROR: Expected 3 entries after CA append, found $ENTRY_COUNT"
        exit 1
    fi
    keytool -list -keystore append-test.jks -storepass changeit || { echo "  ERROR: keytool verification failed"; exit 1; }
else
    echo "  ERROR: keytool not found"
    exit 1
fi

echo ""
echo "====== PKCS#12 Append Tests ======"
echo ""

echo "Test 20: Create initial PKCS#12 truststore"
"$BINARY" --ca ca.crt -p changeit -o append-test.p12 -f pkcs12
echo "  Created append-test.p12 with 1 CA entry"

echo ""
echo "Test 21: Append another CA to existing PKCS#12"
"$BINARY" --input append-test.p12 -c tls.crt:: -p changeit -o append-test.p12 -f pkcs12
echo "  Appended certificate to append-test.p12"

echo ""
echo "Test 22: Verify PKCS#12 after append"
if command -v keytool &> /dev/null; then
    echo "  Verifying append-test.p12:"
    ENTRY_COUNT=$(keytool -list -keystore append-test.p12 -storepass changeit -storetype PKCS12 2>&1 | grep "Your keystore contains" | grep -o '[0-9]\+' || echo "0")
    if [ "$ENTRY_COUNT" -eq "2" ]; then
        echo "  ✓ Contains 2 entries after append (as expected)"
    else
        echo "  ERROR: Expected 2 entries after append, found $ENTRY_COUNT"
        exit 1
    fi
    keytool -list -keystore append-test.p12 -storepass changeit -storetype PKCS12 || { echo "  ERROR: keytool verification failed"; exit 1; }
else
    echo "  ERROR: keytool not found"
    exit 1
fi

# Cleanup
echo ""
echo "Cleaning up test files..."
rm -f test1.jks test2.jks truststore.jks
rm -f test1.p12 test2.p12 truststore.p12 test-legacy.p12
rm -f multi-keys.jks multi-ca.jks
rm -f append-test.jks append-test.p12

echo ""
echo "=== All tests completed successfully ==="
