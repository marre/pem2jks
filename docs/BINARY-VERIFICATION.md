# Binary Verification

All binaries and archives published as part of releases are signed using [Cosign](https://docs.sigstore.dev/cosign/overview/) with keyless signing (OIDC-based) and include SHA256 checksums. This ensures the authenticity and integrity of the release artifacts.

## Verifying Checksums

Each release includes SHA256 checksum files for both binaries and archives. You can verify the integrity of downloaded files:

### Download and Verify Archive

```bash
# Download the binary archive and checksum
wget https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-linux-amd64.tar.gz
wget https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-linux-amd64.tar.gz.sha256

# Verify the checksum
sha256sum -c pem2jks-linux-amd64.tar.gz.sha256

# Expected output:
# pem2jks-linux-amd64.tar.gz: OK

# Extract the archive
tar -xzf pem2jks-linux-amd64.tar.gz
```

### Download and Verify Binary Directly

```bash
# Download the binary and checksum
wget https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-linux-amd64
wget https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-linux-amd64.sha256

# Verify the checksum
sha256sum -c pem2jks-linux-amd64.sha256

# Expected output:
# pem2jks-linux-amd64: OK

# Make executable
chmod +x pem2jks-linux-amd64
```

### macOS Verification

```bash
# Download the binary archive and checksum
curl -LO https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-darwin-amd64.tar.gz
curl -LO https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-darwin-amd64.tar.gz.sha256

# Verify the checksum
shasum -a 256 -c pem2jks-darwin-amd64.tar.gz.sha256

# Expected output:
# pem2jks-darwin-amd64.tar.gz: OK
```

## Verifying Binary Signatures

All binaries are signed using Cosign with keyless signing. This provides cryptographic proof that the binary was built by the official GitHub Actions workflow.

### Prerequisites

Install Cosign:
- [Official installation instructions](https://docs.sigstore.dev/cosign/installation/)
- macOS: `brew install cosign`
- Linux: Download from [releases](https://github.com/sigstore/cosign/releases)

### Verify a Binary Signature

```bash
# Download the binary and signature bundle
wget https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-linux-amd64
wget https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-linux-amd64.sigstore.json

# Verify the signature
cosign verify-blob pem2jks-linux-amd64 \
  --bundle pem2jks-linux-amd64.sigstore.json \
  --certificate-identity-regexp="https://github\\.com/marre/pem2jks/\\.github/workflows/release\\.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

# Successful verification output will include:
# Verified OK
```

### Verify an Archive Signature

Archives are also signed and can be verified before extraction:

```bash
# Download the archive and signature bundle
wget https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-linux-amd64.tar.gz
wget https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-linux-amd64.tar.gz.sigstore.json

# Verify the signature
cosign verify-blob pem2jks-linux-amd64.tar.gz \
  --bundle pem2jks-linux-amd64.tar.gz.sigstore.json \
  --certificate-identity-regexp="https://github\\.com/marre/pem2jks/\\.github/workflows/release\\.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

# Successful verification output will include:
# Verified OK
```

### What Does Signature Verification Prove?

When verification succeeds, it proves:
1. **Authenticity**: The binary was built by the official GitHub Actions workflow in this repository
2. **Integrity**: The binary has not been modified since it was signed
3. **Identity**: The signing certificate is tied to the repository's OIDC identity

## Complete Download and Verification Workflow

Here's a complete example for downloading and verifying a release archive:

```bash
#!/bin/bash
set -e

# Configuration
VERSION="1.0.0"
PLATFORM="linux-amd64"  # or darwin-amd64, linux-arm64, darwin-arm64
BASE_URL="https://github.com/marre/pem2jks/releases/download/v${VERSION}"
ARCHIVE="pem2jks-${PLATFORM}.tar.gz"

# Download archive and verification files
echo "Downloading release v${VERSION} for ${PLATFORM}..."
curl -LO "${BASE_URL}/${ARCHIVE}"
curl -LO "${BASE_URL}/${ARCHIVE}.sha256"
curl -LO "${BASE_URL}/${ARCHIVE}.sigstore.json"

# Verify checksum (works on both Linux and macOS)
echo "Verifying archive checksum..."
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c "${ARCHIVE}.sha256" || exit 1
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 -c "${ARCHIVE}.sha256" || exit 1
else
  echo "Error: neither 'sha256sum' nor 'shasum' is available." >&2
  echo "Please install coreutils (Linux) or use the built-in shasum (macOS)." >&2
  exit 1
fi

# Verify archive signature
echo "Verifying archive signature..."
cosign verify-blob ${ARCHIVE} \
  --bundle ${ARCHIVE}.sigstore.json \
  --certificate-identity-regexp="https://github\\.com/marre/pem2jks/\\.github/workflows/release\\.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" || exit 1

# Extract archive (binary inside is verified by archive signature)
echo "Extracting archive..."
tar -xzf ${ARCHIVE}

echo "✓ Verification successful! Archive and its contents are authentic and unmodified."
echo "You can now use: ./pem2jks-${PLATFORM}"
```

### Alternative: Verify Standalone Binary

If you download the standalone binary (not the archive), verify it separately:

```bash
#!/bin/bash
set -e

# Configuration
VERSION="1.0.0"
PLATFORM="linux-amd64"
BASE_URL="https://github.com/marre/pem2jks/releases/download/v${VERSION}"
BINARY="pem2jks-${PLATFORM}"

# Download binary and verification files
echo "Downloading binary..."
curl -LO "${BASE_URL}/${BINARY}"
curl -LO "${BASE_URL}/${BINARY}.sha256"
curl -LO "${BASE_URL}/${BINARY}.sigstore.json"

# Verify checksum
echo "Verifying binary checksum..."
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c "${BINARY}.sha256" || exit 1
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 -c "${BINARY}.sha256" || exit 1
else
  echo "Error: neither 'sha256sum' nor 'shasum' is available." >&2
  exit 1
fi

# Verify binary signature
echo "Verifying binary signature..."
cosign verify-blob ${BINARY} \
  --bundle ${BINARY}.sigstore.json \
  --certificate-identity-regexp="https://github\\.com/marre/pem2jks/\\.github/workflows/release\\.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" || exit 1

# Make executable
chmod +x ${BINARY}

echo "✓ Verification successful! Binary is authentic and unmodified."
echo "You can now use: ./${BINARY}"
```

## Security Best Practices

1. **Always verify checksums and signatures** before using downloaded binaries
2. **Download from official releases** at https://github.com/marre/pem2jks/releases
3. **Use HTTPS** when downloading to prevent man-in-the-middle attacks
4. **Keep Cosign updated** to benefit from the latest security improvements

## Troubleshooting

### Checksum Verification Fails

If checksum verification fails, the file may have been corrupted during download or tampered with:
- Re-download the file and try again
- If it still fails, report it as a security issue

### Signature Verification Fails

If signature verification fails:
- Ensure you have the correct `.sigstore.json` file for your binary
- Check that you're using the correct certificate identity and issuer parameters
- Verify you have the latest version of Cosign installed
- If the issue persists, report it as a security issue

## Reporting Security Issues

If you discover a security issue or suspect a compromised binary, please report it by opening a confidential security advisory via the repository's **Security** tab on GitHub: https://github.com/marre/pem2jks/security/advisories/new
