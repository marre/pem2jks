# Binary Verification

All binaries published as part of releases are signed using [Cosign](https://docs.sigstore.dev/cosign/overview/) with keyless signing (OIDC-based) and include SHA256 checksums. This ensures the authenticity and integrity of the binaries.

## Verifying Checksums

Each release includes SHA256 checksum files for all binaries and archives. You can verify the integrity of downloaded files:

### Download and Verify

```bash
# Download the binary archive and checksum
wget https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-linux-amd64.tar.gz
wget https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-linux-amd64.tar.gz.sha256

# Verify the checksum
sha256sum -c pem2jks-linux-amd64.tar.gz.sha256

# Expected output:
# pem2jks-linux-amd64.tar.gz: OK
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
# Download the binary, signature, and certificate
wget https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-linux-amd64
wget https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-linux-amd64.sig
wget https://github.com/marre/pem2jks/releases/download/v1.0.0/pem2jks-linux-amd64.pem

# Verify the signature
cosign verify-blob pem2jks-linux-amd64 \
  --signature pem2jks-linux-amd64.sig \
  --certificate pem2jks-linux-amd64.pem \
  --certificate-identity-regexp="https://github.com/marre/pem2jks/.*" \
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

Here's a complete example for downloading and verifying a release:

```bash
#!/bin/bash

# Configuration
VERSION="1.0.0"
PLATFORM="linux-amd64"  # or darwin-amd64, linux-arm64, darwin-arm64
BASE_URL="https://github.com/marre/pem2jks/releases/download/v${VERSION}"
ARCHIVE="pem2jks-${PLATFORM}.tar.gz"

# Download all files
echo "Downloading release v${VERSION} for ${PLATFORM}..."
curl -LO "${BASE_URL}/${ARCHIVE}"
curl -LO "${BASE_URL}/${ARCHIVE}.sha256"
curl -LO "${BASE_URL}/pem2jks-${PLATFORM}.sig"
curl -LO "${BASE_URL}/pem2jks-${PLATFORM}.pem"

# Verify checksum
echo "Verifying checksum..."
sha256sum -c ${ARCHIVE}.sha256 || exit 1

# Extract archive
echo "Extracting archive..."
tar -xzf ${ARCHIVE}

# Verify signature
echo "Verifying binary signature..."
cosign verify-blob pem2jks-${PLATFORM} \
  --signature pem2jks-${PLATFORM}.sig \
  --certificate pem2jks-${PLATFORM}.pem \
  --certificate-identity-regexp="https://github.com/marre/pem2jks/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" || exit 1

echo "✓ Verification successful! Binary is authentic and unmodified."
echo "You can now use: ./pem2jks-${PLATFORM}"
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
- Ensure you have the correct `.sig` and `.pem` files for your binary
- Check that you're using the correct certificate identity and issuer parameters
- Verify you have the latest version of Cosign installed
- If the issue persists, report it as a security issue

## Reporting Security Issues

If you discover a security issue or suspect a compromised binary, please report it according to our [security policy](../SECURITY.md) (if available) or by opening a confidential security advisory on GitHub.
