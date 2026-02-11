# Binary Verification

All binaries published as part of releases include SHA256 checksums and Cosign signatures. The checksums file is signed using [Cosign](https://docs.sigstore.dev/cosign/overview/) with keyless signing (OIDC-based), ensuring the authenticity and integrity of all release artifacts.

## Release Artifacts

Each release includes:
- `pem2jks-{os}-{arch}` — Binaries for linux/darwin × amd64/arm64
- `checksums.txt` — SHA256 checksums for all binaries
- `checksums.txt.sigstore.json` — Cosign signature bundle for the checksums file
- `pem2jks-{os}-{arch}.sbom.spdx.json` — SBOM for each binary

## Verifying Checksums

```bash
# Download the binary and checksums
VERSION="1.0.0"
curl -LO "https://github.com/marre/pem2jks/releases/download/v${VERSION}/pem2jks-linux-amd64"
curl -LO "https://github.com/marre/pem2jks/releases/download/v${VERSION}/checksums.txt"

# Verify the checksum
sha256sum --ignore-missing -c checksums.txt

# Expected output:
# pem2jks-linux-amd64: OK

# Make executable
chmod +x pem2jks-linux-amd64
```

## Verifying Signatures

The checksums file is signed using Cosign with keyless signing. Verifying the signature of the checksums file, combined with checksum verification, cryptographically proves all binaries are authentic.

### Prerequisites

Install Cosign:
- [Official installation instructions](https://docs.sigstore.dev/cosign/installation/)
- macOS: `brew install cosign`
- Linux: Download from [releases](https://github.com/sigstore/cosign/releases)

### Verify the Checksums Signature

```bash
# Download the checksums and signature bundle
VERSION="1.0.0"
curl -LO "https://github.com/marre/pem2jks/releases/download/v${VERSION}/checksums.txt"
curl -LO "https://github.com/marre/pem2jks/releases/download/v${VERSION}/checksums.txt.sigstore.json"

# Verify the signature
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp="https://github\\.com/marre/pem2jks/\\.github/workflows/release\\.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

# Expected output:
# Verified OK
```

### What Does Signature Verification Prove?

When verification succeeds, it proves:
1. **Authenticity**: The checksums file was produced by the official GitHub Actions workflow
2. **Integrity**: The checksums (and therefore the binaries) have not been modified since signing
3. **Identity**: The signing certificate is tied to the repository's OIDC identity

## Complete Download and Verification Workflow

```bash
#!/bin/bash
set -e

VERSION="1.0.0"
PLATFORM="linux-amd64"  # or darwin-amd64, linux-arm64, darwin-arm64
BASE_URL="https://github.com/marre/pem2jks/releases/download/v${VERSION}"
BINARY="pem2jks-${PLATFORM}"

# Download binary and verification files
echo "Downloading release v${VERSION} for ${PLATFORM}..."
curl -LO "${BASE_URL}/${BINARY}"
curl -LO "${BASE_URL}/checksums.txt"
curl -LO "${BASE_URL}/checksums.txt.sigstore.json"

# Verify checksums signature
echo "Verifying checksums signature..."
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp="https://github\\.com/marre/pem2jks/\\.github/workflows/release\\.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" || exit 1

# Verify binary checksum
echo "Verifying binary checksum..."
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum --ignore-missing -c checksums.txt || exit 1
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 --ignore-missing -c checksums.txt || exit 1
else
  echo "Error: neither 'sha256sum' nor 'shasum' is available." >&2
  exit 1
fi

chmod +x "${BINARY}"
echo "Verification successful! Binary is authentic and unmodified."
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
- Ensure you have the correct `checksums.txt.sigstore.json` file
- Check that you're using the correct certificate identity and issuer parameters
- Verify you have the latest version of Cosign installed
- If the issue persists, report it as a security issue

## Reporting Security Issues

If you discover a security issue or suspect a compromised binary, please report it by opening a confidential security advisory via the repository's **Security** tab on GitHub: https://github.com/marre/pem2jks/security/advisories/new
