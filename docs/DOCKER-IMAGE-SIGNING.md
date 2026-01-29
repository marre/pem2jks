# Docker Image Signing

## Overview

All Docker images published as part of the pem2jks release process are cryptographically signed using [Cosign](https://docs.sigstore.dev/cosign/overview/), which is part of the Sigstore project. This ensures the authenticity and integrity of the images.

## Signing Method

We use **keyless signing** with OIDC (OpenID Connect) based authentication:

- **No private keys to manage**: Signing keys are ephemeral and generated on-demand
- **GitHub OIDC integration**: Uses GitHub's identity provider for authentication
- **Transparency Log**: All signatures are recorded in the public Rekor transparency log
- **Certificate-based verification**: Signatures include certificate information that can be verified

## How It Works

### During Release

When a new version tag is pushed (e.g., `v1.0.0`), the GitHub Actions workflow:

1. Builds multi-architecture Docker images (amd64 and arm64)
2. Pushes images to GitHub Container Registry (ghcr.io)
3. Uses Cosign to sign the image digest with GitHub's OIDC token
4. Records the signature in the public transparency log

The signing process uses the following GitHub Actions permissions:
- `id-token: write` - Required for OIDC token generation
- `packages: write` - Required to push images and signatures to GHCR

### Signature Storage

Signatures are stored as OCI artifacts in the same registry as the images, following the Sigstore specification. They are associated with the image digest (not tags) to ensure immutability.

## Verifying Signatures

### Prerequisites

Install Cosign:
```bash
# macOS
brew install cosign

# Linux
wget https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign

# See https://docs.sigstore.dev/cosign/installation/ for other platforms
```

### Verification Commands

Verify the signature of an image:

```bash
# Verify latest image
cosign verify ghcr.io/marre/pem2jks:latest \
  --certificate-identity-regexp="https://github.com/marre/pem2jks/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

# Verify specific version
cosign verify ghcr.io/marre/pem2jks:1.0.0 \
  --certificate-identity-regexp="https://github.com/marre/pem2jks/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

# Verify using image digest (most secure)
cosign verify ghcr.io/marre/pem2jks@sha256:abc123... \
  --certificate-identity-regexp="https://github.com/marre/pem2jks/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

### What Gets Verified

The verification process checks:
1. **Signature validity**: The signature matches the image content
2. **Certificate chain**: The signing certificate chains to a trusted root
3. **Identity**: The certificate matches the expected GitHub workflow identity
4. **OIDC issuer**: The token came from GitHub's OIDC provider
5. **Transparency log**: The signature is recorded in Rekor

### Successful Verification Output

When verification succeeds, you'll see output like:

```
Verification for ghcr.io/marre/pem2jks:latest --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The code-signing certificate was verified using trusted certificate authority certificates

[{"critical":{"identity":{"docker-reference":"ghcr.io/marre/pem2jks"},...},...}]
```

## Kubernetes Admission Control

You can enforce signature verification in Kubernetes using admission controllers:

### Using Kyverno

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-pem2jks-images
spec:
  validationFailureAction: enforce
  rules:
    - name: verify-signature
      match:
        any:
        - resources:
            kinds:
              - Pod
      verifyImages:
      - imageReferences:
        - "ghcr.io/marre/pem2jks*"
        attestors:
        - entries:
          - keyless:
              subject: "https://github.com/marre/pem2jks/.github/workflows/release.yml@*"
              issuer: "https://token.actions.githubusercontent.com"
              rekor:
                url: https://rekor.sigstore.dev
```

### Using Sigstore Policy Controller

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: pem2jks-policy
spec:
  images:
  - glob: "ghcr.io/marre/pem2jks**"
  authorities:
  - keyless:
      url: https://fulcio.sigstore.dev
      identities:
      - issuerRegExp: "https://token.actions.githubusercontent.com"
        subjectRegExp: "https://github.com/marre/pem2jks/.*"
```

## Security Benefits

1. **Authenticity**: Verify that images were built by the official GitHub Actions workflow
2. **Integrity**: Detect any tampering or modification of images after signing
3. **Non-repudiation**: All signatures are recorded in an immutable transparency log
4. **Supply chain security**: Part of a comprehensive software supply chain security strategy
5. **Zero trust**: Don't trust images just because they're in a registry - verify them

## Troubleshooting

### Verification Fails

If verification fails, possible causes:
- **Image not signed**: The image may predate signing implementation
- **Wrong registry**: Ensure you're using `ghcr.io/marre/pem2jks`
- **Network issues**: Can't reach Rekor transparency log
- **Wrong identity**: Certificate identity doesn't match expected pattern

### Image Digest Not Available

Always prefer verifying by digest rather than tag for maximum security:

```bash
# Get the digest
docker pull ghcr.io/marre/pem2jks:1.0.0
docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/marre/pem2jks:1.0.0

# Verify using digest
cosign verify ghcr.io/marre/pem2jks@sha256:... \
  --certificate-identity-regexp="https://github.com/marre/pem2jks/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

## References

- [Sigstore Project](https://www.sigstore.dev/)
- [Cosign Documentation](https://docs.sigstore.dev/cosign/overview/)
- [GitHub OIDC in Actions](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [Rekor Transparency Log](https://docs.sigstore.dev/rekor/overview/)
- [SLSA Framework](https://slsa.dev/)
