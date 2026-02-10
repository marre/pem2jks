# Verification stage - verifies the signed binary
FROM alpine:3.21 AS verifier

ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

# Install cosign for signature verification
# We need cosign v3.0.3+ to support the newer Sigstore bundle format
RUN apk add --no-cache curl && \
    COSIGN_VERSION="v3.0.3" && \
    ARCH=$(uname -m) && \
    if [ "${ARCH}" = "x86_64" ]; then ARCH="amd64"; elif [ "${ARCH}" = "aarch64" ]; then ARCH="arm64"; fi && \
    curl -sL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${ARCH}" -o /usr/local/bin/cosign && \
    chmod +x /usr/local/bin/cosign && \
    apk del curl

WORKDIR /verify

# Copy the signed binary and verification files from build context
# These are provided by the workflow after build-binaries job completes
COPY pem2jks-${TARGETOS}-${TARGETARCH} ./pem2jks-${TARGETOS}-${TARGETARCH}
COPY pem2jks-${TARGETOS}-${TARGETARCH}.sha256 ./pem2jks-${TARGETOS}-${TARGETARCH}.sha256
COPY pem2jks-${TARGETOS}-${TARGETARCH}.sigstore.json ./pem2jks-${TARGETOS}-${TARGETARCH}.sigstore.json

# Verify SHA256 checksum
RUN echo "Verifying checksum..." && \
    sha256sum -c pem2jks-${TARGETOS}-${TARGETARCH}.sha256 && \
    echo "✓ Checksum verified"

# Verify Cosign signature using Sigstore bundle format
RUN echo "Verifying signature..." && \
    cosign verify-blob pem2jks-${TARGETOS}-${TARGETARCH} \
      --bundle pem2jks-${TARGETOS}-${TARGETARCH}.sigstore.json \
      --certificate-identity-regexp="https://github\\.com/marre/pem2jks/\\.github/workflows/release\\.yml@refs/tags/.*" \
      --certificate-oidc-issuer="https://token.actions.githubusercontent.com" && \
    echo "✓ Signature verified"

# Final stage - use verified binary
FROM scratch
ARG TARGETOS
ARG TARGETARCH
COPY --from=verifier /verify/pem2jks-${TARGETOS}-${TARGETARCH} /pem2jks
ENTRYPOINT ["/pem2jks"]
