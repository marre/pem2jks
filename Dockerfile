# Copy cosign from official image
FROM ghcr.io/sigstore/cosign/cosign:v3.0.4@sha256:0b015a3557a64a751712da8a6395534160018eaaa2d969882a85a336de9adb70 AS cosign-bin

# Verification stage - verifies the signed binary
FROM alpine:3.21 AS verifier

ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

# Copy cosign binary from official Sigstore image
COPY --from=cosign-bin /ko-app/cosign /usr/local/bin/cosign

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
