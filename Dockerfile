# Verification stage - verifies the signed binary
FROM alpine:3.21 AS verifier

ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

# Install cosign for signature verification
RUN apk add --no-cache cosign

WORKDIR /verify

# Copy the signed binary and verification files from build context
# These are provided by the workflow after build-binaries job completes
COPY pem2jks-${TARGETOS}-${TARGETARCH} ./pem2jks
COPY pem2jks-${TARGETOS}-${TARGETARCH}.sha256 ./pem2jks.sha256
COPY pem2jks-${TARGETOS}-${TARGETARCH}.sig ./pem2jks.sig
COPY pem2jks-${TARGETOS}-${TARGETARCH}.pem ./pem2jks.pem

# Verify SHA256 checksum
RUN echo "Verifying checksum..." && \
    sha256sum -c pem2jks.sha256 && \
    echo "✓ Checksum verified"

# Verify Cosign signature
RUN echo "Verifying signature..." && \
    cosign verify-blob pem2jks \
      --signature pem2jks.sig \
      --certificate pem2jks.pem \
      --certificate-identity-regexp="https://github.com/marre/pem2jks/.*" \
      --certificate-oidc-issuer="https://token.actions.githubusercontent.com" && \
    echo "✓ Signature verified"

# Final stage - use verified binary
FROM scratch
COPY --from=verifier /verify/pem2jks /pem2jks
ENTRYPOINT ["/pem2jks"]
