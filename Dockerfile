# Build stage
FROM golang:1.21-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /build

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY cmd/ ./cmd/
COPY pkg/ ./pkg/

# Build with version information
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.GitCommit=${COMMIT} -X main.BuildDate=${DATE}" \
    -o pem2jks ./cmd/pem2jks

# Final stage
FROM scratch
COPY --from=builder /build/pem2jks /pem2jks
ENTRYPOINT ["/pem2jks"]
