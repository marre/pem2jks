.PHONY: build test clean docker install test-integration generate-certs fmt vet lint all

# Binary name
BINARY_NAME := pem2jks
BINARY_PATH := bin/$(BINARY_NAME)

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build flags
LDFLAGS := -s -w \
	-X main.Version=$(VERSION) \
	-X main.GitCommit=$(COMMIT) \
	-X main.BuildDate=$(DATE)

# Go parameters
GOCMD   := go
GOBUILD := $(GOCMD) build
GOTEST  := $(GOCMD) test
GOFMT   := $(GOCMD) fmt
GOVET   := $(GOCMD) vet
GOMOD   := $(GOCMD) mod

# Default target
all: lint test build

# Build the binary
build:
	@mkdir -p bin
	$(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BINARY_PATH) ./cmd/pem2jks

# Build static binary (for containers)
static:
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BINARY_PATH) ./cmd/pem2jks

# Run unit tests
test:
	$(GOTEST) -v ./...

# Run integration tests
test-integration: build generate-certs
	@chmod +x scripts/integration-test.sh
	./scripts/integration-test.sh

# Generate test certificates
generate-certs:
	@chmod +x scripts/generate-certs.sh
	./scripts/generate-certs.sh

# Install binary to GOPATH/bin
install:
	$(GOBUILD) -ldflags="$(LDFLAGS)" -o $(GOPATH)/bin/$(BINARY_NAME) ./cmd/pem2jks

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f testdata/*.pem testdata/*.crt testdata/*.key testdata/*.jks testdata/*.p12 testdata/*.srl testdata/*.csr
	rm -f testdata/VerifyKeystore.class

# Build Docker image (single platform, for local use)
docker:
	docker build -t $(BINARY_NAME):$(VERSION) .
	docker tag $(BINARY_NAME):$(VERSION) $(BINARY_NAME):latest

# Build multi-arch Docker image (requires docker buildx)
docker-multiarch:
	docker buildx build --platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(BINARY_NAME):$(VERSION) \
		-t $(BINARY_NAME):latest \
		.

# Build and push multi-arch Docker image
docker-push:
	docker buildx build --platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(BINARY_NAME):$(VERSION) \
		-t $(BINARY_NAME):latest \
		--push \
		.

# Format code
fmt:
	$(GOFMT) ./...

# Run vet
vet:
	$(GOVET) ./...

# Run golangci-lint in Docker
golangci-lint:
	docker run --rm -v $(PWD):/app -w /app golangci/golangci-lint:v2.8.0-alpine golangci-lint run ./...

# Lint (fmt + vet + golangci-lint)
lint: fmt vet golangci-lint

# Update dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Show version info that will be embedded
version:
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
	@echo "Date:    $(DATE)"

# Help
help:
	@echo "Available targets:"
	@echo "  all              - Run lint, test, and build"
	@echo "  build            - Build the binary to bin/"
	@echo "  static           - Build static binary for containers"
	@echo "  test             - Run unit tests"
	@echo "  test-integration - Run integration tests"
	@echo "  generate-certs   - Generate test certificates"
	@echo "  install          - Install to GOPATH/bin"
	@echo "  clean            - Remove build artifacts"
	@echo "  docker           - Build Docker image (local platform)"
	@echo "  docker-multiarch - Build multi-arch Docker image (amd64+arm64)"
	@echo "  docker-push      - Build and push multi-arch Docker image"
	@echo "  fmt              - Format code"
	@echo "  vet              - Run go vet"
	@echo "  golangci-lint    - Run golangci-lint"
	@echo "  lint             - Run fmt, vet, and golangci-lint"
	@echo "  deps             - Update dependencies"
	@echo "  version          - Show version info"
	@echo "  help             - Show this help"
