.PHONY: build test clean docker install test-integration fmt clippy lint all

# Binary name
BINARY_NAME := pem2jks
BINARY_PATH := target/release/$(BINARY_NAME)

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Default target
all: lint test build

# Build the binary
build:
	VERSION=$(VERSION) GIT_COMMIT=$(COMMIT) BUILD_DATE=$(DATE) cargo build --release

# Build static binary (for containers)
static:
	VERSION=$(VERSION) GIT_COMMIT=$(COMMIT) BUILD_DATE=$(DATE) cargo build --release --target x86_64-unknown-linux-musl

# Run unit tests
test:
	cargo test

# Run integration tests (requires Docker)
test-integration:
	cargo test --test integration_test -- --ignored --test-threads=1

# Install binary
install:
	VERSION=$(VERSION) GIT_COMMIT=$(COMMIT) BUILD_DATE=$(DATE) cargo install --path .

# Clean build artifacts
clean:
	cargo clean

# Build Docker image for local testing
docker: static
	@mkdir -p linux/amd64
	cp target/x86_64-unknown-linux-musl/release/$(BINARY_NAME) linux/amd64/$(BINARY_NAME)
	docker buildx build --platform linux/amd64 --load -t $(BINARY_NAME):$(VERSION) -t $(BINARY_NAME):latest .
	rm -rf linux/

# Format code
fmt:
	cargo fmt

# Run clippy
clippy:
	cargo clippy -- -D warnings

# Lint (fmt check + clippy)
lint: 
	cargo fmt -- --check
	cargo clippy -- -D warnings

# Update dependencies
deps:
	cargo update

# Show version info that will be embedded
version:
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
	@echo "Date:    $(DATE)"

# Help
help:
	@echo "Available targets:"
	@echo "  all              - Run lint, test, and build"
	@echo "  build            - Build the release binary"
	@echo "  static           - Build static binary for containers (musl)"
	@echo "  test             - Run unit tests"
	@echo "  test-integration - Run integration tests (requires Docker)"
	@echo "  install          - Install to cargo bin"
	@echo "  clean            - Remove build artifacts"
	@echo "  docker           - Build Docker image"
	@echo "  fmt              - Format code"
	@echo "  clippy           - Run clippy linter"
	@echo "  lint             - Run fmt check and clippy"
	@echo "  deps             - Update dependencies"
	@echo "  version          - Show version info"
	@echo "  help             - Show this help"
