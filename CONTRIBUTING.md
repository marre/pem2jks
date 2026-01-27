# Contributing to pem2jks

Thank you for your interest in contributing to pem2jks!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/pem2jks.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`

## Development

### Prerequisites

- Go 1.25 or later
- Docker (for running golangci-lint and building images)
- Java and keytool (optional, for integration tests)

### Building

```bash
make build
```

### Testing

```bash
# Unit tests
make test

# Linting
make lint

# Integration tests (requires Java)
make test-integration
```

## Making Changes

1. Make your changes in your feature branch
2. Add tests for new functionality
3. Ensure all tests pass: `make test`
4. Run linting: `make lint`
5. Commit with clear, descriptive messages
6. Push to your fork
7. Open a pull request

## Pull Request Guidelines

- Keep PRs focused on a single feature or fix
- Update documentation for user-facing changes
- Add entries to CHANGELOG.md for notable changes
- Ensure CI passes before requesting review

## Code Style

- Follow standard Go conventions
- Run `go fmt` before committing
- Address golangci-lint warnings

## Questions?

Open an issue for questions or discussions about features and bugs.
