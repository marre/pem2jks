# Contributing to pem2jks

Thank you for your interest in contributing to pem2jks!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/pem2jks.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`

## Development

### Prerequisites

- Rust (stable toolchain)
- Docker (for integration tests and building images)

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

# Integration tests (requires Docker)
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

- Follow standard Rust conventions
- Run `cargo fmt` before committing
- Address clippy warnings

## Questions?

Open an issue for questions or discussions about features and bugs.
