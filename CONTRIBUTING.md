# Contributing to VBW

Thank you for your interest in contributing to the Verified Build Witness project.

## Requirements

All contributions must meet the following standards:

### Developer Certificate of Origin (DCO)

All commits **must** be signed off using `git commit -s`, attesting to the
[Developer Certificate of Origin](https://developercertificate.org/):

```
Signed-off-by: Your Name <your.email@example.com>
```

### Code Quality

- **Format**: `cargo fmt --all -- --check` must pass
- **Lint**: `cargo clippy --all-targets --all-features -- -D warnings` must pass
- **Test**: `cargo test --all-features` must pass (debug and release)
- **Audit**: `cargo deny check` must pass (no known vulnerabilities, license violations, or banned crates)

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

<body — explain *why*, not *what*>

Signed-off-by: Your Name <your.email@example.com>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`.

### Pull Request Process

1. Fork the repository and create a feature branch from `main`
2. Ensure all CI checks pass before requesting review
3. PRs require at least one approval from a CODEOWNER
4. Security-sensitive changes require review from `@scqcs/security`
5. Squash commits before merge unless the commit history is meaningful

### Security

- **Never** commit secrets, credentials, or private keys
- **Never** introduce dependencies that pull from git sources (crates.io only)
- **Never** add crates with copyleft licenses
- If you discover a vulnerability, follow the [Security Policy](SECURITY.md)

## Development Setup

```bash
# Clone and build
git clone https://github.com/scqcs/vbw.git
cd vbw
cargo build

# Run all quality checks
make check

# Run tests
make test
```

## License

By contributing, you agree that your contributions will be licensed under the
Apache License 2.0, consistent with the project [LICENSE](LICENSE).
