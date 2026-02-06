# Contributing to libsignal_dart

Thank you for your interest in contributing to libsignal_dart! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Coding Standards](#coding-standards)
- [Advanced Development](#advanced-development)
- [Security Considerations](#security-considerations)

## Code of Conduct

Please be respectful and considerate of others. We expect all contributors to:

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community

## Getting Started

### Prerequisites

- [Dart SDK](https://dart.dev/get-dart) (3.10.0+)
- Git
- **For running tests:** Rust toolchain, protoc

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/libsignal_dart.git
   cd libsignal_dart
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/djx-y-z/libsignal_dart.git
   ```

## Development Setup

### Quick Setup (Recommended)

Run the setup command to install everything automatically:

```bash
make setup
```

This will:
1. Check that Rust toolchain is installed (shows instructions if not)
2. Install FVM (Flutter Version Management) and project's Flutter version
3. Install protoc (Protocol Buffers compiler) via brew/apt/dnf/pacman
4. Install cargo-audit for Rust dependency vulnerability scanning
5. Get all dependencies and configure git hooks

### Verify Setup

```bash
# Show all available commands
make help

# Run tests to ensure everything works
make test
```

### Windows Users

On Windows, you need to install `make` first:
- Via Chocolatey: `choco install make`
- Via Scoop: `scoop install make`
- Or use Git Bash / WSL

Then run `make setup` as above.

### Project Structure

```
libsignal/
├── lib/                    # Main library code
│   ├── libsignal.dart      # Public API exports
│   └── src/
│       ├── rust/           # Auto-generated FRB bindings
│       └── stores/         # Store interfaces and implementations
├── rust/                   # Rust source code
│   ├── Cargo.toml          # Rust dependencies (libsignal version here)
│   └── src/api/            # FRB API functions
├── rust_builder/           # Flutter FFI plugin (Cargokit)
├── test/                   # Test files
├── example/                # Example application
├── scripts/                # Build scripts (use via Makefile!)
└── Makefile                # Entry point for all commands
```

## Making Changes

### Create a Branch

Create a branch for your changes:

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### Types of Contributions

We welcome:

- **Bug fixes** - Fix issues in existing code
- **Documentation** - Improve docs, examples, comments
- **Tests** - Add or improve test coverage
- **Features** - New functionality (please discuss first)
- **Performance** - Optimizations with benchmarks

### Before You Start

For major changes:
1. Open an issue first to discuss the change
2. Wait for feedback from maintainers
3. This helps avoid wasted effort on changes that won't be merged

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run specific test file
make test ARGS="test/keys_test.dart"

# Run with verbose output
make test ARGS="--reporter=expanded"
```

### Writing Tests

- Place tests in the `test/` directory
- Name test files with `_test.dart` suffix
- Test both success and error cases
- Include edge cases for cryptographic operations

Example test structure:

```dart
import 'package:test/test.dart';
import 'package:libsignal/libsignal.dart';

void main() {
  group('Keys', () {
    test('IdentityKeyPair generation works', () {
      final keyPair = IdentityKeyPair.generate();

      expect(keyPair.publicKey, isNotNull);
      expect(keyPair.privateKey, isNotNull);
    });
  });
}
```

## Submitting Changes

### Commit Messages

Write clear, concise commit messages:

```
type: short description

Longer description if needed.

Fixes #123
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `test`: Adding or updating tests
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvement
- `chore`: Maintenance tasks

### Pull Request Process

1. Update your branch with upstream:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. Push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```

3. Create a Pull Request on GitHub

4. In your PR description:
   - Describe what the change does
   - Reference any related issues
   - Note any breaking changes
   - Include testing steps if applicable

5. Wait for review - maintainers will review and may request changes

### PR Checklist

Before submitting:

- [ ] Code follows the project's coding standards
- [ ] Tests pass locally (`make test`)
- [ ] Static analysis passes (`make analyze`)
- [ ] Code is formatted (`make format-check`)
- [ ] Documentation is updated if needed
- [ ] CHANGELOG.md is updated for user-facing changes
- [ ] Commit messages are clear and follow conventions

## Coding Standards

### Dart Style

Follow the [Effective Dart](https://dart.dev/effective-dart) guidelines:

```bash
# Format code
make format

# Check formatting without changes
make format-check

# Run static analysis
make analyze
```

- Use meaningful variable and function names
- Add documentation comments for public APIs
- Keep functions small and focused

### Documentation

- Document all public APIs with `///` comments
- Include examples in documentation where helpful
- Keep comments up to date with code changes

### Memory Safety (FRB Architecture)

This library uses Flutter Rust Bridge (FRB) with libsignal-protocol (pure Rust):

- **Memory is managed automatically** by Rust's ownership system
- **No manual cleanup needed** - FRB handles all resource deallocation
- **No `dispose()` calls** - Rust drops resources when they go out of scope

When adding new Rust API functions:

- Use opaque types with `#[frb(opaque)]` for complex libsignal types
- Return `Result<T, String>` for error handling (FRB converts to Dart exceptions)
- Use `DartFnFuture<T>` for async callbacks to Dart stores

Example Rust API:

```rust
#[frb(opaque)]
pub struct PrivateKey {
    native: libsignal_protocol::PrivateKey,
}

impl PrivateKey {
    #[flutter_rust_bridge::frb(sync)]
    pub fn generate() -> Result<PrivateKey, String> {
        let key = libsignal_protocol::PrivateKey::generate(&mut OsRng);
        Ok(PrivateKey { native: key })
    }
}
```

## Advanced Development

### Makefile Commands Reference

All development tasks should be done via Makefile:

| Command | Description |
|---------|-------------|
| `make setup` | Install all required tools (Rust check, FVM, protoc, cargo-audit) |
| `make setup-fvm` | Install FVM and project Flutter version only |
| `make setup-protoc` | Install protoc (Protocol Buffers compiler) |
| `make setup-rust-tools` | Install Rust tools (cargo-audit, flutter_rust_bridge_codegen) |
| `make setup-web` | Install wasm-pack for web builds (optional) |
| `make setup-android` | Install cargo-ndk for Android builds (optional) |
| `make help` | Show all available commands |
| `make test` | Run all tests |
| `make analyze` | Run static analysis |
| `make rust-audit` | Check Rust dependencies for vulnerabilities |
| `make rust-check` | Quick Rust type check (updates Cargo.lock) |
| `make format` | Format code |
| `make format-check` | Check formatting |
| `make codegen` | Regenerate FRB bindings |
| `make check-new-libsignal-version` | Check for libsignal updates |
| `make check-template-updates` | Check for copier template updates |
| `make rust-update` | Update rust/Cargo.lock |
| `make update-changelog` | Update CHANGELOG.md with AI (requires GITHUB_TOKEN) |
| `make get` | Get dependencies |
| `make clean` | Clean build artifacts |

### Regenerating FRB Bindings

When modifying Rust API code in `rust/src/api/`:

```bash
# Regenerate Flutter Rust Bridge bindings
make codegen

# Test the new bindings
make test
```

When updating the libsignal version:

```bash
# Option 1: Automatic update (recommended)
make check-new-libsignal-version ARGS="--update"

# Option 2: Manual update
# Edit rust/Cargo.toml - update libsignal-protocol tag to new version
# Then run cargo update to update Cargo.lock
cd rust && cargo update && cd ..

# Test
make test
```

**When to regenerate:**
- After modifying Rust API code in `rust/src/api/`
- After updating libsignal version (if API changed)

### Building Native Libraries

Native libraries are built automatically by **Cargokit** during `flutter build`. You don't need to build them manually for most development work.

For development, Cargokit builds from source when you run tests or the example app:

```bash
# Run tests (Cargokit builds the native library automatically)
make test
```

**Build requirements (for source builds):**

| Platform | Build OS | Requirements |
|----------|----------|--------------|
| Linux | Linux | Rust, protoc |
| macOS | macOS | Rust, protoc, Xcode CLI |
| iOS | macOS | Rust, protoc, Xcode |
| Android | Linux/macOS | Rust, protoc, Android NDK |
| Windows | Windows | Rust, protoc, Visual Studio |

## Security Considerations

This is a **cryptographic library**. Security is paramount.

### Reporting Security Issues

**Do not open public issues for security vulnerabilities.**

Instead, report security issues privately:
- Email: [create a security advisory on GitHub]
- Use GitHub's private vulnerability reporting

### Security Review Checklist

For cryptographic code changes:

- [ ] No hardcoded keys or secrets
- [ ] No key material in logs or error messages
- [ ] Cryptographic comparisons done via library methods (avoid raw byte comparison in Dart)
- [ ] `DateTime.now().toUtc()` used for timestamps
- [ ] Store operations properly synchronized
- [ ] Error handling doesn't leak sensitive information
- [ ] In-memory stores used only for testing (not production)

### Upstream Changes

This library wraps [libsignal](https://github.com/signalapp/libsignal). When updating libsignal:

**Automatic (CI):** A daily workflow checks for new libsignal releases and creates a PR with all updates automatically.

**Manual update:**

1. Review the libsignal changelog for security fixes
2. Update libsignal version:
   ```bash
   make check-new-libsignal-version ARGS="--update"
   ```
3. Update Cargo.lock:
   ```bash
   make rust-update
   ```
4. Regenerate FRB bindings (if API changed):
   ```bash
   make codegen
   ```
5. Update CHANGELOG.md (requires `GITHUB_TOKEN` with `models:read` permission):
   ```bash
   GITHUB_TOKEN=your_token make update-changelog ARGS="--version vX.Y.Z"
   ```
6. Test all protocol operations:
   ```bash
   make test
   ```

## Questions?

- Open an issue for general questions
- Check existing issues before creating new ones
- Be patient - maintainers are volunteers

Thank you for contributing!
