# libsignal - Claude Code Configuration

## Important Rules

**ALWAYS use Makefile commands.** Never call scripts directly via `fvm dart run scripts/...`. The Makefile is the single entry point for all operations.

```bash
# Correct - pass arguments via ARGS variable
make test
make analyze ARGS="--fatal-infos"
make check-new-libsignal-version ARGS="--update"

# Wrong - never do this
fvm dart run scripts/check_updates.dart --update
make test test/keys/  # make interprets test/keys/ as target!
```

## Available Makefile Commands

### Setup
```bash
make setup                        # Full setup (FVM + Rust tools + protoc)
make setup-fvm                    # Install FVM + Flutter only
make setup-rust-tools             # Install Rust tools (cargo-audit, frb_codegen)
make setup-protoc                 # Install protoc (Protocol Buffers compiler)
make setup-web                    # Install web build tools (wasm-pack)
make setup-android                # Install Android build tools (cargo-ndk)
```

### Code Generation
```bash
make codegen                      # Generate Dart bindings from Rust code
```

**Note:** `make codegen` automatically creates a `.skip_libsignal_hook` marker file to prevent Build Hooks from downloading libraries during codegen. The marker is automatically removed after completion.

### Build
```bash
make build                              # Build for current platform (debug)
make build ARGS="--release"             # Build for current platform (release)
make build ARGS="--target <target>"     # Build for specific Rust target
make build-android                      # Build for Android (all ABIs)
make build-android ARGS="--target arm64-v8a"  # Build for specific Android ABI
make build-web                          # Build WASM for web
```

### Rust Quality
```bash
make rust-check                   # Check Rust code compiles
make rust-audit                   # Audit Rust dependencies for vulnerabilities
```

### Dart Quality
```bash
make test                                # Run all tests
make test ARGS="test/example_test.dart"  # Run specific test file
make coverage                            # Run tests with coverage report
make analyze                             # Run static analysis
make analyze ARGS="--fatal-infos"        # Strict analysis
make format                              # Format Dart code
make format-check                        # Check formatting without changes
make doc                                 # Generate documentation
```

### Utilities
```bash
make get                          # Get dependencies
make clean                        # Clean build artifacts (including rust/target)
make version                      # Show current crate version
make rust-update                  # Update Cargo.lock
make check-new-libsignal-version  # Check for new upstream libsignal version
make check-new-libsignal-version ARGS="--update"  # Apply update
make check-template-updates       # Check for copier template updates
make check-targets                # Check deployment targets (iOS/macOS/Android)
make check-targets ARGS="--ios --set 14.0"  # Set iOS target everywhere
make update-changelog ARGS="--version vX.Y.Z"  # Update CHANGELOG with AI
make help                         # Show all available commands
```

## Project Overview

Dart bindings for libsignal using Flutter Rust Bridge (FRB) - Signal Protocol implementation for end-to-end encryption.

### Key Features
- Signal Protocol (Double Ratchet, X3DH)
- Sealed Sender (anonymous messaging)
- Group Messaging (SenderKey)
- Native libraries built via Cargokit/Flutter Rust Bridge
- Automated security updates via GitHub Actions

### Upstream Repository
- **libsignal**: https://github.com/signalapp/libsignal

### Security
See [SECURITY.md](SECURITY.md) for security guidelines and code review checklist.

## Project Structure

```
libsignal/
├── lib/                            # Dart library code
│   └── src/
│       ├── rust/                   # Auto-generated FRB bindings
│       ├── stores/                 # Store interfaces and implementations
│       └── libsignal.dart          # Main library initialization
├── rust/                           # Rust source code for FRB
│   ├── Cargo.toml                  # Rust dependencies (libsignal version here)
│   └── src/
│       ├── api/                    # Public FRB API (Dart-callable functions)
│       └── lib.rs                  # Library root
├── rust_builder/                   # Flutter FFI plugin (Cargokit)
│   ├── cargokit/                   # Cargokit build system
│   └── pubspec.yaml                # Plugin configuration
├── scripts/                        # Development scripts (use via Makefile!)
├── test/                           # Tests
├── Makefile                        # Entry point for all commands
├── pubspec.yaml                    # Package config
├── flutter_rust_bridge.yaml        # FRB codegen configuration
└── .github/workflows/              # CI/CD workflows
```

## Build System

This project uses **Cargokit** (via Flutter Rust Bridge) for native libraries.

### How It Works

1. **End users**: Precompiled binaries downloaded from GitHub Releases (no Rust needed)
2. **Developers**: Cargokit builds from source (requires Rust + protoc)
3. **CI**: `build-precompiled.yml` workflow builds and uploads binaries when Rust code changes

### Precompiled Binaries

Configuration in `rust/cargokit.yaml`:
- Binaries uploaded to GitHub Releases with tag `precompiled_<hash>`
- Ed25519 signatures for verification
- Private key stored as GitHub Secret: `CARGOKIT_PRIVATE_KEY`

### Build Requirements (for source builds)

- **Rust toolchain** (rustup, cargo)
- **protoc** (Protocol Buffers compiler, required by libsignal's spqr dependency)
- **Android NDK** (for Android builds)
- **Xcode** (for iOS/macOS builds)
- **wasm-pack** (for Web/WASM builds): `cargo install wasm-pack`

### libsignal Version

The libsignal version is specified in `rust/Cargo.toml`:

```toml
[dependencies]
libsignal-protocol = { git = "https://github.com/signalapp/libsignal", tag = "v0.89.1" }
```

To check/update the version:
```bash
make check-new-libsignal-version              # Check for updates
make check-new-libsignal-version ARGS="--update"  # Update rust/Cargo.toml
make rust-update                              # Update Cargo.lock
make codegen                                  # Regenerate FRB bindings
make update-changelog ARGS="--version vX.Y.Z" # Update CHANGELOG with AI (requires AI_MODELS_TOKEN)
```

### AI-Powered Changelog

The `update-changelog` command uses GitHub Models API to analyze release notes and generate changelog entries. Requires `AI_MODELS_TOKEN` environment variable:

```bash
# Get token from https://github.com/settings/tokens (Models → Read only)
AI_MODELS_TOKEN=xxx make update-changelog ARGS="--version v1.0.0"
```

## Development Workflow

### 1. Implement Rust API

Add your Rust functions in `rust/src/api/`:

```rust
// rust/src/api/greeting.rs
pub fn greet(name: String) -> String {
    format!("Hello, {}!", name)
}
```

Register the module in `rust/src/api/mod.rs`:

```rust
pub mod greeting;
```

### 2. Generate Dart Bindings

```bash
make codegen
```

This generates Dart code in `lib/src/rust/`.

### 3. Build Native Library

```bash
# For current platform
make build

# For specific target
make build ARGS="--target aarch64-apple-darwin"
```

### 4. Run Tests

```bash
make test
```

## Update Crate Version

Version is stored in `rust/Cargo.toml`.

```bash
# 1. Edit rust/Cargo.toml - update version
# 2. Run tests
make test

# 3. Commit and push (CI will build native libraries)
git add rust/Cargo.toml
git commit -m "Bump crate version to X.Y.Z"
git push
```

## Supported Platforms

| Platform | Architecture |
|----------|--------------|
| Linux | x86_64, arm64 |
| macOS | arm64, x86_64 |
| Windows | x86_64 |
| iOS | device, simulator |
| Android | arm64-v8a, armeabi-v7a, x86_64 |
| Web | wasm32 |

## Security Considerations

> **Important:** See [SECURITY.md](SECURITY.md) for full security policy and best practices.

### Supply Chain Security
- All native libraries are built from source in GitHub Actions
- SHA256 checksums verify downloaded libraries
- Pin to specific upstream releases

### Code Review Checklist
1. No hardcoded keys or secrets
2. Memory properly freed after use
3. Sensitive data zeroed before freeing
4. No timing side-channels

## FVM (Flutter Version Management)

This project uses FVM for consistent Flutter/Dart versions.

**Version:** Flutter 3.38.4 (Dart SDK 3.10.0)

FVM is automatically installed by `make setup`.

## Windows Users

On Windows, install `make` first:
- Chocolatey: `choco install make`
- Scoop: `scoop install make`
- Or use Git Bash / WSL

## Architecture

This project uses **Flutter Rust Bridge (FRB)** for Rust-Dart interoperability:

- **Rust layer** (`rust/src/api/`) wraps `libsignal-protocol` crate (pure Rust, not C FFI)
- **FRB codegen** generates Dart bindings in `lib/src/rust/`
- **FRB-generated Dart** is the final API (no additional Dart wrappers)

### Regenerating FRB Bindings

When modifying Rust code in `rust/src/api/`:

```bash
make codegen
```

This runs `flutter_rust_bridge_codegen generate` using `flutter_rust_bridge.yaml` config.

## Unimplemented Functionality

Some libsignal features are not yet implemented in this library:

### zkgroup (Zero-Knowledge Groups)
- Profile keys, credentials, group calls
- Server-side verification
- Not needed for basic Signal Protocol messaging

### Session Establishment
Session establishment via `SessionBuilder.processPreKeyBundle()` is fully implemented using FRB.
The in-memory store pattern avoids FFI callback complexity.

### SVR (Secure Value Recovery)
- Server-side functionality for PIN-based backups
- Not typically needed in client applications

## Stores Architecture

Stores are **required** for Signal Protocol operations due to Double Ratchet:
- Each message changes session state (ratchet advances)
- State must be persisted for correct encryption/decryption
- Without stores, repeated operations will fail or produce incorrect results

### Minimum Required Stores

| Operation | SessionStore | IdentityKeyStore | PreKeyStore | SignedPreKeyStore | KyberPreKeyStore |
|-----------|:---:|:---:|:---:|:---:|:---:|
| Encrypt/Decrypt (existing session) | ✓ | ✓ | - | - | - |
| Process PreKey message (new session) | ✓ | ✓ | ✓ | ✓ | ✓ |
| Group messaging | - | - | - | - | - |

**Note:** Group messaging uses `SenderKeyStore`.

### What Works WITHOUT Stores

- Key generation (`PrivateKey.generate()`, `IdentityKeyPair.generate()`)
- Signing and verification (`privateKey.sign()`, `publicKey.verifySignature()`)
- Message parsing (`SignalMessage.deserialize()`)
- Certificate validation (`SenderCertificate.validate()`)
- Creating `PreKeyBundle` from existing keys

### Available Implementations

**In-memory stores** (in `lib/src/stores/in_memory/`) are for **testing only**:
- `InMemorySessionStore`
- `InMemoryIdentityKeyStore`
- `InMemoryPreKeyStore`
- `InMemorySignedPreKeyStore`
- `InMemoryKyberPreKeyStore`
- `InMemorySenderKeyStore`

For production, implement store interfaces with secure storage (SQLite, SecureStorage, etc.).

## Changelog Format

Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format:

```markdown
## X.Y.Z

### Added
- New features

### Changed
- Changes in existing functionality

### Fixed
- Bug fixes

### Security
- Security-related changes
```

## Publishing Checklist

```bash
# 1. Run quality checks
make analyze
make test
make format-check

# 2. Update version in pubspec.yaml
# 3. Update CHANGELOG.md

# 4. Dry run
make publish-dry-run

# 5. Create annotated tag and push (CI will publish)
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

## Claude Skills

Claude Code skills available in this project (invoke with `/<skill>` or used automatically by Claude):

| Skill | Description |
|-------|-------------|
| `release-package` | Prepare a new version for publication to pub.dev |
| `update-template` | Update copier template to latest version |
