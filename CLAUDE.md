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

## Quick Reference

| Task | Command |
|------|---------|
| Full setup | `make setup` |
| Setup FVM only | `make setup-fvm` |
| Setup protoc only | `make setup-protoc` |
| Setup Rust tools | `make setup-rust-tools` |
| Setup for web builds | `make setup-web` |
| Setup for Android builds | `make setup-android` |
| Show all commands | `make help` |
| Run tests | `make test` |
| Run tests with coverage | `make coverage` |
| Run analysis | `make analyze` |
| Strict analysis | `make analyze ARGS="--fatal-infos"` |
| Rust security audit | `make rust-audit` |
| Rust type check | `make rust-check` |
| Format code | `make format` |
| Generate documentation | `make doc` |
| Regenerate FRB bindings | `make codegen` |
| Build native library | `make build` |
| Build for Android | `make build-android` |
| Build WASM for web | `make build-web` |
| Check for updates | `make check-new-libsignal-version` |
| Check template updates | `make check-template-updates` |
| Update Cargo.lock | `make rust-update` |
| Update CHANGELOG (AI) | `make update-changelog` |
| Get dependencies | `make get` |

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
libsignal-protocol = { git = "https://github.com/signalapp/libsignal", tag = "v0.87.0" }
```

To check/update the version:
```bash
make check-new-libsignal-version              # Check for updates
make check-new-libsignal-version ARGS="--update"  # Update rust/Cargo.toml
make rust-update                              # Update Cargo.lock
make codegen                                  # Regenerate FRB bindings
make update-changelog ARGS="--version vX.Y.Z" # Update CHANGELOG (requires GITHUB_TOKEN)
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

## FVM (Flutter Version Management)

This project uses FVM for consistent Flutter/Dart versions.

**Version:** Flutter 3.38.4 (Dart SDK 3.10.0)

FVM is automatically installed by `make setup`.

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
