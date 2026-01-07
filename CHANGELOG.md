# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Use GitHub App token instead of `GITHUB_TOKEN` in workflows:
  - `check-libsignal-updates.yml`: PR creation, GitHub Models API
  - `build-libsignal.yml`: release version checks
- Skip tests for bot PRs in `test.yml` (native libraries not yet built for version updates)

## [1.0.1] - 2026-01-02

### Added

- Added `make doc` command for local API documentation generation
- Added "Implementation Status" section to README.md with overview of wrapped native functionality
- Added pre-commit git hook for format check and static analysis (configured via `make setup`)
- Added `workflow_dispatch` trigger to test workflow (allows manual test runs from GitHub Actions)

### Changed

- Improved test coverage to 98.4%
- Added `// coverage:ignore` comments to genuinely untestable code (FFI callbacks, finalizers, defensive null checks)
- Removed unused `extractOwnedBuffer` function from `FfiHelpers`
- Refactored CI update workflow: moved AI analysis from bash to Dart script
- Simplified `check-libsignal-updates.yml` workflow (~530 → ~220 lines)
- Added `--ai`, `--no-ai`, `--ci` flags to `check_updates.dart` script
- Script now writes directly to `GITHUB_OUTPUT` in CI mode (no jq parsing needed)
- `build-libsignal.yml` workflow now skips build if release already exists (prevents unnecessary rebuilds when only package version changes)

### Fixed

- Fixed `publish.yml` workflow: use Flutter SDK (via FVM) instead of Dart SDK for publishing Flutter packages
- Added `workflow_dispatch` with dry-run option to publish workflow
- Added duplicate version check (validates against pub.dev API before publishing)
- Added `publish-dry-run` validation step before actual publishing
- Aligned publish workflow structure with liboqs_dart for consistency
- Fixed version parsing in `build-libsignal.yml` workflow (use Dart script instead of grep for reliable parsing)
- Fixed unresolved dartdoc references in `LibSignalException`, `GroupSession`, and `InMemoryIdentityKeyStore`
- Fixed `.pubignore` to include `CONTRIBUTING.md` in published package
- Fixed `.pubignore` to exclude generated `doc/` directory
- Fixed LICENSE file format for proper pub.dev recognition (added full AGPL-3.0 text with SPDX identifier)

## [1.0.0] - 2025-12-31

### Added

- Pre-built native libraries for all platforms (iOS, Android, macOS, Linux, Windows)
- **Signal Protocol**: Double Ratchet algorithm for forward secrecy and break-in recovery
- **X3DH**: Extended Triple Diffie-Hellman for asynchronous key agreement
- **Key Management**: Curve25519 key pairs (`PrivateKey`, `PublicKey`, `IdentityKeyPair`)
- **Pre-keys**: `PreKeyRecord`, `SignedPreKeyRecord`, `PreKeyBundle` for session establishment
- **Post-quantum**: Kyber key pairs (`KyberKeyPair`, `KyberPreKeyRecord`) for quantum resistance
- **Sessions**: `SessionRecord`, `ProtocolAddress` for session management
- **Messages**: `SignalMessage`, `PreKeySignalMessage` for encrypted communication
- **Sealed Sender**: Anonymous message sending (`ServerCertificate`, `SenderCertificate`)
- **Group Messaging**: SenderKey distribution (`GroupSession`, `SenderKeyRecord`, `SenderKeyDistributionMessage`)
- **Cryptographic utilities**: AES-256-GCM-SIV (`Aes256GcmSiv`), HKDF (`Hkdf`), identity fingerprints (`Fingerprint`)
- **Storage interfaces**: `SessionStore`, `IdentityKeyStore`, `PreKeyStore`, `SignedPreKeyStore`, `KyberPreKeyStore`, `SenderKeyStore`
- In-memory store implementations for testing and prototyping
- Automatic native library download via build hooks
- SHA256 verification for native library integrity
- `LibSignal.init()` for optional library pre-initialization
- Comprehensive exception handling with `SignalException`
- GitHub Actions CI/CD pipeline for automated testing and publishing
- Automated upstream version tracking with AI-powered changelog generation
- Cross-platform build scripts for native library compilation
- Example Flutter application and CLI example demonstrating all features

### Security

- Based on libsignal v0.86.9 from Signal Foundation
- Secret keys are handled securely with proper memory management
- Cryptographic operations use constant-time implementations where applicable

[Unreleased]: https://github.com/djx-y-z/libsignal_dart/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/djx-y-z/libsignal_dart/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/djx-y-z/libsignal_dart/releases/tag/v1.0.0
