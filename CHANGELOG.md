# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `make setup-build` command to install native build dependencies (Rust, protoc)
- Add `make setup-fvm` command (renamed from previous `make setup`)
- Restructure `make setup` to run full setup (FVM + build dependencies)
- Add "Skip Build Hook Pattern" documentation to CLAUDE.md
- Add multi-platform testing: Linux x86_64, Linux ARM64, macOS ARM64, Windows x86_64
- Add reusable test workflow (`test-reusable.yml`) to eliminate code duplication between `test.yml` and `publish.yml`

### Changed

- Replace `softprops/action-gh-release` with official `gh` CLI in CI workflows
- Update GitHub Actions to latest versions:
  - `actions/create-github-app-token` v1 → v2
  - `peter-evans/create-pull-request` v7 → v8
  - `ilammy/msvc-dev-cmd` v1 → v1.13.0
- Tests now run in parallel on all 4 platforms
- Extract test logic into reusable workflow for better maintainability
- Update libsignal native library to v0.86.10 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.86.10))
- Simplify `check-libsignal-updates.yml` workflow:
  - Remove AI analysis (GitHub Models) - now only updates `native_version` in pubspec.yaml
  - Remove automatic FFI bindings regeneration (now manual step after merge)
  - Add clear instructions in PR body for manual steps after build completes
- Simplify `check_updates.dart` script:
  - Remove `--ai`, `--no-ai`, `--bump`, `--no-changelog` options
  - No longer updates package version or CHANGELOG.md automatically
- Remove `scripts/src/ai_analysis.dart` (no longer needed)
- Use GitHub App token instead of `GITHUB_TOKEN` in workflows:
  - `check-libsignal-updates.yml`: PR creation
  - `build-libsignal.yml`: release version checks
- Skip tests for bot PRs in `test.yml` (native libraries not yet built for version updates)
- Discard FVM config changes in CI to prevent unwanted `.fvmrc` and `.vscode/settings.json` modifications in PRs
- Extract Rust setup into reusable `.github/actions/setup-rust` action

### Fixed

- Fix duplicate "v" prefix in native library release notes (`vv0.86.10` → `v0.86.10`)
- Remove redundant "Usage" section from native library release description
- Fix ARM64 group messaging crash caused by `SignalUuid` 16-byte struct-by-value FFI limitation ([dart-lang/sdk#36730](https://github.com/dart-lang/sdk/issues/36730))
  - Pass `SignalUuid` as two `Int64` values matching ARM64 AAPCS64 register layout
  - Affects `signal_sender_key_distribution_message_create` and `signal_group_encrypt_message`
- Fix Windows native library build in CI (Git Bash cannot execute `.bat` files directly)
  - Create shell wrapper script for `fvm` in `setup-fvm` action
  - Wrapper script calls `fvm.bat` via `cmd //c` for compatibility with Git Bash
- Fix `make regen` CI failure when `cbindgen` is not pre-installed
- Fix `make regen` CI failure due to missing `protoc` (required by libsignal's spqr dependency)
- Add `protoc` to build prerequisites documentation (README.md, CLAUDE.md)

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
