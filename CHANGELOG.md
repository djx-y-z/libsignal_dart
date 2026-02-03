## [2.2.0] - 2026-02-03

### For Users

#### ✨ Highlights

- **libsignal v0.87.0** — latest upstream Signal Protocol library
- **libsignal_frb v1.0.2** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.87.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.87.0))
  - **Breaking change in upstream**: `PublicKey` ordered comparison (Ord trait) has been removed
  - New: `accountExists()` API exposed to client libraries
  - New: gRPC support for username hash lookup
  - Note: Our `PublicKey.compare()` method continues to work — now compares by serialized bytes
- Update `libsignal_frb` (Rust crate) to v1.0.2
  - Adapted `PublicKey.compare()` to use byte comparison after upstream Ord removal

#### Security

- Updated `bytes` dependency to v1.11.1 to fix integer overflow vulnerability ([RUSTSEC-2026-0007](https://rustsec.org/advisories/RUSTSEC-2026-0007))

### For Contributors

#### Added

- `make update` command to update `rust/Cargo.lock` via `cargo update`
- `make update-changelog` command to update CHANGELOG.md using GitHub Models AI
- AI-powered changelog generation script (`scripts/update_changelog.dart`)
  - Fetches libsignal release notes from GitHub API
  - Uses GitHub Models (gpt-4o-mini) to generate appropriate changelog entry
  - Includes real examples from project's CHANGELOG in AI prompt for consistent formatting
  - Automatically inserts entry in correct CHANGELOG.md location

#### Changed

- Fully automated libsignal update workflow (`check-libsignal-updates.yml`)
  - Now automatically runs `cargo update` to update Cargo.lock
  - Now automatically regenerates FRB bindings via `make codegen`
  - Now automatically updates CHANGELOG.md using AI (requires `AI_MODELS_TOKEN` secret with `models:read` permission)
  - All steps are non-blocking: PR is created even if some steps fail
  - PR description shows status of each step (success/failure)
  - Labels added for failed steps (`cargo-toml-failed`, `cargo-lock-failed`, `codegen-failed`, `changelog-needed`)
  - Added checklist items for `rust/Cargo.toml` version bump and `make rust-check`
- Updated `update_changelog.dart` script to generate two Highlights entries (libsignal + libsignal_frb)
- Updated Claude skill `.claude/skills/update-libsignal/SKILL.md` with "Review Automated PR" section

## [2.1.1] - 2026-01-30

### For Users

#### Changed

- Update libsignal native library to v0.86.16 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.86.16))
  - chat: Make gRPC failures directly convertible to RequestError
  - Make E164Info and AciInfo constructors public
  - Note: These changes do not affect this library's API

## [2.1.0] - 2026-01-29

### For Users

#### ✨ Highlights

- **libsignal v0.86.15** — latest upstream Signal Protocol library

#### Added

- `SecureBytes` class for wrapping sensitive byte data with automatic zeroing on disposal
- `SecureUint8List` extension with `zeroize()` method for manual zeroing of `Uint8List`

#### Changed

- Update libsignal native library to v0.86.15 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.86.15))
  - SVR2: Updated production enclave
  - SVRB: Added new production enclave to `current` set
  - New `accountExists()` typed API
  - Backup: Support for key transparency fields
  - Note: These changes are server-side infrastructure updates, no API changes affect this library

#### Security

- Rust-side zeroing of sensitive input bytes in all `deserialize()` methods (keys, prekeys, sessions)
- Added security documentation comments to methods returning sensitive data (serialize, agree, decrypt)
- Added zeroing best practices to SECURITY.md (Section J)
- Regenerated FRB bindings to include security documentation in Dart API

### For Contributors

#### Changed

- Remove unused `source_files` from iOS podspec
  - Native assets packages don't need CocoaPods to compile Swift code
  - Libraries are loaded via `hook/build.dart`, not CocoaPods
  - See [Flutter docs](https://docs.flutter.dev/platform-integration/bind-native-code)

#### Fixed

- Fix Windows CI: download `make` and `protoc` from GitHub Releases instead of Chocolatey (CDN unreliable)

## [2.0.0] - 2026-01-24

### For Users

#### ⚠️ Breaking Changes

- **Platform requirements**: Minimum iOS raised to 13.0, macOS to 10.15
- **Architecture**: Migrated from C FFI to Flutter Rust Bridge (FRB)
  - No more `dispose()` calls needed — memory managed automatically by Rust
  - Store operations now use DartFn callbacks for async Dart-to-Rust communication

- **API Changes**:
  - `ProtocolAddress('name', 1)` → `ProtocolAddress(name: 'name', deviceId: 1)`
  - `privateKey.serialize().bytes` → `privateKey.serialize()` (returns `Uint8List` directly)
  - `publicKey.verify(message, signature)` → `publicKey.verify(message: message, signature: signature)`
  - `Fingerprint.create(...)` → `Fingerprint(iterations: ..., version: ..., ...)`
  - `Aes256GcmSiv(key)` → `Aes256GcmSiv(key: key)`
  - `cipher.encrypt/decrypt` now requires `associatedData` parameter
  - `GroupSession` class replaced with callback-based functions

#### ✨ Highlights

- **Web platform support (WASM)** — run Signal Protocol in browsers
- **Flutter Rust Bridge architecture** — cleaner API, automatic memory management
- **libsignal v0.86.14** — latest upstream Signal Protocol library
- **Modern platform support** — iOS 13.0+, macOS 10.15+ (Catalina)

#### Security

- Add low-order point validation for public keys in `PreKeyBundle` and `Fingerprint`
  - Reject non-canonical Curve25519 points that could be used in small subgroup attacks

#### Added

- **Web platform support (WASM)** — first-class browser support via wasm-pack
- Native assets build hooks (`hook/build.dart`) for automatic library download
- Precompiled binaries via GitHub Releases — no Rust required for end users
- SHA256 checksum verification for precompiled binaries

#### Changed

- Update libsignal native library to v0.86.14 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.86.14))
  - MSRV bumped to Rust 1.88
- Improve error message for unexpected ciphertext message types (now shows actual type)

#### Removed

- `SecureBytes`, `SerializationValidator`, `LibSignalException` classes
- Manual Dart wrapper classes (replaced by FRB-generated code)

### For Contributors

#### Added

- `make rust-audit` — Rust dependency vulnerability scanning
- `make setup-rust-tools` — installs cargo-audit, flutter_rust_bridge_codegen
- `make setup-protoc` — cross-platform protoc installation
- `make setup-web` — installs wasm-pack for web builds
- `make setup-android` — installs cargo-ndk for Android builds
- Rust security audit job in CI (runs `cargo-audit` on every test run)
- Plaintext handling documentation in SECURITY.md
- CI workflow for building precompiled binaries (`build-libsignal-frb.yml`)

#### Changed

- Update `.claude/skills/` documentation for FRB architecture
- Restructure `make setup` to install all required tools

#### Removed

- Old C FFI code (`lib/src/bindings/`, `rust/src/ffi/`)
- Pre-built native libraries (`bin/`, `macos/Libraries/`, `ios/Libraries/`, etc.)
- `headers/signal_ffi.h`

## [1.1.2] - 2026-01-19

### Changed

- Update libsignal native library to v0.86.12 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.86.12))
  - H2 support for unauthenticated chat (new remote config option)
  - Updated libcrux-ml-kem and spqr dependencies

## [1.1.1] - 2026-01-13

### Added

- `.claude/skills/` folder now included in repository and published package

### Changed

- Update libsignal native library to v0.86.11 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.86.11))
  - Fixes TLS proxy connectivity issue with certain TLS certificates
- Update FFI bindings to match new libsignal API:
  - KyberPreKeyStore callbacks now include `destroy` callback
  - Callback function names updated to longer namespaced format
  - Parameter types updated (`SignalConstPointer*` to `SignalMutPointer*` where applicable)

## [1.1.0] - 2026-01-08

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
- Fix Windows native library build in CI
  - Create shell wrapper for `fvm` in `setup-fvm` action (Git Bash cannot execute `.bat` files)
  - Use PowerShell for build step to ensure MSVC `link.exe` is used instead of Git's `/usr/bin/link`
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

- Based on libsignal v0.86.11 from Signal Foundation
- Secret keys are handled securely with proper memory management
- Cryptographic operations use constant-time implementations where applicable

[Unreleased]: https://github.com/djx-y-z/libsignal_dart/compare/v2.2.0...HEAD
[2.2.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/djx-y-z/libsignal_dart/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v1.1.2...v2.0.0
[1.1.2]: https://github.com/djx-y-z/libsignal_dart/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/djx-y-z/libsignal_dart/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/djx-y-z/libsignal_dart/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/djx-y-z/libsignal_dart/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/djx-y-z/libsignal_dart/releases/tag/v1.0.0
