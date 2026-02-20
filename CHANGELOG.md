## [Unreleased]

### For Users

#### ✨ Highlights

- **libsignal v0.87.4** — updated BoringSSL and internal improvements
- **libsignal_frb v1.2.0** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.87.4 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.87.4))
  - Updated `boring` dependency to v5.0.1 (bundled BoringSSL update)
  - Added RemoteConfig for accountExists gRPC
  - keytrans: removed search-with-version fallback from `monitor_and_search`
  - Note: These changes do not affect this library's public API

## [2.4.0] - 2026-02-18

### For Users

#### ✨ Highlights

- **libsignal v0.87.2** — security hardening for Diffie-Hellman key agreements
- **libsignal_frb v1.1.0** — Rust FFI bindings

#### Security

- Update libsignal native library to v0.87.2 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.87.2))
  - Added validation of X25519 Diffie-Hellman shared secrets — rejects all-zero outputs per [RFC 7748 §6.1](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1), preventing potential use of predictable shared secrets from malicious low-order public keys
  - Enabled overflow checks for release builds
  - Updated BoringSSL to signalapp/boring v4.21.1
  - Note: No changes to this library's public API

### For Contributors

#### Changed

- Adopt copier template v2.3.2 → v2.4.0
  - Added Rust dependency caching (`Swatinem/rust-cache@v2`) in CI setup-rust action — dramatically speeds up Windows builds (~10 min OpenSSL compile cached)
  - Added Strawberry Perl configuration for Windows CI to fix OpenSSL build (MSYS2 Perl from Git Bash is incompatible)
  - Added `IPHONEOS_DEPLOYMENT_TARGET` env var for iOS CI builds — fixes linker errors when vendored C code is compiled with newer Xcode
  - Added `make check-targets` command and `scripts/check_deployment_targets.dart` for checking deployment target consistency (iOS/macOS/Android) across all project files
  - Added "Setting up Coverage Badge" and "Setting up pub.dev Publishing" sections to CONTRIBUTING.md
  - Replaced `dart run scripts/` with `dart scripts/` in Makefile commands, removing `.skip_libsignal_hook` workaround (scripts only use `dart:` imports, so `dart run` build hooks are unnecessary)
  - Fixed WASM build hook: local builds now take priority over cached/downloaded files, avoiding stale content hash mismatches

## [2.3.1] - 2026-02-11

### For Users

#### Changed

- Remove `flutter` SDK constraint from `environment` — pub.dev now displays both Dart and Flutter SDK badges ([#14](https://github.com/djx-y-z/libsignal_dart/pull/14), thanks [@ahnaineh](https://github.com/ahnaineh))

### For Contributors

#### Changed

- Adopt copier template v2.2.0 → v2.3.2
  - Publishing checklist now uses annotated tags (`git tag -a`) instead of lightweight tags
  - Added `git push origin main` step before pushing tag in publishing checklist
  - Replaced "Claude Commands" section with "Claude Skills" section in CLAUDE.md
  - Removed redundant `prepare-release` and `update-template` Claude commands (functionality covered by Claude skills)
  - Updated platform support table in README: SDK 24+, iOS 13.0+, macOS 10.15+, WASM label
  - Improved `frb-patterns` Claude skill with additional patterns:
    - Added anti-pattern example to Constructor-Style API Pattern section
    - Added Transparent Struct Pattern section
    - Added Bridging Sync Traits to Async Callbacks section with `block_on` example
    - Added Adapter Pattern documentation for bridging DartFn callbacks to upstream traits
    - Added `block_on` panics troubleshooting entry
    - Added "When to regenerate" checklist to Regenerating Bindings section
    - Added No Threading on WASM warning

#### Fixed

- Restore 100% test coverage by adding `coverage:ignore` markers to untestable platform-specific code in `platform_io.dart`
  - AOT mode library loading path (unreachable during `dart test` which runs in JIT mode)
  - `openLibraryFromPath()` function (only called with custom `libraryPath`, already ignored at call site)

## [2.3.0] - 2026-02-07

### For Users

#### ✨ Highlights

- **libsignal v0.87.1** — latest upstream native library
- **libsignal_frb v1.0.3** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.87.1 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.87.1))
  - `CallLinkRootKey` now allows variable sizing; call link epochs removed from backup
  - Test infrastructure improvements (reusable session fuzz test support)
  - Note: These changes do not affect this library's API
- Update `libsignal_frb` (Rust crate) to v1.0.3

#### Security

- Updated `bytes` dependency to v1.11.1 to address [RUSTSEC-2026-0009](https://rustsec.org/advisories/RUSTSEC-2026-0009)

### For Contributors

#### Changed

- Adopt copier template (`copier-dart-frb-wrapper`) v2.0.1 for project structure
  - Standardized scripts naming: `check_new_upstream_version.dart`, `check_exists_frb_release.dart`
  - Unified common utilities in `scripts/src/common.dart`
  - Renamed workflow: `build-libsignal-frb.yml` → `build-libsignal.yml`
  - Configurable `version_tag_prefix` for upstream version tag handling
  - Improved version normalization in `check_updates.dart` — supports configurable tag prefix instead of hardcoded `v` stripping
- Renamed `make update` → `make rust-update` to avoid ambiguity
- Refactored build hook (`hook/build.dart`)
  - Added SHA256 checksum verification for WASM downloads (supply chain security)
  - Smarter app root detection: verifies pubspec depends on this package before copying WASM files
  - WASM file caching with shared output directory (avoids redundant downloads)
  - Incremental file copy: only copies if source is newer than destination
  - Added `_crateName` constant to eliminate hardcoded `libsignal_frb` strings
  - Added `rust/Cargo.toml` as dependency for cache invalidation on local builds
  - Improved error messages with actionable guidance throughout
- Replaced copier template placeholders with dynamic values from helper scripts
  - `{{ android_min_sdk }}` → reads from `android/build.gradle` at build time
  - `{{ crate_name }}` → uses `_crateName` constant
  - `fvm install` → `fvm use` with version from `.fvmrc`
- Updated example app platform configs to use template-standard naming
  - Renamed `libsignal_example` → `example` in web, Windows, macOS, Linux, iOS configs
- Renamed Claude skill `ffi-patterns` → `frb-patterns` to match current FRB architecture
- Improved CI workflows with better step status tracking
  - Each step now reports `success=true/false` for clearer PR status
  - PR body shows inline status for each updated file
- Removed unused `GITHUB_TOKEN` from `check_updates.dart` (not needed for public GitHub API)
- Fully automated libsignal update workflow (`check-libsignal-updates.yml`)
  - Now automatically runs `cargo update` to update Cargo.lock
  - Now automatically regenerates FRB bindings via `make codegen`
  - Now automatically updates CHANGELOG.md using AI (requires `AI_MODELS_TOKEN` secret with `models:read` permission)
  - All steps are non-blocking: PR is created even if some steps fail
  - PR description shows status of each step (success/failure)
  - Labels added for failed steps (`cargo-toml-failed`, `cargo-lock-failed`, `codegen-failed`, `changelog-needed`)

#### Fixed

- Fix `workflow_run` trigger in `test.yml` — referenced wrong workflow name (`"Build libsignal Native Libraries"` → `"Build libsignal FRB Libraries"`), causing tests to never auto-trigger after build completion
- Fix env var name in `build-libsignal.yml` check-release step (`GH_TOKEN` → `GITHUB_TOKEN`) — Dart script reads `GITHUB_TOKEN`, not `GH_TOKEN`
- Fix outdated script filenames in `scripts/README.md` (`check_new_libsignal_version.dart` → `check_new_upstream_version.dart`, `check_exists_libsignal_frb_release.dart` → `check_exists_frb_release.dart`)
- Fix incorrect env var reference in `CLAUDE.md` inline comment (`GITHUB_TOKEN` → `AI_MODELS_TOKEN`)
- Upgrade `flutter_lints` in example app from `^5.0.0` to `^6.0.0`
- Fix `.pubignore` — include Rust source files in published package (only exclude `rust/target/` build artifacts, not entire `rust/` directory); add trailing newline

#### Removed

- Removed legacy scripts with project-specific naming
  - `scripts/check_new_libsignal_version.dart` → `scripts/check_new_upstream_version.dart`
  - `scripts/check_exists_libsignal_frb_release.dart` → `scripts/check_exists_frb_release.dart`
  - `scripts/src/check_new_libsignal_version.dart` → `scripts/src/check_updates.dart`
- Removed unused `scripts/combine_artifacts.dart`

#### Added

- `make check-template-updates` command to check for new copier template versions
- `check-template-updates.yml` workflow — daily CI check for template updates with automated notification PR
- `update-template` Claude skill — step-by-step guide for applying template updates
  - Documents `--defaults` flag for non-interactive `copier update` (required for Claude Code)
  - Documents manual `_commit` update in `.copier-answers.yml` when copier fails to update it (conflicts or no file changes)
- `make rust-update` command to update `rust/Cargo.lock` via `cargo update`
- `make update-changelog` command to update CHANGELOG.md using GitHub Models AI
- AI-powered changelog generation script (`scripts/update_changelog.dart`)
  - Fetches libsignal release notes from GitHub API
  - Uses GitHub Models (gpt-4o-mini) to generate appropriate changelog entry
  - Includes real examples from project's CHANGELOG in AI prompt for consistent formatting
  - Automatically inserts entry in correct CHANGELOG.md location
- Helper scripts for dynamic build configuration
  - `scripts/get_android_min_sdk.dart` — reads `minSdk` from `android/build.gradle`
  - `scripts/get_flutter_version.dart` — reads Flutter version from `.fvmrc`
- Analyzer exclusions for `hook/**`, `scripts/**`, `example/**`, `example_cli/**` (separate packages, not part of main analysis)

## [2.2.1] - 2026-02-03

### For Users

#### Fixed

- Fix native library loading for pure Dart CLI applications
  - **JIT mode** (`dart run`): loads from `.dart_tool/lib/`
  - **AOT mode** (`dart build cli`): loads from `bundle/lib/` relative to executable
  - Enables standalone executables to be distributed and run from any location

#### Security

- Remove CWD-based library search to prevent library hijacking attacks
  - Previously searched `rust/target/release/` in current working directory
  - Attacker could place malicious library in CWD to hijack application
  - Now only searches trusted paths: build hook locations and executable-relative paths

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

#### Fixed

- Fix native library loading for pure Dart CLI applications using `dart run`
  - `DynamicLibrary.open()` doesn't resolve native asset IDs in JIT mode
  - Now reads `.dart_tool/native_assets.yaml` to get the actual library path
  - Enables `example_cli` and other CLI apps to work with published package

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

[Unreleased]: https://github.com/djx-y-z/libsignal_dart/compare/v2.4.0...HEAD
[2.4.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.3.1...v2.4.0
[2.3.1]: https://github.com/djx-y-z/libsignal_dart/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/djx-y-z/libsignal_dart/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/djx-y-z/libsignal_dart/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v1.1.2...v2.0.0
[1.1.2]: https://github.com/djx-y-z/libsignal_dart/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/djx-y-z/libsignal_dart/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/djx-y-z/libsignal_dart/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/djx-y-z/libsignal_dart/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/djx-y-z/libsignal_dart/releases/tag/v1.0.0
