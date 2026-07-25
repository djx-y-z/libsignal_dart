## [6.1.1] - 2026-07-25

### For Users

#### ✨ Highlights

- **libsignal v0.99.1** — internal/dependency update, no public-API impact
- **libsignal_frb v5.1.2** — Rust FFI bindings

#### Changed

- **libsignal native library → v0.99.1** ([compare](https://github.com/signalapp/libsignal/compare/v0.97.4...v0.99.1))
  - Upstream user-facing changes target the chat/backup/registration services and logging — none of which this library exposes
  - The crates we bind (`libsignal-protocol`, `signal-crypto`, `libsignal-core`) saw internal refactors to track the updated RustCrypto / curve25519-dalek / spqr dependencies, with no change to behaviour or the FFI surface (FRB bindings regenerate byte-for-byte identical)

#### Security

- **Upstream libcrux advisories resolved** — v0.99.1 pulls in `libcrux-sha3` 0.0.10 and `libcrux-secrets` 0.0.6, which fix RUSTSEC-2026-0207, RUSTSEC-2026-0208 (incremental/AVX2 SHAKE) and RUSTSEC-2026-0212 (aarch64 const-time swap). The interim `cargo-audit` / `cargo-deny` suppressions for these three have been removed

## [6.1.0] - 2026-07-21

### For Users

#### ✨ Highlights

- **Build provenance attestation (Sigstore, SLSA Build L2)** — every native-release archive is now cryptographically attested to this repository's tag-triggered build, closing the previously documented authenticity gap (verify with `gh attestation verify`)
- **Web: stale-WASM-after-upgrade fixed** — the web build hook now refreshes `web/pkg/` on a version change instead of serving the previous version's WASM, which could crash Dart-store-callback paths (`processPreKeyBundle`, `SessionCipher`, sealed sender, group messaging) after an upgrade
- **Smaller package & explicit minimum OS versions** — the vestigial platform-plugin scaffolding is removed (smaller published archive) and the prebuilt binaries are now built against the documented macOS 10.15 / Android API 24 minimums
- **libsignal v0.97.4** — internal/dependency update, no public-API impact
- **libsignal_frb v5.1.1** — Rust FFI bindings

#### Changed

- **Platform-plugin scaffolding removed from the published package** — the vestigial `ios/`, `macos/`, `android/`, `linux/`, `windows/` directories (podspecs, Gradle project, CMakeLists, plugin stubs) are gone. The package has never declared a `flutter: plugin:` section, so flutter_tools never consumed them; native delivery is (and remains) via the `hook/build.dart` build hook. No consumer action required — the published archive just gets smaller
- **Explicit minimum OS versions for the prebuilt binaries** — CI now builds the macOS dylibs with `MACOSX_DEPLOYMENT_TARGET: '10.15'` (previously rustc's per-target default, 10.12 for x86_64) and links the Android `.so`s against API level 24 via cargo-ndk `--platform 24` (previously cargo-ndk's default, 21), matching the documented platform-support table
- **libsignal v0.97.4 update** — bump the bound native library ([compare](https://github.com/signalapp/libsignal/compare/v0.97.3...v0.97.4))
  - Upstream changes are limited to `AuthAccountsService` (registration-lock set/clear, discoverable-by-phone-number, registration-recovery-password), `UnauthBackupsService.copyMedia`/`copyBackupMedia`, SVR2 node APIs, and language-binding / bridge tooling (node/java/swift/ts) — none of which this library exposes
  - The only change to the crates we bind (`libsignal-protocol`, `signal-crypto`, `libsignal-core`) is the `libsignal-core` version string (`rust/core/src/version.rs`); `make codegen` produces no binding diff
  - Note: These changes do not affect this library's public API
- **libsignal v0.97.3 update** — bump the bound native library ([compare](https://github.com/signalapp/libsignal/compare/v0.97.2...v0.97.3))
  - Upstream changes are limited to `AuthUsernamesService.deleteUsernameHash()`/`deleteUsernameLink()` (username services), reclassifying an established chat connection's transport errors as retryable (`.ioError`, Swift binding), and increasing the key-transparency clock-skew tolerance interval — none of which this library exposes
  - The crates we bind (`libsignal-protocol`, `signal-crypto`, `libsignal-core`) are unchanged apart from version strings; `make codegen` produces no binding diff
  - Note: These changes do not affect this library's public API

#### Security

- **Build provenance attestation (Sigstore, SLSA Build L2)** — every native-release archive is now attested with GitHub Artifact Attestations: CI signs a provenance statement proving the archive was built by this repository's tag-triggered `build-libsignal.yml` from a specific commit, closing the previously documented authenticity gap (the SHA256 checksums file ships in the same release as the archives). Verify with `gh attestation verify <archive> --repo djx-y-z/libsignal_dart`; a Sigstore bundle (`libsignal_frb-<version>.sigstore.jsonl`) is attached to each release for fully offline verification. See SECURITY.md → Authenticity (the build hook itself still verifies SHA256 only — attestation verification is manual)

#### Fixed

- **Stale web WASM after a package upgrade** — the web build hook (`hook/build.dart`) now records the provisioned crate version in `web/pkg/.wasm-version` and re-downloads when it changes, instead of skipping whenever the two WASM files merely exist. Previously, upgrading the package kept the prior version's WASM in the consuming app's `web/pkg/` (it survives `flutter clean`), so on web any FRB entry that calls Dart store callbacks — `SessionBuilder.processPreKeyBundle`, `SessionCipher`, `SealedSenderCipher`, group messaging — panicked with an argument-count mismatch (`called Option::unwrap() on a None value`) once the wire signature had changed between versions. The download cache is now version-keyed and `rust/Cargo.toml` is a declared web-build dependency, both mirroring the native path (which was unaffected)
- **Build hook download/cache resilience** — the hook (`hook/build.dart`) is more robust against partial/transient failures: a download-cache entry is only reused after a `.download-complete` marker proves the extraction finished (an interrupted `tar` no longer leaves a truncated library that is reused forever), a locally built `rust/target/` library is used only when it matches the target OS **and** architecture (previously a host build could be bundled for a cross-target, e.g. a macOS dylib into an iOS app), the web path no longer fetches checksums when a warm cache can serve the files offline, and both the checksums fetch and the binary download now retry on transient HTTP 5xx/429 instead of failing the build on a single blip

### For Contributors

#### Added

- **`make release-frb` + `release-frb-crate` skill** — one-command native-crate release (stage 1): bumps `rust/Cargo.toml`, stamps the CHANGELOG `libsignal_frb` Highlights line, and creates a signed commit + `libsignal_frb-<version>` tag, pushing to trigger the native build. The commit/tag/push inherit the terminal, so the signing passphrase is entered interactively during the command. Pairs with `release-package` (stage 2)
- **`make release` + updated `release-package` skill** — one-command Dart package release (stage 2) symmetric to `make release-frb`: verifies the stage-1 native binary exists on GitHub Releases, bumps `pubspec.yaml`, finalizes the CHANGELOG (`[Unreleased]` → dated version + a fresh `[Unreleased]` + the bottom compare-link refs), validates with a publish dry-run, then signs a commit + `vX.Y.Z` tag and pushes to trigger the pub.dev publish. The two release commands share git/terminal helpers in `scripts/src/release_common.dart`
- **Repository-protection tooling** — the branch and release-tag rulesets now live in-repo as committed JSON (`.github/rulesets/*.json`, the source of truth), and `make setup-repo-protections` applies them to GitHub via `gh` (idempotent by ruleset name) and configures the `native-build` environment. A new **Protect release tags** ruleset restricts tag creation (all tags) to Admins/Maintainers — covering the release-triggering `libsignal_frb-*` / `v*` and any other — and the native-crate publish (`build-libsignal.yml`) now runs in the required-reviewer `native-build` environment — gating tag-push and `workflow_dispatch` alike, mirroring the `pub.dev` environment that gates pub.dev publishing
- **Dependabot for GitHub Actions** — `.github/dependabot.yml`: weekly grouped update PRs (Monday 06:00 UTC, `chore(deps)` prefix) bump the pinned actions — both the commit SHA and its `# vX.Y.Z` comment — across the workflows and the composite actions (a `directories` glob covers `/.github/actions/*`, since `/` only scans `.github/workflows/`). `dtolnay/rust-toolchain` is ignored: it has no versioned releases (master-SHA pin, toolchain selected via input) and stays manually bumped

#### Changed

- **Accept unremediable upstream libcrux crypto advisories in cargo-deny / cargo-audit** — three RustSec advisories published 2026-07-17 (`RUSTSEC-2026-0207` / `-0208`, incorrect / panicking SHAKE in `libcrux-sha3` 0.0.8; `RUSTSEC-2026-0212`, incorrect aarch64 constant-time swap in `libcrux-secrets` 0.0.5) live in libsignal's git-pinned ML-KEM stack and are not fixable from this repo — the fix requires a libsignal release that bumps `libcrux-ml-kem` (v0.97.4 still ships the old libcrux). Added to `rust/deny.toml` `[advisories].ignore` and the `rust-audit` `--ignore` flags as a tracked interim suppression so the `cargo-deny` / `cargo-audit` CI jobs pass — to be removed once a fixed libsignal release lands
- **Decoupled the `libsignal_frb` native release from libsignal dependency updates** — automated update PRs no longer bump the crate version or build binaries; dependency updates accumulate on `main` (tested from source in CI), and the native build is now triggered by pushing a `libsignal_frb-<version>` tag instead of by pushing to `main`. The crate-version bump is now a deliberate release decision (`make release-frb`). See CLAUDE.md → Release Flow
- **AI changelog generator classifies upstream changes against the bound-crate surface** — the prompt now states which crates/APIs this wrapper actually binds, so out-of-scope upstream changes (net / chat / keytrans / username services / zkgroup / …) are framed as "none of which this library exposes", and it links to a version `compare` instead of the (often incomplete) release notes
- **CI enforces deployment-target consistency** — `test-reusable.yml` now runs `make check-targets` (Linux leg) so the build fails if the iOS / macOS / Android minimum deployment targets drift out of sync across the CI build env vars, the example Xcode projects and the README platform table. Previously the check existed (`make check-targets`) but was never run automatically
- **Deployment-target sources consolidated** — `.copier-answers.yml` remains the single source of truth; with the platform scaffolding removed, `make check-targets` and `scripts/get_android_min_sdk.dart` no longer read the podspecs/`build.gradle` but verify the CI workflow (`IPHONEOS_DEPLOYMENT_TARGET`, `MACOSX_DEPLOYMENT_TARGET`, cargo-ndk `--platform`) instead
- **Upstream tag names validated before reaching the shell** — `check_updates.dart` / `check_template_updates.dart` reject a release `tag_name` that is not a plain semver-ish tag before it lands in `GITHUB_OUTPUT`, and the update workflows pass step outputs/inputs into `run:` blocks via `env:` instead of inline `${{ }}` interpolation — closing a shell-injection path from upstream release names (backport of the liboqs audit)
- **Least-privilege `GITHUB_TOKEN` everywhere** — `publish.yml` and `build-libsignal.yml` now default to `contents: read` with job-level opt-ups (`id-token: write` on the pub.dev publish job, `contents: write` on the release jobs); the two update-checker workflows drop `contents/pull-requests: write` entirely (all writes go through the App token)
- **Third-party actions pinned to commit SHAs** — `dart-lang/setup-dart`, `peter-evans/create-pull-request`, `android-actions/setup-android`, `ilammy/msvc-dev-cmd`, `schneegans/dynamic-badges-action`, `Swatinem/rust-cache`, `dtolnay/rust-toolchain` (toolchain now passed via the `toolchain` input since the ref no longer selects it)
- **`setup-make` verifies gnumake.exe by SHA256** — release assets are mutable, so the size check alone did not lock the Windows make binary; a hardcoded SHA256 (updated together with the version) now does
- **Pre-release hardening pass (audit fixes)** — a review of this cycle's changes fixed, among others: `make release-frb` now syncs and stages `rust/Cargo.lock` alongside `rust/Cargo.toml` (the pre-commit `cargo check` no longer leaves a dirty tree that blocked stage 2, and the signed tag no longer carries a stale lock); `Swatinem/rust-cache` is repinned from the floating `v2` tag object to the real `v2.9.1` commit (would have broken every Rust job when upstream re-tagged `v2`); the pub.dev release notes are written via `--notes-file` instead of an inline heredoc (a literal `EOF` line in the changelog can no longer break out into the shell); `build-libsignal.yml` no longer delete-then-recreates a release (fail-loud, no silent clobber) and the release-existence probe fails closed on API errors; the `fuzz.yml` dispatch `duration` input is validated and passed via `env:`; `make check-targets` fails closed when a checked file/pattern disappears; and `--date` in `make release` is validated. Docs corrected across README/CLAUDE/CONTRIBUTING/SECURITY/rulesets (build-hook fallback, `AI_MODELS_TOKEN`, two-stage publishing, `.skip_*_hook` semantics, stale Cargokit/loading-order references)
- **Adopt copier template v3.0.0** — most of this template release (the two-stage release flow, repository rulesets, Dependabot, and the CI deployment-target check) was already backported into this repo, so the update reduced to a documentation and tooling sync: `CONTRIBUTING.md` gains the "Releasing (two stages)" and "Repository rulesets & tag protection" sections, and the `Makefile` `.PHONY` list is reordered to match the template (no behavior change)

## [6.0.0] - 2026-07-14

### For Users

#### ✨ Highlights

- **Identity-trust enforcement (breaking)** — a remote identity key that differs from the stored one is now rejected with `UntrustedIdentity` on every session operation (MITM / safety-number-change detection), instead of being silently accepted
- **Hardened supply chain & binary** — the native-binary download is now fail-closed (aborts if it can't be verified), and the wrapper crate is built with integer-overflow checks
- **App store additional permission** — the license now allows AGPL-compliant apps to ship through app stores with AGPL-incompatible terms (e.g. the Apple App Store); see `LICENSE.appstore`
- **libsignal v0.97.2** — internal/dependency update, no public-API impact
- **libsignal_frb v5.0.0 (internal Rust FFI crate)** — breaking (major): adds a required `get_identity` callback

#### Changed (Breaking)

- **Identity-trust is now enforced on every session operation**, matching upstream libsignal's `is_trusted_identity` semantics. `SessionBuilder.processPreKeyBundle`, `SessionCipher.encrypt`/`decrypt` (both pre-key and regular Whisper messages), and `SealedSenderCipher.encrypt`/`decrypt` now consult your `IdentityKeyStore.getIdentity` and reject a remote identity key that differs from the stored one with an `UntrustedIdentity` error. Previously a substituted identity (e.g. from a malicious key-distribution server) was accepted without error. First contact is still trusted-on-first-use.
  - **Action required:** catch `UntrustedIdentity` (its message contains `untrusted identity`) and treat it as a safety-number change — verify with the user, then save the new identity (or clear the old one) in your store and archive the old session for that address before retrying. Requires your `IdentityKeyStore.getIdentity` to be implemented correctly.

#### Changed

- Update libsignal native library to v0.97.2 ([compare](https://github.com/signalapp/libsignal/compare/v0.96.4...v0.97.2))
  - Upstream changes between v0.96.4 and v0.97.2 are limited to net/registration, chat/backups gRPC, bridge/codegen tooling, and CI / language-binding (node/swift/java) updates — none of which this library exposes
  - The only diffs in the crates we bind are cosmetic: a test-only import in `kem.rs`, an internal `TryFrom` refactor in `state/bundle.rs` (`and_then(…map…)` → `.zip(…)`, behavior identical), and the `libsignal-core` version string
  - Note: These changes do not affect this library's public API
- **App store additional permission (AGPL §7)** — the package license now carries an explicit app-store exception (the Feeel/wger wording, see `LICENSE.appstore`): GPL/AGPL-compliant applications may distribute this package in object-code form through app stores whose terms are incompatible with the AGPL (such as the Apple App Store), provided their source stays available under the AGPL through an unrestricted channel. The permission covers only this repository's code; the status of an equivalent permission for the bundled upstream `libsignal` is tracked in [signalapp/libsignal#684](https://github.com/signalapp/libsignal/issues/684). Requested in [#44](https://github.com/djx-y-z/libsignal_dart/issues/44)

#### Security

- **Fail-closed native library verification** — the build hook (`hook/build.dart`) now aborts the build if the SHA256 checksums for a downloaded binary cannot be fetched or the archive has no entry, instead of silently proceeding unverified. An escape hatch (`LIBSIGNAL_ALLOW_UNVERIFIED_DOWNLOAD=1`) remains for releases with no checksums file
- **Hardened crate build** — the wrapper's release profile enables `overflow-checks`, so an integer overflow in the wrapper is a deterministic (catchable) panic rather than silent wraparound (the audited crypto dependencies are left untouched)
- **Secret-lifetime & zeroing caveats documented** — `SECURITY.md` now spells out that opaque secret handles (`PrivateKey`, `KyberSecretKey`, `SessionRecord`, …) stay resident in native memory until a non-deterministic GC finalizer runs, so security-critical code should call `dispose()` to bound that window (noting the extractable key types are `Copy`/plain-boxed and thus not zeroized on drop — `dispose()` shortens the exposure window, it does not wipe), and that Rust's `zeroize` covers Rust memory only: secret bytes that cross the FFI boundary into a Dart `Uint8List` live on the un-zeroed GC heap where `SecureBytes`/`zeroize()` are best-effort. `PrivateKey.cloneKey()` / `KyberSecretKey.cloneKey()` now carry a `# Security` doc note that each copy is an independent secret

#### Fixed

- **Device ID truncation** — the `ProtocolAddress` and `PreKeyBundle` constructors no longer truncate the `u32` device ID to `u8` before validating (e.g. `257` is no longer accepted as device `1`); out-of-range IDs are rejected as documented (1–127)
- **HKDF output bound** — `hkdfDerive` now rejects an output length above the RFC 5869 maximum (`255 × 32 = 8160` bytes) before allocating, instead of attempting an oversized allocation
- **In-memory identity-store equality** — `InMemoryIdentityKeyStore` now compares identity keys by value (`equals()`) rather than by object reference, so a re-presented key is correctly seen as unchanged (matters for production stores copied from this reference implementation)
- **Native-library download cache key** — the build hook (`hook/build.dart`) now keys its download cache by crate version and the full platform variant (e.g. `ios-device-arm64` vs `ios-simulator-arm64`) rather than only OS + architecture. On Apple-silicon hosts iOS device and simulator builds shared a key, so whichever built first poisoned the cache for the other and `dyld` rejected the bundled library at runtime (`incompatible platform: have 'iOS-simulator', need 'iOS'`); a version bump could also serve a stale cached binary

### For Contributors

#### Added

- **Fuzzing harness** — `cargo-fuzz` targets (`rust/fuzz/`) covering every byte-parsing entry point (keys, messages, records, sealed-sender certificates, crypto primitives, pre-key decryption), a seed-corpus generator, and a `Fuzz` CI workflow (per-PR smoke run + weekly deep run). See `make fuzz-list` / `make fuzz`
- **Dependency policy** — `cargo-deny` (`rust/deny.toml`, `make rust-deny`, CI `deny` job) enforcing RustSec advisories, an AGPL-compatible license allow-list, and a source allow-list restricted to crates.io and the official Signal repositories
- **Rust linting (Clippy)** — `cargo clippy --all-targets -- -D warnings` now runs in CI (the reusable test workflow, on the Linux x86_64 leg) and locally via `make rust-clippy`; the hand-written wrapper is lint-clean, with the FRB-inherent lints (many-callback store signatures, complex tuple returns) annotated with justified site-local `#[allow]`s

#### Changed

- **CI least-privilege** — the reusable test workflow now declares `permissions: contents: read`
- **Rust lint** — hand-written Rust is compiled with `unsafe_code = "deny"` (only the FRB-generated bridge is exempt)
- **Copier template adopted (v2.5.1)** — `flutter_rust_bridge_codegen` is now pinned via `make setup-frb-codegen` (kept in sync with the `flutter_rust_bridge` dependency, `2.12.0`); the libsignal-update workflow installs the codegen binary (fixing a codegen step that failed with exit 127) and skips regenerating an update PR that already exists; `check_updates.dart` bumps the wrapper crate version mirroring the upstream SemVer delta, `update_changelog.dart` classifies update severity via AI, and the `update-libsignal` skill now analyzes the full upstream diff

## [5.0.9] - 2026-06-27

### For Users

#### ✨ Highlights

- **libsignal v0.96.4** — internal improvements and updates
- **libsignal_frb v4.0.9** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.96.4 ([compare](https://github.com/signalapp/libsignal/compare/v0.96.3...v0.96.4))
  - Upstream changes are limited to net/registration and chat gRPC helpers, server-side SVR enclave rotation (2026Q2), FFI bridge tooling, and new typed `reserveUsernameHash()` / donation-permit client APIs — none of which this library exposes
  - The `libsignal-protocol` and `signal-crypto` crates are unchanged; `libsignal-core` only bumps its internal version string
  - Note: These changes do not affect this library's public API

## [5.0.8] - 2026-06-24

### For Users

#### ✨ Highlights

- **libsignal v0.96.3** — internal improvements and updates
- **libsignal_frb v4.0.8** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.96.3 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.96.3))
  - Upstream changes are limited to an internal ML-KEM parameter key type fix plus net/node/gRPC/server-side updates, none of which this library exposes
  - Note: These changes do not affect this library's public API

## [5.0.7] - 2026-06-20

### For Users

#### ✨ Highlights

- **libsignal v0.96.2** — internal improvements and updates
- **libsignal_frb v4.0.7** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.96.2 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.96.2))
  - Upstream changes are limited to zkgroup donation credentials (`DonationPermit`), which this library does not expose
  - Note: These changes do not affect this library's public API

## [5.0.6] - 2026-06-19

### For Users

#### ✨ Highlights

- **libsignal v0.96.1** — internal improvements and updates
- **libsignal_frb v4.0.6** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.96.1 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.96.1))
  - Internal improvements and updates
  - Note: These changes do not affect this library's public API

## [5.0.5] - 2026-06-12

### For Users

#### ✨ Highlights

- **libsignal v0.96.0** — internal improvements and updates
- **libsignal_frb v4.0.5** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.96.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.96.0))
  - Internal improvements and updates
  - Note: These changes do not affect this library's public API

## [5.0.4] - 2026-06-10

### For Users

#### ✨ Highlights

- **libsignal v0.95.0** — internal improvements and updates
- **libsignal_frb v4.0.4** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.95.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.95.0))
  - Internal improvements and updates
  - Note: These changes do not affect this library's public API

## [5.0.3] - 2026-06-04

### For Users

#### ✨ Highlights

- **libsignal v0.94.4** — internal improvements and updates
- **libsignal_frb v4.0.3** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.94.4 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.94.4))
  - Internal improvements and updates
  - Note: These changes do not affect this library's public API

## [5.0.2] - 2026-05-31

### For Users

#### ✨ Highlights

- **libsignal v0.94.3** — internal improvements and updates
- **libsignal_frb v4.0.2** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.94.3 ([compare](https://github.com/signalapp/libsignal/compare/v0.94.1...v0.94.3))
  - Binding/tooling improvements (JNI, Node, Swift type converters), backup validator and reflector routing updates
  - Note: No changes to the libsignal-protocol crate — does not affect this library's public API

#### Documentation

- Document `flutter build web --wasm` (dart2wasm) limitation in README — Rust returns fail with `Type 'JSValue' is not a subtype of type 'List<dynamic>'` under dart2wasm. Upstream limitation in `flutter_rust_bridge` ([#2575](https://github.com/fzyzcjy/flutter_rust_bridge/issues/2575)), affects every FRB-based Dart package. Standard `flutter build web` (dart2js) target continues to work.

## [5.0.1] - 2026-05-19

### For Users

#### ✨ Highlights

- **libsignal v0.94.1** — internal improvements and updates
- **libsignal_frb v4.0.1** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.94.1 ([compare](https://github.com/signalapp/libsignal/compare/v0.94.0...v0.94.1))
  - Networking improvements: gRPC/H2 transport additions, reflector proxy support
  - Key Transparency: added account data reset, additional logging around monitor versions
  - Note: No changes to libsignal-protocol crate — does not affect this library's public API

## [5.0.0] - 2026-05-12

### For Users

#### ✨ Highlights

- **libsignal v0.94.0** — extends sender/recipient address binding to `SignalMessage.verifyMac()`
- **libsignal_frb v4.0.0** — Rust FFI bindings updated with new sender/recipient address parameters on `verifyMac` (breaking)

#### Changed

- Update libsignal native library to v0.94.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.94.0))
  - **Breaking:** `SignalMessage.verifyMac()` now requires `senderAddressName`, `senderAddressDeviceId`, `recipientAddressName`, and `recipientAddressDeviceId` parameters
  - Upstream made the previous `SignalMessage::verify_mac` method private and exposed `verify_mac_with_addresses` as the public replacement, extending the misdirection protection (started in v0.91.0) to message MAC verification

## [4.0.1] - 2026-05-06

### For Users

#### ✨ Highlights

- **libsignal v0.93.2** — internal improvements and updates
- **libsignal_frb v3.0.1** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.93.2 ([compare](https://github.com/signalapp/libsignal/compare/v0.93.1...v0.93.2))
  - Networking improvements: H2 GOAWAY (graceful shutdown) handling for WebSockets
  - Updated `hickory-proto` DNS dependency to 0.26.1
  - Updated CDSI production enclave and added new SVR enclaves (server-side)
  - Note: No changes to libsignal-protocol crate — does not affect this library's public API

## [4.0.0] - 2026-05-01

### For Users

#### ✨ Highlights

- **libsignal v0.93.1** — extends sender/recipient address binding to remaining session APIs
- **libsignal_frb v3.0.0** — Rust FFI bindings updated with new `localAddress` parameter (breaking)

#### Changed

- Update libsignal native library to v0.93.1 ([v0.93.0](https://github.com/signalapp/libsignal/releases/tag/v0.93.0), [v0.93.1](https://github.com/signalapp/libsignal/releases/tag/v0.93.1))
  - **Breaking:** `SessionBuilder` constructor now requires `localAddress` parameter
  - **Breaking:** `processPrekeyBundleWithCallbacks` now requires `localName` and `localDeviceId` parameters
  - **Breaking:** `messageDecryptSignalWithCallbacks` now requires `localName` and `localDeviceId` parameters
  - `process_prekey_bundle` and `message_decrypt_signal` now bind sender/recipient addresses, completing the misdirection protection introduced in v0.91.0

## [3.0.3] - 2026-04-20

### For Users

#### ✨ Highlights

- **libsignal v0.92.2** — internal refactors and dependency updates
- **libsignal_frb v2.0.2** — Rust FFI bindings (libsignal upstream bump)

#### Changed

- Update libsignal native library to v0.92.2 ([compare](https://github.com/signalapp/libsignal/compare/v0.92.1...v0.92.2))
  - Internal refactor of 1:1 messaging code
  - Key Transparency (keytrans) improvements: persist latest distinguished tree head, validate search responses
  - Upgraded `rand` crate and `rustls-webpki`
  - Note: These changes do not affect this library's public API

## [3.0.2] - 2026-04-12

### For Users

#### ✨ Highlights

- **libsignal v0.92.1** — SPQR v1 enforcement and dependency updates
- **libsignal_frb v2.0.1** — updated native dependencies

#### Changed

- Update libsignal native library to v0.92.1 ([v0.92.0](https://github.com/signalapp/libsignal/releases/tag/v0.92.0), [v0.92.1](https://github.com/signalapp/libsignal/releases/tag/v0.92.1))
  - Force use of SPQR v1 for all newly initiated sessions (v0.92.0) — fallback to non-PQR sessions is no longer allowed
  - Expose `getUploadForm()` for backup uploads (v0.92.1)
  - Note: These changes do not affect this library's public API

## [3.0.1] - 2026-04-03

#### Fixed

- Fix README examples for `SessionCipher` and `SealedSenderCipher` to match new API (added `localAddress` and all required stores)
- Fix incorrect class name `SealedSessionCipher` → `SealedSenderCipher` in README
- Fix incorrect method name `decryptPreKeySignalMessage` → `decryptPreKeyMessage` in README

## [3.0.0] - 2026-04-03

### For Users

#### ✨ Highlights

- **libsignal v0.91.0** — message encryption now includes sender/recipient addresses in MAC for misdirection protection
- **libsignal_frb v2.0.0** — Rust FFI bindings updated with new `localAddress` parameter (breaking)

#### Changed

- Update libsignal native library to v0.91.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.91.0))
  - **Breaking:** `SessionCipher` and `SealedSenderCipher` constructors now require `localAddress` parameter
  - **Breaking:** `messageEncryptWithCallbacks` and `messageDecryptPrekeyWithCallbacks` now require `localName` and `localDeviceId` parameters
  - **Breaking:** `sealedSenderDecryptWithCallbacks` now requires `localName` and `localDeviceId` parameters
  - 1:1 message encryption and decryption now includes sender/recipient addresses in the message MAC to prevent message misdirection attacks
  - Backward compatible with messages from older clients that don't include addresses

## [2.9.0] - 2026-03-29

### For Users

#### ✨ Highlights

- **libsignal v0.90.0** — `CiphertextMessage` now implements `Clone`
- **libsignal_frb v1.5.0** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.90.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.90.0))
  - `CiphertextMessage` enum now derives `Clone` (previously only `Debug`)
  - Networking improvements: authenticated WebSocket message sending, key transparency API simplification
  - Note: These changes do not affect this library's public API
- Update Flutter Rust Bridge to v2.12.0 ([fix](https://github.com/fzyzcjy/flutter_rust_bridge/pull/3010))
  - Fixes web build compatibility with wasm-bindgen >=0.2.109
  - Removed version pins for wasm-bindgen, js-sys, and web-sys

## [2.8.2] - 2026-03-25

### For Users

#### ✨ Highlights

- **libsignal v0.89.2** — dependency updates and networking improvements
- **libsignal_frb v1.4.5** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.89.2 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.89.2))
  - Updated libcrux and SPQR (post-quantum) dependencies
  - Updated rustls-webpki and tokio-util dependencies
  - Networking improvements: service-level backoff, request cancellation
  - Note: No changes to `libsignal-protocol` crate API — this library's public API is unaffected

## [2.8.1] - 2026-03-20

### For Users

#### ✨ Highlights

- **libsignal v0.89.1** — patch release with dependency updates
- **libsignal_frb v1.4.4** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.89.1 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.89.1))
  - Patch release with internal dependency updates
  - No public API changes

## [2.8.0] - 2026-03-18

### For Users

#### ✨ Highlights

- **libsignal v0.89.0** — internal improvements and updates
- **libsignal_frb v1.4.3** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.89.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.89.0))
  - Internal improvements to the FFI bridge and callback mechanisms
  - Enhanced backup/export functionalities
  - Updates to keytrans handling
  - Note: These changes do not affect this library's public API

## [2.7.2] - 2026-03-15

### For Users

#### ✨ Highlights

- **libsignal v0.88.3** — internal improvements and updates
- **libsignal_frb v1.4.2** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.88.3 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.88.3))
  - Internal changes: FFI bridge callback improvements, backup/export refactoring, keytrans updates
  - Note: These changes do not affect this library's public API

## [2.7.1] - 2026-03-07

### For Users

#### ✨ Highlights

- **libsignal v0.88.1** — internal bridge refactoring
- **libsignal_frb v1.4.1** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.88.1 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.88.1))
  - Internal refactoring: further improvements to SenderKeyStore bridge implementations
  - Note: These changes do not affect this library's public API

## [2.7.0] - 2026-03-03

### For Users

#### ✨ Highlights

- **libsignal v0.88.0** — internal bridge refactoring, no protocol changes
- **libsignal_frb v1.4.0** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.88.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.88.0))
  - Internal refactoring: consolidated SenderKeyStore bridge implementations
  - No changes to `libsignal-protocol` crate API — this library's public API is unaffected

## [2.6.0] - 2026-02-27

### For Users

#### ✨ Highlights

- **libsignal v0.87.5** — updated post-quantum cryptography dependencies
- **libsignal_frb v1.3.0** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.87.5 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.87.5))
  - Updated SPQR (SparsePostQuantumRatchet) to v1.5.0
  - Updated hpke-rs to v0.6.0 and libcrux-ml-kem to v0.0.7
  - Added `zeroize` support for HPKE Rng in signal-crypto
  - Note: These changes do not affect this library's public API

## [2.5.0] - 2026-02-21

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

[Unreleased]: https://github.com/djx-y-z/libsignal_dart/compare/v6.1.1...HEAD
[6.1.1]: https://github.com/djx-y-z/libsignal_dart/compare/v6.1.0...v6.1.1
[6.1.0]: https://github.com/djx-y-z/libsignal_dart/compare/v6.0.0...v6.1.0
[6.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.9...v6.0.0
[5.0.9]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.8...v5.0.9
[5.0.8]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.7...v5.0.8
[5.0.7]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.6...v5.0.7
[5.0.6]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.5...v5.0.6
[5.0.5]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.4...v5.0.5
[5.0.4]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.3...v5.0.4
[5.0.3]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.2...v5.0.3
[5.0.2]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.1...v5.0.2
[5.0.1]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.0...v5.0.1
[5.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v4.0.1...v5.0.0
[4.0.1]: https://github.com/djx-y-z/libsignal_dart/compare/v4.0.0...v4.0.1
[4.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v3.0.3...v4.0.0
[3.0.3]: https://github.com/djx-y-z/libsignal_dart/compare/v3.0.2...v3.0.3
[3.0.2]: https://github.com/djx-y-z/libsignal_dart/compare/v3.0.1...v3.0.2
[3.0.1]: https://github.com/djx-y-z/libsignal_dart/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.9.0...v3.0.0
[2.9.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.8.2...v2.9.0
[2.8.2]: https://github.com/djx-y-z/libsignal_dart/compare/v2.8.1...v2.8.2
[2.8.1]: https://github.com/djx-y-z/libsignal_dart/compare/v2.8.0...v2.8.1
[2.8.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.7.2...v2.8.0
[2.7.2]: https://github.com/djx-y-z/libsignal_dart/compare/v2.7.1...v2.7.2
[2.7.1]: https://github.com/djx-y-z/libsignal_dart/compare/v2.7.0...v2.7.1
[2.7.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.4.0...v2.5.0
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
