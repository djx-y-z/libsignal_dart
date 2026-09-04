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
make setup-rust-tools             # Install Rust tools (cargo-audit, cargo-deny, frb_codegen)
make setup-frb-codegen            # Install the pinned flutter_rust_bridge_codegen
make setup-protoc                 # Install protoc (Protocol Buffers compiler)
make setup-web                    # Install web build tools (wasm-pack)
make setup-android                # Install Android build tools (cargo-ndk)
make setup-repo-protections       # Apply the GitHub repo rulesets (.github/rulesets/)
```

### Code Generation
```bash
make codegen                      # Generate Dart bindings from Rust code
```

**Note:** `make codegen` automatically creates a `.skip_libsignal_hook` marker file to prevent Build Hooks from downloading libraries during codegen. The marker is automatically removed after completion.

### Build
```bash
make build                              # Build for current platform (always release)
make build ARGS="--target <target>"     # Build for specific Rust target
make build-android                      # Build for Android (all ABIs)
make build-android ARGS="--target arm64-v8a"  # Build for specific Android ABI
make build-web                          # Build WASM for web
```

### Rust Quality
```bash
make rust-check                   # Check Rust code compiles
make rust-clippy                  # Lint Rust code with clippy (warnings = errors)
make rust-audit                   # Audit Rust dependencies for vulnerabilities
make rust-deny                    # Check advisories/licenses/sources (cargo-deny)
```

### Fuzzing
```bash
make setup-fuzz                   # One-time: install nightly + cargo-fuzz
make fuzz-list                    # List available fuzz targets
make fuzz-seed                    # Generate the seed corpus (rust/fuzz/corpus/)
make fuzz ARGS="keys -- -max_total_time=60"  # Run a target
```

Fuzz targets live in `rust/fuzz/fuzz_targets/`; the seed generator is
`rust/fuzz/examples/gen_corpus.rs`. A `Fuzz` CI workflow runs a smoke pass on
`rust/**` PRs and a longer weekly pass. See `SECURITY.md` for the coverage table.

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
make rust-update                  # Update Cargo.lock + regenerate notices
make third-party-notices          # Regenerate THIRD_PARTY_NOTICES.txt
make verify-third-party-notices   # Check it matches the dependency graph
make verify-frb-pins              # Check every file names the same FRB version
make check-new-libsignal-version  # Check for new upstream libsignal version
make check-new-libsignal-version ARGS="--update"  # Apply update
make check-template-updates       # Check for copier template updates
make update-template ARGS="--version vX.Y.Z"  # Apply a template update (runs copier)
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
- Native libraries delivered via Dart build hooks (`hook/build.dart` + `code_assets`)
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
├── hook/                           # Dart build hook (hooks/code_assets)
│   └── build.dart                  # Downloads precompiled native libraries
├── scripts/                        # Development scripts (use via Makefile!)
├── test/                           # Tests
├── Makefile                        # Entry point for all commands
├── pubspec.yaml                    # Package config
├── flutter_rust_bridge.yaml        # FRB codegen configuration
└── .github/workflows/              # CI/CD workflows
```

## Build System

This is a **plain Dart FFI package** — no `flutter: plugin:` section and no
platform scaffolding (`ios/`, `macos/`, `android/`, `linux/`, `windows/` dirs
do not exist). Native libraries are delivered via Dart **build hooks**
(`hook/build.dart`, using the `hooks`/`code_assets` packages).

### How It Works

1. **End users**: `hook/build.dart` downloads the precompiled binary for the
   target platform from the GitHub Release `libsignal_frb-<version>` (no Rust
   needed) and registers it as a code asset
2. **Developers**: build from source via `make build` (or `make build-web`); the
   hook then picks up the host-matching `rust/target/` build automatically (no
   marker needed). Cross-target builds (`make build-android`, `make build
   --target <triple>`, iOS) land in `rust/target/<triple>/` and are **not**
   picked up — those targets always download the released binary.
   `.skip_libsignal_hook` is only an
   internal escape the Makefile uses while wrapping pub-get/codegen/doc — when
   present the hook returns immediately and registers **no** asset
3. **CI**: `build-libsignal.yml` builds and uploads binaries when a
   `libsignal_frb-<version>` tag is pushed (stage 1 of the release flow)

### Precompiled Binaries

- Uploaded to a GitHub Release tagged `libsignal_frb-<version>` (must equal the
  `rust/Cargo.toml` crate version)
- SHA256 checksums are resolved before download; the hook fails closed if a
  trusted checksum cannot be obtained

### Deployment Targets

Source of truth is `.copier-answers.yml` (`ios_min_version`,
`macos_min_version`, `android_min_sdk`). `make check-targets` verifies (or with
`--update`/`--set` fixes) every copy: the CI build env vars
(`IPHONEOS_DEPLOYMENT_TARGET`, `MACOSX_DEPLOYMENT_TARGET`, cargo-ndk
`--platform`), the example Xcode projects, and the README platform table.
`make build-android` reads the minSdk from it via
`scripts/get_android_min_sdk.dart`.

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
libsignal-protocol = { git = "https://github.com/signalapp/libsignal", tag = "v0.102.0" }
```

To check/update the version:
```bash
make check-new-libsignal-version              # Check for updates
make check-new-libsignal-version ARGS="--update"  # Update rust/Cargo.toml
make rust-update                              # Update Cargo.lock
make codegen                                  # Regenerate FRB bindings
make update-changelog ARGS="--version vX.Y.Z" # Update CHANGELOG with AI (requires an AI provider key)
```

> This updates the **libsignal dependency** only. It does **not** bump the
> `libsignal_frb` crate version — that happens at release time via
> `make release-frb` (see [Release Flow](#release-flow-two-stages)).

### AI-Powered Changelog

`make update-changelog` (and the CHANGELOG entry `make update-template` writes)
hand the release notes to an AI model. **Which** model is configuration, not
code: `AI_MODELS` holds an ordered, comma-separated list of `provider/model`
entries and the first one that has a key and answers wins.

**There is no default list.** With `AI_MODELS` unset nothing is called and the
entry is simply not written — a model that writes into this repository's
CHANGELOG is one somebody named, not one the template picked. Keys without a
list is a misconfiguration rather than an opt-out, so that case warns loudly
instead of going quiet.

```bash
ANTHROPIC_API_KEY=xxx make update-changelog ARGS="--version v1.0.0"

# Pick a different model, or a different order, without touching the code
AI_MODELS=google/gemini-3.5-flash-lite ANTHROPIC_API_KEY=… GEMINI_API_KEY=… \
  make update-changelog ARGS="--version v1.0.0"
```

| Variable | Purpose |
|----------|---------|
| `AI_MODELS` | Ordered `provider/model` list, highest priority first. **Required** — there is no default; unset means no model is called. |
| `ANTHROPIC_API_KEY` | Key for `anthropic/…` entries ([console](https://console.anthropic.com/settings/keys)). |
| `GEMINI_API_KEY` | Key for `google/…` entries ([AI Studio](https://aistudio.google.com/apikey)). |
| `OPENROUTER_API_KEY` | Key for `openrouter/…` entries ([keys](https://openrouter.ai/keys)). |
| `AI_EFFORT` | How hard the model is asked to think: `low`, `medium` (default), `high`, `xhigh`, `max`. Ignored by providers that have no such knob. |

An entry whose key is unset is skipped silently — that is how the list says
"use this if it is available". A malformed entry or an unknown provider is
warned about loudly, because it is a typo, not a choice.

Keys are read from the environment and go out in one request header each
(`x-api-key`, `x-goog-api-key`, `Authorization`). They are never put in a URL,
in process arguments, or in the prompt, and nothing logs them — the priority
line prints model ids and variable *names* only. Provider error bodies are
quoted into logs and pull-request output, so the key is stripped from those
before they are reported.

`openrouter` is an aggregator, so its model half is itself a `vendor/model`
pair — an entry reads `openrouter/anthropic/claude-opus-5`. It buys one key for
many models (swapping model costs neither code nor a new secret), at the price
of a third party on the path and a weaker schema guarantee: structured-output
support is per model **and** per backing provider, and `strict` is enforced
exactly by some and treated as guidance by others. A model that cannot do
structured outputs is rejected outright rather than silently downgraded.

The next entry is tried only when a model produced **no** answer: a network
failure, an auth/rate-limit/server status, a refusal, or a response cut off at
the token limit. Never on the *content* of an answer — switching providers
because an entry read poorly would make the CHANGELOG silently inconsistent.

In CI these are step-scoped: `AI_MODELS` as a repository/organization
**variable**, the keys as **secrets**. The pull request body names the model
that wrote the entry.

If no model answers, nothing is guessed: the entry is left unwritten, the run
says why, and the pull request is labelled `changelog-needed`.

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

## Release Flow (two stages)

Releasing is **two independent stages**, each with its own command and tag. The
`libsignal_frb` native crate (`rust/Cargo.toml` version) and the `libsignal` Dart
package (`pubspec.yaml` version) are versioned and released separately.

```
libsignal dep-update PRs  ──►  merge to main  ──►  (accumulate, no binary)
                                                        │
   Stage 1: native crate ── make release-frb ARGS="--version X.Y.Z"
     bumps rust/Cargo.toml, stamps CHANGELOG frb Highlight, signs commit +
     tag `libsignal_frb-X.Y.Z`, pushes  ──►  build-libsignal.yml builds &
     publishes the native binaries (GitHub Release `libsignal_frb-X.Y.Z`)
                                                        │
   Stage 2: Dart package ── make release ARGS="--version X.Y.Z"
     verifies the stage-1 binary exists, dry-runs, bumps pubspec, finalizes
     CHANGELOG, signs commit + tag `vX.Y.Z`, pushes  ──►  publish.yml → pub.dev
     (the build hook downloads the stage-1 binary, which already exists)
```

**Key rules:**

- **Automated libsignal update PRs do NOT bump the `libsignal_frb` crate version
  and do NOT build binaries.** They only update the dependency + CHANGELOG.
  Dependency updates accumulate on `main` (CI still builds from source and tests
  them); no throwaway native binary is produced.
- **The native build is triggered by pushing a `libsignal_frb-<version>` tag**
  (created by `make release-frb`), not by pushing to `main`. The tag must equal
  the `rust/Cargo.toml` crate version (the workflow validates this).
- **Stage 1 must finish before stage 2** — the published Dart package's build
  hook downloads the precompiled `libsignal_frb-<crate>` binary, so it must
  already exist before you tag the pub.dev release.
- Skills: [`release-frb-crate`] (stage 1) and [`release-package`] (stage 2).

### Stage 1 — release the native crate

```bash
# From a clean, up-to-date main. You enter your signing passphrase during the
# command (commit + tag are signed; the terminal is inherited).
make release-frb ARGS="--version X.Y.Z"      # bump + commit + tag + push
make release-frb ARGS="--version X.Y.Z --no-push"   # local only
```

Choose `X.Y.Z` by SemVer of the FFI surface (see the `release-frb-crate` skill):
a non-empty `lib/src/rust/` codegen diff since the last frb release means the
wire signature moved (≥ minor; major if breaking).

### Stage 2 — release the Dart package

```bash
# After the stage-1 native build has finished. Same interactive signing flow.
make release ARGS="--version X.Y.Z"                # verify frb binary + dry-run +
                                                   # bump + finalize CHANGELOG
                                                   # + signed commit/tag/push
make release ARGS="--version X.Y.Z --no-push"      # local only
```

`make release` refuses to proceed until the stage-1 GitHub Release
`libsignal_frb-<rust/Cargo.toml version>` exists (the published build hook
downloads it; pass `--skip-frb-check` only if you verified it manually). It runs
`make publish-dry-run` (on the clean, pre-bump tree), bumps `pubspec.yaml`, then
finalizes the CHANGELOG (renames `[Unreleased]` → `[X.Y.Z] - <today>` in place —
no empty `[Unreleased]` is left behind — and rewrites the bottom `[Unreleased]:`
compare link to `vX.Y.Z...HEAD`), then signs a commit + tag `vX.Y.Z` and pushes —
`publish.yml` publishes to pub.dev. Choose `X.Y.Z` by SemVer of the **public Dart
API** (independent of the crate version).

| Variable | Purpose |
|----------|---------|
| `AI_MODELS` | Ordered `provider/model` list, highest priority first. **Required** — there is no default; unset means no model is called. |
| `ANTHROPIC_API_KEY` | Key for `anthropic/…` entries ([console](https://console.anthropic.com/settings/keys)). |
| `GEMINI_API_KEY` | Key for `google/…` entries ([AI Studio](https://aistudio.google.com/apikey)). |
| `OPENROUTER_API_KEY` | Key for `openrouter/…` entries ([keys](https://openrouter.ai/keys)). |
| `AI_EFFORT` | How hard the model is asked to think: `low`, `medium` (default), `high`, `xhigh`, `max`. Ignored by providers that have no such knob. |

An entry whose key is unset is skipped silently — that is how the list says
"use this if it is available". A malformed entry or an unknown provider is
warned about loudly, because it is a typo, not a choice.

Keys are read from the environment and go out in one request header each
(`x-api-key`, `x-goog-api-key`, `Authorization`). They are never put in a URL,
in process arguments, or in the prompt, and nothing logs them — the priority
line prints model ids and variable *names* only. Provider error bodies are
quoted into logs and pull-request output, so the key is stripped from those
before they are reported.

`openrouter` is an aggregator, so its model half is itself a `vendor/model`
pair — an entry reads `openrouter/anthropic/claude-opus-5`. It buys one key for
many models (swapping model costs neither code nor a new secret), at the price
of a third party on the path and a weaker schema guarantee: structured-output
support is per model **and** per backing provider, and `strict` is enforced
exactly by some and treated as guidance by others. A model that cannot do
structured outputs is rejected outright rather than silently downgraded.

The next entry is tried only when a model produced **no** answer: a network
failure, an auth/rate-limit/server status, a refusal, or a response cut off at
the token limit. Never on the *content* of an answer — switching providers
because an entry read poorly would make the CHANGELOG silently inconsistent.

In CI these are step-scoped: `AI_MODELS` as a repository/organization
**variable**, the keys as **secrets**. The pull request body names the model
that wrote the entry.

If no model answers, nothing is guessed: the entry is left unwritten, the run
says why, and the pull request is labelled `changelog-needed`.

### What the entry is judged against

`.github/agent-prompts/changelog-scope.md` holds this project's own statement of
what it binds and exposes, and the prompt classifies every upstream change
against it: anything that cannot be tied to something named there is invisible
to this package's users and must not be presented as a feature of it. The
template writes that file once and never overwrites it, so keeping it current is
this project's job — a stale list is how somebody else's release notes end up
described as our features.

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
- Message parsing — `SignalMessage`, `PreKeySignalMessage`, `SenderKeyMessage`,
  `SenderKeyDistributionMessage`, `PlaintextContent`,
  `UnidentifiedSenderMessageContent` (construct *and* parse), and
  `sealedSenderV2ParseSentMessage`. Parsing validates structure only — it never
  authenticates; see SECURITY.md
- Certificate validation (`validateSenderCertificate()`)
- Creating `PreKeyBundle` from existing keys

### Sealed-Sender Envelope Operations (identity only, no session stores)

| Operation | Needs |
|-----------|-------|
| `sealedSenderEncryptFromUsmc` | identity key pair + `getIdentity` for the recipient |
| `sealedSenderDecryptToUsmc` | identity key pair + trust root (validates the sender certificate) |
| `sealedSenderMultiRecipientEncrypt` | identity key pair + `getIdentity` per destination + caller-supplied `SessionRecord` bytes |

None of these write to a store — they do no Double Ratchet work.

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

Each release is a `## [X.Y.Z] - YYYY-MM-DD` heading split into **audience-scoped**
sections. Keep this structure so entries stay consistent across releases.

```markdown
## [X.Y.Z] - YYYY-MM-DD

### For Users

#### ✨ Highlights

- **<headline>** — short description (mark breaking ones **(breaking)**)
- **libsignal vX.Y.Z** — ... (state "unchanged this release" if it didn't move)
- **libsignal_frb vX.Y.Z** — Rust FFI bindings

#### Changed (Breaking)

- **<summary>** — what broke. Include an **Action required:** note.

#### Changed

- **<summary>** — non-breaking behavior/API change

#### Security

- **<summary>** — security-relevant, user-observable change

#### Fixed

- **<summary>** — bug fix

### For Contributors

#### Added

- **<summary>** — internal tooling only (fuzzing, cargo-deny, scripts, …)

#### Changed

- **<summary>** — CI / lints / build config / template adoption
```

Rules:
- **`### For Users`** = anything a consumer of the published package can observe
  (public API, runtime behavior, the native binary, the build hook). A change is
  "For Users" even if it feels internal when a consumer sees it at build/run time
  (e.g. `overflow-checks` in the shipped binary).
- **`### For Contributors`** = changes that do NOT affect the published package's
  behavior (CI, dev tooling, lints, fuzzing, cargo-deny, build scripts, template
  adoption).
- Every bullet starts with a **bold summary** + em-dash, then the detail.
- Omit any section/subsection with no entries. Order subsections as shown
  (Highlights → Changed (Breaking) → Changed → Security → Fixed).
- Released sections are immutable; edit the top pending version until release.

## Publishing Checklist

**Do not tag or bump versions by hand** — that bypasses the stage-1 native-binary
existence check, the CHANGELOG finalization, and the publish dry-run. Use the
two-stage flow documented above (see [Release Flow](#release-flow-two-stages)):

```bash
# 0. (optional) quality gates — the release scripts also run these
make analyze && make test && make format-check

# Stage 1 — native crate (bumps rust/Cargo.toml, tags libsignal_frb-X.Y.Z):
make release-frb ARGS="--version X.Y.Z"
# …wait for build-libsignal.yml to publish the native binaries…

# Stage 2 — Dart package (verifies the stage-1 binary, dry-runs, bumps pubspec,
# finalizes CHANGELOG, tags vX.Y.Z → publish.yml publishes to pub.dev):
make release ARGS="--version X.Y.Z"
```

## Claude Skills

Claude Code skills available in this project (invoke with `/<skill>` or used automatically by Claude):

| Skill | Description |
|-------|-------------|
| `release-frb-crate` | Release the `libsignal_frb` native crate (stage 1): bump, tag `libsignal_frb-*`, build binaries |
| `release-package` | Prepare a new version for publication to pub.dev (stage 2) |
| `update-template` | Update copier template to latest version |
