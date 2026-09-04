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
- [Third-party notices](#third-party-notices)
- [Security Considerations](#security-considerations)

## Code of Conduct

Please be respectful and considerate of others. We expect all contributors to:

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community

## Getting Started

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (1.88+) — `rust-version` in
  `rust/Cargo.toml` is the authority; this is the same number
- [Dart SDK]( https://dart.dev/get-dart ) (^3.10.0) or Flutter
  (>=3.38.0) — `make setup` installs the pinned Flutter through fvm
- `make` (see **Windows Users** below)
- Git

Nothing here is needed to *use* the published package: consumers get a
precompiled native library through the build hook.

### Fork and Clone

1. Fork the repository on GitHub
2. Clone **your fork**, not this repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/libsignal_dart.git
   cd libsignal_dart
   ```
3. Add the upstream remote, so you can keep the fork current:
   ```bash
   git remote add upstream https://github.com/djx-y-z/libsignal_dart.git
   ```

## Development Setup

### Quick Setup

```bash
make setup
```

It checks that a Rust toolchain is present (and tells you where to get one if
not), installs fvm and the Flutter version pinned in `.fvmrc`, installs
protoc, then installs the Rust tooling the gates need — `cargo-audit`,
`cargo-deny` and `flutter_rust_bridge_codegen` at the exact version this
project pins.

Optional, per platform: `make setup-android` (cargo-ndk),
`make setup-web` (wasm-pack), `make setup-fuzz`
(nightly + cargo-fuzz).

### Verify Setup

```bash
# Every command this project has, with a one-line description each
make help

# The end-to-end check: this builds the native library if it is missing
make test
```

### Editor Setup (FVM)

`.fvmrc` and `.vscode/settings.json` are both committed, and `.fvmrc` sets
`"updateVscodeSettings": false` so that fvm manages neither of them.

`fvm install` warns on every run that it is not managing VS Code settings and
asks you to remove that setting. **Leave it as it is.** With fvm managing those
files, every `fvm install` — which `make codegen` triggers twice per run —
rewrites both, so each codegen leaves two modified files unrelated to the
generated bindings; and on a machine where fvm cannot create its own symlink it
writes an absolute, machine-local SDK path into a committed file. The warning is
cosmetic and fvm offers no way to silence it on its own.

On Windows, enable [Developer Mode][windows-dev-mode] before the first
`fvm install`: fvm needs it to create the `.fvm/flutter_sdk` symlink that
`dart.flutterSdkPath` points at.

[windows-dev-mode]: https://learn.microsoft.com/en-us/windows/apps/get-started/enable-your-device-for-development

### Windows Users

Every task in this project runs through `make`, which Windows does not ship.
Install it first:

- Chocolatey: `choco install make`
- Scoop: `scoop install make`
- Or work in Git Bash or WSL, where it is already present

Then `make setup` as above.

### Project Structure

```
libsignal_dart/
├── lib/
│   ├── libsignal.dart       # public API — the only file consumers import
│   └── src/
│       ├── rust/            # FRB-generated bindings (do NOT hand-edit)
│       └── stores/          # Store interfaces and implementations
├── rust/                    # The native crate
│   ├── Cargo.toml           # Dependencies, features, profiles, MSRV
│   └── src/api/             # What FRB exposes; everything else is internal
├── test/                    # Dart tests
├── hook/build.dart          # Build hook: downloads or finds the native library
├── scripts/                 # Automation — invoke through the Makefile
├── example/                 # Example app
└── Makefile                 # The single entry point for every task
```

Two of those are load-bearing conventions rather than layout: `lib/src/rust/`
is generated output that `make codegen` rewrites, so an edit there survives
exactly until the next run; and `scripts/` is called through `make`, which is
where the arguments and the environment each script expects are set.

## Making Changes

### Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/the-thing-that-is-broken
```

### Types of Contributions

- **Bug fixes** — with a test that fails before the fix
- **Documentation** — including the comments that explain why a constraint exists
- **Tests** — especially for a path only one platform reaches
- **Features** — please open an issue first
- **Performance** — with a measurement, not an argument

### Before You Start

For anything larger than a fix, open an issue and wait for a reply. This
project pins versions, caps constraints and gates releases on grounds that are
written down but not always obvious from the diff — a change can be correct and
still be wrong here, and finding that out in review is expensive for you.

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run specific test file
make test ARGS="test/keys/private_key_test.dart"

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
- [ ] Both documentation gates pass (`make doc`, `make rust-doc`) — they BLOCK in CI
- [ ] If a `cfg(target_arch = "wasm32")` branch changed, `make test-web` passes
      (it is the only check that executes web code, and it needs a chromedriver:
      `make test-web CHROMEDRIVER=/path/to/chromedriver`)
- [ ] Generated bindings are regenerated and committed, never hand-edited
- [ ] New constraints, pins and caps carry a comment saying why
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
- **No `dispose()` calls needed for correctness** - Rust drops resources when the
  owning Dart object is garbage-collected
- **But cleanup timing is not deterministic** - security-critical code holding
  secrets should still call `dispose()` explicitly to bound how long the secret
  lives in native memory (see `SECURITY.md` → A: Memory Safety)

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
| `make doc` | Dartdoc gate — fails on an unresolved doc reference |
| `make rust-doc` | Rustdoc gate — intra-doc links under `-D warnings` |
| `make test-web` | Run the crate's browser tests (headless Chrome) |
| `make rust-audit` | Check Rust dependencies for vulnerabilities |
| `make rust-check` | Quick Rust type check (updates Cargo.lock) |
| `make rust-test` | Run the crate's own Rust unit tests |
| `make format` | Format code |
| `make format-check` | Check formatting |
| `make codegen` | Regenerate FRB bindings |
| `make check-new-libsignal-version` | Check for libsignal updates |
| `make check-template-updates` | Check for copier template updates |
| `make rust-update` | Update rust/Cargo.lock (also regenerates THIRD_PARTY_NOTICES.txt) |
| `make third-party-notices` | Regenerate THIRD_PARTY_NOTICES.txt from the dependency graph |
| `make verify-third-party-notices` | Verify THIRD_PARTY_NOTICES.txt matches the dependency graph |
| `make update-changelog` | Update CHANGELOG.md with AI (requires `AI_MODELS` + a key) |
| `make verify-frb-pins` | Verify every file names the same flutter_rust_bridge version |
| `make release-frb` | Release the `libsignal_frb` native crate (stage 1) — see [Releasing](#releasing-two-stages) |
| `make release` | Release the Dart package to pub.dev (stage 2) — see [Releasing](#releasing-two-stages) |
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

Regenerate after anything in `rust/src/api/` changes — a signature, a type, an
enum variant, or a doc comment, which flutter_rust_bridge copies into the Dart
output verbatim. Commit the result: the bindings are checked in, and the runtime
asserts that its own flutter_rust_bridge version equals the one recorded in them.

Never hand-edit a generated file to fix a build. The next `make codegen` reverts
it, which turns a red build into a red build nobody can reproduce.

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

Native libraries are downloaded automatically by the build hook (`hook/build.dart`) during `flutter build` / `dart run`. You don't need to build them manually for most development work.

For development, build the native library from source and the hook picks up the
host-matching `rust/target/` build automatically — no marker needed:

```bash
# Native platforms
make build

# Web/WASM
make build-web
```

**Build requirements (for source builds):**

| Platform | Build tooling |
|----------|---------------|
| Linux / macOS / Windows | Rust toolchain (rustup, cargo), protoc |
| Android | + Android NDK, cargo-ndk |
| iOS | + Xcode |
| Web | + wasm-pack |

### Third-party notices

`THIRD_PARTY_NOTICES.txt` is generated from the resolved Rust dependency graph
and verified byte-for-byte in CI, in `build-<package>.yml` and in both release
preflights. Regenerate it with `make third-party-notices` after any dependency
change — `make rust-update` already does. `make verify-third-party-notices`
prints the first differing line and the entries unique to each side, so a CI
failure is readable without reproducing it locally.

The crate set comes from `cargo tree --edges normal,build --target all`. The
`--target all` is load-bearing: with a specific triple, cargo still resolves
build-dependencies *and proc-macro subtrees* for the build host, so the file
would differ between a macOS, Linux and Windows contributor — with the crate
count sometimes unchanged, which makes the drift invisible in the summary. The
result over-attributes (build tooling, platform-gated crates a given build never
links); that is the deliberate trade for output that does not change with the
machine.

To re-validate completeness against an independent implementation:

```bash
cargo install cargo-about --locked --features cli   # the CLI needs that feature
cat > /tmp/about.toml <<'EOF'
accepted = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause",
  "BSD-3-Clause", "ISC", "Zlib", "Unicode-3.0", "Unicode-DFS-2016", "CC0-1.0",
  "MPL-2.0", "OpenSSL", "BSL-1.0", "Unlicense", "AGPL-3.0", "CDLA-Permissive-2.0", "0BSD"]
targets = ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin", "x86_64-pc-windows-msvc",
  "aarch64-linux-android", "wasm32-unknown-unknown"]
ignore-build-dependencies = false
ignore-dev-dependencies = true
EOF
cargo about generate --config /tmp/about.toml --manifest-path rust/Cargo.toml \
  --format json --output-file /tmp/about.json
```

Compare the crate names in `/tmp/about.json` with those in
`THIRD_PARTY_NOTICES.txt`: the only crate cargo-about should report that the
inventory omits is this repository's own crate, which is excluded on purpose.
Note that cargo-about resolves build-dependencies for the host exactly as a
per-target `cargo tree` does, so it validates the *contents*, not the
reproducibility.

### Setting up Coverage Badge

The CI automatically measures test coverage and can update a badge in your README. To enable this:

1. Create a **public** GitHub Gist at https://gist.github.com
   - Filename: `coverage.json`
   - Content: `{"schemaVersion":1,"label":"coverage","message":"0%","color":"red"}`
2. Copy the **Gist ID** from the URL (e.g., `https://gist.github.com/username/abc123` → `abc123`)
3. Create a **Fine-grained Personal Access Token** at https://github.com/settings/tokens?type=beta
   - Required permission: **Gists → Read and write**
4. Add as repository secret: Settings → Secrets and variables → Actions → New repository secret → `GIST_TOKEN`
5. Add as repository variable: Settings → Secrets and variables → Actions → Variables → New repository variable → `COVERAGE_GIST_ID` (value: the Gist ID from step 2)
6. Update `README.md`: uncomment the coverage badge line and replace `COVERAGE_GIST_ID` with your actual Gist ID

### Setting up the GitHub App

Several workflows open pull requests, file issues or push signed commits. None
of them uses the default `GITHUB_TOKEN` for that: a pull request opened with it
does not trigger workflows, which would leave the four-platform matrix — the
only oracle those pull requests have — silently absent.

1. Create a GitHub App (Settings → Developer settings → GitHub Apps) and install
   it on this repository
2. Repository permissions it needs: **Contents → Read and write**,
   **Pull requests → Read and write**, **Issues → Read and write**,
   **Workflows → Read and write** (the last one only if the automation may ever
   touch `.github/workflows/`, which template updates do)
3. Generate a private key and add it as a repository secret:
   Settings → Secrets and variables → Actions → New repository secret →
   `APP_PRIVATE_KEY`
4. Add the App's **Client ID** as a repository variable → `APP_CLIENT_ID`.
   This is the `Iv23li…` string on the App's page, **not** the numeric App ID
   shown beside it; `create-github-app-token` fails the mint if given the wrong
   one, and that failure takes out the only credential these workflows can write
   with.

### Setting up the repair and review agents

Two workflows run an agent: `repair-build.yml` attempts a fix when `main` goes
red and reports when it cannot, and `ai-review.yml` reviews pull requests and
leaves one comment. Both are **off entirely** until an engine is named — an
unset `AGENT_ENGINE` produces a notice and no run, which is what an
unconfigured repository is supposed to look like.

1. Choose the engine: variable `AGENT_ENGINE` = `claude-code` or `opencode`
2. Name the model — there is deliberately no default:
   - `claude-code` → variable `AGENT_CLAUDECODE_MODEL`, secret
     `ANTHROPIC_API_KEY`
   - `opencode` → variable `AGENT_OPENCODE_MODEL` in `provider/model` form
     (an aggregator's model half carries its own slash, e.g.
     `openrouter/openai/gpt-5.6-luna`), and the provider's own key as a secret.
     Which variable that key is read from is `AGENT_OPENCODE_PROVIDER_ENV`,
     default `OPENROUTER_API_KEY`; `AGENT_OPENCODE_API_KEY` overrides it.
3. Optional: `REVIEW_AGENT_ENGINE`, `REVIEW_AGENT_CLAUDECODE_MODEL` and
   `REVIEW_AGENT_OPENCODE_MODEL` run the reviewer on a different model from the
   repair agent — worth having, since a reviewer drawn from the same family as
   the writer shares its blind spots. Each falls back to the `AGENT_*` setting.
4. Optional: `REVIEW_ALLOWED_BOTS`, a comma-separated list including your App's
   slug. Only the `claude-code` engine reads it, and without it that engine
   refuses to review pull requests opened by a bot — which is most of them here.

Both agents hold no write credential: the job that runs the agent cannot reach
the repository, and the job that publishes runs no agent. Read the header of
either workflow before changing that split.

The reviewer **gates nothing** and has no verdict meaning "approved". Before
wiring it to anything that blocks a merge, measure its false-positive rate by
replaying merged pull requests through it — published measurements put roughly
four in five findings of this kind in the false-positive bin, and three runs
over one unchanged diff here produced three different lists.

### Setting up pub.dev Publishing

The publish workflow uses OIDC authentication to publish to pub.dev without tokens. This requires a one-time setup.

**On pub.dev:**

1. Go to https://pub.dev and sign in
2. Navigate to your publisher page (or create one)
3. Go to **Admin** → **Automated publishing**
4. Click **Enable automated publishing**
5. Add your GitHub repository: `djx-y-z/libsignal_dart`
6. Set **Publishing from**: **GitHub Actions with tag** → tag pattern: `v*`

See [dart.dev/tools/pub/automated-publishing](https://dart.dev/tools/pub/automated-publishing) for details.

**On GitHub (create environment):**

1. Go to your repository → **Settings → Environments**
2. Click **New environment** → name it exactly `pub.dev`
3. Under **Deployment protection rules**:
   - Check **Required reviewers** → add yourself (and/or your team) as reviewer
   - Uncheck **Allow administrators to bypass configured protection rules**
4. Click **Save protection rules**

> The `pub.dev` environment is required by the publish workflow. Protection rules ensure that every publish requires manual approval, preventing accidental releases.

## The flutter_rust_bridge pin

Six files record it, and two of them are compared with `==` at runtime:
`frb_generated.dart` carries the version of the generator that produced it, and
`RustLib.init()` throws unless the runtime package's version is the same string.
So the constraint in `pubspec.yaml` is one version written as a range,
`>=X.Y.Z <X.Y.Z+1` — a caret admits versions that assert rejects, and a bare
`X.Y.Z` admits only the right one but makes the package unpublishable, because
`dart pub publish` warns that a single-version constraint "should allow more
than one version" and exits 65 on any warning.

The sixth, `rust/fuzz/Cargo.toml`, fails a different way and earlier. The fuzz
crate depends on `flutter_rust_bridge` directly *and* on the main crate by
path, so a stale pin there does not drift: cargo cannot resolve the two
together at all, and every fuzz target stops building. Nothing else notices —
`rust/fuzz` is its own workspace root, so no resolution under `rust/` passes
through it, and the `Fuzz` workflow runs only on `rust/**` pull requests and a
weekly cron, never on a push.

`make verify-frb-pins` checks all six agree and that the constraint is written
in that form. It runs in CI on the Linux leg and costs six file reads — no
build, no network. Moving the version means moving `frb_version` in
`.copier-answers.yml` and the `=` pin in both cargo manifests, then
`make setup-frb-codegen` and `make codegen` so the installed generator and the
committed bindings match; a pull request that edits one of the six is wrong by
construction, which is why Dependabot is told to leave `flutter_rust_bridge`
alone.

## Releasing (two stages)

Releasing happens in **two independent stages**, each with its own command and git
tag — the `libsignal_frb` native crate and the `libsignal` Dart package
are versioned and released separately.

1. **Native crate (stage 1)** — from a clean, up-to-date `main`:
   ```bash
   make release-frb ARGS="--version X.Y.Z"
   ```
   Bumps `rust/Cargo.toml`, stamps the CHANGELOG highlight, and creates a
   **signed** commit + tag `libsignal_frb-X.Y.Z`, then pushes. The tag triggers
   the native build workflow, which builds and publishes the platform binaries.
   The commit/tag/push inherit your terminal, so you enter your signing passphrase
   interactively during the command.

2. **Dart package (stage 2)** — after the native build succeeds:
   ```bash
   make release ARGS="--version X.Y.Z"
   ```
   Verifies the stage-1 `libsignal_frb-<crate>` release exists, validates with
   a publish dry-run (on the clean, pre-bump tree), bumps `pubspec.yaml`,
   finalizes the CHANGELOG (`[Unreleased]` → `[X.Y.Z]` + compare links; no empty
   `[Unreleased]` is left behind — the next unreleased change recreates it), then
   creates a **signed** commit + tag `vX.Y.Z` and pushes. `publish.yml` publishes
   to pub.dev.

   > **Do not delete the footer `[Unreleased]:` compare link** even when no
   > `## [Unreleased]` heading is present between releases — it is load-bearing
   > (the release scripts read it for the base URL and previous version, and the
   > next unreleased change re-references it). It is intentionally retained, not
   > stale.

**Order matters:** stage 1 must finish first — the published package's build hook
downloads the precompiled `libsignal_frb-<crate>` binary, so it must already
exist before you tag the pub.dev release.

> Automated libsignal update PRs **do not** bump the `libsignal_frb`
> crate or build binaries — dependency updates accumulate on `main` (tested from
> source in CI), and you cut a native release deliberately with `make release-frb`.

## Repository rulesets & tag protection

This repository should be guarded by GitHub **repository rulesets** and a
required-reviewer **environment**, so the native/crypto library's releases can't
be published without the right people and review:

- **Signed commits** required on all branches (configure SSH or GPG signing).
- **`main`** protected (changes land via PR; force-push and deletion blocked).
- **Tags** — all tags creatable only by Admins/Maintainers and must be signed;
  the release-triggering `libsignal_frb-*` / `v*` are the critical subset (they
  start native / pub.dev publishing).
- The **native-build publish** waits on a required reviewer (the `native-build`
  environment), mirroring the `pub.dev` environment that gates pub.dev publishing.

The maintainer runbook — what each ruleset does, exact `gh` commands to apply /
verify / roll back, and how to configure the `native-build` environment — is in
[`.github/rulesets/README.md`](.github/rulesets/README.md).

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
- [ ] Store writes durable before the ciphertext is sent / the plaintext is acted on
- [ ] Cipher operations serialized per address at the call site (a store-internal lock does not cover `load → ratchet → store`)
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
3. Update Cargo.lock — this also regenerates `THIRD_PARTY_NOTICES.txt`, which
   is derived from the dependency graph and verified against it in CI:
   ```bash
   make rust-update
   ```
4. Regenerate FRB bindings (if API changed):
   ```bash
   make codegen
   ```
5. Update CHANGELOG.md (requires `AI_MODELS` plus a key for each provider it
   names — there is no default list):
   ```bash
   AI_MODELS=anthropic/claude-opus-5 ANTHROPIC_API_KEY=your_key \
     make update-changelog ARGS="--version vX.Y.Z"
   ```

   What the entry is classified against lives in
   `.github/agent-prompts/changelog-scope.md` — this repository's own statement
   of what it binds and exposes. A template update never overwrites it, so keep
   it current: an upstream change that cannot be tied to something named there
   is invisible to this package's users, and a stale list is how somebody
   else's release notes end up described as our features.
6. Test all protocol operations:
   ```bash
   make test
   ```

> Updating the dependency does **not** bump the `libsignal_frb` crate version or
> build native binaries — that is a separate, deliberate step. When you are ready
> to ship, cut the release with `make release-frb` (see [Releasing](#releasing-two-stages)).

## Questions?

- Open an issue for general questions
- Check existing issues before creating new ones
- Be patient - maintainers are volunteers

Thank you for contributing!
