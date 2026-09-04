---
name: update-libsignal
description: Update libsignal native library version. Use when checking for updates, upgrading libsignal, bumping version, or updating native dependencies.
---

# Update libsignal Version

Guide for updating the libsignal native library version in this project.

## Review Automated PR (Most Common)

When the CI creates an automated PR for libsignal update, follow these steps:

### Step 1: Analyze Upstream Changes (IMPORTANT — go beyond release notes)

Release notes are often terse or incomplete. Always examine what actually
changed between the two tags. `vOLD` is the version being replaced (see the
PR title/diff), `vNEW` is the new one.

**1a. Release notes (starting point, not the whole story):**

```bash
gh api repos/signalapp/libsignal/releases/tags/vNEW --jq '.body'
```

**1b. Full commit list between the tags:**

```bash
gh api "repos/signalapp/libsignal/compare/vOLD...vNEW" --paginate \
  --jq '.commits[].commit.message | split("\n")[0]'
```

**1c. Which files changed, scoped to the crates we bind:**

```bash
gh api "repos/signalapp/libsignal/compare/vOLD...vNEW" --paginate --jq '.files[].filename' \
  | grep -E 'libsignal-protocol|libsignal-core|signal-crypto'
```

For large ranges the compare API truncates `files` — fall back to a shallow clone:

```bash
git clone --filter=blob:none https://github.com/signalapp/libsignal /tmp/upstream
git -C /tmp/upstream diff vOLD..vNEW --stat -- <crate dirs>
```

**1d. Check the public API surface we actually bind.** List the upstream
types/functions referenced in `rust/src/api/*.rs`, then look for them in the
diff:

```bash
git -C /tmp/upstream diff vOLD..vNEW -- <crate>/src | grep -E '^[-+].*(pub fn|pub struct|pub enum|pub trait)'
```

**1e. Upstream `Cargo.toml` deltas** — MSRV bumps, new/removed features,
dependency updates with security advisories.

⚠ **An MSRV bump moves two files, not one.** `rust-version` in
`rust/Cargo.toml` is what CI reads — `test-reusable.yml` greps it and feeds it
to the toolchain action — but that line is *rendered* from the `rust_version`
answer in `.copier-answers.yml`, and so is the version README.md advertises to
contributors. Raise the answer together with the manifest. Otherwise the README
keeps promising a toolchain that can no longer build the crate, nothing
notices (the two are never compared), and the next `copier update` renders the
stale number straight back over the manifest.

Summarize findings as:
- **Breaking changes** (API removals, signature changes) → Rust wrapper must adapt
- **New features / new APIs** → candidates to expose in `rust/src/api/`
- **Security fixes** → must be called out in CHANGELOG.md
- **Internal-only changes** → one CHANGELOG line ("does not affect this library's API")

### Step 2: Check Why Codegen Failed (if applicable)

```bash
# Check if Rust code compiles
make rust-check
```

Common issues:
- **Removed traits** (e.g., `Ord` for `PublicKey`)
- **Changed function signatures**
- **Renamed types**
- **An item moved behind a cargo feature.** `E0599: no variant named X` (or
  `no method named X`) reads exactly like a removal, and upstream release notes
  tend to say "gated" rather than "removed", so the two are easy to conflate —
  the wrong diagnosis costs a wrapper rewritten to live without something that
  is still there. Check the feature table in that crate's `Cargo.toml` before
  adapting anything. Features are **not** transitive across crates: enabling
  one on the top-level crate does not enable it for a sibling crate this
  project depends on directly, so every dependency line in `rust/Cargo.toml`
  that names the gated item needs the feature of its own.

### Step 2b: Keep diagnostic features out of the shipped binary

Cargo features are additive and unified across every dependency table, so a
feature enabled anywhere — including under
`[target.'cfg(target_arch = "wasm32")'.dependencies]` — is enabled everywhere
the crate is built. There is no "for tests only", and no "native only": the
published library and the wasm module carry it too.

The features worth watching are the ones that change what error *values*
contain rather than what the API offers. One that turns errors into symbolized
backtraces needs no panic to reach a caller: the string travels the ordinary
error channel, crosses FFI, and lands in the consuming application's logs
naming internal paths and, on some platforms, absolute build paths.

When a bump adds such a feature, or moves an existing one, check the artifacts
rather than the manifest — the manifest is where the mistake looks harmless:

```bash
make build && make build-web
# 0 hits required, on the native library AND the wasm module
strings <built artifact> | grep -c '<a string the feature introduces>'
```

### Step 3: Fix Rust Code (if needed)

If `make rust-check` fails, fix the errors in `rust/src/api/`:
- Update code to match new libsignal API
- Add workarounds for removed functionality

### Step 4: Regenerate FRB Bindings

```bash
make codegen
```

### Step 5: Run Tests

```bash
make test
```

### Step 6: Run Analysis

```bash
make analyze
```

### Step 7: Update CHANGELOG.md

Verify the AI-generated entry against YOUR findings from Step 1 — the AI only
sees the release notes and commit subjects, not the diffs:
- Fix incorrect descriptions
- Add breaking changes, workarounds, and security fixes you found in the diff
- Ensure `libsignal_frb` version in Highlights matches `rust/Cargo.toml`

### Step 8: Verify libsignal_frb Version Bump

The automated update bumps the version in `rust/Cargo.toml` in two stages:
a deterministic bump mirroring the upstream SemVer delta, then an AI severity
check (from the release notes and commit list) that can raise it — e.g. to
major when a 0.x upstream ships breaking changes in a minor release.

- If the PR carries the **`bump-unverified`** label (or the ⚠️ warning in the
  PR body), the AI check did not run — classify the update yourself using
  your Step 1 findings and fix the version if needed.
- Even when verified, adjust if the *wrapper's own* API changed differently —
  e.g. bump major if adapting to upstream forced breaking changes in
  `rust/src/api/`:

```toml
version = "X.Y.Z"
```

### Step 9: Sync Cargo.lock

```bash
make rust-check
```

### Step 9b: Re-validate the advisory ignores

`.cargo/audit.toml` and `rust/deny.toml` carry ignores that were justified
against the dependency graph as it stood when each was added. A bump moves that
graph: an advisory can become unreachable, or a new one can arrive in the same
crate an old entry silently covers.

Empty both lists, run `make rust-audit` and `make rust-deny`, and re-add only
what fires again — each with a reason written for the graph as it is now. An
entry that matches nothing is reported by cargo-deny as `advisory-not-detected`
and should be deleted rather than kept in case the crate comes back; the two
files are not interchangeable either, since cargo-deny also reports
*unmaintained* advisories that `cargo audit` does not fail on.

### Step 10: Commit Changes

```bash
git add rust/Cargo.toml rust/Cargo.lock rust/src/api/ lib/src/rust/ CHANGELOG.md
git commit -m "fix: adapt for libsignal vX.Y.Z breaking changes"
```

### Checklist Summary

- [ ] Read release notes AND the actual commit list / diff between the tags
- [ ] Check the diff against the API surface bound in `rust/src/api/`
- [ ] Fix Rust compilation errors (if any)
- [ ] `make codegen` — regenerate FRB bindings
- [ ] `make test` — all tests pass
- [ ] `make analyze` — no issues
- [ ] CHANGELOG.md — accurate and complete (breaking changes, security fixes)
- [ ] `rust/Cargo.toml` — `libsignal_frb` version bumped (automatic; verify)
- [ ] An `E0599` was checked against the upstream feature table before being
      treated as a removal
- [ ] No diagnostic/test-only upstream feature ships — checked with `strings`
      on the built artifacts, not by reading the manifest
- [ ] Advisory ignores emptied and re-added from what still fires
- [ ] MSRV: `rust-version` and the `rust_version` answer moved together
- [ ] `make rust-check` — sync Cargo.lock
- [ ] Commit all changes

---

## Quick Update (Automatic)

```bash
# Check for updates
make check-new-libsignal-version

# Check and apply updates automatically
make check-new-libsignal-version ARGS="--update"
```

This will:
1. Check GitHub for latest libsignal release
2. Update `rust/Cargo.toml` with new libsignal dependency tags
3. Show next steps for completing the update

## Manual Update Process

### Step 1: Check Current Version

Check `rust/Cargo.toml`:
```toml
[dependencies]
libsignal-protocol = { git = "https://github.com/signalapp/libsignal", tag = "v0.97.3" }
```

### Step 2: Update Version

Edit `rust/Cargo.toml` and update the tag for all three libsignal crates:
- `libsignal-protocol`
- `libsignal-core`
- `signal-crypto`

### Step 3: Update Cargo.lock

```bash
make rust-update
```

### Step 4: Regenerate FRB Bindings (if API changed)

```bash
make codegen
```

### Step 5: Run Tests

```bash
make test
```

### Step 6: Commit Changes

```bash
git add rust/Cargo.toml rust/Cargo.lock
git commit -m "chore(deps): update libsignal to vX.Y.Z"
git push
```

## Check Options

```bash
# Just check (no changes)
make check-new-libsignal-version

# Check and update
make check-new-libsignal-version ARGS="--update"

# Update to specific version
make check-new-libsignal-version ARGS="--update --version v0.97.3"

# Force update even if versions match
make check-new-libsignal-version ARGS="--update --force"

# JSON output for CI
make check-new-libsignal-version ARGS="--json"
```

## Version Locations

Files automatically updated by `make check-new-libsignal-version ARGS="--update"`:

| File | What | Description |
|------|------|-------------|
| `rust/Cargo.toml` | libsignal-* tags | Native library dependency version |
| `rust/Cargo.toml` | `version` | `libsignal_frb` bump mirroring upstream SemVer delta (adjust manually if wrapper API changed differently) |
| `README.md` | Badge | Version badge in header |
| `CLAUDE.md` | Example | Code example in documentation |

Files that need manual update:

| File | What | Description |
|------|------|-------------|
| `rust/Cargo.lock` | Dependencies | Run `make rust-update` after changing Cargo.toml |
| `CHANGELOG.md` | Entry | AI-generated in CI; verify against the upstream diff |

## Breaking Changes to Watch For

### API Changes
- New functions in libsignal-protocol crate
- Removed functions
- Changed function signatures
- New struct fields

### Behavior Changes
- Protocol version updates
- New cryptographic algorithms (e.g., Kyber/ML-KEM)
- Changed error types

### Binding Regeneration

After updating, if API changed, run:
```bash
make codegen
```

Then check for:
- Compilation errors in `rust/src/api/` files
- Missing functions that your code depends on
- Changed function signatures

## Troubleshooting

### "No updates available"
- You're already on the latest version
- Check https://github.com/signalapp/libsignal/releases

### "Cargo build failed"
- New libsignal version may have breaking API changes
- Check libsignal release notes
- May need to update Rust wrapper code in `rust/src/api/`

### Tests fail after update
- API may have changed
- Protocol version may have changed
- Review libsignal changelog for breaking changes

## Upstream Resources

- [libsignal Releases](https://github.com/signalapp/libsignal/releases)
- [libsignal Repository](https://github.com/signalapp/libsignal)
- [Signal Protocol Specification](https://signal.org/docs/)
