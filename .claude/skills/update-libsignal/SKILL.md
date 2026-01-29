---
name: update-libsignal
description: Update libsignal native library version. Use when checking for updates, upgrading libsignal, bumping version, or updating native dependencies.
---

# Update libsignal Version

Guide for updating the libsignal native library version in this project.

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
libsignal-protocol = { git = "https://github.com/signalapp/libsignal", tag = "v0.86.15" }
```

### Step 2: Update Version

Edit `rust/Cargo.toml` and update the tag for all three libsignal crates:
- `libsignal-protocol`
- `libsignal-core`
- `signal-crypto`

### Step 3: Update Cargo.lock

```bash
cd rust && cargo update && cd ..
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
git commit -m "chore(deps): update libsignal to v0.87.0"
git push
```

## Check Options

```bash
# Just check (no changes)
make check-new-libsignal-version

# Check and update
make check-new-libsignal-version ARGS="--update"

# Update to specific version
make check-new-libsignal-version ARGS="--update --version v0.87.0"

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
| `README.md` | Badge | Version badge in header |
| `CLAUDE.md` | Example | Code example in documentation |
| `.claude/skills/update-libsignal/SKILL.md` | Example | Code example in skill |

Files that need manual update:

| File | What | Description |
|------|------|-------------|
| `rust/Cargo.toml` | `version` | Rust crate version (bump patch for deps update) |
| `rust/Cargo.lock` | Dependencies | Run `cargo update` after changing Cargo.toml |
| `CHANGELOG.md` | Entry | Document the libsignal version change |

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
