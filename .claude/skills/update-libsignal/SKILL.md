---
name: update-libsignal
description: Update libsignal native library version. Use when checking for updates, upgrading libsignal, bumping version, or updating native dependencies.
---

# Update libsignal Version

Guide for updating the libsignal native library version in this project.

## Quick Update (Automatic)

```bash
# Check for updates
make check

# Check and apply updates automatically
make check ARGS="--update"
```

This will:
1. Check GitHub for latest libsignal release
2. Update `pubspec.yaml` with new `libsignal.native_version`
3. Update CHANGELOG.md with new entry

## Manual Update Process

### Step 1: Check Current Version

```bash
make version
```

Or check `pubspec.yaml`:
```yaml
libsignal:
  native_version: "0.86.10"  # Current version
```

### Step 2: Update Version

Edit `pubspec.yaml`:
```yaml
libsignal:
  native_version: "0.87.0"  # New version
```

### Step 3: Regenerate FFI Bindings

```bash
make regen
```

This downloads the new libsignal headers and regenerates `lib/src/bindings/libsignal_bindings.dart`.

### Step 4: Run Tests

```bash
make test
```

### Step 5: Commit Changes

```bash
git add pubspec.yaml lib/src/bindings/ CHANGELOG.md
git commit -m "Update libsignal to 0.87.0"
git push
```

CI will automatically build native libraries for all platforms.

## Check Options

```bash
# Just check (no changes)
make check

# Check and update
make check ARGS="--update"

# Update to specific version
make check ARGS="--update --version 0.87.0"

# Force version bump type
make check ARGS="--update --bump major"
make check ARGS="--update --bump minor"
make check ARGS="--update --bump patch"

# Skip changelog (CI uses this)
make check ARGS="--update --no-changelog"

# JSON output for CI
make check ARGS="--json"
```

## Version Locations

| File | Field | Description |
|------|-------|-------------|
| `pubspec.yaml` | `libsignal.native_version` | Native library version |
| `pubspec.yaml` | `version` | Dart package version |
| `CHANGELOG.md` | Latest entry | What changed |

## After CI Builds

When CI completes after pushing:

1. Native libraries are built for all platforms
2. Artifacts are combined
3. FFI bindings are regenerated (if API changed)
4. SHA256 checksums created for verification
5. GitHub Release created with assets

## Breaking Changes to Watch For

### API Changes
- New functions in `signal_ffi.h`
- Removed functions
- Changed function signatures
- New struct fields

### Behavior Changes
- Protocol version updates
- New cryptographic algorithms (e.g., Kyber/ML-KEM)
- Changed error codes

### Binding Regeneration

After `make regen`, check for:
- Compilation errors in `lib/src/bindings/libsignal_bindings.dart`
- Missing functions that your code depends on
- Changed function signatures

## Troubleshooting

### "No updates available"
- You're already on the latest version
- Check https://github.com/signalapp/libsignal/releases

### "Binding generation failed"
- New libsignal version may have breaking API changes
- Check libsignal release notes
- May need to update wrapper code in `lib/src/`

### Tests fail after update
- API may have changed
- Protocol version may have changed
- Review libsignal changelog for breaking changes

### ARM64 Issues
Some functions may have ABI issues on ARM64. Check `CLAUDE.md` for workarounds.

## Upstream Resources

- [libsignal Releases](https://github.com/signalapp/libsignal/releases)
- [libsignal Repository](https://github.com/signalapp/libsignal)
- [Signal Protocol Specification](https://signal.org/docs/)
