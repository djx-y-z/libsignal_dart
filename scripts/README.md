# libsignal Build Scripts

Cross-platform Dart scripts for building libsignal native libraries.
These scripts work on Windows, macOS, and Linux.

> **Recommended:** Use `make build` instead of calling scripts directly.
> The Makefile automatically handles Build Hook skip markers to avoid
> chicken-and-egg problems during native library compilation.
> See the root [CLAUDE.md](../CLAUDE.md) for details.

## Prerequisites

- [FVM](https://fvm.app/) (Flutter Version Management)
- Rust toolchain (rustup, cargo)
- cbindgen (for C header generation)

## Quick Start

**Using Makefile (recommended):**
```bash
# Install FVM and project Flutter version
make setup

# Build for your current platform
make build ARGS="macos"
make build ARGS="linux"
make build ARGS="windows"

# List available platforms
make build ARGS="list"
```

**Direct script invocation (advanced):**
```bash
# Note: Direct invocation doesn't skip Build Hooks automatically.
# Use `touch .skip_libsignal_hook` before and `rm .skip_libsignal_hook` after.
fvm dart run scripts/build.dart macos
fvm dart run scripts/build.dart linux
fvm dart run scripts/build.dart windows
```

## Scripts

| Script | Description |
|--------|-------------|
| `build.dart` | Build native libraries for any platform |
| `regenerate_bindings.dart` | Regenerate Dart FFI bindings |
| `check_updates.dart` | Check for libsignal updates and update files |
| `combine_artifacts.dart` | Combine CI artifacts (used by GitHub Actions) |
| `get_version.dart` | Get version info from pubspec.yaml |

## Build Commands

### Linux

```bash
fvm dart run scripts/build.dart linux
```

Output: `bin/linux/libsignal_ffi.so`

Requirements: Rust toolchain, cbindgen

### macOS

```bash
# Universal Binary (default)
fvm dart run scripts/build.dart macos

# Specific architecture
fvm dart run scripts/build.dart macos --arch arm64
fvm dart run scripts/build.dart macos --arch x86_64
```

Output:
- `bin/macos/libsignal_ffi.dylib`
- `macos/Libraries/libsignal_ffi.dylib` (Flutter plugin)

Requirements: Rust toolchain, cbindgen, Xcode Command Line Tools

### iOS

```bash
# XCFramework with all targets (default)
fvm dart run scripts/build.dart ios

# Specific target
fvm dart run scripts/build.dart ios --target device
fvm dart run scripts/build.dart ios --target simulator-arm64
fvm dart run scripts/build.dart ios --target simulator-x86_64
```

Output: `ios/Libraries/libsignal_ffi.dylib`

Requirements: macOS, Rust toolchain, cbindgen, Xcode

### Android

```bash
# All ABIs (default)
fvm dart run scripts/build.dart android

# Specific ABI
fvm dart run scripts/build.dart android --abi arm64-v8a
fvm dart run scripts/build.dart android --abi armeabi-v7a
fvm dart run scripts/build.dart android --abi x86_64
```

Output: `android/src/main/jniLibs/{abi}/libsignal_ffi.so`

Requirements: Rust toolchain, cbindgen, Android NDK

**Android NDK Setup:**
```bash
# Option 1: Environment variable
export ANDROID_NDK_HOME=/path/to/ndk/26.3.11579264

# Option 2: Install via Android Studio
# SDK Manager → SDK Tools → NDK (Side by side)
```

### Windows

```bash
fvm dart run scripts/build.dart windows
```

Output: `bin/windows/signal_ffi.dll`

Requirements: Rust toolchain, Visual Studio with C++ workload

**Note:** Run from "Developer PowerShell for VS" or after running `vcvars64.bat`.

## Checking for Updates

Check for new libsignal releases and optionally update local files:

```bash
# Just check for updates
fvm dart run scripts/check_updates.dart

# Check and update pubspec.yaml and CHANGELOG.md
fvm dart run scripts/check_updates.dart --update

# Update to specific version
fvm dart run scripts/check_updates.dart --update --version v0.87.0

# Force major version bump
fvm dart run scripts/check_updates.dart --update --bump major

# Update without changelog (for CI - AI generates changelog separately)
fvm dart run scripts/check_updates.dart --update --no-changelog

# Output JSON for CI integration
fvm dart run scripts/check_updates.dart --json
```

This script is used by both local development and the `check-libsignal-updates.yml` workflow.
The workflow uses `--no-changelog` flag and generates AI-enhanced changelog separately.

## Getting Version Information

```bash
# Show all version info
fvm dart run scripts/get_version.dart

# Get specific field
fvm dart run scripts/get_version.dart --field version
fvm dart run scripts/get_version.dart --field build
fvm dart run scripts/get_version.dart --field full

# Output as JSON
fvm dart run scripts/get_version.dart --json
```

Or use Makefile shortcuts:
```bash
make version         # Show all version info
make get-version     # Just native_version
make get-build       # Just native_build
make get-full-version # version + build (e.g., v0.86.9-1)
```

## Regenerating FFI Bindings

When updating libsignal version:

```bash
# Option 1: Automatic update (recommended)
make check ARGS="--update"

# Option 2: Manual update
# Edit pubspec.yaml - update libsignal.native_version to new version

# Regenerate bindings
make regen

# Test
make test
```

## Platform Requirements Summary

| Platform | Build OS | Requirements |
|----------|----------|--------------|
| Linux | Linux | Rust, cbindgen |
| macOS | macOS | Rust, cbindgen, Xcode CLI |
| iOS | macOS | Rust, cbindgen, Xcode |
| Android | Linux/macOS | Rust, cbindgen, Android NDK |
| Windows | Windows | Rust, Visual Studio |

## Rust Targets

| Platform | Rust Target |
|----------|-------------|
| Linux x86_64 | `x86_64-unknown-linux-gnu` |
| Linux arm64 | `aarch64-unknown-linux-gnu` |
| macOS arm64 | `aarch64-apple-darwin` |
| macOS x86_64 | `x86_64-apple-darwin` |
| iOS device | `aarch64-apple-ios` |
| iOS simulator arm64 | `aarch64-apple-ios-sim` |
| iOS simulator x86_64 | `x86_64-apple-ios` |
| Android arm64 | `aarch64-linux-android` |
| Android arm | `armv7-linux-androideabi` |
| Android x86_64 | `x86_64-linux-android` |
| Windows | `x86_64-pc-windows-msvc` |

## CI Integration

These scripts are used by GitHub Actions workflow (`.github/workflows/build-libsignal.yml`).
The workflow:
1. Builds each platform on appropriate runners
2. Uploads artifacts
3. Combines artifacts using `combine_artifacts.dart`
4. Regenerates FFI bindings
5. Commits to repository

## Why Dart Scripts?

Previous shell scripts had cross-platform issues:
- `.sh` scripts don't work natively on Windows
- `.ps1` scripts don't work on Linux/macOS

Dart scripts solve this:
- FVM provides consistent Dart SDK version
- Same script works on all platforms
- Easier to maintain (one language)
- Better error handling and debugging
