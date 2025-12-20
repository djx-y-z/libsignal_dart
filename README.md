# libsignal

Dart FFI bindings for [libsignal](https://github.com/signalapp/libsignal) — Signal Protocol implementation for end-to-end encryption, sealed sender, group messaging, and secure cryptographic operations.

[![pub package](https://img.shields.io/pub/v/libsignal.svg)](https://pub.dev/packages/libsignal)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://opensource.org/licenses/AGPL-3.0)

## Features

- **Signal Protocol** — End-to-end encryption with perfect forward secrecy (Double Ratchet, X3DH)
- **Sealed Sender** — Anonymous message sending
- **Group Messaging** — Efficient group encryption using SenderKey
- **Cross-platform** — Android, iOS, Linux, macOS, Windows
- **Automatic native library management** — Build hooks download pre-built libraries

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  libsignal: ^0.1.0
```

Native libraries are downloaded automatically during the build process.

## Supported Platforms

| Platform | Architecture | Status |
|----------|--------------|--------|
| Android | arm64-v8a, armeabi-v7a, x86_64 | ✅ |
| iOS | arm64 (device), arm64/x86_64 (simulator) | ✅ |
| Linux | x86_64, arm64 | ✅ |
| macOS | arm64, x86_64 | ✅ |
| Windows | x86_64 | ✅ |

## Quick Start

```dart
import 'package:libsignal/libsignal.dart';

void main() {
  // Initialize the library
  LibSignal.init();

  // Get supported algorithms
  final algorithms = LibSignal.getSupportedAlgorithms();
  print('Key agreement: ${algorithms['key_agreement']}');
  print('Signatures: ${algorithms['signature']}');

  // Clean up when done
  LibSignal.cleanup();
}
```

## Documentation

- [API Reference](https://pub.dev/documentation/libsignal/latest/)
- [Signal Protocol Specification](https://signal.org/docs/)
- [libsignal Repository](https://github.com/signalapp/libsignal)

## Building from Source

### Prerequisites

- [Rust](https://rustup.rs/) (for building native libraries)
- [Flutter](https://flutter.dev/) 3.38+
- [FVM](https://fvm.app/) (optional, for version management)

### Setup

```bash
# Clone the repository
git clone https://github.com/djx-y-z/libsignal_dart.git
cd libsignal_dart

# Install dependencies
make setup

# Build native libraries for your platform
make build ARGS="macos"  # or linux, windows, ios, android
```

### Available Commands

```bash
make help           # Show all commands
make build ARGS="<platform>"  # Build native libraries
make test           # Run tests
make analyze        # Static analysis
make regen          # Regenerate FFI bindings
```

## How It Works

1. **Native Library Build**: libsignal is built from Rust source using Cargo
2. **C Headers**: cbindgen generates C headers from Rust FFI layer
3. **Dart Bindings**: ffigen generates Dart bindings from C headers
4. **Build Hooks**: Dart build hooks download pre-built libraries from GitHub Releases

## Architecture

```
┌─────────────────────────────────────────────┐
│           libsignal (Rust)                  │  ← Core implementation
├─────────────────────────────────────────────┤
│           libsignal-ffi (Rust)              │  ← C FFI layer
├─────────────────────────────────────────────┤
│          signal_ffi.h (C header)            │  ← cbindgen output
├─────────────────────────────────────────────┤
│     libsignal_bindings.dart (Dart FFI)      │  ← ffigen output
├─────────────────────────────────────────────┤
│         libsignal (Dart API)                │  ← High-level API
└─────────────────────────────────────────────┘
```

## Security

This package wraps the official Signal libsignal library. All cryptographic operations are performed by the native library, which is audited and used in production by Signal.

- All native libraries are built from source in GitHub Actions
- SHA256 checksums are verified during download
- Sensitive data is securely zeroed before freeing

## Contributing

Contributions are welcome! Please read the [contributing guidelines](CONTRIBUTING.md) first.

## License

This project is licensed under the [AGPL-3.0 License](LICENSE), consistent with the upstream libsignal library.

## Acknowledgments

- [Signal](https://signal.org/) for the libsignal library
- [liboqs_dart](https://github.com/djx-y-z/liboqs_dart) for architecture inspiration
