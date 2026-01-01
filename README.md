# libsignal - Signal Protocol for Dart

[![pub package](https://img.shields.io/pub/v/libsignal.svg)](https://pub.dev/packages/libsignal)
[![CI](https://github.com/djx-y-z/libsignal_dart/actions/workflows/test.yml/badge.svg)](https://github.com/djx-y-z/libsignal_dart/actions/workflows/test.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/djx-y-z/246880c242ae85c452f4de0e6e91838c/raw/coverage.json)](https://gist.github.com/djx-y-z/246880c242ae85c452f4de0e6e91838c)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Dart](https://img.shields.io/badge/dart-%3E%3D3.10.0-brightgreen.svg)](https://dart.dev)
[![Flutter](https://img.shields.io/badge/flutter-%3E%3D3.38.0-blue.svg)](https://flutter.dev)
[![libsignal](https://img.shields.io/badge/libsignal-v0.86.9-orange.svg)](https://github.com/signalapp/libsignal)

A Dart FFI wrapper for [libsignal](https://github.com/signalapp/libsignal), providing Signal Protocol implementation for end-to-end encryption, sealed sender, group messaging, and secure cryptographic operations.

## Platform Support

|             | Android | iOS   | macOS  | Linux      | Windows |
|-------------|---------|-------|--------|------------|---------|
| **Support** | SDK 21+ | 12.0+ | 10.14+ | arm64, x64 | x64     |
| **Arch**    | arm64, armv7, x64 | arm64 | arm64, x64 | arm64, x64 | x64 |

## Features

- **Flutter & CLI Support**: Works with Flutter apps and standalone Dart CLI applications
- **Signal Protocol**: End-to-end encryption with perfect forward secrecy (Double Ratchet, X3DH)
- **Sealed Sender**: Anonymous message sending (server won't know who sent the message)
- **Group Messaging**: Efficient group encryption using SenderKey distribution
- **Zero Configuration**: Pre-built native libraries included via Build Hooks
- **High Performance**: Direct FFI bindings with minimal overhead
- **Automated Updates**: Native libraries auto-rebuild when new libsignal versions are released

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  libsignal: ^1.0.0
```

Native libraries are downloaded automatically during the build process.

## Quick Start

```dart
import 'package:libsignal/libsignal.dart';

void main() {
  // Initialize the library (optional but recommended for performance)
  LibSignal.init();

  // Generate identity key pair
  final identity = IdentityKeyPair.generate();
  print('Identity public key: ${identity.publicKey.serialize().length} bytes');

  // Clean up when done
  identity.dispose();
  LibSignal.cleanup();
}
```

## API Reference

### Key Types

```dart
import 'package:libsignal/libsignal.dart';

// Identity Key Pair (long-term identity)
final identity = IdentityKeyPair.generate();
print('Public key length: ${identity.publicKey.serialize().length}');
print('Private key length: ${identity.privateKey.serialize().length}');

// Pre-Keys (one-time keys for X3DH)
final preKey = PreKeyPair.generate(preKeyId: 1);
final signedPreKey = SignedPreKeyPair.generate(
  signedPreKeyId: 1,
  identityKeyPair: identity,
);

// Kyber Pre-Keys (post-quantum key exchange)
final kyberPreKey = KyberPreKeyPair.generate(
  kyberPreKeyId: 1,
  identityKeyPair: identity,
);

// Clean up
identity.dispose();
preKey.dispose();
signedPreKey.dispose();
kyberPreKey.dispose();
```

### Session Encryption (Double Ratchet)

```dart
import 'package:libsignal/libsignal.dart';

// Create stores
final sessionStore = InMemorySessionStore();
final identityStore = InMemoryIdentityKeyStore(identity, registrationId);

// Build session from pre-key bundle
final builder = SessionBuilder(
  sessionStore: sessionStore,
  identityKeyStore: identityStore,
);
await builder.processPreKeyBundle(recipientAddress, preKeyBundle);

// Encrypt messages
final cipher = SessionCipher(
  sessionStore: sessionStore,
  identityKeyStore: identityStore,
);
final encrypted = await cipher.encrypt(recipientAddress, plaintext);

// Decrypt messages
final decrypted = await cipher.decrypt(senderAddress, ciphertext);
```

### Sealed Sender (Anonymous Messaging)

```dart
import 'package:libsignal/libsignal.dart';

// Create sealed session cipher
final sealedCipher = SealedSessionCipher(
  sessionStore: sessionStore,
  identityKeyStore: identityStore,
);

// Create sender certificate (issued by server)
final senderCert = SenderCertificate.create(
  senderUuid: 'my-uuid',
  deviceId: 1,
  senderKey: identity.publicKey,
  expiration: DateTime.now().toUtc().add(Duration(days: 30)),
  signerCertificate: serverCert,
  signerKey: serverPrivateKey,
);

// Encrypt with sealed sender (server won't know who sent it)
final sealed = await sealedCipher.encrypt(
  recipientAddress,
  plaintext,
  senderCert,
  contentHint: ContentHint.resendable,
);

// Recipient decrypts and learns sender identity
final result = await recipientCipher.decrypt(
  sealed,
  trustRoot: trustRootPublicKey,
  timestamp: DateTime.now().toUtc(),
  localUuid: 'recipient-uuid',
  localDeviceId: 1,
);
print('Message from: ${result.senderUuid}');
```

### Group Messaging (SenderKey)

```dart
import 'package:libsignal/libsignal.dart';

// Create group session
final groupSession = GroupSession(
  senderKeyStore: InMemorySenderKeyStore(),
);

// Create distribution message (send to all group members)
final distributionMessage = await groupSession.createDistributionMessage(
  sender: myAddress,
  distributionId: groupId,
);

// Encrypt for group
final groupCiphertext = await groupSession.encrypt(
  sender: myAddress,
  distributionId: groupId,
  plaintext: message,
);

// Decrypt group message
final plaintext = await groupSession.decrypt(
  sender: senderAddress,
  distributionId: groupId,
  ciphertext: groupCiphertext,
);
```

## Resource Management

### Basic Usage

```dart
final identity = IdentityKeyPair.generate();
// Use identity...
identity.dispose(); // Clean up when done
```

### Performance Optimization

For better performance, initialize once at app start:

```dart
void main() {
  LibSignal.init(); // Recommended at app startup
  runApp(MyApp());
}
```

## Security Notes

**Key Features:**
- **Signal Protocol** - Battle-tested encryption used by Signal, WhatsApp, and others
- **Perfect Forward Secrecy** - Past messages stay secure even if keys are compromised
- **Kyber Support** - Post-quantum key exchange for future-proof security

**Best Practices:**
- Always call `dispose()` on key pairs and sessions to free native resources
- Call `clearSecrets()` on sensitive data when done for immediate memory zeroing
- Secrets are also auto-zeroed via Finalizers on GC (defense-in-depth), but don't rely solely on this
- Use `LibSignalUtils.constantTimeEquals()` for comparing secrets (prevents timing attacks)
- Keep the library updated to the latest version
- Use UTC timestamps for certificate validation to avoid timezone issues

```dart
// Secure usage example
final identity = IdentityKeyPair.generate();
// ... use identity for encryption ...

// Clean up sensitive data
identity.clearSecrets();
identity.dispose();
```

## Building from Source

### Prerequisites

- [Flutter](https://flutter.dev/) 3.38+
- [FVM](https://fvm.app/) (optional, for version management)
- **Rust toolchain** (for building native libraries):
  - [rustup](https://rustup.rs/) - Rust toolchain installer and version manager
  - `cargo` - Rust package manager (installed automatically with rustup)
  - `cbindgen` - C header generator (installed automatically during build via `cargo install`)

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
make coverage       # Run tests with coverage report
make analyze        # Static analysis
make regen          # Regenerate FFI bindings
```

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

## Acknowledgements

This library would not be possible without [libsignal](https://github.com/signalapp/libsignal) by [Signal](https://signal.org/), which provides the underlying Rust implementation of the Signal Protocol.

## License

This project is licensed under the AGPL-3.0 License - see the [LICENSE](LICENSE) file for details.

The bundled libsignal library is also licensed under AGPL-3.0 - see [LICENSE.libsignal](LICENSE.libsignal) for the Signal license.

## Related Projects

- [libsignal](https://github.com/signalapp/libsignal) - The underlying Rust library
- [Signal](https://signal.org/) - The Signal project
- [Signal Protocol Specification](https://signal.org/docs/) - Protocol documentation

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting issues or pull requests.

For major changes, please open an issue first to discuss what you would like to change.
