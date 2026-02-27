# libsignal - Signal Protocol for Dart

[![pub package](https://img.shields.io/pub/v/libsignal.svg)](https://pub.dev/packages/libsignal)
[![CI](https://github.com/djx-y-z/libsignal_dart/actions/workflows/test.yml/badge.svg)](https://github.com/djx-y-z/libsignal_dart/actions/workflows/test.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/djx-y-z/246880c242ae85c452f4de0e6e91838c/raw/coverage.json)](https://gist.github.com/djx-y-z/246880c242ae85c452f4de0e6e91838c)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Dart](https://img.shields.io/badge/dart-%3E%3D3.10.0-brightgreen.svg)](https://dart.dev)
[![Flutter](https://img.shields.io/badge/flutter-%3E%3D3.38.0-blue.svg)](https://flutter.dev)
[![libsignal](https://img.shields.io/badge/libsignal-v0.87.5-orange.svg)](https://github.com/signalapp/libsignal)

Dart bindings for [libsignal](https://github.com/signalapp/libsignal), providing Signal Protocol implementation for end-to-end encryption, sealed sender, group messaging, and secure cryptographic operations.

## Platform Support

|             | Android | iOS   | macOS  | Linux      | Windows | Web |
|-------------|---------|-------|--------|------------|---------|-----|
| **Support** | SDK 24+ | 13.0+ | 10.15+ | arm64, x64 | x64     | WASM |
| **Arch**    | arm64, armv7, x64 | arm64 | arm64, x64 | arm64, x64 | x64 | wasm32 |

## Features

- **Flutter & CLI Support**: Works with Flutter apps and standalone Dart CLI applications
- **Signal Protocol**: End-to-end encryption with perfect forward secrecy (Double Ratchet, X3DH)
- **Sealed Sender**: Anonymous message sending (server won't know who sent the message)
- **Group Messaging**: Efficient group encryption using SenderKey distribution
- **Automatic Builds**: Native libraries downloaded automatically via build hooks
- **High Performance**: Direct Rust integration via Flutter Rust Bridge

## Implementation Status

Overview of wrapped functionality from the native [libsignal](https://github.com/signalapp/libsignal) library:

| Category | Status | Description |
|----------|:------:|-------------|
| Signal Protocol | ✓ | Double Ratchet, X3DH, session encryption/decryption |
| Key Management | ✓ | Ed25519, X25519, Kyber (post-quantum) |
| Pre-Keys | ✓ | Regular, signed, and Kyber pre-keys |
| Group Messaging | ✓ | SenderKey protocol for efficient group encryption |
| Sealed Sender | ✓ | Anonymous message sending with certificates |
| Fingerprints | ✓ | Safety numbers for identity verification |
| Crypto Utilities | ✓ | HKDF, AES-256-GCM-SIV |
| Store Interfaces | ✓ | All 6 store types with in-memory implementations |
| zkgroup | ✗ | Zero-knowledge groups, profile credentials |
| Registration | ✗ | Account registration service |
| Backup | ✗ | Message backup and restore |
| SVR | ✗ | Secure Value Recovery (PIN-based backup) |
| Call Links | ✗ | Call link credentials and authentication |
| Connection Manager | ✗ | Network connection handling |

<details>
<summary><strong>Detailed Implementation</strong></summary>

### Implemented Features

#### Keys

| Class | Key Methods |
|-------|-------------|
| `PrivateKey` | generate, sign, agree, serialize |
| `PublicKey` | verify, serialize, compare |
| `IdentityKeyPair` | generate, serialize, signAlternateIdentity |

#### Protocol

| Class | Key Methods |
|-------|-------------|
| `SessionCipher` | encrypt, decryptSignalMessage, decryptPreKeySignalMessage |
| `SessionBuilder` | processPreKeyBundle |
| `SessionRecord` | serialize, deserialize |
| `ProtocolAddress` | new, name, deviceId |
| `SignalMessage` | serialize, body, counter, verifyMac |
| `PreKeySignalMessage` | serialize, preKeyId, signedPreKeyId |

#### Groups

| Class | Key Methods |
|-------|-------------|
| `GroupSession` | createDistributionMessage, encrypt, decrypt |
| `SenderKeyRecord` | serialize, deserialize |
| `SenderKeyMessage` | serialize, getDistributionId |
| `SenderKeyDistributionMessage` | create, serialize |

#### Sealed Sender

| Class | Key Methods |
|-------|-------------|
| `SealedSessionCipher` | encrypt, decrypt |
| `SenderCertificate` | create, validate, serialize |
| `ServerCertificate` | create, serialize |
| `UnidentifiedSenderMessageContent` | create, serialize |

#### Crypto

| Class | Key Methods |
|-------|-------------|
| `Hkdf` | deriveSecrets |
| `Aes256GcmSiv` | encrypt, decrypt |
| `Fingerprint` | displayString, scannableEncoding, compare |

#### Stores

| Interface | In-Memory Implementation | Purpose |
|-----------|-------------------------|---------|
| `SessionStore` | `InMemorySessionStore` | Session state persistence |
| `IdentityKeyStore` | `InMemoryIdentityKeyStore` | Identity key management |
| `PreKeyStore` | `InMemoryPreKeyStore` | One-time pre-keys |
| `SignedPreKeyStore` | `InMemorySignedPreKeyStore` | Signed pre-keys |
| `KyberPreKeyStore` | `InMemoryKyberPreKeyStore` | Post-quantum pre-keys |
| `SenderKeyStore` | `InMemorySenderKeyStore` | Group messaging keys |

### Not Implemented

| Category | Reason |
|----------|--------|
| zkgroup | Server-side verification, not needed for basic messaging |
| Registration | Account registration service |
| Backup | Message backup and restore |
| SVR | Secure Value Recovery for PIN-based backup |
| Call Links | Call link credentials |
| Connection Manager | Network connection handling |
| HSM Enclave | Hardware security module communication |
| CDSI | Contact Discovery Service |

</details>

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  libsignal: ^x.x.x
```

Native libraries are downloaded automatically during build via Dart build hooks.

**No Rust required** for end users - precompiled binaries are downloaded from GitHub Releases. Fallback to source build if Rust is installed.

### Web Support

For web builds, WASM files are automatically downloaded to `web/pkg/` during the build process.

**Manual setup** (if automatic download fails):
```bash
# In the libsignal package directory
make build-web
```

Then copy `rust/target/wasm32/` files to your app's `web/pkg/` directory.

## Quick Start

```dart
import 'package:libsignal/libsignal.dart';

void main() async {
  // Initialize the library
  await LibSignal.init();

  // Generate identity key pair
  final identity = IdentityKeyPair.generate();
  print('Identity public key: ${identity.publicKey.length} bytes');

  // Clean up when done
  LibSignal.cleanup();
}
```

## API Reference

### Key Types

```dart
import 'package:libsignal/libsignal.dart';

// Identity Key Pair (long-term identity)
final identity = IdentityKeyPair.generate();
print('Public key length: ${identity.publicKey.length}');

// Pre-Key (one-time key for X3DH)
final preKeyPrivate = PrivateKey.generate();
final preKeyPublic = preKeyPrivate.getPublicKey();
final preKey = PreKeyRecord(
  id: 1,
  publicKey: preKeyPublic,
  privateKey: preKeyPrivate,
);

// Signed Pre-Key
final signedPreKeyPrivate = PrivateKey.generate();
final signedPreKeyPublic = signedPreKeyPrivate.getPublicKey();
final identityPrivate = PrivateKey.deserialize(bytes: identity.privateKey.toList());
final signature = identityPrivate.sign(message: signedPreKeyPublic.serialize().toList());
final signedPreKey = SignedPreKeyRecord(
  id: 1,
  timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
  publicKey: signedPreKeyPublic,
  privateKey: signedPreKeyPrivate,
  signature: signature.toList(),
);

// Kyber Pre-Key (post-quantum key exchange)
final kyberKeyPair = KyberKeyPair.generate();
final kyberSignature = identityPrivate.sign(
  message: kyberKeyPair.getPublicKey().serialize().toList(),
);
final kyberPreKey = KyberPreKeyRecord.create(
  id: 1,
  timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
  keyPair: kyberKeyPair,
  signature: kyberSignature.toList(),
);
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
// FRB handles cleanup automatically via finalizers
```

### Performance Optimization

For better performance, initialize once at app start:

```dart
void main() async {
  await LibSignal.init(); // Recommended at app startup
  runApp(MyApp());
}
```

## Security Notes

**Key Features:**
- **Signal Protocol** - Battle-tested encryption used by Signal, WhatsApp, and others
- **Perfect Forward Secrecy** - Past messages stay secure even if keys are compromised
- **Kyber Support** - Post-quantum key exchange for future-proof security
- **Rust Implementation** - All cryptographic operations run in Rust (libsignal-protocol) with constant-time implementations

**Best Practices:**
- Keep the library updated to the latest version
- Use UTC timestamps for certificate validation to avoid timezone issues
- Let the library handle cryptographic comparisons — avoid comparing secrets in Dart code
- Use `SecureBytes.wrap()` or `zeroize()` for sensitive data (serialized keys, shared secrets) — see [SECURITY.md](SECURITY.md)

## Stores

Signal Protocol requires persistent storage for session state (Double Ratchet). This library provides store interfaces and in-memory implementations.

### In-Memory Stores (Testing Only)

```dart
final sessionStore = InMemorySessionStore();
final identityStore = InMemoryIdentityKeyStore(identity, registrationId);
final preKeyStore = InMemoryPreKeyStore();
final signedPreKeyStore = InMemorySignedPreKeyStore();
final kyberPreKeyStore = InMemoryKyberPreKeyStore();
final senderKeyStore = InMemorySenderKeyStore();
```

> **Warning:** In-memory stores lose all data on app restart. Use only for:
> - Unit tests
> - Development/debugging
> - Demo applications

### Production Requirements

For production apps, implement the store interfaces with secure storage:

| Store | Purpose | Security Level |
|-------|---------|----------------|
| `SessionStore` | Encrypted session state | High (contains key material) |
| `IdentityKeyStore` | Identity keys | Critical (long-term secrets) |
| `PreKeyStore` | One-time pre-keys | High |
| `SignedPreKeyStore` | Signed pre-keys | High |
| `KyberPreKeyStore` | Post-quantum pre-keys | High |
| `SenderKeyStore` | Group messaging keys | High |

## Building from Source

### For End Users

**No setup required!** Precompiled native libraries are downloaded automatically from GitHub Releases during `flutter build`.

### For Contributors / Source Builds

If you want to build from source (or precompiled binaries are not available):

- [Flutter](https://flutter.dev/) 3.38+
- [FVM](https://fvm.app/) (optional, for version management)
- **Rust toolchain**:
  - [rustup](https://rustup.rs/) - Rust toolchain installer
  - `cargo` - Rust package manager (installed with rustup)
- **protoc** - Protocol Buffers compiler:
  - macOS: `brew install protobuf`
  - Ubuntu/Debian: `apt-get install protobuf-compiler`
  - Windows: [Download from GitHub](https://github.com/protocolbuffers/protobuf/releases)

### Setup

```bash
# Clone the repository
git clone https://github.com/djx-y-z/libsignal_dart.git
cd libsignal_dart

# Install FVM and dependencies
make setup

# Run tests
make test
```

### Available Commands

```bash
# Setup
make setup              # Install all required tools (Rust check, FVM, protoc, cargo-audit)
make setup-fvm          # Install FVM and project Flutter version only
make setup-protoc       # Install protoc (Protocol Buffers compiler)
make setup-rust-tools   # Install Rust tools (cargo-audit, flutter_rust_bridge_codegen)
make setup-web          # Install wasm-pack for web builds (optional)
make setup-android      # Install cargo-ndk for Android builds (optional)

# Development
make codegen            # Regenerate Flutter Rust Bridge bindings
make build              # Build Rust library locally (native)
make build-android      # Build for Android (requires cargo-ndk + NDK)
make build-web          # Build WASM for web (requires wasm-pack)

# CI / Version Management
make check-new-libsignal-version  # Check for new upstream libsignal version
make check-template-updates       # Check for new copier template version
make rust-update        # Update rust/Cargo.lock (cargo update)
make update-changelog   # Update CHANGELOG.md with AI (requires GITHUB_TOKEN)

# Quality Assurance
make test               # Run tests
make coverage           # Run tests with coverage report
make analyze            # Run static analysis
make rust-audit         # Check Rust dependencies for vulnerabilities
make rust-check         # Quick Rust type check (updates Cargo.lock)
make format             # Format Dart code
make format-check       # Check Dart code formatting
make doc                # Generate API documentation

# Utilities
make get                # Get dependencies
make clean              # Clean build artifacts
make help               # Show all commands
```

It also checks for copier template updates daily and creates notification PRs with changelog and update instructions.

## Architecture

```
┌─────────────────────────────────────────────┐
│     libsignal-protocol (Rust crate)         │  ← Core implementation
├─────────────────────────────────────────────┤
│       rust/src/api/*.rs (Rust wrappers)     │  ← FRB-annotated functions
├─────────────────────────────────────────────┤
│      lib/src/rust/*.dart (FRB generated)    │  ← Auto-generated Dart API
├─────────────────────────────────────────────┤
│           lib/src/stores/*.dart             │  ← Store interfaces
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
