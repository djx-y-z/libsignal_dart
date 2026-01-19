# libsignal - Signal Protocol for Dart

[![pub package](https://img.shields.io/pub/v/libsignal.svg)](https://pub.dev/packages/libsignal)
[![CI](https://github.com/djx-y-z/libsignal_dart/actions/workflows/test.yml/badge.svg)](https://github.com/djx-y-z/libsignal_dart/actions/workflows/test.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/djx-y-z/246880c242ae85c452f4de0e6e91838c/raw/coverage.json)](https://gist.github.com/djx-y-z/246880c242ae85c452f4de0e6e91838c)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Dart](https://img.shields.io/badge/dart-%3E%3D3.10.0-brightgreen.svg)](https://dart.dev)
[![Flutter](https://img.shields.io/badge/flutter-%3E%3D3.38.0-blue.svg)](https://flutter.dev)
[![libsignal](https://img.shields.io/badge/libsignal-v0.86.12-orange.svg)](https://github.com/signalapp/libsignal)

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

#### Keys (`lib/src/keys/`)

| Class | Key Methods | Native Functions |
|-------|-------------|------------------|
| `PrivateKey` | generate, sign, agree, serialize | `signal_privatekey_*` |
| `PublicKey` | verify, serialize, compare | `signal_publickey_*` |
| `IdentityKeyPair` | generate, serialize, signAlternateIdentity | `signal_identitykeypair_*` |
| `PreKeyPair` | generate, serialize | `signal_pre_key_record_*` |
| `SignedPreKeyPair` | generate, serialize | `signal_signed_pre_key_record_*` |
| `KyberPreKeyPair` | generate, serialize | `signal_kyber_*` |

#### Protocol (`lib/src/protocol/`)

| Class | Key Methods | Native Functions |
|-------|-------------|------------------|
| `SessionCipher` | encrypt, decryptSignalMessage, decryptPreKeySignalMessage | `signal_encrypt_message`, `signal_decrypt_*` |
| `SessionBuilder` | processPreKeyBundle | `signal_process_prekey_bundle` |
| `SessionRecord` | serialize, deserialize | `signal_session_record_*` |
| `ProtocolAddress` | new, name, deviceId | `signal_address_*` |
| `SignalMessage` | serialize, body, counter, verifyMac | `signal_message_*` |
| `PreKeySignalMessage` | serialize, preKeyId, signedPreKeyId | `signal_pre_key_signal_message_*` |

#### Groups (`lib/src/groups/`)

| Class | Key Methods | Native Functions |
|-------|-------------|------------------|
| `GroupSession` | createDistributionMessage, encrypt, decrypt | `signal_group_encrypt_message`, `signal_group_decrypt_message` |
| `SenderKeyRecord` | serialize, deserialize | `signal_sender_key_record_*` |
| `SenderKeyMessage` | serialize, getDistributionId | `signal_sender_key_message_*` |
| `SenderKeyDistributionMessage` | create, serialize | `signal_sender_key_distribution_message_*` |

#### Sealed Sender (`lib/src/sealed_sender/`)

| Class | Key Methods | Native Functions |
|-------|-------------|------------------|
| `SealedSessionCipher` | encrypt, decrypt | `signal_sealed_session_cipher_*` |
| `SenderCertificate` | create, validate, serialize | `signal_sender_certificate_*` |
| `ServerCertificate` | create, serialize | `signal_server_certificate_*` |
| `UnidentifiedSenderMessageContent` | create, serialize | `signal_unidentified_sender_message_content_*` |

#### Crypto (`lib/src/crypto/`)

| Class | Key Methods | Native Functions |
|-------|-------------|------------------|
| `Hkdf` | deriveSecrets | `signal_hkdf_derive` |
| `Aes256GcmSiv` | encrypt, decrypt | `signal_aes_gcm_siv_*` |
| `Fingerprint` | displayString, scannableEncoding, compare | `signal_fingerprint_*` |

#### Stores (`lib/src/stores/`)

| Interface | In-Memory Implementation | Purpose |
|-----------|-------------------------|---------|
| `SessionStore` | `InMemorySessionStore` | Session state persistence |
| `IdentityKeyStore` | `InMemoryIdentityKeyStore` | Identity key management |
| `PreKeyStore` | `InMemoryPreKeyStore` | One-time pre-keys |
| `SignedPreKeyStore` | `InMemorySignedPreKeyStore` | Signed pre-keys |
| `KyberPreKeyStore` | `InMemoryKyberPreKeyStore` | Post-quantum pre-keys |
| `SenderKeyStore` | `InMemorySenderKeyStore` | Group messaging keys |

### Not Implemented

| Category | Native Functions | Reason |
|----------|------------------|--------|
| zkgroup | `signal_group_secret_params_*`, `signal_profile_key_*` | Server-side verification, not needed for basic messaging |
| Registration | `signal_registration_*` | Account registration service |
| Backup | `signal_backup_*`, `signal_message_backup_*` | Message backup and restore |
| SVR | `signal_svr_*` | Secure Value Recovery for PIN-based backup |
| Call Links | `signal_call_link_*` | Call link credentials |
| Connection Manager | `signal_connection_manager_*` | Network connection handling |
| HSM Enclave | `signal_hsm_enclave_*` | Hardware security module communication |
| CDSI | `signal_cdsi_*` | Contact Discovery Service |

</details>

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  libsignal: ^x.x.x
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

**Recommended storage options:**
- `flutter_secure_storage` - for identity keys and other critical secrets
- `drift` / `sqflite` with SQLCipher - for session records
- `hive` with encryption - lightweight alternative

## Building from Source

### Prerequisites

- [Flutter](https://flutter.dev/) 3.38+
- [FVM](https://fvm.app/) (optional, for version management)
- **Rust toolchain** (for building native libraries):
  - [rustup](https://rustup.rs/) - Rust toolchain installer and version manager
  - `cargo` - Rust package manager (installed automatically with rustup)
  - `cbindgen` - C header generator (installed automatically during build via `cargo install`)
- **protoc** - Protocol Buffers compiler (required by libsignal's spqr dependency):
  - macOS: `brew install protobuf`
  - Ubuntu/Debian: `apt-get install protobuf-compiler`
  - Windows: [Download from GitHub](https://github.com/protocolbuffers/protobuf/releases)

### Setup

```bash
# Clone the repository
git clone https://github.com/djx-y-z/libsignal_dart.git
cd libsignal_dart

# Full setup (FVM + Rust + protoc)
make setup

# Or install components separately:
make setup-fvm      # FVM, Flutter, dependencies, git hooks
make setup-build    # Rust toolchain, protoc

# Build native libraries for your platform
make build ARGS="macos"  # or linux, windows, ios, android
```

### Available Commands

```bash
# Setup
make setup          # Full setup (FVM + build dependencies)
make setup-fvm      # Install FVM and Flutter only
make setup-build    # Install native build dependencies (Rust, protoc)

# Build
make build ARGS="<platform>"  # Build native libraries (macos, ios, android, linux, windows)

# Development
make regen          # Regenerate FFI bindings from libsignal headers
make check          # Check for libsignal updates

# Quality Assurance
make test           # Run tests
make coverage       # Run tests with coverage report
make analyze        # Run static analysis
make format         # Format Dart code
make format-check   # Check Dart code formatting
make doc            # Generate API documentation

# Utilities
make get            # Get dependencies
make clean          # Clean build artifacts
make version        # Show current libsignal version
make help           # Show all commands
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
