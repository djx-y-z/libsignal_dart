/// Dart FFI bindings for libsignal - Signal Protocol implementation.
///
/// This package provides end-to-end encryption using the Signal Protocol,
/// including key management, session establishment, sealed sender, and
/// group messaging capabilities.
///
/// ## Getting Started
///
/// ```dart
/// import 'package:libsignal/libsignal.dart';
///
/// void main() {
///   // Initialize the library
///   LibSignal.init();
///
///   // Generate identity key pair
///   final identity = IdentityKeyPair.generate();
///   print('Public key: ${identity.publicKey}');
///
///   // Clean up when done
///   identity.dispose();
/// }
/// ```
///
/// ## Features
///
/// - **Key Management**: Generate and manage cryptographic keys
///   - Curve25519 key pairs ([PrivateKey], [PublicKey])
///   - Identity key pairs ([IdentityKeyPair])
///   - Post-quantum Kyber keys ([KyberKeyPair])
///
/// - **Signal Protocol**: End-to-end encryption with forward secrecy
///   - Session management ([SessionRecord])
///   - Protocol addressing ([ProtocolAddress])
///   - Pre-keys ([PreKeyRecord], [SignedPreKeyRecord], [KyberPreKeyRecord])
///   - Pre-key bundles ([PreKeyBundle])
///
/// - **Sealed Sender**: Anonymous message sending
///   - Server certificates ([ServerCertificate])
///   - Sender certificates ([SenderCertificate])
///
/// - **Group Messaging**: Efficient group message encryption
///   - Sender keys ([SenderKeyRecord])
///   - Group sessions ([GroupSession])
///   - Distribution messages ([SenderKeyDistributionMessage])
///
/// - **Cryptographic Utilities**:
///   - AES-256-GCM-SIV ([Aes256GcmSiv])
///   - HKDF key derivation ([Hkdf])
///   - Identity verification fingerprints ([Fingerprint])
///
/// - **Storage Interfaces**:
///   - Session store ([SessionStore])
///   - Identity key store ([IdentityKeyStore])
///   - Pre-key stores ([PreKeyStore], [SignedPreKeyStore], [KyberPreKeyStore])
///   - Sender key store ([SenderKeyStore])
///   - In-memory implementations for testing
///
/// See the [README](https://github.com/user/libsignal_dart) for more details.
library;

// Core
export 'src/exception.dart';
export 'src/libsignal.dart';
export 'src/secure_bytes.dart';

// Cryptographic utilities
export 'src/crypto/crypto.dart';

// Groups
export 'src/groups/groups.dart';

// Keys
export 'src/keys/keys.dart';

// Kyber (post-quantum)
export 'src/kyber/kyber.dart';

// Pre-keys
export 'src/prekeys/prekeys.dart';

// Protocol
export 'src/protocol/protocol.dart';

// Sealed sender
export 'src/sealed_sender/sealed_sender.dart';

// Stores
export 'src/stores/stores.dart';
