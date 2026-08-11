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
/// void main() async {
///   // Initialize the library
///   await LibSignal.init();
///
///   // Generate identity key pair
///   final identity = IdentityKeyPair.generate();
///   print('Public key: ${identity.publicKey}');
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
///   - Session establishment ([SessionBuilder])
///   - Message encryption/decryption ([SessionCipher])
///   - Session management ([SessionRecord])
///   - Protocol addressing ([ProtocolAddress])
///   - Pre-keys ([PreKeyRecord], [SignedPreKeyRecord], [KyberPreKeyRecord])
///   - Pre-key bundles ([PreKeyBundle])
///
/// - **Sealed Sender**: Anonymous message sending
///   - Sealed sender encryption/decryption ([SealedSenderCipher])
///   - Sender certificates ([SenderCertificate])
///
/// - **Group Messaging**: Efficient group message encryption
///   - Group encryption/decryption ([GroupCipher])
///   - Sender key distribution ([SenderKeyDistributionMessage])
///
/// - **Cryptographic Utilities**:
///   - AES-256-GCM-SIV ([Aes256GcmSiv])
///   - HKDF key derivation ([hkdfDerive])
///   - Identity verification fingerprints ([Fingerprint])
///
/// - **Storage Interfaces**:
///   - Session store ([SessionStore])
///   - Identity key store ([IdentityKeyStore])
///   - Pre-key stores ([PreKeyStore], [SignedPreKeyStore], [KyberPreKeyStore])
///   - Sender key store ([SenderKeyStore])
///   - In-memory implementations for testing
///
/// See the [README](https://github.com/djx-y-z/libsignal_dart) for more details.
library;

// Group messaging (high-level Dart API)
export 'src/groups/group_cipher.dart';
// Core initialization
export 'src/libsignal.dart';
// Protocol wrappers (high-level Dart API)
export 'src/protocol/protocol.dart';
// FRB-generated API
export 'src/rust/api/address.dart';
export 'src/rust/api/bundle.dart';
export 'src/rust/api/crypto.dart';
export 'src/rust/api/group_session.dart';
export 'src/rust/api/keys.dart';
export 'src/rust/api/kyber.dart';
export 'src/rust/api/message.dart';
export 'src/rust/api/prekey.dart';
export 'src/rust/api/sealed_sender.dart';
export 'src/rust/api/session.dart';
export 'src/rust/api/session_builder.dart';
export 'src/rust/api/session_cipher.dart';
export 'src/rust/api/signed_prekey.dart';
// Sealed sender (high-level Dart API)
export 'src/sealed_sender/content_hint.dart';
export 'src/sealed_sender/sealed_sender_cipher.dart';
// Security utilities
export 'src/security/secure_bytes.dart';
export 'src/security/secure_uint8list.dart';
// Stores (Dart-side implementations)
export 'src/stores/stores.dart';
