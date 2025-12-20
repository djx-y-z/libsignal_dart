/// Cryptographic utilities for Signal Protocol.
///
/// This module provides:
/// - [Aes256GcmSiv] - Nonce-misuse resistant authenticated encryption
/// - [Hkdf] - HMAC-based key derivation function
/// - [Fingerprint] - Identity verification fingerprints
///
/// Example:
/// ```dart
/// // HKDF key derivation
/// final derivedKey = Hkdf.deriveSecrets(
///   inputKeyMaterial: sharedSecret,
///   info: utf8.encode('my-context'),
///   outputLength: 32,
/// );
///
/// // AES-GCM-SIV encryption
/// final cipher = Aes256GcmSiv(key);
/// final ciphertext = cipher.encrypt(
///   plaintext: data,
///   nonce: nonce,
///   associatedData: aad,
/// );
/// cipher.dispose();
///
/// // Fingerprint verification
/// final fingerprint = Fingerprint.create(
///   localIdentifier: localId,
///   localKey: localKey,
///   remoteIdentifier: remoteId,
///   remoteKey: remoteKey,
/// );
/// print('Safety Number: ${fingerprint.displayString}');
/// fingerprint.dispose();
/// ```
library;

export 'aes_gcm_siv.dart';
export 'fingerprint.dart';
export 'hkdf.dart';
