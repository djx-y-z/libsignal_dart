/// Signed pre-key store interface for Signal Protocol.
library;

import '../prekeys/signed_pre_key_record.dart';

/// Abstract interface for storing signed pre-keys.
///
/// Signed pre-keys are medium-term keys (typically rotated every few weeks)
/// that are signed by the identity key. Unlike regular pre-keys, they can
/// be reused until rotated.
///
/// The store should retain old signed pre-keys for a period of time to
/// allow decryption of messages that were encrypted before rotation.
///
/// Example implementation:
/// ```dart
/// class MySignedPreKeyStore implements SignedPreKeyStore {
///   final _signedPreKeys = <int, Uint8List>{};
///
///   @override
///   Future<SignedPreKeyRecord?> loadSignedPreKey(int signedPreKeyId) async {
///     final data = _signedPreKeys[signedPreKeyId];
///     return data != null ? SignedPreKeyRecord.deserialize(data) : null;
///   }
///   // ... other methods
/// }
/// ```
abstract interface class SignedPreKeyStore {
  /// Loads a signed pre-key by its ID.
  ///
  /// Returns `null` if no signed pre-key exists with this ID.
  Future<SignedPreKeyRecord?> loadSignedPreKey(int signedPreKeyId);

  /// Stores a signed pre-key.
  Future<void> storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record);

  /// Checks if a signed pre-key exists with the given ID.
  Future<bool> containsSignedPreKey(int signedPreKeyId);

  /// Removes a signed pre-key by its ID.
  ///
  /// Old signed pre-keys should be removed after a reasonable retention
  /// period (e.g., 30 days after rotation).
  Future<void> removeSignedPreKey(int signedPreKeyId);

  /// Gets all stored signed pre-key IDs.
  Future<List<int>> getAllSignedPreKeyIds();
}
