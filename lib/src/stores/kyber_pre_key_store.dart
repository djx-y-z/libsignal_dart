/// Kyber pre-key store interface for Signal Protocol.
library;

import '../prekeys/kyber_pre_key_record.dart';

/// Abstract interface for storing Kyber (post-quantum) pre-keys.
///
/// Kyber pre-keys provide post-quantum security for session establishment.
/// They work similarly to regular pre-keys but use Kyber KEM for
/// key encapsulation.
///
/// Like regular pre-keys, Kyber pre-keys are one-time use (for "last resort"
/// keys) or can be reused (for signed Kyber pre-keys).
///
/// Example implementation:
/// ```dart
/// class MyKyberPreKeyStore implements KyberPreKeyStore {
///   final _kyberPreKeys = <int, Uint8List>{};
///   final _usedKyberPreKeys = <int>{};
///
///   @override
///   Future<KyberPreKeyRecord?> loadKyberPreKey(int kyberPreKeyId) async {
///     final data = _kyberPreKeys[kyberPreKeyId];
///     return data != null ? KyberPreKeyRecord.deserialize(data) : null;
///   }
///   // ... other methods
/// }
/// ```
abstract interface class KyberPreKeyStore {
  /// Loads a Kyber pre-key by its ID.
  ///
  /// Returns `null` if no Kyber pre-key exists with this ID.
  Future<KyberPreKeyRecord?> loadKyberPreKey(int kyberPreKeyId);

  /// Stores a Kyber pre-key.
  Future<void> storeKyberPreKey(int kyberPreKeyId, KyberPreKeyRecord record);

  /// Checks if a Kyber pre-key exists with the given ID.
  Future<bool> containsKyberPreKey(int kyberPreKeyId);

  /// Marks a Kyber pre-key as used.
  ///
  /// For one-time Kyber pre-keys, this typically means they should
  /// not be used again. The implementation may choose to remove
  /// the key or just mark it as used.
  Future<void> markKyberPreKeyUsed(int kyberPreKeyId);

  /// Removes a Kyber pre-key by its ID.
  Future<void> removeKyberPreKey(int kyberPreKeyId);

  /// Gets all stored Kyber pre-key IDs.
  Future<List<int>> getAllKyberPreKeyIds();
}
