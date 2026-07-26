/// Kyber pre-key store interface for Signal Protocol.
library;

import '../rust/api/kyber.dart';

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
///
/// ## Durability (critical)
///
/// Writes to this store must be **durably persisted before the returned future
/// completes**, or be part of a transaction committed durably before the
/// decrypted plaintext is acted upon. [markKyberPreKeyUsed] is such a write:
/// it is how a one-time Kyber pre-key is consumed. See [PreKeyStore] for the
/// consequences of losing a consumption write and [SessionStore] for the full
/// contract.
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
  ///
  /// **The mark must be durable before the decrypted plaintext is acted
  /// upon** — the library awaits this call before returning that plaintext.
  ///
  /// The mark only protects anything if [loadKyberPreKey] actually refuses to
  /// serve a marked **one-time** key (a last-resort key is meant to be reused,
  /// and the record does not say which it is — your store must remember that
  /// from the moment it generated the key). Persisting the mark and still
  /// serving the key, or losing the write, both leave the key usable again.
  ///
  /// **Known gap:** this callback is invoked by `SessionCipher.decrypt` only.
  /// `SealedSenderCipher.decrypt` consumes a Kyber pre-key without marking it
  /// (it does remove the one-time EC pre-key), so a store that retires marked
  /// keys will keep serving one that arrived through sealed sender. Retire
  /// one-time Kyber pre-keys from the application side when you publish a new
  /// bundle; see `SECURITY.md` → Known Limitations.
  Future<void> markKyberPreKeyUsed(int kyberPreKeyId);

  /// Removes a Kyber pre-key by its ID.
  Future<void> removeKyberPreKey(int kyberPreKeyId);

  /// Gets all stored Kyber pre-key IDs.
  Future<List<int>> getAllKyberPreKeyIds();
}
