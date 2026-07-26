/// Pre-key store interface for Signal Protocol.
library;

import '../rust/api/prekey.dart';

/// Abstract interface for storing pre-keys.
///
/// Pre-keys are one-time use keys that enable asynchronous session
/// establishment. When a pre-key is used to establish a session,
/// it should typically be removed from the store.
///
/// A user should maintain a pool of pre-keys and replenish them
/// as they are consumed.
///
/// Example implementation:
/// ```dart
/// class MyPreKeyStore implements PreKeyStore {
///   final _preKeys = <int, Uint8List>{};
///
///   @override
///   Future<PreKeyRecord?> loadPreKey(int preKeyId) async {
///     final data = _preKeys[preKeyId];
///     return data != null ? PreKeyRecord.deserialize(data) : null;
///   }
///   // ... other methods
/// }
/// ```
///
/// ## Durability (critical)
///
/// Writes to this store must be **durably persisted before the returned future
/// completes**, or be part of a transaction committed durably before the
/// decrypted plaintext is acted upon. Consumption of a one-time pre-key is a
/// write: see [removePreKey]. This is a different failure mode from
/// [SessionStore] — nothing rewinds the ratchet, but a pre-key that survives
/// its use can be used again.
abstract interface class PreKeyStore {
  /// Loads a pre-key by its ID.
  ///
  /// Returns `null` if no pre-key exists with this ID.
  Future<PreKeyRecord?> loadPreKey(int preKeyId);

  /// Stores a pre-key.
  Future<void> storePreKey(int preKeyId, PreKeyRecord record);

  /// Checks if a pre-key exists with the given ID.
  Future<bool> containsPreKey(int preKeyId);

  /// Removes a pre-key by its ID.
  ///
  /// This is typically called after the pre-key has been used
  /// to establish a session.
  ///
  /// **The removal must be durable before the decrypted plaintext is acted
  /// upon.** The library awaits this call before returning that plaintext. If
  /// the removal is lost, the same pre-key message can be processed again after
  /// a restart: the one-time pre-key retains value to an attacker who later
  /// compromises the device (weakening forward secrecy for the initial
  /// message), and a replayed initial message can re-establish a session whose
  /// message keys have already been used.
  Future<void> removePreKey(int preKeyId);

  /// Gets all stored pre-key IDs.
  Future<List<int>> getAllPreKeyIds();
}
