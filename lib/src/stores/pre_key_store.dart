/// Pre-key store interface for Signal Protocol.
library;

import '../prekeys/pre_key_record.dart';

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
  Future<void> removePreKey(int preKeyId);

  /// Gets all stored pre-key IDs.
  Future<List<int>> getAllPreKeyIds();
}
