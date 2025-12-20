/// In-memory pre-key store implementation.
library;

import 'dart:typed_data';

import '../../prekeys/pre_key_record.dart';
import '../pre_key_store.dart';

/// In-memory implementation of [PreKeyStore].
///
/// This implementation stores pre-keys in a [Map] and is suitable for
/// testing and prototyping. For production use, implement a persistent
/// store backed by secure storage.
///
/// Note: This implementation does NOT persist data across app restarts.
class InMemoryPreKeyStore implements PreKeyStore {
  final Map<int, Uint8List> _preKeys = {};

  @override
  Future<PreKeyRecord?> loadPreKey(int preKeyId) async {
    final data = _preKeys[preKeyId];
    if (data == null) return null;
    return PreKeyRecord.deserialize(data);
  }

  @override
  Future<void> storePreKey(int preKeyId, PreKeyRecord record) async {
    _preKeys[preKeyId] = record.serialize();
  }

  @override
  Future<bool> containsPreKey(int preKeyId) async {
    return _preKeys.containsKey(preKeyId);
  }

  @override
  Future<void> removePreKey(int preKeyId) async {
    _preKeys.remove(preKeyId);
  }

  @override
  Future<List<int>> getAllPreKeyIds() async {
    return _preKeys.keys.toList();
  }

  /// Clears all stored pre-keys.
  void clear() => _preKeys.clear();

  /// Gets the number of stored pre-keys.
  int get length => _preKeys.length;
}
