/// In-memory signed pre-key store implementation.
library;

import 'dart:typed_data';

import '../../prekeys/signed_pre_key_record.dart';
import '../signed_pre_key_store.dart';

/// In-memory implementation of [SignedPreKeyStore].
///
/// This implementation stores signed pre-keys in a [Map] and is suitable for
/// testing and prototyping. For production use, implement a persistent
/// store backed by secure storage.
///
/// Note: This implementation does NOT persist data across app restarts.
class InMemorySignedPreKeyStore implements SignedPreKeyStore {
  final Map<int, Uint8List> _signedPreKeys = {};

  @override
  Future<SignedPreKeyRecord?> loadSignedPreKey(int signedPreKeyId) async {
    final data = _signedPreKeys[signedPreKeyId];
    if (data == null) return null;
    return SignedPreKeyRecord.deserialize(data);
  }

  @override
  Future<void> storeSignedPreKey(
    int signedPreKeyId,
    SignedPreKeyRecord record,
  ) async {
    _signedPreKeys[signedPreKeyId] = record.serialize();
  }

  @override
  Future<bool> containsSignedPreKey(int signedPreKeyId) async {
    return _signedPreKeys.containsKey(signedPreKeyId);
  }

  @override
  Future<void> removeSignedPreKey(int signedPreKeyId) async {
    _signedPreKeys.remove(signedPreKeyId);
  }

  @override
  Future<List<int>> getAllSignedPreKeyIds() async {
    return _signedPreKeys.keys.toList();
  }

  /// Clears all stored signed pre-keys.
  void clear() => _signedPreKeys.clear();

  /// Gets the number of stored signed pre-keys.
  int get length => _signedPreKeys.length;
}
