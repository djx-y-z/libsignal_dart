/// In-memory Kyber pre-key store implementation.
library;

import 'dart:typed_data';

import '../../prekeys/kyber_pre_key_record.dart';
import '../kyber_pre_key_store.dart';

/// In-memory implementation of [KyberPreKeyStore].
///
/// This implementation stores Kyber pre-keys in a [Map] and is suitable for
/// testing and prototyping. For production use, implement a persistent
/// store backed by secure storage.
///
/// Note: This implementation does NOT persist data across app restarts.
class InMemoryKyberPreKeyStore implements KyberPreKeyStore {
  final Map<int, Uint8List> _kyberPreKeys = {};
  final Set<int> _usedKyberPreKeys = {};

  @override
  Future<KyberPreKeyRecord?> loadKyberPreKey(int kyberPreKeyId) async {
    final data = _kyberPreKeys[kyberPreKeyId];
    if (data == null) return null;
    return KyberPreKeyRecord.deserialize(data);
  }

  @override
  Future<void> storeKyberPreKey(
    int kyberPreKeyId,
    KyberPreKeyRecord record,
  ) async {
    _kyberPreKeys[kyberPreKeyId] = record.serialize();
  }

  @override
  Future<bool> containsKyberPreKey(int kyberPreKeyId) async {
    return _kyberPreKeys.containsKey(kyberPreKeyId);
  }

  @override
  Future<void> markKyberPreKeyUsed(int kyberPreKeyId) async {
    _usedKyberPreKeys.add(kyberPreKeyId);
  }

  @override
  Future<void> removeKyberPreKey(int kyberPreKeyId) async {
    _kyberPreKeys.remove(kyberPreKeyId);
    _usedKyberPreKeys.remove(kyberPreKeyId);
  }

  @override
  Future<List<int>> getAllKyberPreKeyIds() async {
    return _kyberPreKeys.keys.toList();
  }

  /// Checks if a Kyber pre-key has been used.
  bool isKyberPreKeyUsed(int kyberPreKeyId) {
    return _usedKyberPreKeys.contains(kyberPreKeyId);
  }

  /// Clears all stored Kyber pre-keys.
  void clear() {
    _kyberPreKeys.clear();
    _usedKyberPreKeys.clear();
  }

  /// Gets the number of stored Kyber pre-keys.
  int get length => _kyberPreKeys.length;
}
