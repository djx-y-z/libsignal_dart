/// In-memory Kyber pre-key store implementation.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../../rust/api/keys.dart';
import '../../rust/api/kyber.dart';
import '../kyber_pre_key_store.dart';

/// In-memory implementation of [KyberPreKeyStore].
///
/// This implementation stores Kyber pre-keys in a [Map] and is suitable for
/// testing and prototyping. For production use, implement a persistent
/// store backed by secure storage.
///
/// Note: This implementation does NOT persist data across app restarts.
///
/// Like libsignal's own in-memory reference store, this one records the PQXDH
/// agreements it has seen ([wasAgreementSeen]) but never retires a key: it
/// cannot tell a one-time key from a last-resort one. A production store must
/// make that distinction — see `DurableKyberPreKeyStore` in `example_cli`.
class InMemoryKyberPreKeyStore implements KyberPreKeyStore {
  final Map<int, Uint8List> _kyberPreKeys = {};
  final Set<int> _usedKyberPreKeys = {};

  /// The `(kyberPreKeyId, signedPreKeyId, baseKey)` triples already marked used.
  final Set<String> _agreementsSeen = {};

  static String _agreementKey(
    int kyberPreKeyId,
    int signedPreKeyId,
    PublicKey baseKey,
  ) => '$kyberPreKeyId/$signedPreKeyId/${base64Encode(baseKey.serialize())}';

  @override
  Future<KyberPreKeyRecord?> loadKyberPreKey(int kyberPreKeyId) async {
    final data = _kyberPreKeys[kyberPreKeyId];
    if (data == null) return null;
    return KyberPreKeyRecord.deserialize(bytes: data.toList());
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
  Future<void> markKyberPreKeyUsed(
    int kyberPreKeyId,
    int signedPreKeyId,
    PublicKey baseKey,
  ) async {
    _usedKyberPreKeys.add(kyberPreKeyId);
    _agreementsSeen.add(_agreementKey(kyberPreKeyId, signedPreKeyId, baseKey));
  }

  @override
  Future<void> removeKyberPreKey(int kyberPreKeyId) async {
    _kyberPreKeys.remove(kyberPreKeyId);
    _usedKyberPreKeys.remove(kyberPreKeyId);
    _agreementsSeen.removeWhere((key) => key.startsWith('$kyberPreKeyId/'));
  }

  @override
  Future<List<int>> getAllKyberPreKeyIds() async {
    return _kyberPreKeys.keys.toList();
  }

  /// Checks if a Kyber pre-key has been used.
  bool isKyberPreKeyUsed(int kyberPreKeyId) {
    return _usedKyberPreKeys.contains(kyberPreKeyId);
  }

  /// Whether this exact PQXDH agreement was already marked used.
  ///
  /// A second occurrence of the same triple means the same pre-key message
  /// established a session twice — the replay a last-resort key is exposed to.
  bool wasAgreementSeen(
    int kyberPreKeyId,
    int signedPreKeyId,
    PublicKey baseKey,
  ) => _agreementsSeen.contains(
    _agreementKey(kyberPreKeyId, signedPreKeyId, baseKey),
  );

  /// Clears all stored Kyber pre-keys.
  void clear() {
    _kyberPreKeys.clear();
    _usedKyberPreKeys.clear();
    _agreementsSeen.clear();
  }

  /// Gets the number of stored Kyber pre-keys.
  int get length => _kyberPreKeys.length;
}
