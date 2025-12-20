/// In-memory sender key store implementation.
library;

import 'dart:typed_data';

import '../sender_key_store.dart';

/// In-memory implementation of [SenderKeyStore].
///
/// This implementation stores sender keys in a [Map] and is suitable for
/// testing and prototyping. For production use, implement a persistent
/// store backed by secure storage.
///
/// Note: This implementation does NOT persist data across app restarts.
class InMemorySenderKeyStore implements SenderKeyStore {
  final Map<String, Uint8List> _senderKeys = {};

  String _key(SenderKeyName name) =>
      '${name.sender.name}:${name.sender.deviceId}:${name.distributionId}';

  @override
  Future<Uint8List?> loadSenderKey(SenderKeyName senderKeyName) async {
    return _senderKeys[_key(senderKeyName)];
  }

  @override
  Future<void> storeSenderKey(
    SenderKeyName senderKeyName,
    Uint8List record,
  ) async {
    _senderKeys[_key(senderKeyName)] = record;
  }

  /// Clears all stored sender keys.
  void clear() => _senderKeys.clear();

  /// Gets the number of stored sender keys.
  int get length => _senderKeys.length;
}
