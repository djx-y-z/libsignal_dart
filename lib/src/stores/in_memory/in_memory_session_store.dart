/// In-memory session store implementation.
library;

import 'dart:typed_data';

import '../../protocol/protocol_address.dart';
import '../../protocol/session_record.dart';
import '../session_store.dart';

/// In-memory implementation of [SessionStore].
///
/// This implementation stores sessions in a [Map] and is suitable for
/// testing and prototyping. For production use, implement a persistent
/// store backed by a database or secure storage.
///
/// Note: This implementation does NOT persist data across app restarts.
class InMemorySessionStore implements SessionStore {
  final Map<String, Uint8List> _sessions = {};

  String _key(ProtocolAddress address) => '${address.name}:${address.deviceId}';

  @override
  Future<SessionRecord?> loadSession(ProtocolAddress address) async {
    final data = _sessions[_key(address)];
    if (data == null) return null;
    return SessionRecord.deserialize(data);
  }

  @override
  Future<void> storeSession(
    ProtocolAddress address,
    SessionRecord record,
  ) async {
    _sessions[_key(address)] = record.serialize();
  }

  @override
  Future<bool> containsSession(ProtocolAddress address) async {
    return _sessions.containsKey(_key(address));
  }

  @override
  Future<void> deleteSession(ProtocolAddress address) async {
    _sessions.remove(_key(address));
  }

  @override
  Future<void> deleteAllSessions(String name) async {
    _sessions.removeWhere((key, _) => key.startsWith('$name:'));
  }

  @override
  Future<List<int>> getSubDeviceSessions(String name) async {
    final prefix = '$name:';
    return _sessions.keys
        .where((key) => key.startsWith(prefix))
        .map((key) => int.parse(key.substring(prefix.length)))
        .toList();
  }

  /// Clears all stored sessions.
  void clear() => _sessions.clear();

  /// Gets the number of stored sessions.
  int get length => _sessions.length;
}
