/// Session store interface for Signal Protocol.
library;

import '../protocol/protocol_address.dart';
import '../protocol/session_record.dart';

/// Abstract interface for storing and retrieving session records.
///
/// Implementations must provide persistent storage for Signal Protocol
/// sessions. Each session is identified by a [ProtocolAddress] (user + device).
///
/// Example implementation:
/// ```dart
/// class MySessionStore implements SessionStore {
///   final _sessions = <String, Uint8List>{};
///
///   @override
///   Future<SessionRecord?> loadSession(ProtocolAddress address) async {
///     final key = '${address.name}:${address.deviceId}';
///     final data = _sessions[key];
///     return data != null ? SessionRecord.deserialize(data) : null;
///   }
///   // ... other methods
/// }
/// ```
abstract interface class SessionStore {
  /// Loads a session record for the given address.
  ///
  /// Returns `null` if no session exists for this address.
  Future<SessionRecord?> loadSession(ProtocolAddress address);

  /// Stores a session record for the given address.
  ///
  /// This will overwrite any existing session for this address.
  Future<void> storeSession(ProtocolAddress address, SessionRecord record);

  /// Checks if a session exists for the given address.
  Future<bool> containsSession(ProtocolAddress address);

  /// Deletes the session for the given address.
  ///
  /// Does nothing if no session exists.
  Future<void> deleteSession(ProtocolAddress address);

  /// Deletes all sessions for the given name (user).
  ///
  /// This removes sessions for all devices of that user.
  Future<void> deleteAllSessions(String name);

  /// Gets all device IDs with sessions for the given name (user).
  Future<List<int>> getSubDeviceSessions(String name);
}
