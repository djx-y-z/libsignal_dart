/// Sender key store interface for Signal Protocol group messaging.
library;

import 'dart:typed_data';

import '../protocol/protocol_address.dart';

/// Unique identifier for a sender key, combining sender address and distribution ID.
///
/// A sender key is identified by:
/// - The sender's protocol address (user + device)
/// - A distribution ID (UUID identifying the group/distribution)
final class SenderKeyName {
  /// The sender's protocol address.
  final ProtocolAddress sender;

  /// The distribution ID (typically a UUID string).
  final String distributionId;

  /// Creates a new sender key name.
  const SenderKeyName(this.sender, this.distributionId);

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! SenderKeyName) return false;
    return sender == other.sender && distributionId == other.distributionId;
  }

  @override
  int get hashCode => Object.hash(sender, distributionId);

  @override
  String toString() => 'SenderKeyName($sender, $distributionId)';
}

/// Abstract interface for storing sender keys for group messaging.
///
/// Sender keys enable efficient group messaging by using symmetric
/// encryption within a group. Each group member distributes their
/// sender key to other members, allowing them to decrypt messages
/// from that sender.
///
/// Example implementation:
/// ```dart
/// class MySenderKeyStore implements SenderKeyStore {
///   final _senderKeys = <String, Uint8List>{};
///
///   String _key(SenderKeyName name) =>
///     '${name.sender.name}:${name.sender.deviceId}:${name.distributionId}';
///
///   @override
///   Future<Uint8List?> loadSenderKey(SenderKeyName senderKeyName) async {
///     return _senderKeys[_key(senderKeyName)];
///   }
///   // ... other methods
/// }
/// ```
abstract interface class SenderKeyStore {
  /// Loads a sender key record.
  ///
  /// Returns the serialized sender key record, or `null` if not found.
  Future<Uint8List?> loadSenderKey(SenderKeyName senderKeyName);

  /// Stores a sender key record.
  ///
  /// The [record] is the serialized sender key record.
  Future<void> storeSenderKey(SenderKeyName senderKeyName, Uint8List record);
}
