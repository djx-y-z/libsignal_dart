/// Group messaging support for Signal Protocol.
///
/// This module provides sender key encryption for efficient group messaging:
///
/// - [SenderKeyRecord] - Stores group messaging state
/// - [SenderKeyMessage] - An encrypted group message
/// - [SenderKeyDistributionMessage] - Distributes sender keys to group members
/// - [GroupSession] - High-level API for group encryption/decryption
///
/// Example:
/// ```dart
/// // Create a group session
/// final session = GroupSession(
///   myAddress,
///   GroupSession.uuidFromString('550e8400-e29b-41d4-a716-446655440000'),
///   senderKeyStore,
/// );
///
/// // Create and distribute sender key
/// final distMessage = await session.createDistributionMessage();
/// // Send distMessage to all group members encrypted individually...
///
/// // Encrypt a message for the group
/// final encrypted = await session.encrypt(plaintext);
///
/// // Decrypt a message from a group member
/// final decrypted = await session.decrypt(senderAddress, encrypted);
/// ```
library;

export 'group_session.dart';
export 'sender_key_distribution_message.dart';
export 'sender_key_message.dart';
export 'sender_key_record.dart';
