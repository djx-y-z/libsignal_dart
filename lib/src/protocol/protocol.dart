/// Signal Protocol types for session management and messaging.
///
/// This module provides the core protocol types:
/// - [ProtocolAddress] - Identifies a user and device
/// - [SessionRecord] - Stores session cryptographic state
/// - [SessionBuilder] - Establishes sessions via X3DH
/// - [SessionCipher] - Encrypts/decrypts messages
/// - [CiphertextMessageType] - Message type enumeration
library;

export 'ciphertext_message_type.dart';
export 'decryption_error_message.dart';
export 'protocol_address.dart';
export 'session_builder.dart';
export 'session_cipher.dart';
export 'session_record.dart';
