/// Ciphertext message types for Signal Protocol.
library;

import 'dart:typed_data';

/// The type of ciphertext message.
enum CiphertextMessageType {
  /// A regular Signal message (whisper message).
  ///
  /// Used for messages after a session has been established.
  signal(2),

  /// A pre-key Signal message.
  ///
  /// Used for the first message to establish a new session.
  preKey(3),

  /// A sender key message.
  ///
  /// Used for group messaging.
  senderKey(7),

  /// A plaintext content message (not encrypted).
  plaintextContent(8);

  const CiphertextMessageType(this.value);

  /// The numeric value of this message type.
  final int value;

  /// Creates a [CiphertextMessageType] from its numeric value.
  ///
  /// Throws [ArgumentError] if the value is not a valid message type.
  static CiphertextMessageType fromValue(int value) {
    // Note: Signal Protocol uses 2 for Whisper/Signal messages, but
    // the Rust code returns 1 for Whisper internally. We handle both.
    switch (value) {
      case 1:
      case 2:
        return CiphertextMessageType.signal;
      case 3:
        return CiphertextMessageType.preKey;
      case 7:
        return CiphertextMessageType.senderKey;
      case 8:
        return CiphertextMessageType.plaintextContent;
      default:
        throw ArgumentError('Invalid ciphertext message type: $value');
    }
  }
}

/// An encrypted Signal Protocol message.
///
/// This class wraps the ciphertext and message type returned from
/// encryption operations. The message type indicates whether this is
/// a regular Signal message or a pre-key message (for session establishment).
class CiphertextMessage {
  /// Creates a new CiphertextMessage.
  const CiphertextMessage({required this.type, required this.ciphertext});

  /// Creates a CiphertextMessage from raw type value and ciphertext.
  factory CiphertextMessage.fromRaw({
    required int messageType,
    required Uint8List ciphertext,
  }) {
    return CiphertextMessage(
      type: CiphertextMessageType.fromValue(messageType),
      ciphertext: ciphertext,
    );
  }

  /// The type of this message.
  final CiphertextMessageType type;

  /// The encrypted message bytes.
  final Uint8List ciphertext;

  /// Whether this is a pre-key message (for session establishment).
  bool get isPreKeyMessage => type == CiphertextMessageType.preKey;

  /// Whether this is a regular Signal message.
  bool get isSignalMessage => type == CiphertextMessageType.signal;
}
