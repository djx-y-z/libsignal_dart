/// Ciphertext message types for Signal Protocol.
library;

/// The type of a ciphertext message.
///
/// Used to identify the format of an encrypted message.
enum CiphertextMessageType {
  /// A standard Signal message (after session is established).
  whisper(2),

  /// A pre-key message (for establishing a new session).
  preKey(3),

  /// A sender key message (for group messaging).
  senderKey(7),

  /// A plaintext message (unencrypted, for special cases).
  plaintext(8);

  /// The numeric value of this message type.
  final int value;

  const CiphertextMessageType(this.value);

  /// Creates a [CiphertextMessageType] from its numeric value.
  ///
  /// Throws [ArgumentError] if the value is not recognized.
  static CiphertextMessageType fromValue(int value) {
    return switch (value) {
      2 => whisper,
      3 => preKey,
      7 => senderKey,
      8 => plaintext,
      _ => throw ArgumentError('Unknown CiphertextMessageType value: $value'),
    };
  }
}
