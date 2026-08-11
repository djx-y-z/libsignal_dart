/// Content hints for sealed sender messages.
library;

/// Tells a recipient what to do about a message it could not decrypt.
///
/// Carried by [UnidentifiedSenderMessageContent] and readable without
/// decrypting the message body, which is the point: a client that hits a
/// decryption failure uses the hint to decide whether asking for a resend is
/// worthwhile.
enum ContentHint {
  /// No hint. A decryption failure is worth surfacing and requesting a resend
  /// for.
  none(0),

  /// The sender can resend this message on request.
  resendable(1),

  /// The message can be dropped silently — it will be superseded by later
  /// state, so a resend request would only add noise.
  implicit(2);

  const ContentHint(this.value);

  /// The numeric value on the wire.
  final int value;

  /// The hint for [value], or null if it is one this version does not know.
  ///
  /// Unknown values are passed through by libsignal rather than rejected, so
  /// treat null as "some future hint" and fall back to [ContentHint.none]
  /// behaviour.
  static ContentHint? fromValue(int value) {
    for (final hint in ContentHint.values) {
      if (hint.value == value) return hint;
    }
    return null;
  }
}
