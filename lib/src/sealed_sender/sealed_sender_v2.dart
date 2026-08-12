/// Fan-out helper for Sealed Sender v2 SentMessages.
library;

import 'dart:typed_data';

import '../rust/api/sealed_sender.dart';

/// Assembles per-recipient messages from what [sealedSenderV2ParseSentMessage]
/// returns.
extension SealedSenderV2Fanout on SealedSenderV2SentMessage {
  /// The single-recipient *ReceivedMessage* to deliver to [recipient], ready
  /// for `SealedSenderCipher.decrypt` on that recipient's device.
  ///
  /// [data] must be the same bytes passed to [sealedSenderV2ParseSentMessage] —
  /// the parsed offsets index into it. Returns an empty list for an excluded
  /// recipient (one with no devices), which has no message.
  ///
  /// Be precise about what is enforced: a buffer whose length differs from the
  /// parsed one is refused, and so is a [recipient] whose offsets fall outside
  /// it. A *different* buffer of the *same* length cannot be told apart from
  /// the right one — it will assemble a well-formed message that no recipient
  /// can decrypt. Keep the parsed bytes and this call together.
  ///
  /// Building one message at a time is the point. Every recipient's message
  /// ends with the same shared body, so materialising them all at once costs
  /// roughly `recipients × message size`; call this per recipient, deliver, and
  /// let it go.
  ///
  /// ```dart
  /// final parsed = await sealedSenderV2ParseSentMessage(data: blob);
  /// for (final recipient in parsed.recipients) {
  ///   if (recipient.devices.isEmpty) continue; // excluded
  ///   await deliver(
  ///     recipient.serviceId,
  ///     parsed.receivedMessageFor(recipient: recipient, data: blob),
  ///   );
  /// }
  /// ```
  ///
  /// Throws [ArgumentError] if [data] is not [parsedLength] bytes long, or if
  /// [recipient]'s offsets do not fit inside it.
  Uint8List receivedMessageFor({
    required SealedSenderV2Recipient recipient,
    required List<int> data,
  }) {
    if (data.length != parsedLength) {
      throw ArgumentError.value(
        data,
        'data',
        'is ${data.length} bytes but the message that was parsed was '
            '$parsedLength; the offsets index that buffer, not this one',
      );
    }
    if (recipient.devices.isEmpty) return Uint8List(0);

    final keyStart = recipient.keyMaterialStart;
    final keyEnd = recipient.keyMaterialEnd;
    if (keyStart > keyEnd ||
        keyEnd > parsedLength ||
        sharedBytesOffset > parsedLength) {
      throw ArgumentError.value(
        recipient,
        'recipient',
        'offsets [$keyStart, $keyEnd) and shared $sharedBytesOffset '
            'do not fit in $parsedLength bytes',
      );
    }

    final keyLength = keyEnd - keyStart;
    final sharedLength = parsedLength - sharedBytesOffset;
    final out = Uint8List(1 + keyLength + sharedLength)
      ..[0] = receivedMessageVersion
      ..setRange(1, 1 + keyLength, data, keyStart)
      ..setRange(
        1 + keyLength,
        1 + keyLength + sharedLength,
        data,
        sharedBytesOffset,
      );
    return out;
  }
}
