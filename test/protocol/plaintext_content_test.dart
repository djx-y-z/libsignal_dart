import 'dart:convert';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

/// A decryption error report for a group message.
///
/// The sender-key branch carries no ratchet key, so libsignal does not parse
/// [originalBytes] and the test does not need a real ciphertext.
DecryptionErrorMessage _errorMessage() =>
    DecryptionErrorMessage.forOriginalMessage(
      originalBytes: utf8.encode('the message we could not read'),
      messageType: CiphertextMessageType.senderKey.value,
      timestamp: BigInt.from(1700000000000),
      originalSenderDeviceId: 3,
    );

void main() {
  setUpAll(LibSignal.init);

  group('PlaintextContent', () {
    test('wraps a decryption error message and survives the round trip', () {
      final dem = _errorMessage();

      final content = PlaintextContent.fromDecryptionErrorMessage(message: dem);
      final wire = content.serialize();

      // The envelope is what actually goes on the wire as
      // CiphertextMessageType.plaintextContent.
      expect(wire, isNotEmpty);
      expect(
        wire.first,
        equals(0xC0),
        reason: 'plaintext content identifier byte',
      );
      expect(content.body(), equals(wire.sublist(1)));

      // And the receiving side gets the original message back out. Note it
      // takes the body, not the envelope — the identifier byte is rejected.
      final recovered = DecryptionErrorMessage.extractFromSerializedContent(
        bytes: content.body(),
      );
      expect(
        () => DecryptionErrorMessage.extractFromSerializedContent(bytes: wire),
        throwsA(anything),
        reason: 'the envelope must be stripped first',
      );
      expect(recovered.timestamp(), equals(dem.timestamp()));
      expect(recovered.deviceId(), equals(dem.deviceId()));
      expect(recovered.serialize(), equals(dem.serialize()));
    });

    test('deserialize round-trips the envelope', () {
      final wire = PlaintextContent.fromDecryptionErrorMessage(
        message: _errorMessage(),
      ).serialize();

      final parsed = PlaintextContent.deserialize(data: wire);
      expect(parsed.serialize(), equals(wire));
      expect(parsed.cloneMessage().serialize(), equals(wire));
    });

    test('rejects content that is not marked as plaintext-safe', () {
      // Missing the 0xC0 identifier byte.
      expect(
        () => PlaintextContent.deserialize(data: <int>[0x01, 0x02, 0x03]),
        throwsA(anything),
      );
    });
  });
}
