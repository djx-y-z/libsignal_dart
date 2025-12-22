import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('SenderKeyMessage', () {
    group('deserialize()', () {
      test('rejects empty data', () {
        expect(
          () => SenderKeyMessage.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects garbage data', () {
        final garbage = Uint8List.fromList([0x99, 0x88, 0x77, 0x66, 0x55]);
        expect(
          () => SenderKeyMessage.deserialize(garbage),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    // Full tests for SenderKeyMessage properties require a valid message,
    // which needs GroupSession.encrypt(). See group_session_test.dart for integration tests.
  });
}
