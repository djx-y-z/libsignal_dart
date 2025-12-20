import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

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

      test('rejects invalid data', () {
        final invalidData = Uint8List.fromList([1, 2, 3, 4, 5]);
        expect(
          () => SenderKeyMessage.deserialize(invalidData),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects garbage data', () {
        final garbage = randomBytes(100);
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
