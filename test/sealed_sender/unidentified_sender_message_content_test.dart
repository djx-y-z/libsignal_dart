import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('UnidentifiedSenderMessageContent', () {
    group('deserialize()', () {
      test('rejects empty data', () {
        expect(
          () => UnidentifiedSenderMessageContent.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects invalid data', () {
        final invalidData = Uint8List.fromList([1, 2, 3, 4, 5]);
        expect(
          () => UnidentifiedSenderMessageContent.deserialize(invalidData),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects garbage data', () {
        final garbage = randomBytes(100);
        expect(
          () => UnidentifiedSenderMessageContent.deserialize(garbage),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('ContentHint constants', () {
      test('none is 0', () {
        expect(ContentHint.none, equals(0));
      });

      test('resendable is 1', () {
        expect(ContentHint.resendable, equals(1));
      });

      test('implicit is 2', () {
        expect(ContentHint.implicit, equals(2));
      });
    });
  });
}
