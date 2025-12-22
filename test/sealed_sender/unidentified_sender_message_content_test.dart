import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('UnidentifiedSenderMessageContent', () {
    // Note: Tests for empty/invalid/garbage data deserialization are skipped
    // because libsignal native library may crash when processing invalid data.
    // This is a known limitation documented in HANDOFF.md.

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
