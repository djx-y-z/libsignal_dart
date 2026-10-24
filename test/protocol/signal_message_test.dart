import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/error_matchers.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('SignalMessage', () {
    group('deserialize', () {
      test('throws on empty data', () {
        expect(
          () => SignalMessage.deserialize(data: []),
          failsWith(LibSignalErrorCode.invalidMessage),
        );
      });

      test('rejects garbage data', () {
        final garbage = [0x99, 0x88, 0x77, 0x66, 0x55];
        expect(
          () => SignalMessage.deserialize(data: garbage),
          failsWith(LibSignalErrorCode.invalidMessage),
        );
      });

      test('rejects short data', () {
        expect(
          () => SignalMessage.deserialize(data: [0x33, 0x00, 0x00]),
          failsWith(LibSignalErrorCode.invalidMessage),
        );
      });
    });

    // Note: Tests requiring session establishment are skipped because
    // processPrekeyBundle() is a stub that requires Dart-side SessionBuilder.
    // Full SignalMessage tests would require established sessions to encrypt/decrypt.
  });
}
