import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';
import '../test_helpers/error_matchers.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('KyberSecretKey', () {
    group('serialize() / deserialize()', () {
      test('round-trip preserves secret key', () {
        final keyPair = KyberKeyPair.generate();
        final original = keyPair.getSecretKey();

        final serialized = original.serialize();
        expect(serialized, isNotEmpty);
        // Kyber1024 secret key (includes format byte prefix)
        expect(serialized.length, equals(3169));

        final restored = KyberSecretKey.deserialize(bytes: serialized.toList());
        expect(restored.serialize(), equals(serialized));
      });

      test('deserialize rejects empty data', () {
        expect(
          () => KyberSecretKey.deserialize(bytes: []),
          failsWith(LibSignalErrorCode.invalidKey),
        );
      });

      // Note: Tests for invalid/garbage/wrong-size data are skipped because
      // libsignal native library may crash when retrieving error messages
      // for certain deserialization failures. This is a known limitation.
    });

    group('cloneKey()', () {
      test('creates independent copy', () {
        final keyPair = KyberKeyPair.generate();
        final original = keyPair.getSecretKey();
        final cloned = original.cloneKey();

        expect(cloned, isNotNull);
        expect(cloned.serialize(), equals(original.serialize()));
      });
    });
  });
}
