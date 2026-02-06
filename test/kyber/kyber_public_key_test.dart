import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('KyberPublicKey', () {
    group('serialize() / deserialize()', () {
      test('round-trip preserves public key', () {
        final keyPair = KyberKeyPair.generate();
        final original = keyPair.getPublicKey();

        final serialized = original.serialize();
        expect(serialized, isNotEmpty);
        // Kyber1024 public key (includes format byte prefix)
        expect(serialized.length, equals(1569));

        final restored = KyberPublicKey.deserialize(bytes: serialized.toList());
        expect(restored.equals(other: original), isTrue);
      });

      test('deserialize rejects empty data', () {
        expect(() => KyberPublicKey.deserialize(bytes: []), throwsA(anything));
      });

      // Note: Tests for invalid/garbage/wrong-size data are skipped because
      // libsignal native library may crash when retrieving error messages
      // for certain deserialization failures. This is a known limitation.
    });

    group('equals()', () {
      test('returns true for same key', () {
        final keyPair = KyberKeyPair.generate();
        final pub1 = keyPair.getPublicKey();
        final pub2 = keyPair.getPublicKey();

        expect(pub1.equals(other: pub2), isTrue);
      });

      test('returns false for different keys', () {
        final keyPair1 = KyberKeyPair.generate();
        final keyPair2 = KyberKeyPair.generate();

        final pub1 = keyPair1.getPublicKey();
        final pub2 = keyPair2.getPublicKey();

        expect(pub1.equals(other: pub2), isFalse);
      });

      test('returns true for cloned key', () {
        final keyPair = KyberKeyPair.generate();
        final original = keyPair.getPublicKey();
        final cloned = original.cloneKey();

        expect(original.equals(other: cloned), isTrue);
      });

      test('returns true for deserialized key', () {
        final keyPair = KyberKeyPair.generate();
        final original = keyPair.getPublicKey();
        final deserialized = KyberPublicKey.deserialize(
          bytes: original.serialize().toList(),
        );

        expect(original.equals(other: deserialized), isTrue);
      });
    });

    group('cloneKey()', () {
      test('creates independent copy', () {
        final keyPair = KyberKeyPair.generate();
        final original = keyPair.getPublicKey();
        final cloned = original.cloneKey();

        expect(cloned, isNotNull);
        expect(cloned.serialize(), equals(original.serialize()));
      });
    });
  });
}
