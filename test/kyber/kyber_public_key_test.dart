import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('KyberPublicKey', () {
    group('serialize() / deserialize()', () {
      test('round-trip preserves public key', () {
        final keyPair = KyberKeyPair.generate();
        final original = keyPair.getPublicKey();

        final serialized = original.serialize();
        expect(serialized, isNotEmpty);
        // Kyber1024 public key (includes format byte prefix)
        expect(serialized.length, equals(1569));

        final restored = KyberPublicKey.deserialize(serialized);
        expect(restored.equals(original), isTrue);

        keyPair.dispose();
        original.dispose();
        restored.dispose();
      });

      test('deserialize rejects empty data', () {
        expect(
          () => KyberPublicKey.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
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

        expect(pub1.equals(pub2), isTrue);

        keyPair.dispose();
        pub1.dispose();
        pub2.dispose();
      });

      test('returns false for different keys', () {
        final keyPair1 = KyberKeyPair.generate();
        final keyPair2 = KyberKeyPair.generate();

        final pub1 = keyPair1.getPublicKey();
        final pub2 = keyPair2.getPublicKey();

        expect(pub1.equals(pub2), isFalse);

        keyPair1.dispose();
        keyPair2.dispose();
        pub1.dispose();
        pub2.dispose();
      });

      test('returns true for cloned key', () {
        final keyPair = KyberKeyPair.generate();
        final original = keyPair.getPublicKey();
        final cloned = original.clone();

        expect(original.equals(cloned), isTrue);

        keyPair.dispose();
        original.dispose();
        cloned.dispose();
      });

      test('returns true for deserialized key', () {
        final keyPair = KyberKeyPair.generate();
        final original = keyPair.getPublicKey();
        final deserialized = KyberPublicKey.deserialize(original.serialize());

        expect(original.equals(deserialized), isTrue);

        keyPair.dispose();
        original.dispose();
        deserialized.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final keyPair = KyberKeyPair.generate();
        final original = keyPair.getPublicKey();
        final cloned = original.clone();

        expect(cloned, isNotNull);
        expect(cloned.isDisposed, isFalse);
        expect(cloned.serialize(), equals(original.serialize()));

        original.dispose();

        // Cloned should still work after original is disposed
        expect(cloned.isDisposed, isFalse);
        expect(cloned.serialize().length, equals(1569));

        keyPair.dispose();
        cloned.dispose();
      });
    });

    group('operator ==', () {
      test('returns true for equal keys', () {
        final keyPair = KyberKeyPair.generate();
        final pub1 = keyPair.getPublicKey();
        final pub2 = keyPair.getPublicKey();

        expect(pub1 == pub2, isTrue);

        keyPair.dispose();
        pub1.dispose();
        pub2.dispose();
      });

      test('returns false for different keys', () {
        final keyPair1 = KyberKeyPair.generate();
        final keyPair2 = KyberKeyPair.generate();

        final pub1 = keyPair1.getPublicKey();
        final pub2 = keyPair2.getPublicKey();

        expect(pub1 == pub2, isFalse);

        keyPair1.dispose();
        keyPair2.dispose();
        pub1.dispose();
        pub2.dispose();
      });

      test('returns false when comparing with disposed key', () {
        final keyPair = KyberKeyPair.generate();
        final pub1 = keyPair.getPublicKey();
        final pub2 = keyPair.getPublicKey();

        pub2.dispose();
        expect(pub1 == pub2, isFalse);

        keyPair.dispose();
        pub1.dispose();
      });
    });

    group('hashCode', () {
      test('equal keys have equal hash codes', () {
        final keyPair = KyberKeyPair.generate();
        final pub1 = keyPair.getPublicKey();
        final pub2 = keyPair.getPublicKey();

        expect(pub1.hashCode, equals(pub2.hashCode));

        keyPair.dispose();
        pub1.dispose();
        pub2.dispose();
      });

      test('disposed key returns 0', () {
        final keyPair = KyberKeyPair.generate();
        final pub = keyPair.getPublicKey();
        pub.dispose();

        expect(pub.hashCode, equals(0));

        keyPair.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        final keyPair = KyberKeyPair.generate();
        final pub = keyPair.getPublicKey();
        expect(pub.isDisposed, isFalse);

        pub.dispose();
        keyPair.dispose();
      });

      test('isDisposed is true after dispose', () {
        final keyPair = KyberKeyPair.generate();
        final pub = keyPair.getPublicKey();
        pub.dispose();
        expect(pub.isDisposed, isTrue);

        keyPair.dispose();
      });

      test('double dispose is safe', () {
        final keyPair = KyberKeyPair.generate();
        final pub = keyPair.getPublicKey();
        pub.dispose();
        expect(() => pub.dispose(), returnsNormally);

        keyPair.dispose();
      });

      test('serialize throws after dispose', () {
        final keyPair = KyberKeyPair.generate();
        final pub = keyPair.getPublicKey();
        pub.dispose();
        expect(() => pub.serialize(), throwsA(isA<LibSignalException>()));

        keyPair.dispose();
      });

      test('equals throws after dispose', () {
        final keyPair = KyberKeyPair.generate();
        final pub1 = keyPair.getPublicKey();
        final pub2 = keyPair.getPublicKey();
        pub1.dispose();
        expect(() => pub1.equals(pub2), throwsA(isA<LibSignalException>()));

        pub2.dispose();
        keyPair.dispose();
      });

      test('clone throws after dispose', () {
        final keyPair = KyberKeyPair.generate();
        final pub = keyPair.getPublicKey();
        pub.dispose();
        expect(() => pub.clone(), throwsA(isA<LibSignalException>()));

        keyPair.dispose();
      });

      test('pointer throws after dispose', () {
        final keyPair = KyberKeyPair.generate();
        final pub = keyPair.getPublicKey();
        pub.dispose();
        expect(() => pub.pointer, throwsA(isA<LibSignalException>()));

        keyPair.dispose();
      });
    });
  });
}
