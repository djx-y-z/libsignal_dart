import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('PublicKey', () {
    late PrivateKey privateKey;
    late PublicKey publicKey;

    setUp(() {
      privateKey = PrivateKey.generate();
      publicKey = privateKey.getPublicKey();
    });

    tearDown(() {
      if (!privateKey.isDisposed) privateKey.dispose();
      if (!publicKey.isDisposed) publicKey.dispose();
    });

    group('serialize() / deserialize()', () {
      test('serialize returns 33 bytes', () {
        final serialized = publicKey.serialize();
        expect(serialized.length, equals(33));
      });

      test('round-trip preserves key', () {
        final serialized = publicKey.serialize();
        final restored = PublicKey.deserialize(serialized);

        expect(restored.equals(publicKey), isTrue);
        expect(restored.serialize(), equals(serialized));

        restored.dispose();
      });

      test('deserialize rejects empty data', () {
        expect(
          () => PublicKey.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects invalid data', () {
        final invalidData = Uint8List.fromList([1, 2, 3, 4, 5]);
        expect(
          () => PublicKey.deserialize(invalidData),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('first byte is key type prefix', () {
        final serialized = publicKey.serialize();
        // Type prefix for Curve25519 is 0x05
        expect(serialized[0], equals(0x05));
      });
    });

    group('getPublicKeyBytes()', () {
      test('returns 32 bytes', () {
        final bytes = publicKey.getPublicKeyBytes();
        expect(bytes.length, equals(32));
      });

      test('matches serialized data without prefix', () {
        final serialized = publicKey.serialize();
        final rawBytes = publicKey.getPublicKeyBytes();

        // Raw bytes should be serialized data minus the first byte
        expect(rawBytes, equals(serialized.sublist(1)));
      });
    });

    group('verify()', () {
      test('verifies valid signature', () {
        final message = testMessage('Test message');
        final signature = privateKey.sign(message);

        expect(publicKey.verify(message, signature), isTrue);
      });

      test('rejects signature for wrong message', () {
        final message = testMessage('Test message');
        final wrongMessage = testMessage('Wrong message');
        final signature = privateKey.sign(message);

        expect(publicKey.verify(wrongMessage, signature), isFalse);
      });

      test('rejects signature from different key', () {
        final message = testMessage('Test message');

        final otherPrivate = PrivateKey.generate();
        final signature = otherPrivate.sign(message);

        expect(publicKey.verify(message, signature), isFalse);

        otherPrivate.dispose();
      });

      test('rejects tampered signature', () {
        final message = testMessage('Test message');
        final signature = privateKey.sign(message);

        // Tamper with signature
        signature[0] ^= 0xFF;

        expect(publicKey.verify(message, signature), isFalse);
      });

      test('verifies empty message', () {
        final message = Uint8List(0);
        final signature = privateKey.sign(message);

        expect(publicKey.verify(message, signature), isTrue);
      });

      test('rejects empty signature for non-empty message', () {
        final message = testMessage('Test message');
        final emptySignature = Uint8List(0);

        expect(publicKey.verify(message, emptySignature), isFalse);
      });
    });

    group('equals()', () {
      test('same key equals itself', () {
        expect(publicKey.equals(publicKey), isTrue);
      });

      test('cloned key equals original', () {
        final cloned = publicKey.clone();
        expect(publicKey.equals(cloned), isTrue);
        cloned.dispose();
      });

      test('different keys are not equal', () {
        final otherPrivate = PrivateKey.generate();
        final otherPublic = otherPrivate.getPublicKey();

        expect(publicKey.equals(otherPublic), isFalse);

        otherPrivate.dispose();
        otherPublic.dispose();
      });

      test('deserialized key equals original', () {
        final serialized = publicKey.serialize();
        final restored = PublicKey.deserialize(serialized);

        expect(publicKey.equals(restored), isTrue);

        restored.dispose();
      });
    });

    group('compare()', () {
      test('key compares equal to itself', () {
        final cloned = publicKey.clone();
        expect(publicKey.compare(cloned), equals(0));
        cloned.dispose();
      });

      test('different keys have non-zero comparison', () {
        final otherPrivate = PrivateKey.generate();
        final otherPublic = otherPrivate.getPublicKey();

        final comparison = publicKey.compare(otherPublic);
        expect(comparison, isNot(equals(0)));

        // Comparison should be consistent
        expect(otherPublic.compare(publicKey), equals(-comparison));

        otherPrivate.dispose();
        otherPublic.dispose();
      });

      test('comparison is transitive', () {
        final key1 = PrivateKey.generate().getPublicKey();
        final key2 = PrivateKey.generate().getPublicKey();
        final key3 = PrivateKey.generate().getPublicKey();

        // Get all pairwise comparisons
        final cmp12 = key1.compare(key2);
        final cmp23 = key2.compare(key3);
        final cmp13 = key1.compare(key3);

        // If key1 < key2 and key2 < key3, then key1 < key3
        if (cmp12 < 0 && cmp23 < 0) {
          expect(cmp13, lessThan(0));
        }
        // If key1 > key2 and key2 > key3, then key1 > key3
        if (cmp12 > 0 && cmp23 > 0) {
          expect(cmp13, greaterThan(0));
        }

        key1.dispose();
        key2.dispose();
        key3.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final cloned = publicKey.clone();

        expect(cloned.serialize(), equals(publicKey.serialize()));
        expect(cloned.equals(publicKey), isTrue);

        publicKey.dispose();

        // Cloned key should still work
        expect(cloned.isDisposed, isFalse);
        expect(() => cloned.serialize(), returnsNormally);

        cloned.dispose();
      });
    });

    group('== and hashCode', () {
      test('equal keys have same hashCode', () {
        final cloned = publicKey.clone();
        expect(publicKey.hashCode, equals(cloned.hashCode));
        cloned.dispose();
      });

      test('operator == works correctly', () {
        final cloned = publicKey.clone();
        expect(publicKey == cloned, isTrue);
        cloned.dispose();
      });

      test('different keys have different == result', () {
        final otherPrivate = PrivateKey.generate();
        final otherPublic = otherPrivate.getPublicKey();

        expect(publicKey == otherPublic, isFalse);

        otherPrivate.dispose();
        otherPublic.dispose();
      });

      test('disposed keys return hashCode 0', () {
        final key = PrivateKey.generate().getPublicKey();
        key.dispose();
        expect(key.hashCode, equals(0));
      });

      test('disposed keys are not equal', () {
        final key1 = PrivateKey.generate().getPublicKey();
        final key2 = key1.clone();

        key1.dispose();

        expect(key1 == key2, isFalse);
        expect(key2 == key1, isFalse);

        key2.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        expect(publicKey.isDisposed, isFalse);
      });

      test('isDisposed is true after dispose', () {
        final key = PrivateKey.generate().getPublicKey();
        key.dispose();
        expect(key.isDisposed, isTrue);
      });

      test('double dispose is safe', () {
        final key = PrivateKey.generate().getPublicKey();
        key.dispose();
        expect(() => key.dispose(), returnsNormally);
      });

      test('serialize throws after dispose', () {
        final key = PrivateKey.generate().getPublicKey();
        key.dispose();
        expect(() => key.serialize(), throwsStateError);
      });

      test('getPublicKeyBytes throws after dispose', () {
        final key = PrivateKey.generate().getPublicKey();
        key.dispose();
        expect(() => key.getPublicKeyBytes(), throwsStateError);
      });

      test('verify throws after dispose', () {
        final key = PrivateKey.generate().getPublicKey();
        key.dispose();
        expect(() => key.verify(Uint8List(0), Uint8List(0)), throwsStateError);
      });

      test('equals throws after dispose', () {
        final key1 = PrivateKey.generate().getPublicKey();
        final key2 = PrivateKey.generate().getPublicKey();

        key1.dispose();

        expect(() => key1.equals(key2), throwsStateError);

        key2.dispose();
      });

      test('compare throws after dispose', () {
        final key1 = PrivateKey.generate().getPublicKey();
        final key2 = PrivateKey.generate().getPublicKey();

        key1.dispose();

        expect(() => key1.compare(key2), throwsStateError);

        key2.dispose();
      });

      test('clone throws after dispose', () {
        final key = PrivateKey.generate().getPublicKey();
        key.dispose();
        expect(() => key.clone(), throwsStateError);
      });

      test('pointer throws after dispose', () {
        final key = PrivateKey.generate().getPublicKey();
        key.dispose();
        expect(() => key.pointer, throwsStateError);
      });
    });
  });
}
