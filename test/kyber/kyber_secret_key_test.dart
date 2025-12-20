import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('KyberSecretKey', () {
    group('serialize() / deserialize()', () {
      test('round-trip preserves secret key', () {
        final keyPair = KyberKeyPair.generate();
        final original = keyPair.getSecretKey();

        final serialized = original.serialize();
        expect(serialized, isNotEmpty);
        // Kyber1024 secret key (includes format byte prefix)
        expect(serialized.length, equals(3169));

        final restored = KyberSecretKey.deserialize(serialized);
        expect(restored.serialize(), equals(serialized));

        keyPair.dispose();
        original.dispose();
        restored.dispose();
      });

      test('deserialize rejects empty data', () {
        expect(
          () => KyberSecretKey.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects invalid data', () {
        final invalidData = Uint8List.fromList([1, 2, 3, 4, 5]);
        expect(
          () => KyberSecretKey.deserialize(invalidData),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects garbage data', () {
        final garbage = randomBytes(3168);
        expect(
          () => KyberSecretKey.deserialize(garbage),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects wrong size data', () {
        final wrongSize = Uint8List(2000);
        expect(
          () => KyberSecretKey.deserialize(wrongSize),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final keyPair = KyberKeyPair.generate();
        final original = keyPair.getSecretKey();
        final cloned = original.clone();

        expect(cloned, isNotNull);
        expect(cloned.isDisposed, isFalse);
        expect(cloned.serialize(), equals(original.serialize()));

        original.dispose();

        // Cloned should still work after original is disposed
        expect(cloned.isDisposed, isFalse);
        expect(cloned.serialize().length, equals(3169));

        keyPair.dispose();
        cloned.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        final keyPair = KyberKeyPair.generate();
        final secret = keyPair.getSecretKey();
        expect(secret.isDisposed, isFalse);

        secret.dispose();
        keyPair.dispose();
      });

      test('isDisposed is true after dispose', () {
        final keyPair = KyberKeyPair.generate();
        final secret = keyPair.getSecretKey();
        secret.dispose();
        expect(secret.isDisposed, isTrue);

        keyPair.dispose();
      });

      test('double dispose is safe', () {
        final keyPair = KyberKeyPair.generate();
        final secret = keyPair.getSecretKey();
        secret.dispose();
        expect(() => secret.dispose(), returnsNormally);

        keyPair.dispose();
      });

      test('serialize throws after dispose', () {
        final keyPair = KyberKeyPair.generate();
        final secret = keyPair.getSecretKey();
        secret.dispose();
        expect(() => secret.serialize(), throwsStateError);

        keyPair.dispose();
      });

      test('clone throws after dispose', () {
        final keyPair = KyberKeyPair.generate();
        final secret = keyPair.getSecretKey();
        secret.dispose();
        expect(() => secret.clone(), throwsStateError);

        keyPair.dispose();
      });

      test('pointer throws after dispose', () {
        final keyPair = KyberKeyPair.generate();
        final secret = keyPair.getSecretKey();
        secret.dispose();
        expect(() => secret.pointer, throwsStateError);

        keyPair.dispose();
      });
    });
  });
}
