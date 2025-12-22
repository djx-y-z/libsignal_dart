import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('KyberSecretKey', () {
    group('serialize() / deserialize()', () {
      test('round-trip preserves secret key', () {
        final keyPair = KyberKeyPair.generate();
        final original = keyPair.getSecretKey();

        final serialized = original.serialize();
        expect(serialized.bytes, isNotEmpty);
        // Kyber1024 secret key (includes format byte prefix)
        expect(serialized.length, equals(3169));

        final restored = KyberSecretKey.deserialize(serialized.bytes);
        final restoredBytes = restored.serialize();
        expect(restoredBytes.bytes, equals(serialized.bytes));
        restoredBytes.dispose();

        serialized.dispose();
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

      // Note: Tests for invalid/garbage/wrong-size data are skipped because
      // libsignal native library may crash when retrieving error messages
      // for certain deserialization failures. This is a known limitation.
    });

    group('clone()', () {
      test('creates independent copy', () {
        final keyPair = KyberKeyPair.generate();
        final original = keyPair.getSecretKey();
        final cloned = original.clone();

        expect(cloned, isNotNull);
        expect(cloned.isDisposed, isFalse);

        final clonedBytes = cloned.serialize();
        final originalBytes = original.serialize();
        expect(clonedBytes.bytes, equals(originalBytes.bytes));
        clonedBytes.dispose();
        originalBytes.dispose();

        original.dispose();

        // Cloned should still work after original is disposed
        expect(cloned.isDisposed, isFalse);
        final clonedAfterDispose = cloned.serialize();
        expect(clonedAfterDispose.length, equals(3169));
        clonedAfterDispose.dispose();

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
