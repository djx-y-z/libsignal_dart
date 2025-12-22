import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('KyberKeyPair', () {
    group('generate()', () {
      test('generates valid key pair', () {
        final keyPair = KyberKeyPair.generate();

        expect(keyPair, isNotNull);
        expect(keyPair.isDisposed, isFalse);

        keyPair.dispose();
      });

      test('generates unique key pairs', () {
        final keyPair1 = KyberKeyPair.generate();
        final keyPair2 = KyberKeyPair.generate();

        final pub1 = keyPair1.getPublicKey();
        final pub2 = keyPair2.getPublicKey();

        expect(pub1.serialize(), isNot(equals(pub2.serialize())));

        keyPair1.dispose();
        keyPair2.dispose();
        pub1.dispose();
        pub2.dispose();
      });
    });

    group('getPublicKey()', () {
      test('returns valid Kyber public key', () {
        final keyPair = KyberKeyPair.generate();
        final publicKey = keyPair.getPublicKey();

        expect(publicKey, isNotNull);
        expect(publicKey.isDisposed, isFalse);
        // Kyber1024 public key is 1568 bytes
        expect(publicKey.serialize().length, greaterThan(1000));

        publicKey.dispose();
        keyPair.dispose();
      });

      test('multiple calls return equivalent public keys', () {
        final keyPair = KyberKeyPair.generate();

        final pub1 = keyPair.getPublicKey();
        final pub2 = keyPair.getPublicKey();

        expect(pub1.equals(pub2), isTrue);
        expect(pub1.serialize(), equals(pub2.serialize()));

        pub1.dispose();
        pub2.dispose();
        keyPair.dispose();
      });
    });

    group('getSecretKey()', () {
      test('returns valid Kyber secret key', () {
        final keyPair = KyberKeyPair.generate();
        final secretKey = keyPair.getSecretKey();

        expect(secretKey, isNotNull);
        expect(secretKey.isDisposed, isFalse);
        // Kyber1024 secret key is 3168 bytes
        expect(secretKey.serialize().length, greaterThan(3000));

        secretKey.dispose();
        keyPair.dispose();
      });

      test('multiple calls return equivalent secret keys', () {
        final keyPair = KyberKeyPair.generate();

        final secret1 = keyPair.getSecretKey();
        final secret2 = keyPair.getSecretKey();

        final secret1Bytes = secret1.serialize();
        final secret2Bytes = secret2.serialize();
        expect(secret1Bytes.bytes, equals(secret2Bytes.bytes));
        secret1Bytes.dispose();
        secret2Bytes.dispose();

        secret1.dispose();
        secret2.dispose();
        keyPair.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final original = KyberKeyPair.generate();
        final cloned = original.clone();

        expect(cloned, isNotNull);
        expect(cloned.isDisposed, isFalse);

        original.dispose();

        // Cloned should still work after original is disposed
        expect(cloned.isDisposed, isFalse);
        final pub = cloned.getPublicKey();
        expect(pub, isNotNull);

        pub.dispose();
        cloned.dispose();
      });

      test('cloned key pair has same keys', () {
        final original = KyberKeyPair.generate();
        final cloned = original.clone();

        final origPub = original.getPublicKey();
        final clonedPub = cloned.getPublicKey();
        expect(clonedPub.equals(origPub), isTrue);

        final origSecret = original.getSecretKey();
        final clonedSecret = cloned.getSecretKey();
        final origSecretBytes = origSecret.serialize();
        final clonedSecretBytes = clonedSecret.serialize();
        expect(clonedSecretBytes.bytes, equals(origSecretBytes.bytes));
        origSecretBytes.dispose();
        clonedSecretBytes.dispose();

        original.dispose();
        cloned.dispose();
        origPub.dispose();
        clonedPub.dispose();
        origSecret.dispose();
        clonedSecret.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        final keyPair = KyberKeyPair.generate();
        expect(keyPair.isDisposed, isFalse);
        keyPair.dispose();
      });

      test('isDisposed is true after dispose', () {
        final keyPair = KyberKeyPair.generate();
        keyPair.dispose();
        expect(keyPair.isDisposed, isTrue);
      });

      test('double dispose is safe', () {
        final keyPair = KyberKeyPair.generate();
        keyPair.dispose();
        expect(() => keyPair.dispose(), returnsNormally);
      });

      test('getPublicKey throws after dispose', () {
        final keyPair = KyberKeyPair.generate();
        keyPair.dispose();
        expect(() => keyPair.getPublicKey(), throwsStateError);
      });

      test('getSecretKey throws after dispose', () {
        final keyPair = KyberKeyPair.generate();
        keyPair.dispose();
        expect(() => keyPair.getSecretKey(), throwsStateError);
      });

      test('clone throws after dispose', () {
        final keyPair = KyberKeyPair.generate();
        keyPair.dispose();
        expect(() => keyPair.clone(), throwsStateError);
      });

      test('pointer throws after dispose', () {
        final keyPair = KyberKeyPair.generate();
        keyPair.dispose();
        expect(() => keyPair.pointer, throwsStateError);
      });
    });
  });
}
