import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('KyberKeyPair', () {
    group('generate()', () {
      test('generates valid key pair', () {
        final keyPair = KyberKeyPair.generate();

        expect(keyPair, isNotNull);
      });

      test('generates unique key pairs', () {
        final keyPair1 = KyberKeyPair.generate();
        final keyPair2 = KyberKeyPair.generate();

        final pub1 = keyPair1.getPublicKey();
        final pub2 = keyPair2.getPublicKey();

        expect(pub1.serialize(), isNot(equals(pub2.serialize())));
      });
    });

    group('getPublicKey()', () {
      test('returns valid Kyber public key', () {
        final keyPair = KyberKeyPair.generate();
        final publicKey = keyPair.getPublicKey();

        expect(publicKey, isNotNull);
        // Kyber1024 public key is 1568 bytes (+ 1 format byte)
        expect(publicKey.serialize().length, greaterThan(1000));
      });

      test('multiple calls return equivalent public keys', () {
        final keyPair = KyberKeyPair.generate();

        final pub1 = keyPair.getPublicKey();
        final pub2 = keyPair.getPublicKey();

        expect(pub1.equals(other: pub2), isTrue);
        expect(pub1.serialize(), equals(pub2.serialize()));
      });
    });

    group('getSecretKey()', () {
      test('returns valid Kyber secret key', () {
        final keyPair = KyberKeyPair.generate();
        final secretKey = keyPair.getSecretKey();

        expect(secretKey, isNotNull);
        // Kyber1024 secret key is 3168 bytes (+ 1 format byte)
        expect(secretKey.serialize().length, greaterThan(3000));
      });

      test('multiple calls return equivalent secret keys', () {
        final keyPair = KyberKeyPair.generate();

        final secret1 = keyPair.getSecretKey();
        final secret2 = keyPair.getSecretKey();

        expect(secret1.serialize(), equals(secret2.serialize()));
      });
    });

    group('cloneKey()', () {
      test('creates independent copy', () {
        final original = KyberKeyPair.generate();
        final cloned = original.cloneKey();

        expect(cloned, isNotNull);

        // Cloned should still work
        final pub = cloned.getPublicKey();
        expect(pub, isNotNull);
      });

      test('cloned key pair has same keys', () {
        final original = KyberKeyPair.generate();
        final cloned = original.cloneKey();

        final origPub = original.getPublicKey();
        final clonedPub = cloned.getPublicKey();
        expect(clonedPub.equals(other: origPub), isTrue);

        final origSecret = original.getSecretKey();
        final clonedSecret = cloned.getSecretKey();
        expect(clonedSecret.serialize(), equals(origSecret.serialize()));
      });
    });
  });
}
