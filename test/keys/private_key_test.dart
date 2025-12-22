import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('PrivateKey', () {
    group('generate()', () {
      test('generates valid private key', () {
        final key = PrivateKey.generate();
        expect(key, isNotNull);
        expect(key.isDisposed, isFalse);
        key.dispose();
      });

      test('each generation produces unique key', () {
        final key1 = PrivateKey.generate();
        final key2 = PrivateKey.generate();

        final bytes1 = key1.serialize();
        final bytes2 = key2.serialize();

        expect(bytes1, isNot(equals(bytes2)));

        key1.dispose();
        key2.dispose();
      });

      test('generated key can derive public key', () {
        final key = PrivateKey.generate();
        final publicKey = key.getPublicKey();

        expect(publicKey, isNotNull);
        expect(publicKey.isDisposed, isFalse);

        key.dispose();
        publicKey.dispose();
      });
    });

    group('serialize() / deserialize()', () {
      test('serialize returns 32 bytes', () {
        final key = PrivateKey.generate();
        final serialized = key.serialize();

        expect(serialized.length, equals(32));

        key.dispose();
      });

      test('round-trip preserves key', () {
        final original = PrivateKey.generate();
        final serialized = original.serialize();
        final restored = PrivateKey.deserialize(serialized);

        // Keys should produce the same serialization
        expect(restored.serialize(), equals(original.serialize()));

        // Keys should derive the same public key
        final pub1 = original.getPublicKey();
        final pub2 = restored.getPublicKey();
        expect(pub1.equals(pub2), isTrue);

        original.dispose();
        restored.dispose();
        pub1.dispose();
        pub2.dispose();
      });

      test('deserialize rejects empty data', () {
        expect(
          () => PrivateKey.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects data with wrong length', () {
        final invalidData = Uint8List.fromList([1, 2, 3, 4, 5]);
        expect(
          () => PrivateKey.deserialize(invalidData),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('getPublicKey()', () {
      test('returns valid public key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        expect(publicKey, isNotNull);
        expect(publicKey.isDisposed, isFalse);
        expect(publicKey.serialize().length, equals(33));

        privateKey.dispose();
        publicKey.dispose();
      });

      test('same private key always produces same public key', () {
        final privateKey = PrivateKey.generate();

        final pub1 = privateKey.getPublicKey();
        final pub2 = privateKey.getPublicKey();

        expect(pub1.equals(pub2), isTrue);

        privateKey.dispose();
        pub1.dispose();
        pub2.dispose();
      });
    });

    group('sign()', () {
      test('signs empty message', () {
        final key = PrivateKey.generate();
        final signature = key.sign(Uint8List(0));

        expect(signature, isNotNull);
        expect(signature.length, equals(64)); // Ed25519 signature

        key.dispose();
      });

      test('signs non-empty message', () {
        final key = PrivateKey.generate();
        final message = testMessage('Hello, Signal!');
        final signature = key.sign(message);

        expect(signature, isNotNull);
        expect(signature.length, equals(64));

        key.dispose();
      });

      test('multiple signatures from same key are all valid', () {
        final key = PrivateKey.generate();
        final publicKey = key.getPublicKey();
        final message = testMessage('Test message');

        // Sign multiple times
        final sig1 = key.sign(message);
        final sig2 = key.sign(message);

        // Both signatures should be valid
        expect(publicKey.verify(message, sig1), isTrue);
        expect(publicKey.verify(message, sig2), isTrue);

        key.dispose();
        publicKey.dispose();
      });

      test('different messages produce different signatures', () {
        final key = PrivateKey.generate();
        final msg1 = testMessage('Message 1');
        final msg2 = testMessage('Message 2');

        final sig1 = key.sign(msg1);
        final sig2 = key.sign(msg2);

        expect(sig1, isNot(equals(sig2)));

        key.dispose();
      });

      test('signature can be verified by public key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();
        final message = testMessage('Test message for signing');

        final signature = privateKey.sign(message);
        final isValid = publicKey.verify(message, signature);

        expect(isValid, isTrue);

        privateKey.dispose();
        publicKey.dispose();
      });
    });

    group('agree()', () {
      test('performs key agreement', () {
        final privateKeyA = PrivateKey.generate();
        final publicKeyA = privateKeyA.getPublicKey();

        final privateKeyB = PrivateKey.generate();
        final publicKeyB = privateKeyB.getPublicKey();

        final sharedA = privateKeyA.agree(publicKeyB);
        final sharedB = privateKeyB.agree(publicKeyA);

        expect(sharedA.length, equals(32));
        expect(sharedA, equals(sharedB));

        privateKeyA.dispose();
        publicKeyA.dispose();
        privateKeyB.dispose();
        publicKeyB.dispose();
      });

      test('different key pairs produce different shared secrets', () {
        final privateKey = PrivateKey.generate();

        final otherKey1 = PrivateKey.generate();
        final otherPub1 = otherKey1.getPublicKey();

        final otherKey2 = PrivateKey.generate();
        final otherPub2 = otherKey2.getPublicKey();

        final shared1 = privateKey.agree(otherPub1);
        final shared2 = privateKey.agree(otherPub2);

        expect(shared1, isNot(equals(shared2)));

        privateKey.dispose();
        otherKey1.dispose();
        otherPub1.dispose();
        otherKey2.dispose();
        otherPub2.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final original = PrivateKey.generate();
        final cloned = original.clone();

        expect(cloned.serialize(), equals(original.serialize()));

        original.dispose();

        // Cloned key should still work after original is disposed
        expect(cloned.isDisposed, isFalse);
        expect(() => cloned.serialize(), returnsNormally);

        cloned.dispose();
      });

      test('cloned key produces same public key', () {
        final original = PrivateKey.generate();
        final cloned = original.clone();

        final pub1 = original.getPublicKey();
        final pub2 = cloned.getPublicKey();

        expect(pub1.equals(pub2), isTrue);

        original.dispose();
        cloned.dispose();
        pub1.dispose();
        pub2.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        final key = PrivateKey.generate();
        expect(key.isDisposed, isFalse);
        key.dispose();
      });

      test('isDisposed is true after dispose', () {
        final key = PrivateKey.generate();
        key.dispose();
        expect(key.isDisposed, isTrue);
      });

      test('double dispose is safe', () {
        final key = PrivateKey.generate();
        key.dispose();
        expect(() => key.dispose(), returnsNormally);
      });

      test('serialize throws after dispose', () {
        final key = PrivateKey.generate();
        key.dispose();
        expect(() => key.serialize(), throwsStateError);
      });

      test('getPublicKey throws after dispose', () {
        final key = PrivateKey.generate();
        key.dispose();
        expect(() => key.getPublicKey(), throwsStateError);
      });

      test('sign throws after dispose', () {
        final key = PrivateKey.generate();
        key.dispose();
        expect(() => key.sign(Uint8List(0)), throwsStateError);
      });

      test('agree throws after dispose', () {
        final key = PrivateKey.generate();
        final other = PrivateKey.generate();
        final otherPub = other.getPublicKey();

        key.dispose();

        expect(() => key.agree(otherPub), throwsStateError);

        other.dispose();
        otherPub.dispose();
      });

      test('clone throws after dispose', () {
        final key = PrivateKey.generate();
        key.dispose();
        expect(() => key.clone(), throwsStateError);
      });

      test('pointer throws after dispose', () {
        final key = PrivateKey.generate();
        key.dispose();
        expect(() => key.pointer, throwsStateError);
      });
    });
  });
}
