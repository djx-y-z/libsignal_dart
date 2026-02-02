import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('PrivateKey', () {
    group('generate()', () {
      test('generates valid private key', () {
        final key = PrivateKey.generate();
        expect(key, isNotNull);
      });

      test('each generation produces unique key', () {
        final key1 = PrivateKey.generate();
        final key2 = PrivateKey.generate();

        final bytes1 = key1.serialize();
        final bytes2 = key2.serialize();

        expect(bytes1, isNot(equals(bytes2)));
      });

      test('generated key can derive public key', () {
        final key = PrivateKey.generate();
        final publicKey = key.getPublicKey();

        expect(publicKey, isNotNull);
      });
    });

    group('serialize() / deserialize()', () {
      test('serialize returns 32 bytes', () {
        final key = PrivateKey.generate();
        final serialized = key.serialize();

        expect(serialized.length, equals(32));
      });

      test('round-trip preserves key', () {
        final original = PrivateKey.generate();
        final serialized = original.serialize();
        final restored = PrivateKey.deserialize(bytes: serialized.toList());

        // Keys should produce the same serialization
        final restoredBytes = restored.serialize();
        final originalBytes = original.serialize();
        expect(restoredBytes, equals(originalBytes));

        // Keys should derive the same public key
        final pub1 = original.getPublicKey();
        final pub2 = restored.getPublicKey();
        expect(pub1.equals(other: pub2), isTrue);
      });

      test('deserialize rejects empty data', () {
        expect(() => PrivateKey.deserialize(bytes: []), throwsA(anything));
      });

      test('deserialize rejects data with wrong length', () {
        final invalidData = [1, 2, 3, 4, 5];
        expect(
          () => PrivateKey.deserialize(bytes: invalidData),
          throwsA(anything),
        );
      });
    });

    group('getPublicKey()', () {
      test('returns valid public key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        expect(publicKey, isNotNull);
        expect(publicKey.serialize().length, equals(33));
      });

      test('same private key always produces same public key', () {
        final privateKey = PrivateKey.generate();

        final pub1 = privateKey.getPublicKey();
        final pub2 = privateKey.getPublicKey();

        expect(pub1.equals(other: pub2), isTrue);
      });
    });

    group('sign()', () {
      test('signs empty message', () {
        final key = PrivateKey.generate();
        final signature = key.sign(message: []);

        expect(signature, isNotNull);
        expect(signature.length, equals(64)); // Ed25519 signature
      });

      test('signs non-empty message', () {
        final key = PrivateKey.generate();
        final message = testMessage('Hello, Signal!');
        final signature = key.sign(message: message.toList());

        expect(signature, isNotNull);
        expect(signature.length, equals(64));
      });

      test('multiple signatures from same key are all valid', () {
        final key = PrivateKey.generate();
        final publicKey = key.getPublicKey();
        final message = testMessage('Test message');

        // Sign multiple times
        final sig1 = key.sign(message: message.toList());
        final sig2 = key.sign(message: message.toList());

        // Both signatures should be valid
        expect(
          publicKey.verify(message: message.toList(), signature: sig1.toList()),
          isTrue,
        );
        expect(
          publicKey.verify(message: message.toList(), signature: sig2.toList()),
          isTrue,
        );
      });

      test('different messages produce different signatures', () {
        final key = PrivateKey.generate();
        final msg1 = testMessage('Message 1');
        final msg2 = testMessage('Message 2');

        final sig1 = key.sign(message: msg1.toList());
        final sig2 = key.sign(message: msg2.toList());

        expect(sig1, isNot(equals(sig2)));
      });

      test('signature can be verified by public key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();
        final message = testMessage('Test message for signing');

        final signature = privateKey.sign(message: message.toList());
        final isValid = publicKey.verify(
          message: message.toList(),
          signature: signature.toList(),
        );

        expect(isValid, isTrue);
      });
    });

    group('agree()', () {
      test('performs key agreement', () {
        final privateKeyA = PrivateKey.generate();
        final publicKeyA = privateKeyA.getPublicKey();

        final privateKeyB = PrivateKey.generate();
        final publicKeyB = privateKeyB.getPublicKey();

        final sharedA = privateKeyA.agree(publicKey: publicKeyB);
        final sharedB = privateKeyB.agree(publicKey: publicKeyA);

        expect(sharedA.length, equals(32));
        expect(sharedA, equals(sharedB));
      });

      test('different key pairs produce different shared secrets', () {
        final privateKey = PrivateKey.generate();

        final otherKey1 = PrivateKey.generate();
        final otherPub1 = otherKey1.getPublicKey();

        final otherKey2 = PrivateKey.generate();
        final otherPub2 = otherKey2.getPublicKey();

        final shared1 = privateKey.agree(publicKey: otherPub1);
        final shared2 = privateKey.agree(publicKey: otherPub2);

        expect(shared1, isNot(equals(shared2)));
      });
    });

    group('cloneKey()', () {
      test('creates independent copy', () {
        final original = PrivateKey.generate();
        final cloned = original.cloneKey();

        final clonedBytes = cloned.serialize();
        final originalBytes = original.serialize();
        expect(clonedBytes, equals(originalBytes));
      });

      test('cloned key produces same public key', () {
        final original = PrivateKey.generate();
        final cloned = original.cloneKey();

        final pub1 = original.getPublicKey();
        final pub2 = cloned.getPublicKey();

        expect(pub1.equals(other: pub2), isTrue);
      });
    });
  });
}
