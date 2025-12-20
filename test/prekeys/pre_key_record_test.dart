import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('PreKeyRecord', () {
    group('create()', () {
      test('creates valid pre-key record', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        expect(preKey, isNotNull);
        expect(preKey.isDisposed, isFalse);
        expect(preKey.id, equals(1));

        preKey.dispose();
        privateKey.dispose();
        publicKey.dispose();
      });

      test('creates pre-key with various IDs', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        for (final id in [0, 1, 100, 0xFFFF, 0xFFFFFF]) {
          final preKey = PreKeyRecord.create(
            id: id,
            publicKey: publicKey,
            privateKey: privateKey,
          );

          expect(preKey.id, equals(id));
          preKey.dispose();
        }

        privateKey.dispose();
        publicKey.dispose();
      });

      test('created pre-key returns correct public key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 42,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final retrievedPubKey = preKey.getPublicKey();
        expect(retrievedPubKey.equals(publicKey), isTrue);

        preKey.dispose();
        privateKey.dispose();
        publicKey.dispose();
        retrievedPubKey.dispose();
      });

      test('created pre-key returns correct private key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 42,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final retrievedPrivKey = preKey.getPrivateKey();
        expect(retrievedPrivKey.serialize(), equals(privateKey.serialize()));

        preKey.dispose();
        privateKey.dispose();
        publicKey.dispose();
        retrievedPrivKey.dispose();
      });
    });

    group('serialize() / deserialize()', () {
      test('round-trip preserves pre-key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final original = PreKeyRecord.create(
          id: 123,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final serialized = original.serialize();
        expect(serialized, isNotEmpty);

        final restored = PreKeyRecord.deserialize(serialized);

        expect(restored.id, equals(original.id));

        final origPub = original.getPublicKey();
        final restoredPub = restored.getPublicKey();
        expect(restoredPub.equals(origPub), isTrue);

        final origPriv = original.getPrivateKey();
        final restoredPriv = restored.getPrivateKey();
        expect(restoredPriv.serialize(), equals(origPriv.serialize()));

        original.dispose();
        restored.dispose();
        privateKey.dispose();
        publicKey.dispose();
        origPub.dispose();
        restoredPub.dispose();
        origPriv.dispose();
        restoredPriv.dispose();
      });

      test('deserialize rejects empty data', () {
        expect(
          () => PreKeyRecord.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects invalid data', () {
        final invalidData = Uint8List.fromList([1, 2, 3, 4, 5]);
        expect(
          () => PreKeyRecord.deserialize(invalidData),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects garbage data', () {
        final garbage = randomBytes(100);
        expect(
          () => PreKeyRecord.deserialize(garbage),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('id', () {
      test('returns correct id', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 999,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        expect(preKey.id, equals(999));

        preKey.dispose();
        privateKey.dispose();
        publicKey.dispose();
      });
    });

    group('getPublicKey()', () {
      test('returns valid public key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final retrievedPub = preKey.getPublicKey();

        expect(retrievedPub, isNotNull);
        expect(retrievedPub.isDisposed, isFalse);
        expect(retrievedPub.serialize().length, equals(33));

        preKey.dispose();
        privateKey.dispose();
        publicKey.dispose();
        retrievedPub.dispose();
      });

      test('multiple calls return equivalent keys', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final pub1 = preKey.getPublicKey();
        final pub2 = preKey.getPublicKey();

        expect(pub1.equals(pub2), isTrue);

        preKey.dispose();
        privateKey.dispose();
        publicKey.dispose();
        pub1.dispose();
        pub2.dispose();
      });
    });

    group('getPrivateKey()', () {
      test('returns valid private key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final retrievedPriv = preKey.getPrivateKey();

        expect(retrievedPriv, isNotNull);
        expect(retrievedPriv.isDisposed, isFalse);
        expect(retrievedPriv.serialize().length, equals(32));

        preKey.dispose();
        privateKey.dispose();
        publicKey.dispose();
        retrievedPriv.dispose();
      });

      test('retrieved private key can derive same public key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final retrievedPriv = preKey.getPrivateKey();
        final derivedPub = retrievedPriv.getPublicKey();
        final preKeyPub = preKey.getPublicKey();

        expect(derivedPub.equals(preKeyPub), isTrue);

        preKey.dispose();
        privateKey.dispose();
        publicKey.dispose();
        retrievedPriv.dispose();
        derivedPub.dispose();
        preKeyPub.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final original = PreKeyRecord.create(
          id: 42,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final cloned = original.clone();

        expect(cloned.id, equals(original.id));
        expect(cloned.serialize(), equals(original.serialize()));

        original.dispose();

        // Cloned should still work after original is disposed
        expect(cloned.isDisposed, isFalse);
        expect(cloned.id, equals(42));

        cloned.dispose();
        privateKey.dispose();
        publicKey.dispose();
      });

      test('cloned pre-key has same keys', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final original = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final cloned = original.clone();

        final origPub = original.getPublicKey();
        final clonedPub = cloned.getPublicKey();
        expect(clonedPub.equals(origPub), isTrue);

        final origPriv = original.getPrivateKey();
        final clonedPriv = cloned.getPrivateKey();
        expect(clonedPriv.serialize(), equals(origPriv.serialize()));

        original.dispose();
        cloned.dispose();
        privateKey.dispose();
        publicKey.dispose();
        origPub.dispose();
        clonedPub.dispose();
        origPriv.dispose();
        clonedPriv.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        expect(preKey.isDisposed, isFalse);

        preKey.dispose();
        privateKey.dispose();
        publicKey.dispose();
      });

      test('isDisposed is true after dispose', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        preKey.dispose();
        expect(preKey.isDisposed, isTrue);

        privateKey.dispose();
        publicKey.dispose();
      });

      test('double dispose is safe', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        preKey.dispose();
        expect(() => preKey.dispose(), returnsNormally);

        privateKey.dispose();
        publicKey.dispose();
      });

      test('id throws after dispose', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        preKey.dispose();
        expect(() => preKey.id, throwsStateError);

        privateKey.dispose();
        publicKey.dispose();
      });

      test('serialize throws after dispose', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        preKey.dispose();
        expect(() => preKey.serialize(), throwsStateError);

        privateKey.dispose();
        publicKey.dispose();
      });

      test('getPublicKey throws after dispose', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        preKey.dispose();
        expect(() => preKey.getPublicKey(), throwsStateError);

        privateKey.dispose();
        publicKey.dispose();
      });

      test('getPrivateKey throws after dispose', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        preKey.dispose();
        expect(() => preKey.getPrivateKey(), throwsStateError);

        privateKey.dispose();
        publicKey.dispose();
      });

      test('clone throws after dispose', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        preKey.dispose();
        expect(() => preKey.clone(), throwsStateError);

        privateKey.dispose();
        publicKey.dispose();
      });

      test('pointer throws after dispose', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord.create(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        preKey.dispose();
        expect(() => preKey.pointer, throwsStateError);

        privateKey.dispose();
        publicKey.dispose();
      });
    });
  });
}
