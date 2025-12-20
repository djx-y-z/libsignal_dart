import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('SignedPreKeyRecord', () {
    late IdentityKeyPair identityKeyPair;

    setUp(() {
      identityKeyPair = IdentityKeyPair.generate();
    });

    tearDown(() {
      identityKeyPair.dispose();
    });

    /// Helper to create a signed pre-key record with valid signature
    SignedPreKeyRecord createSignedPreKey({
      required int id,
      required int timestamp,
    }) {
      final privateKey = PrivateKey.generate();
      final publicKey = privateKey.getPublicKey();
      final signature = identityKeyPair.privateKey.sign(publicKey.serialize());

      final signedPreKey = SignedPreKeyRecord.create(
        id: id,
        timestamp: timestamp,
        publicKey: publicKey,
        privateKey: privateKey,
        signature: signature,
      );

      privateKey.dispose();
      publicKey.dispose();

      return signedPreKey;
    }

    group('create()', () {
      test('creates valid signed pre-key record', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();
        final signature = identityKeyPair.privateKey.sign(publicKey.serialize());

        final signedPreKey = SignedPreKeyRecord.create(
          id: 1,
          timestamp: 1000000,
          publicKey: publicKey,
          privateKey: privateKey,
          signature: signature,
        );

        expect(signedPreKey, isNotNull);
        expect(signedPreKey.isDisposed, isFalse);
        expect(signedPreKey.id, equals(1));
        expect(signedPreKey.timestamp, equals(1000000));

        signedPreKey.dispose();
        privateKey.dispose();
        publicKey.dispose();
      });

      test('creates signed pre-key with various IDs', () {
        for (final id in [0, 1, 100, 0xFFFF, 0xFFFFFF]) {
          final signedPreKey = createSignedPreKey(
            id: id,
            timestamp: 1000000,
          );

          expect(signedPreKey.id, equals(id));
          signedPreKey.dispose();
        }
      });

      test('creates signed pre-key with various timestamps', () {
        final timestamps = [
          0,
          1,
          DateTime.now().millisecondsSinceEpoch,
          0x7FFFFFFFFFFFFFFF, // Max int64
        ];

        for (final ts in timestamps) {
          final signedPreKey = createSignedPreKey(id: 1, timestamp: ts);
          expect(signedPreKey.timestamp, equals(ts));
          signedPreKey.dispose();
        }
      });

      test('created signed pre-key returns correct signature', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();
        final signature = identityKeyPair.privateKey.sign(publicKey.serialize());

        final signedPreKey = SignedPreKeyRecord.create(
          id: 42,
          timestamp: 1000000,
          publicKey: publicKey,
          privateKey: privateKey,
          signature: signature,
        );

        expect(signedPreKey.signature, equals(signature));

        signedPreKey.dispose();
        privateKey.dispose();
        publicKey.dispose();
      });

      test('signature is verifiable by identity public key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();
        final signature = identityKeyPair.privateKey.sign(publicKey.serialize());

        final signedPreKey = SignedPreKeyRecord.create(
          id: 1,
          timestamp: 1000000,
          publicKey: publicKey,
          privateKey: privateKey,
          signature: signature,
        );

        final retrievedPub = signedPreKey.getPublicKey();
        final retrievedSig = signedPreKey.signature;

        final isValid = identityKeyPair.publicKey.verify(
          retrievedPub.serialize(),
          retrievedSig,
        );

        expect(isValid, isTrue);

        signedPreKey.dispose();
        privateKey.dispose();
        publicKey.dispose();
        retrievedPub.dispose();
      });
    });

    group('serialize() / deserialize()', () {
      test('round-trip preserves signed pre-key', () {
        final original = createSignedPreKey(id: 123, timestamp: 9876543210);
        final serialized = original.serialize();

        expect(serialized, isNotEmpty);

        final restored = SignedPreKeyRecord.deserialize(serialized);

        expect(restored.id, equals(original.id));
        expect(restored.timestamp, equals(original.timestamp));
        expect(restored.signature, equals(original.signature));

        final origPub = original.getPublicKey();
        final restoredPub = restored.getPublicKey();
        expect(restoredPub.equals(origPub), isTrue);

        final origPriv = original.getPrivateKey();
        final restoredPriv = restored.getPrivateKey();
        expect(restoredPriv.serialize(), equals(origPriv.serialize()));

        original.dispose();
        restored.dispose();
        origPub.dispose();
        restoredPub.dispose();
        origPriv.dispose();
        restoredPriv.dispose();
      });

      test('deserialize rejects empty data', () {
        expect(
          () => SignedPreKeyRecord.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects invalid data', () {
        final invalidData = Uint8List.fromList([1, 2, 3, 4, 5]);
        expect(
          () => SignedPreKeyRecord.deserialize(invalidData),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects garbage data', () {
        final garbage = randomBytes(200);
        expect(
          () => SignedPreKeyRecord.deserialize(garbage),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('id', () {
      test('returns correct id', () {
        final signedPreKey = createSignedPreKey(id: 999, timestamp: 1000);
        expect(signedPreKey.id, equals(999));
        signedPreKey.dispose();
      });
    });

    group('timestamp', () {
      test('returns correct timestamp', () {
        final now = DateTime.now().millisecondsSinceEpoch;
        final signedPreKey = createSignedPreKey(id: 1, timestamp: now);
        expect(signedPreKey.timestamp, equals(now));
        signedPreKey.dispose();
      });
    });

    group('signature', () {
      test('returns non-empty signature', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        final sig = signedPreKey.signature;

        expect(sig, isNotEmpty);
        expect(sig.length, equals(64)); // Ed25519 signature

        signedPreKey.dispose();
      });
    });

    group('getPublicKey()', () {
      test('returns valid public key', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        final pub = signedPreKey.getPublicKey();

        expect(pub, isNotNull);
        expect(pub.isDisposed, isFalse);
        expect(pub.serialize().length, equals(33));

        signedPreKey.dispose();
        pub.dispose();
      });

      test('multiple calls return equivalent keys', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);

        final pub1 = signedPreKey.getPublicKey();
        final pub2 = signedPreKey.getPublicKey();

        expect(pub1.equals(pub2), isTrue);

        signedPreKey.dispose();
        pub1.dispose();
        pub2.dispose();
      });
    });

    group('getPrivateKey()', () {
      test('returns valid private key', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        final priv = signedPreKey.getPrivateKey();

        expect(priv, isNotNull);
        expect(priv.isDisposed, isFalse);
        expect(priv.serialize().length, equals(32));

        signedPreKey.dispose();
        priv.dispose();
      });

      test('retrieved private key can derive same public key', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);

        final retrievedPriv = signedPreKey.getPrivateKey();
        final derivedPub = retrievedPriv.getPublicKey();
        final signedPreKeyPub = signedPreKey.getPublicKey();

        expect(derivedPub.equals(signedPreKeyPub), isTrue);

        signedPreKey.dispose();
        retrievedPriv.dispose();
        derivedPub.dispose();
        signedPreKeyPub.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final original = createSignedPreKey(id: 42, timestamp: 1234567890);
        final cloned = original.clone();

        expect(cloned.id, equals(original.id));
        expect(cloned.timestamp, equals(original.timestamp));
        expect(cloned.signature, equals(original.signature));
        expect(cloned.serialize(), equals(original.serialize()));

        original.dispose();

        // Cloned should still work after original is disposed
        expect(cloned.isDisposed, isFalse);
        expect(cloned.id, equals(42));

        cloned.dispose();
      });

      test('cloned signed pre-key has same keys', () {
        final original = createSignedPreKey(id: 1, timestamp: 1000);
        final cloned = original.clone();

        final origPub = original.getPublicKey();
        final clonedPub = cloned.getPublicKey();
        expect(clonedPub.equals(origPub), isTrue);

        final origPriv = original.getPrivateKey();
        final clonedPriv = cloned.getPrivateKey();
        expect(clonedPriv.serialize(), equals(origPriv.serialize()));

        original.dispose();
        cloned.dispose();
        origPub.dispose();
        clonedPub.dispose();
        origPriv.dispose();
        clonedPriv.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        expect(signedPreKey.isDisposed, isFalse);
        signedPreKey.dispose();
      });

      test('isDisposed is true after dispose', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        signedPreKey.dispose();
        expect(signedPreKey.isDisposed, isTrue);
      });

      test('double dispose is safe', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        signedPreKey.dispose();
        expect(() => signedPreKey.dispose(), returnsNormally);
      });

      test('id throws after dispose', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        signedPreKey.dispose();
        expect(() => signedPreKey.id, throwsStateError);
      });

      test('timestamp throws after dispose', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        signedPreKey.dispose();
        expect(() => signedPreKey.timestamp, throwsStateError);
      });

      test('signature throws after dispose', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        signedPreKey.dispose();
        expect(() => signedPreKey.signature, throwsStateError);
      });

      test('serialize throws after dispose', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        signedPreKey.dispose();
        expect(() => signedPreKey.serialize(), throwsStateError);
      });

      test('getPublicKey throws after dispose', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        signedPreKey.dispose();
        expect(() => signedPreKey.getPublicKey(), throwsStateError);
      });

      test('getPrivateKey throws after dispose', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        signedPreKey.dispose();
        expect(() => signedPreKey.getPrivateKey(), throwsStateError);
      });

      test('clone throws after dispose', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        signedPreKey.dispose();
        expect(() => signedPreKey.clone(), throwsStateError);
      });

      test('pointer throws after dispose', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        signedPreKey.dispose();
        expect(() => signedPreKey.pointer, throwsStateError);
      });
    });
  });
}
