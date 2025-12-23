import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('KyberPreKeyRecord', () {
    late IdentityKeyPair identityKeyPair;

    setUp(() {
      identityKeyPair = IdentityKeyPair.generate();
    });

    tearDown(() {
      identityKeyPair.dispose();
    });

    /// Helper to create a Kyber pre-key record with valid signature
    KyberPreKeyRecord createKyberPreKey({
      required int id,
      required int timestamp,
    }) {
      final keyPair = KyberKeyPair.generate();
      final publicKey = keyPair.getPublicKey();
      final signature = identityKeyPair.privateKey.sign(publicKey.serialize());

      final kyberPreKey = KyberPreKeyRecord.create(
        id: id,
        timestamp: timestamp,
        keyPair: keyPair,
        signature: signature,
      );

      publicKey.dispose();
      keyPair.dispose();

      return kyberPreKey;
    }

    group('create()', () {
      test('creates valid Kyber pre-key record', () {
        final keyPair = KyberKeyPair.generate();
        final publicKey = keyPair.getPublicKey();
        final signature = identityKeyPair.privateKey.sign(publicKey.serialize());

        final kyberPreKey = KyberPreKeyRecord.create(
          id: 1,
          timestamp: 1000000,
          keyPair: keyPair,
          signature: signature,
        );

        expect(kyberPreKey, isNotNull);
        expect(kyberPreKey.isDisposed, isFalse);
        expect(kyberPreKey.id, equals(1));
        expect(kyberPreKey.timestamp, equals(1000000));

        kyberPreKey.dispose();
        keyPair.dispose();
        publicKey.dispose();
      });

      test('creates Kyber pre-key with various IDs', () {
        for (final id in [0, 1, 100, 0xFFFF, 0xFFFFFF]) {
          final kyberPreKey = createKyberPreKey(id: id, timestamp: 1000000);
          expect(kyberPreKey.id, equals(id));
          kyberPreKey.dispose();
        }
      });

      test('creates Kyber pre-key with various timestamps', () {
        final timestamps = [
          0,
          1,
          DateTime.now().toUtc().millisecondsSinceEpoch,
          0x7FFFFFFFFFFFFFFF, // Max int64
        ];

        for (final ts in timestamps) {
          final kyberPreKey = createKyberPreKey(id: 1, timestamp: ts);
          expect(kyberPreKey.timestamp, equals(ts));
          kyberPreKey.dispose();
        }
      });

      test('created Kyber pre-key returns correct signature', () {
        final keyPair = KyberKeyPair.generate();
        final publicKey = keyPair.getPublicKey();
        final signature = identityKeyPair.privateKey.sign(publicKey.serialize());

        final kyberPreKey = KyberPreKeyRecord.create(
          id: 42,
          timestamp: 1000000,
          keyPair: keyPair,
          signature: signature,
        );

        expect(kyberPreKey.signature, equals(signature));

        kyberPreKey.dispose();
        keyPair.dispose();
        publicKey.dispose();
      });

      test('signature is verifiable by identity public key', () {
        final keyPair = KyberKeyPair.generate();
        final publicKey = keyPair.getPublicKey();
        final signature = identityKeyPair.privateKey.sign(publicKey.serialize());

        final kyberPreKey = KyberPreKeyRecord.create(
          id: 1,
          timestamp: 1000000,
          keyPair: keyPair,
          signature: signature,
        );

        final retrievedPub = kyberPreKey.getPublicKey();
        final retrievedSig = kyberPreKey.signature;

        final isValid = identityKeyPair.publicKey.verify(
          retrievedPub.serialize(),
          retrievedSig,
        );

        expect(isValid, isTrue);

        kyberPreKey.dispose();
        keyPair.dispose();
        publicKey.dispose();
        retrievedPub.dispose();
      });
    });

    group('serialize() / deserialize()', () {
      test('round-trip preserves Kyber pre-key', () {
        final original = createKyberPreKey(id: 123, timestamp: 9876543210);
        final serialized = original.serialize();

        expect(serialized, isNotEmpty);

        final restored = KyberPreKeyRecord.deserialize(serialized);

        expect(restored.id, equals(original.id));
        expect(restored.timestamp, equals(original.timestamp));
        expect(restored.signature, equals(original.signature));

        final origPub = original.getPublicKey();
        final restoredPub = restored.getPublicKey();
        expect(restoredPub.serialize(), equals(origPub.serialize()));

        original.dispose();
        restored.dispose();
        origPub.dispose();
        restoredPub.dispose();
      });

      test('rejects empty data', () {
        expect(
          () => KyberPreKeyRecord.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects garbage data', () {
        final garbage = Uint8List.fromList([0x99, 0x88, 0x77, 0x66, 0x55]);
        expect(
          () => KyberPreKeyRecord.deserialize(garbage),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('id', () {
      test('returns correct id', () {
        final kyberPreKey = createKyberPreKey(id: 999, timestamp: 1000);
        expect(kyberPreKey.id, equals(999));
        kyberPreKey.dispose();
      });
    });

    group('timestamp', () {
      test('returns correct timestamp', () {
        final now = DateTime.now().toUtc().millisecondsSinceEpoch;
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: now);
        expect(kyberPreKey.timestamp, equals(now));
        kyberPreKey.dispose();
      });
    });

    group('signature', () {
      test('returns non-empty signature', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        final sig = kyberPreKey.signature;

        expect(sig, isNotEmpty);
        expect(sig.length, equals(64)); // Ed25519 signature

        kyberPreKey.dispose();
      });
    });

    group('getPublicKey()', () {
      test('returns valid Kyber public key', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        final pub = kyberPreKey.getPublicKey();

        expect(pub, isNotNull);
        expect(pub.isDisposed, isFalse);
        // Kyber1024 public key is 1568 bytes
        expect(pub.serialize().length, greaterThan(1000));

        kyberPreKey.dispose();
        pub.dispose();
      });

      test('multiple calls return equivalent keys', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);

        final pub1 = kyberPreKey.getPublicKey();
        final pub2 = kyberPreKey.getPublicKey();

        expect(pub1.serialize(), equals(pub2.serialize()));

        kyberPreKey.dispose();
        pub1.dispose();
        pub2.dispose();
      });
    });

    group('getSecretKey()', () {
      test('returns valid Kyber secret key', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        final secret = kyberPreKey.getSecretKey();

        expect(secret, isNotNull);
        expect(secret.isDisposed, isFalse);
        // Kyber1024 secret key is 3168 bytes
        expect(secret.serialize().length, greaterThan(3000));

        kyberPreKey.dispose();
        secret.dispose();
      });
    });

    group('getKeyPair()', () {
      test('returns valid Kyber key pair', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        final keyPair = kyberPreKey.getKeyPair();

        expect(keyPair, isNotNull);
        expect(keyPair.isDisposed, isFalse);

        final pubFromRecord = kyberPreKey.getPublicKey();
        final pubFromPair = keyPair.getPublicKey();

        expect(pubFromPair.serialize(), equals(pubFromRecord.serialize()));

        kyberPreKey.dispose();
        keyPair.dispose();
        pubFromRecord.dispose();
        pubFromPair.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final original = createKyberPreKey(id: 42, timestamp: 1234567890);
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

      test('cloned Kyber pre-key has same keys', () {
        final original = createKyberPreKey(id: 1, timestamp: 1000);
        final cloned = original.clone();

        final origPub = original.getPublicKey();
        final clonedPub = cloned.getPublicKey();
        expect(clonedPub.serialize(), equals(origPub.serialize()));

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
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        expect(kyberPreKey.isDisposed, isFalse);
        kyberPreKey.dispose();
      });

      test('isDisposed is true after dispose', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        kyberPreKey.dispose();
        expect(kyberPreKey.isDisposed, isTrue);
      });

      test('double dispose is safe', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        kyberPreKey.dispose();
        expect(() => kyberPreKey.dispose(), returnsNormally);
      });

      test('id throws after dispose', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        kyberPreKey.dispose();
        expect(() => kyberPreKey.id, throwsStateError);
      });

      test('timestamp throws after dispose', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        kyberPreKey.dispose();
        expect(() => kyberPreKey.timestamp, throwsStateError);
      });

      test('signature throws after dispose', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        kyberPreKey.dispose();
        expect(() => kyberPreKey.signature, throwsStateError);
      });

      test('serialize throws after dispose', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        kyberPreKey.dispose();
        expect(() => kyberPreKey.serialize(), throwsStateError);
      });

      test('getPublicKey throws after dispose', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        kyberPreKey.dispose();
        expect(() => kyberPreKey.getPublicKey(), throwsStateError);
      });

      test('getSecretKey throws after dispose', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        kyberPreKey.dispose();
        expect(() => kyberPreKey.getSecretKey(), throwsStateError);
      });

      test('getKeyPair throws after dispose', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        kyberPreKey.dispose();
        expect(() => kyberPreKey.getKeyPair(), throwsStateError);
      });

      test('clone throws after dispose', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        kyberPreKey.dispose();
        expect(() => kyberPreKey.clone(), throwsStateError);
      });

      test('pointer throws after dispose', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        kyberPreKey.dispose();
        expect(() => kyberPreKey.pointer, throwsStateError);
      });
    });
  });
}
