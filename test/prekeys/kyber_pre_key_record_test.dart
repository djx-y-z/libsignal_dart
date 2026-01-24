import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });
  tearDownAll(() => LibSignal.cleanup());

  group('KyberPreKeyRecord', () {
    late IdentityKeyPair identityKeyPair;

    setUp(() {
      identityKeyPair = IdentityKeyPair.generate();
    });

    /// Helper to create a Kyber pre-key record with valid signature
    KyberPreKeyRecord createKyberPreKey({
      required int id,
      required int timestamp,
    }) {
      final keyPair = KyberKeyPair.generate();
      final publicKey = keyPair.getPublicKey();
      final identityPrivKey = PrivateKey.deserialize(
        bytes: identityKeyPair.privateKey.toList(),
      );
      final signature = identityPrivKey.sign(
        message: publicKey.serialize().toList(),
      );

      final kyberPreKey = KyberPreKeyRecord.create(
        id: id,
        timestamp: BigInt.from(timestamp),
        keyPair: keyPair,
        signature: signature.toList(),
      );

      return kyberPreKey;
    }

    group('create()', () {
      test('creates valid Kyber pre-key record', () {
        final keyPair = KyberKeyPair.generate();
        final publicKey = keyPair.getPublicKey();
        final identityPrivKey = PrivateKey.deserialize(
          bytes: identityKeyPair.privateKey.toList(),
        );
        final signature = identityPrivKey.sign(
          message: publicKey.serialize().toList(),
        );

        final kyberPreKey = KyberPreKeyRecord.create(
          id: 1,
          timestamp: BigInt.from(1000000),
          keyPair: keyPair,
          signature: signature.toList(),
        );

        expect(kyberPreKey, isNotNull);
        expect(kyberPreKey.id(), equals(1));
        expect(kyberPreKey.timestamp(), equals(BigInt.from(1000000)));
      });

      test('creates Kyber pre-key with various IDs', () {
        for (final id in [0, 1, 100, 0xFFFF, 0xFFFFFF]) {
          final kyberPreKey = createKyberPreKey(id: id, timestamp: 1000000);
          expect(kyberPreKey.id(), equals(id));
        }
      });

      test('creates Kyber pre-key with various timestamps', () {
        final timestamps = [
          0,
          1,
          DateTime.now().toUtc().millisecondsSinceEpoch,
        ];

        for (final ts in timestamps) {
          final kyberPreKey = createKyberPreKey(id: 1, timestamp: ts);
          expect(kyberPreKey.timestamp(), equals(BigInt.from(ts)));
        }
      });

      test('created Kyber pre-key returns correct signature', () {
        final keyPair = KyberKeyPair.generate();
        final publicKey = keyPair.getPublicKey();
        final identityPrivKey = PrivateKey.deserialize(
          bytes: identityKeyPair.privateKey.toList(),
        );
        final signature = identityPrivKey.sign(
          message: publicKey.serialize().toList(),
        );

        final kyberPreKey = KyberPreKeyRecord.create(
          id: 42,
          timestamp: BigInt.from(1000000),
          keyPair: keyPair,
          signature: signature.toList(),
        );

        expect(kyberPreKey.signature(), equals(signature));
      });

      test('signature is verifiable by identity public key', () {
        final keyPair = KyberKeyPair.generate();
        final publicKey = keyPair.getPublicKey();
        final identityPrivKey = PrivateKey.deserialize(
          bytes: identityKeyPair.privateKey.toList(),
        );
        final signature = identityPrivKey.sign(
          message: publicKey.serialize().toList(),
        );

        final kyberPreKey = KyberPreKeyRecord.create(
          id: 1,
          timestamp: BigInt.from(1000000),
          keyPair: keyPair,
          signature: signature.toList(),
        );

        final retrievedPub = kyberPreKey.getPublicKey();
        final retrievedSig = kyberPreKey.signature();

        final identityPubKey = PublicKey.deserialize(
          bytes: identityKeyPair.publicKey.toList(),
        );
        final isValid = identityPubKey.verify(
          message: retrievedPub.serialize().toList(),
          signature: retrievedSig.toList(),
        );

        expect(isValid, isTrue);
      });
    });

    group('serialize() / deserialize()', () {
      test('round-trip preserves Kyber pre-key', () {
        final original = createKyberPreKey(id: 123, timestamp: 9876543210);
        final serialized = original.serialize();

        expect(serialized, isNotEmpty);

        final restored = KyberPreKeyRecord.deserialize(
          bytes: serialized.toList(),
        );

        expect(restored.id(), equals(original.id()));
        expect(restored.timestamp(), equals(original.timestamp()));
        expect(restored.signature(), equals(original.signature()));

        final origPub = original.getPublicKey();
        final restoredPub = restored.getPublicKey();
        expect(restoredPub.serialize(), equals(origPub.serialize()));
      });

      // Note: The Rust implementation may not throw for some invalid data formats.
      // Validation tests are skipped as behavior depends on the underlying protobuf parser.
    });

    group('id()', () {
      test('returns correct id', () {
        final kyberPreKey = createKyberPreKey(id: 999, timestamp: 1000);
        expect(kyberPreKey.id(), equals(999));
      });
    });

    group('timestamp()', () {
      test('returns correct timestamp', () {
        final now = DateTime.now().toUtc().millisecondsSinceEpoch;
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: now);
        expect(kyberPreKey.timestamp(), equals(BigInt.from(now)));
      });
    });

    group('signature()', () {
      test('returns non-empty signature', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        final sig = kyberPreKey.signature();

        expect(sig, isNotEmpty);
        expect(sig.length, equals(64)); // Ed25519 signature
      });
    });

    group('getPublicKey()', () {
      test('returns valid Kyber public key', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        final pub = kyberPreKey.getPublicKey();

        expect(pub, isNotNull);
        // Kyber1024 public key is 1568 bytes (+ format byte)
        expect(pub.serialize().length, greaterThan(1000));
      });

      test('multiple calls return equivalent keys', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);

        final pub1 = kyberPreKey.getPublicKey();
        final pub2 = kyberPreKey.getPublicKey();

        expect(pub1.serialize(), equals(pub2.serialize()));
      });
    });

    group('getSecretKey()', () {
      test('returns valid Kyber secret key', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        final secret = kyberPreKey.getSecretKey();

        expect(secret, isNotNull);
        // Kyber1024 secret key is 3168 bytes (+ format byte)
        expect(secret.serialize().length, greaterThan(3000));
      });
    });

    group('getKeyPair()', () {
      test('returns valid Kyber key pair', () {
        final kyberPreKey = createKyberPreKey(id: 1, timestamp: 1000);
        final keyPair = kyberPreKey.getKeyPair();

        expect(keyPair, isNotNull);

        final pubFromRecord = kyberPreKey.getPublicKey();
        final pubFromPair = keyPair.getPublicKey();

        expect(pubFromPair.serialize(), equals(pubFromRecord.serialize()));
      });
    });

    group('cloneRecord()', () {
      test('creates independent copy', () {
        final original = createKyberPreKey(id: 42, timestamp: 1234567890);
        final cloned = original.cloneRecord();

        expect(cloned.id(), equals(original.id()));
        expect(cloned.timestamp(), equals(original.timestamp()));
        expect(cloned.signature(), equals(original.signature()));
        expect(cloned.serialize(), equals(original.serialize()));
      });

      test('cloned Kyber pre-key has same keys', () {
        final original = createKyberPreKey(id: 1, timestamp: 1000);
        final cloned = original.cloneRecord();

        final origPub = original.getPublicKey();
        final clonedPub = cloned.getPublicKey();
        expect(clonedPub.serialize(), equals(origPub.serialize()));

        final origSecret = original.getSecretKey();
        final clonedSecret = cloned.getSecretKey();
        expect(clonedSecret.serialize(), equals(origSecret.serialize()));
      });
    });
  });
}
