import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });
  tearDownAll(() => LibSignal.cleanup());

  group('SignedPreKeyRecord', () {
    late IdentityKeyPair identityKeyPair;

    setUp(() {
      identityKeyPair = IdentityKeyPair.generate();
    });

    /// Helper to create a signed pre-key record with valid signature
    SignedPreKeyRecord createSignedPreKey({
      required int id,
      required int timestamp,
    }) {
      final privateKey = PrivateKey.generate();
      final publicKey = privateKey.getPublicKey();
      final identityPrivKey = PrivateKey.deserialize(
        bytes: identityKeyPair.privateKey.toList(),
      );
      final signature = identityPrivKey.sign(
        message: publicKey.serialize().toList(),
      );

      final signedPreKey = SignedPreKeyRecord(
        id: id,
        timestamp: BigInt.from(timestamp),
        publicKey: publicKey,
        privateKey: privateKey,
        signature: signature.toList(),
      );

      return signedPreKey;
    }

    group('constructor', () {
      test('creates valid signed pre-key record', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();
        final identityPrivKey = PrivateKey.deserialize(
          bytes: identityKeyPair.privateKey.toList(),
        );
        final signature = identityPrivKey.sign(
          message: publicKey.serialize().toList(),
        );

        final signedPreKey = SignedPreKeyRecord(
          id: 1,
          timestamp: BigInt.from(1000000),
          publicKey: publicKey,
          privateKey: privateKey,
          signature: signature.toList(),
        );

        expect(signedPreKey, isNotNull);
        expect(signedPreKey.id(), equals(1));
        expect(signedPreKey.timestamp(), equals(BigInt.from(1000000)));
      });

      test('creates signed pre-key with various IDs', () {
        for (final id in [0, 1, 100, 0xFFFF, 0xFFFFFF]) {
          final signedPreKey = createSignedPreKey(id: id, timestamp: 1000000);
          expect(signedPreKey.id(), equals(id));
        }
      });

      test('creates signed pre-key with various timestamps', () {
        final timestamps = [
          0,
          1,
          DateTime.now().toUtc().millisecondsSinceEpoch,
        ];

        for (final ts in timestamps) {
          final signedPreKey = createSignedPreKey(id: 1, timestamp: ts);
          expect(signedPreKey.timestamp(), equals(BigInt.from(ts)));
        }
      });

      test('created signed pre-key returns correct signature', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();
        final identityPrivKey = PrivateKey.deserialize(
          bytes: identityKeyPair.privateKey.toList(),
        );
        final signature = identityPrivKey.sign(
          message: publicKey.serialize().toList(),
        );

        final signedPreKey = SignedPreKeyRecord(
          id: 42,
          timestamp: BigInt.from(1000000),
          publicKey: publicKey,
          privateKey: privateKey,
          signature: signature.toList(),
        );

        expect(signedPreKey.signature(), equals(signature));
      });

      test('signature is verifiable by identity public key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();
        final identityPrivKey = PrivateKey.deserialize(
          bytes: identityKeyPair.privateKey.toList(),
        );
        final signature = identityPrivKey.sign(
          message: publicKey.serialize().toList(),
        );

        final signedPreKey = SignedPreKeyRecord(
          id: 1,
          timestamp: BigInt.from(1000000),
          publicKey: publicKey,
          privateKey: privateKey,
          signature: signature.toList(),
        );

        final retrievedPub = signedPreKey.publicKey();
        final retrievedSig = signedPreKey.signature();

        final identityPubKey = PublicKey.deserialize(
          bytes: identityKeyPair.publicKey.toList(),
        );
        final isValid = identityPubKey.verify(
          message: retrievedPub.toList(),
          signature: retrievedSig.toList(),
        );

        expect(isValid, isTrue);
      });
    });

    group('serialize() / deserialize()', () {
      test('round-trip preserves signed pre-key', () {
        final original = createSignedPreKey(id: 123, timestamp: 9876543210);
        final serialized = original.serialize();

        expect(serialized, isNotEmpty);

        final restored = SignedPreKeyRecord.deserialize(
          bytes: serialized.toList(),
        );

        expect(restored.id(), equals(original.id()));
        expect(restored.timestamp(), equals(original.timestamp()));
        expect(restored.signature(), equals(original.signature()));
        expect(restored.publicKey(), equals(original.publicKey()));
        expect(restored.privateKey(), equals(original.privateKey()));
      });

      // Note: The Rust implementation may not throw for some invalid data formats.
      // Validation tests are skipped as behavior depends on the underlying protobuf parser.
    });

    group('id()', () {
      test('returns correct id', () {
        final signedPreKey = createSignedPreKey(id: 999, timestamp: 1000);
        expect(signedPreKey.id(), equals(999));
      });
    });

    group('timestamp()', () {
      test('returns correct timestamp', () {
        final now = DateTime.now().toUtc().millisecondsSinceEpoch;
        final signedPreKey = createSignedPreKey(id: 1, timestamp: now);
        expect(signedPreKey.timestamp(), equals(BigInt.from(now)));
      });
    });

    group('signature()', () {
      test('returns non-empty signature', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        final sig = signedPreKey.signature();

        expect(sig, isNotEmpty);
        expect(sig.length, equals(64)); // Ed25519 signature
      });
    });

    group('publicKey()', () {
      test('returns valid public key bytes', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        final pub = signedPreKey.publicKey();

        expect(pub, isNotNull);
        expect(pub.length, equals(33));
      });

      test('multiple calls return equivalent keys', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);

        final pub1 = signedPreKey.publicKey();
        final pub2 = signedPreKey.publicKey();

        expect(pub1, equals(pub2));
      });
    });

    group('privateKey()', () {
      test('returns valid private key bytes', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);
        final priv = signedPreKey.privateKey();

        expect(priv, isNotNull);
        expect(priv.length, equals(32));
      });

      test('retrieved private key can derive same public key', () {
        final signedPreKey = createSignedPreKey(id: 1, timestamp: 1000);

        final retrievedPrivBytes = signedPreKey.privateKey();
        final retrievedPriv = PrivateKey.deserialize(
          bytes: retrievedPrivBytes.toList(),
        );
        final derivedPub = retrievedPriv.getPublicKey();
        final signedPreKeyPub = signedPreKey.publicKey();

        expect(derivedPub.serialize(), equals(signedPreKeyPub));
      });
    });
  });
}
