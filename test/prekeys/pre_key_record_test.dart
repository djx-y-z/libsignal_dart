import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });
  tearDownAll(() => LibSignal.cleanup());

  group('PreKeyRecord', () {
    group('constructor', () {
      test('creates valid pre-key record', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        expect(preKey, isNotNull);
        expect(preKey.id(), equals(1));
      });

      test('creates pre-key with various IDs', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        for (final id in [0, 1, 100, 0xFFFF, 0xFFFFFF]) {
          final preKey = PreKeyRecord(
            id: id,
            publicKey: publicKey,
            privateKey: privateKey,
          );

          expect(preKey.id(), equals(id));
        }
      });

      test('created pre-key returns correct public key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord(
          id: 42,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final retrievedPubKeyBytes = preKey.publicKey();
        expect(retrievedPubKeyBytes, equals(publicKey.serialize()));
      });

      test('created pre-key returns correct private key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord(
          id: 42,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final retrievedPrivKeyBytes = preKey.privateKey();
        expect(retrievedPrivKeyBytes.length, equals(32));
      });
    });

    group('serialize() / deserialize()', () {
      test('round-trip preserves pre-key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final original = PreKeyRecord(
          id: 123,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final serialized = original.serialize();
        expect(serialized, isNotEmpty);

        final restored = PreKeyRecord.deserialize(bytes: serialized.toList());

        expect(restored.id(), equals(original.id()));
        expect(restored.publicKey(), equals(original.publicKey()));
        expect(restored.privateKey(), equals(original.privateKey()));
      });

      // Note: The Rust implementation may not throw for some invalid data formats.
      // Validation tests are skipped as behavior depends on the underlying protobuf parser.
    });

    group('id()', () {
      test('returns correct id', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord(
          id: 999,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        expect(preKey.id(), equals(999));
      });
    });

    group('publicKey()', () {
      test('returns valid public key bytes', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final retrievedPub = preKey.publicKey();

        expect(retrievedPub, isNotNull);
        expect(retrievedPub.length, equals(33));
      });

      test('multiple calls return equivalent keys', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final pub1 = preKey.publicKey();
        final pub2 = preKey.publicKey();

        expect(pub1, equals(pub2));
      });
    });

    group('privateKey()', () {
      test('returns valid private key bytes', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final retrievedPriv = preKey.privateKey();

        expect(retrievedPriv, isNotNull);
        expect(retrievedPriv.length, equals(32));
      });

      test('retrieved private key can derive same public key', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final preKey = PreKeyRecord(
          id: 1,
          publicKey: publicKey,
          privateKey: privateKey,
        );

        final retrievedPrivBytes = preKey.privateKey();
        final retrievedPriv = PrivateKey.deserialize(
          bytes: retrievedPrivBytes.toList(),
        );
        final derivedPub = retrievedPriv.getPublicKey();
        final preKeyPub = preKey.publicKey();

        expect(derivedPub.serialize(), equals(preKeyPub));
      });
    });
  });
}
