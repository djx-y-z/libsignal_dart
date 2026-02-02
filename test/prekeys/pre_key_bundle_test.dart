// ignore_for_file: avoid_redundant_argument_values
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('PreKeyBundle', () {
    late IdentityKeyPair identityKeyPair;
    late Uint8List identityPublicKeyBytes;

    setUp(() {
      identityKeyPair = IdentityKeyPair.generate();
      identityPublicKeyBytes = identityKeyPair.publicKey;
    });

    /// Helper to create a full pre-key bundle with all keys
    PreKeyBundle createFullBundle({
      int registrationId = 12345,
      int deviceId = 1,
      int preKeyId = 100,
      int kyberPreKeyId = 200,
    }) {
      final preKeyPriv = PrivateKey.generate();
      final preKey = preKeyPriv.getPublicKey();

      final signedPreKeyPriv = PrivateKey.generate();
      final signedPreKey = signedPreKeyPriv.getPublicKey();
      final identityPrivKey = PrivateKey.deserialize(
        bytes: identityKeyPair.privateKey.toList(),
      );
      final signedPreKeySignature = identityPrivKey.sign(
        message: signedPreKey.serialize().toList(),
      );

      final kyberKeyPair = KyberKeyPair.generate();
      final kyberPreKey = kyberKeyPair.getPublicKey();
      final kyberPreKeySignature = identityPrivKey.sign(
        message: kyberPreKey.serialize().toList(),
      );

      final bundle = PreKeyBundle(
        registrationId: registrationId,
        deviceId: deviceId,
        preKeyId: preKeyId,
        preKeyPublic: preKey.serialize(),
        signedPreKeyId: 1,
        signedPreKeyPublic: signedPreKey.serialize().toList(),
        signedPreKeySignature: signedPreKeySignature.toList(),
        identityKey: identityPublicKeyBytes.toList(),
        kyberPreKeyId: kyberPreKeyId,
        kyberPreKeyPublic: kyberPreKey.serialize().toList(),
        kyberPreKeySignature: kyberPreKeySignature.toList(),
      );

      return bundle;
    }

    group('constructor', () {
      test('creates full bundle with all keys', () {
        final bundle = createFullBundle();

        expect(bundle, isNotNull);
        expect(bundle.registrationId(), equals(12345));
        expect(bundle.deviceId(), equals(1));
        expect(bundle.preKeyId(), equals(100));
        expect(bundle.kyberPreKeyId(), equals(200));

        final preKeyPub = bundle.preKeyPublic();
        expect(preKeyPub, isNotNull);
        expect(preKeyPub!.length, equals(33));

        final kyberPub = bundle.kyberPreKeyPublic();
        expect(kyberPub, isNotNull);
        expect(kyberPub.length, greaterThan(1000));
      });

      test('creates bundle with custom pre-key ID', () {
        final bundle = createFullBundle(preKeyId: 42);

        expect(bundle.preKeyId(), equals(42));

        final preKeyPub = bundle.preKeyPublic();
        expect(preKeyPub, isNotNull);
        expect(preKeyPub!.length, equals(33));
      });

      test('creates bundle with custom Kyber pre-key ID', () {
        final bundle = createFullBundle(kyberPreKeyId: 99);

        expect(bundle.kyberPreKeyId(), equals(99));

        final kyberPub = bundle.kyberPreKeyPublic();
        expect(kyberPub, isNotNull);
        expect(kyberPub.length, greaterThan(1000));
      });

      test('creates bundle with various registration IDs', () {
        for (final regId in [0, 1, 100, 0xFFFF, 0xFFFFFFFF]) {
          final bundle = createFullBundle(registrationId: regId);
          expect(bundle.registrationId(), equals(regId));
        }
      });

      test('creates bundle with device ID 1', () {
        final bundle = createFullBundle(deviceId: 1);
        expect(bundle.deviceId(), equals(1));
      });

      test('creates bundle with device ID 100', () {
        final bundle = createFullBundle(deviceId: 100);
        expect(bundle.deviceId(), equals(100));
      });
    });

    group('registrationId()', () {
      test('returns correct registration ID', () {
        final bundle = createFullBundle(registrationId: 999999);
        expect(bundle.registrationId(), equals(999999));
      });
    });

    group('deviceId()', () {
      test('returns correct device ID', () {
        final bundle = createFullBundle(deviceId: 42);
        expect(bundle.deviceId(), equals(42));
      });
    });

    group('preKeyId()', () {
      test('returns correct pre-key ID', () {
        final bundle = createFullBundle(preKeyId: 12345);
        expect(bundle.preKeyId(), equals(12345));
      });

      test('returns default pre-key ID', () {
        final bundle = createFullBundle();
        expect(bundle.preKeyId(), equals(100));
      });
    });

    group('preKeyPublic()', () {
      test('returns valid public key bytes', () {
        final bundle = createFullBundle();
        final preKeyPub = bundle.preKeyPublic();

        expect(preKeyPub, isNotNull);
        expect(preKeyPub!.length, equals(33));
      });

      test('multiple calls return equivalent keys', () {
        final bundle = createFullBundle();
        final pub1 = bundle.preKeyPublic();
        final pub2 = bundle.preKeyPublic();

        expect(pub1, equals(pub2));
      });
    });

    group('signedPreKeyId()', () {
      test('returns correct signed pre-key ID', () {
        final preKeyPriv = PrivateKey.generate();
        final preKey = preKeyPriv.getPublicKey();

        final signedPreKeyPriv = PrivateKey.generate();
        final signedPreKey = signedPreKeyPriv.getPublicKey();
        final identityPrivKey = PrivateKey.deserialize(
          bytes: identityKeyPair.privateKey.toList(),
        );
        final signedPreKeySignature = identityPrivKey.sign(
          message: signedPreKey.serialize().toList(),
        );

        final kyberKeyPair = KyberKeyPair.generate();
        final kyberPreKey = kyberKeyPair.getPublicKey();
        final kyberPreKeySignature = identityPrivKey.sign(
          message: kyberPreKey.serialize().toList(),
        );

        final bundle = PreKeyBundle(
          registrationId: 1,
          deviceId: 1,
          preKeyId: 1,
          preKeyPublic: preKey.serialize(),
          signedPreKeyId: 42,
          signedPreKeyPublic: signedPreKey.serialize().toList(),
          signedPreKeySignature: signedPreKeySignature.toList(),
          identityKey: identityPublicKeyBytes.toList(),
          kyberPreKeyId: 1,
          kyberPreKeyPublic: kyberPreKey.serialize().toList(),
          kyberPreKeySignature: kyberPreKeySignature.toList(),
        );

        expect(bundle.signedPreKeyId(), equals(42));
      });
    });

    group('signedPreKeyPublic()', () {
      test('returns valid signed pre-key public key bytes', () {
        final bundle = createFullBundle();
        final signedPreKeyPub = bundle.signedPreKeyPublic();

        expect(signedPreKeyPub, isNotNull);
        expect(signedPreKeyPub.length, equals(33));
      });
    });

    group('signedPreKeySignature()', () {
      test('returns non-empty signature', () {
        final bundle = createFullBundle();
        final sig = bundle.signedPreKeySignature();

        expect(sig, isNotEmpty);
        expect(sig.length, equals(64)); // Ed25519 signature
      });

      test('signature is verifiable by identity key', () {
        final bundle = createFullBundle();

        final signedPreKeyPub = bundle.signedPreKeyPublic();
        final sig = bundle.signedPreKeySignature();
        final identityKeyBytes = bundle.identityKey();

        final identityKey = PublicKey.deserialize(
          bytes: identityKeyBytes.toList(),
        );
        final isValid = identityKey.verify(
          message: signedPreKeyPub.toList(),
          signature: sig.toList(),
        );
        expect(isValid, isTrue);
      });
    });

    group('identityKey()', () {
      test('returns valid identity public key bytes', () {
        final bundle = createFullBundle();
        final identityKey = bundle.identityKey();

        expect(identityKey, isNotNull);
        expect(identityKey, equals(identityPublicKeyBytes));
      });
    });

    group('kyberPreKeyId()', () {
      test('returns correct Kyber pre-key ID', () {
        final bundle = createFullBundle(kyberPreKeyId: 555);
        expect(bundle.kyberPreKeyId(), equals(555));
      });

      test('returns default Kyber pre-key ID', () {
        final bundle = createFullBundle();
        expect(bundle.kyberPreKeyId(), equals(200));
      });
    });

    group('kyberPreKeyPublic()', () {
      test('returns valid Kyber public key bytes', () {
        final bundle = createFullBundle();
        final kyberPub = bundle.kyberPreKeyPublic();

        expect(kyberPub, isNotNull);
        expect(kyberPub.length, greaterThan(1000));
      });

      test('multiple calls return equivalent keys', () {
        final bundle = createFullBundle();
        final kyber1 = bundle.kyberPreKeyPublic();
        final kyber2 = bundle.kyberPreKeyPublic();

        expect(kyber1, equals(kyber2));
      });
    });

    group('kyberPreKeySignature()', () {
      test('returns non-empty signature', () {
        final bundle = createFullBundle();
        final sig = bundle.kyberPreKeySignature();

        expect(sig, isNotEmpty);
        expect(sig.length, equals(64)); // Ed25519 signature
      });

      test('Kyber signature is verifiable by identity key', () {
        final bundle = createFullBundle();

        final kyberPub = bundle.kyberPreKeyPublic();
        final sig = bundle.kyberPreKeySignature();
        final identityKeyBytes = bundle.identityKey();

        final identityKey = PublicKey.deserialize(
          bytes: identityKeyBytes.toList(),
        );
        final isValid = identityKey.verify(
          message: kyberPub.toList(),
          signature: sig.toList(),
        );
        expect(isValid, isTrue);
      });
    });
  });
}
