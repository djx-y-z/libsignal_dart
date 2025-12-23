import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('PreKeyBundle', () {
    late IdentityKeyPair identityKeyPair;
    late PublicKey identityPublicKey;

    setUp(() {
      identityKeyPair = IdentityKeyPair.generate();
      identityPublicKey = identityKeyPair.publicKey.clone();
    });

    tearDown(() {
      identityKeyPair.dispose();
      identityPublicKey.dispose();
    });

    /// Helper to create a full pre-key bundle with all keys
    /// Note: libsignal requires all Kyber pre-key arguments (id, key, signature)
    /// to be either all present or all absent. Using a full bundle ensures consistency.
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
      final signedPreKeySignature = identityKeyPair.privateKey.sign(
        signedPreKey.serialize(),
      );

      final kyberKeyPair = KyberKeyPair.generate();
      final kyberPreKey = kyberKeyPair.getPublicKey();
      final kyberPreKeySignature = identityKeyPair.privateKey.sign(
        kyberPreKey.serialize(),
      );

      final bundle = PreKeyBundle.create(
        registrationId: registrationId,
        deviceId: deviceId,
        preKeyId: preKeyId,
        preKey: preKey,
        signedPreKeyId: 1,
        signedPreKey: signedPreKey,
        signedPreKeySignature: signedPreKeySignature,
        identityKey: identityPublicKey,
        kyberPreKeyId: kyberPreKeyId,
        kyberPreKey: kyberPreKey,
        kyberPreKeySignature: kyberPreKeySignature,
      );

      preKeyPriv.dispose();
      preKey.dispose();
      signedPreKeyPriv.dispose();
      signedPreKey.dispose();
      kyberKeyPair.dispose();
      kyberPreKey.dispose();

      return bundle;
    }

    group('create()', () {
      test('creates full bundle with all keys', () {
        final bundle = createFullBundle();

        expect(bundle, isNotNull);
        expect(bundle.isDisposed, isFalse);
        expect(bundle.registrationId, equals(12345));
        expect(bundle.deviceId, equals(1));
        expect(bundle.preKeyId, equals(100));
        expect(bundle.kyberPreKeyId, equals(200));

        final preKeyPub = bundle.getPreKeyPublic();
        expect(preKeyPub, isNotNull);
        expect(preKeyPub!.serialize().length, equals(33));

        final kyberPub = bundle.getKyberPreKeyPublic();
        expect(kyberPub, isNotNull);
        expect(kyberPub!.serialize().length, greaterThan(1000));

        bundle.dispose();
        preKeyPub.dispose();
        kyberPub.dispose();
      });

      test('creates bundle with custom pre-key ID', () {
        final bundle = createFullBundle(preKeyId: 42);

        expect(bundle.preKeyId, equals(42));

        final preKeyPub = bundle.getPreKeyPublic();
        expect(preKeyPub, isNotNull);
        expect(preKeyPub!.serialize().length, equals(33));

        bundle.dispose();
        preKeyPub.dispose();
      });

      test('creates bundle with custom Kyber pre-key ID', () {
        final bundle = createFullBundle(kyberPreKeyId: 99);

        expect(bundle.kyberPreKeyId, equals(99));

        final kyberPub = bundle.getKyberPreKeyPublic();
        expect(kyberPub, isNotNull);
        expect(kyberPub!.serialize().length, greaterThan(1000));

        bundle.dispose();
        kyberPub.dispose();
      });

      test('creates bundle with various registration IDs', () {
        for (final regId in [0, 1, 100, 0xFFFF, 0xFFFFFFFF]) {
          final bundle = createFullBundle(registrationId: regId);
          expect(bundle.registrationId, equals(regId));
          bundle.dispose();
        }
      });

      test('creates bundle with various device IDs', () {
        for (final devId in [0, 1, 100, 0xFFFF, 0xFFFFFFFF]) {
          final bundle = createFullBundle(deviceId: devId);
          expect(bundle.deviceId, equals(devId));
          bundle.dispose();
        }
      });
    });

    group('registrationId', () {
      test('returns correct registration ID', () {
        final bundle = createFullBundle(registrationId: 999999);
        expect(bundle.registrationId, equals(999999));
        bundle.dispose();
      });
    });

    group('deviceId', () {
      test('returns correct device ID', () {
        final bundle = createFullBundle(deviceId: 42);
        expect(bundle.deviceId, equals(42));
        bundle.dispose();
      });
    });

    group('preKeyId', () {
      test('returns correct pre-key ID', () {
        final bundle = createFullBundle(preKeyId: 12345);
        expect(bundle.preKeyId, equals(12345));
        bundle.dispose();
      });

      test('returns default pre-key ID', () {
        final bundle = createFullBundle();
        expect(bundle.preKeyId, equals(100));
        bundle.dispose();
      });
    });

    group('getPreKeyPublic()', () {
      test('returns valid public key', () {
        final bundle = createFullBundle();
        final preKeyPub = bundle.getPreKeyPublic();

        expect(preKeyPub, isNotNull);
        expect(preKeyPub!.isDisposed, isFalse);
        expect(preKeyPub.serialize().length, equals(33));

        bundle.dispose();
        preKeyPub.dispose();
      });

      test('multiple calls return equivalent keys', () {
        final bundle = createFullBundle();
        final pub1 = bundle.getPreKeyPublic();
        final pub2 = bundle.getPreKeyPublic();

        expect(pub1!.equals(pub2!), isTrue);

        bundle.dispose();
        pub1.dispose();
        pub2.dispose();
      });
    });

    group('signedPreKeyId', () {
      test('returns correct signed pre-key ID', () {
        // Create a bundle with custom signedPreKeyId
        final preKeyPriv = PrivateKey.generate();
        final preKey = preKeyPriv.getPublicKey();

        final signedPreKeyPriv = PrivateKey.generate();
        final signedPreKey = signedPreKeyPriv.getPublicKey();
        final signedPreKeySignature = identityKeyPair.privateKey.sign(
          signedPreKey.serialize(),
        );

        final kyberKeyPair = KyberKeyPair.generate();
        final kyberPreKey = kyberKeyPair.getPublicKey();
        final kyberPreKeySignature = identityKeyPair.privateKey.sign(
          kyberPreKey.serialize(),
        );

        final bundle = PreKeyBundle.create(
          registrationId: 1,
          deviceId: 1,
          preKeyId: 1,
          preKey: preKey,
          signedPreKeyId: 42,
          signedPreKey: signedPreKey,
          signedPreKeySignature: signedPreKeySignature,
          identityKey: identityPublicKey,
          kyberPreKeyId: 1,
          kyberPreKey: kyberPreKey,
          kyberPreKeySignature: kyberPreKeySignature,
        );

        expect(bundle.signedPreKeyId, equals(42));

        bundle.dispose();
        preKeyPriv.dispose();
        preKey.dispose();
        signedPreKeyPriv.dispose();
        signedPreKey.dispose();
        kyberKeyPair.dispose();
        kyberPreKey.dispose();
      });
    });

    group('getSignedPreKeyPublic()', () {
      test('returns valid signed pre-key public key', () {
        final bundle = createFullBundle();
        final signedPreKeyPub = bundle.getSignedPreKeyPublic();

        expect(signedPreKeyPub, isNotNull);
        expect(signedPreKeyPub.isDisposed, isFalse);
        expect(signedPreKeyPub.serialize().length, equals(33));

        bundle.dispose();
        signedPreKeyPub.dispose();
      });
    });

    group('signedPreKeySignature', () {
      test('returns non-empty signature', () {
        final bundle = createFullBundle();
        final sig = bundle.signedPreKeySignature;

        expect(sig, isNotEmpty);
        expect(sig.length, equals(64)); // Ed25519 signature

        bundle.dispose();
      });

      test('signature is verifiable by identity key', () {
        final bundle = createFullBundle();

        final signedPreKeyPub = bundle.getSignedPreKeyPublic();
        final sig = bundle.signedPreKeySignature;
        final identityKey = bundle.getIdentityKey();

        final isValid = identityKey.verify(signedPreKeyPub.serialize(), sig);
        expect(isValid, isTrue);

        bundle.dispose();
        signedPreKeyPub.dispose();
        identityKey.dispose();
      });
    });

    group('getIdentityKey()', () {
      test('returns valid identity public key', () {
        final bundle = createFullBundle();
        final identityKey = bundle.getIdentityKey();

        expect(identityKey, isNotNull);
        expect(identityKey.isDisposed, isFalse);
        expect(identityKey.equals(identityPublicKey), isTrue);

        bundle.dispose();
        identityKey.dispose();
      });
    });

    group('kyberPreKeyId', () {
      test('returns correct Kyber pre-key ID', () {
        final bundle = createFullBundle(kyberPreKeyId: 555);
        expect(bundle.kyberPreKeyId, equals(555));
        bundle.dispose();
      });

      test('returns default Kyber pre-key ID', () {
        final bundle = createFullBundle();
        expect(bundle.kyberPreKeyId, equals(200));
        bundle.dispose();
      });
    });

    group('getKyberPreKeyPublic()', () {
      test('returns valid Kyber public key', () {
        final bundle = createFullBundle();
        final kyberPub = bundle.getKyberPreKeyPublic();

        expect(kyberPub, isNotNull);
        expect(kyberPub!.isDisposed, isFalse);
        expect(kyberPub.serialize().length, greaterThan(1000));

        bundle.dispose();
        kyberPub.dispose();
      });

      test('multiple calls return equivalent keys', () {
        final bundle = createFullBundle();
        final kyber1 = bundle.getKyberPreKeyPublic();
        final kyber2 = bundle.getKyberPreKeyPublic();

        expect(kyber1!.serialize(), equals(kyber2!.serialize()));

        bundle.dispose();
        kyber1.dispose();
        kyber2.dispose();
      });
    });

    group('kyberPreKeySignature', () {
      test('returns non-empty signature', () {
        final bundle = createFullBundle();
        final sig = bundle.kyberPreKeySignature;

        expect(sig, isNotEmpty);
        expect(sig.length, equals(64)); // Ed25519 signature

        bundle.dispose();
      });

      test('Kyber signature is verifiable by identity key', () {
        final bundle = createFullBundle();

        final kyberPub = bundle.getKyberPreKeyPublic();
        final sig = bundle.kyberPreKeySignature;
        final identityKey = bundle.getIdentityKey();

        final isValid = identityKey.verify(kyberPub!.serialize(), sig);
        expect(isValid, isTrue);

        bundle.dispose();
        kyberPub.dispose();
        identityKey.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final original = createFullBundle();
        final cloned = original.clone();

        expect(cloned.registrationId, equals(original.registrationId));
        expect(cloned.deviceId, equals(original.deviceId));
        expect(cloned.preKeyId, equals(original.preKeyId));
        expect(cloned.signedPreKeyId, equals(original.signedPreKeyId));
        expect(cloned.kyberPreKeyId, equals(original.kyberPreKeyId));

        original.dispose();

        // Cloned should still work
        expect(cloned.isDisposed, isFalse);
        expect(cloned.registrationId, equals(12345));

        cloned.dispose();
      });

      test('cloned bundle has same keys', () {
        final original = createFullBundle();
        final cloned = original.clone();

        final origPreKey = original.getPreKeyPublic();
        final clonedPreKey = cloned.getPreKeyPublic();
        expect(clonedPreKey!.equals(origPreKey!), isTrue);

        final origKyber = original.getKyberPreKeyPublic();
        final clonedKyber = cloned.getKyberPreKeyPublic();
        expect(clonedKyber!.serialize(), equals(origKyber!.serialize()));

        final origIdentity = original.getIdentityKey();
        final clonedIdentity = cloned.getIdentityKey();
        expect(clonedIdentity.equals(origIdentity), isTrue);

        original.dispose();
        cloned.dispose();
        origPreKey.dispose();
        clonedPreKey.dispose();
        origKyber.dispose();
        clonedKyber.dispose();
        origIdentity.dispose();
        clonedIdentity.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        final bundle = createFullBundle();
        expect(bundle.isDisposed, isFalse);
        bundle.dispose();
      });

      test('isDisposed is true after dispose', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(bundle.isDisposed, isTrue);
      });

      test('double dispose is safe', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(() => bundle.dispose(), returnsNormally);
      });

      test('registrationId throws after dispose', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(() => bundle.registrationId, throwsA(isA<LibSignalException>()));
      });

      test('deviceId throws after dispose', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(() => bundle.deviceId, throwsA(isA<LibSignalException>()));
      });

      test('preKeyId throws after dispose', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(() => bundle.preKeyId, throwsA(isA<LibSignalException>()));
      });

      test('getPreKeyPublic throws after dispose', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(() => bundle.getPreKeyPublic(), throwsA(isA<LibSignalException>()));
      });

      test('signedPreKeyId throws after dispose', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(() => bundle.signedPreKeyId, throwsA(isA<LibSignalException>()));
      });

      test('getSignedPreKeyPublic throws after dispose', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(() => bundle.getSignedPreKeyPublic(), throwsA(isA<LibSignalException>()));
      });

      test('signedPreKeySignature throws after dispose', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(() => bundle.signedPreKeySignature, throwsA(isA<LibSignalException>()));
      });

      test('getIdentityKey throws after dispose', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(() => bundle.getIdentityKey(), throwsA(isA<LibSignalException>()));
      });

      test('kyberPreKeyId throws after dispose', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(() => bundle.kyberPreKeyId, throwsA(isA<LibSignalException>()));
      });

      test('getKyberPreKeyPublic throws after dispose', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(() => bundle.getKyberPreKeyPublic(), throwsA(isA<LibSignalException>()));
      });

      test('kyberPreKeySignature throws after dispose', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(() => bundle.kyberPreKeySignature, throwsA(isA<LibSignalException>()));
      });

      test('clone throws after dispose', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(() => bundle.clone(), throwsA(isA<LibSignalException>()));
      });

      test('pointer throws after dispose', () {
        final bundle = createFullBundle();
        bundle.dispose();
        expect(() => bundle.pointer, throwsA(isA<LibSignalException>()));
      });
    });
  });
}
