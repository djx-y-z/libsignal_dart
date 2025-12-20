import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('SenderCertificate', () {
    late PrivateKey trustRootPrivate;
    late PublicKey trustRootPublic;
    late PrivateKey serverPrivate;
    late PublicKey serverKey;
    late ServerCertificate serverCert;
    late PrivateKey senderPrivate;
    late PublicKey senderKey;

    setUp(() {
      trustRootPrivate = PrivateKey.generate();
      trustRootPublic = trustRootPrivate.getPublicKey();

      serverPrivate = PrivateKey.generate();
      serverKey = serverPrivate.getPublicKey();

      serverCert = ServerCertificate.create(
        keyId: 1,
        serverKey: serverKey,
        trustRoot: trustRootPrivate,
      );

      senderPrivate = PrivateKey.generate();
      senderKey = senderPrivate.getPublicKey();
    });

    tearDown(() {
      trustRootPrivate.dispose();
      trustRootPublic.dispose();
      serverPrivate.dispose();
      serverKey.dispose();
      serverCert.dispose();
      senderPrivate.dispose();
      senderKey.dispose();
    });

    group('create()', () {
      test('creates valid sender certificate with all fields', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          senderE164: '+1234567890',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        expect(cert, isNotNull);
        expect(cert.isDisposed, isFalse);
        expect(cert.senderUuid, equals('test-uuid-1234'));
        expect(cert.senderE164, equals('+1234567890'));
        expect(cert.deviceId, equals(1));

        cert.dispose();
      });

      test('creates certificate without E164', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          senderE164: null,
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        expect(cert.senderE164, isNull);

        cert.dispose();
      });

      test('creates certificate with various device IDs', () {
        final expiration = DateTime.now().add(const Duration(days: 30));

        for (final deviceId in [1, 2, 100, 0xFFFF]) {
          final cert = SenderCertificate.create(
            senderUuid: 'test-uuid-1234',
            deviceId: deviceId,
            senderKey: senderKey,
            expiration: expiration,
            signerCertificate: serverCert,
            signerKey: serverPrivate,
          );

          expect(cert.deviceId, equals(deviceId));
          cert.dispose();
        }
      });

      test('created certificate has valid signature', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        final signature = cert.signature;
        expect(signature, isNotEmpty);
        expect(signature.length, equals(64)); // Ed25519 signature

        cert.dispose();
      });

      test('created certificate has certificate data', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        final certData = cert.certificate;
        expect(certData, isNotEmpty);

        cert.dispose();
      });

      test('expiration time is preserved', () {
        // Round to seconds to avoid millisecond precision issues
        final now = DateTime.now();
        final expiration = DateTime(
          now.year,
          now.month,
          now.day + 30,
          now.hour,
          now.minute,
          now.second,
        );

        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        // Compare milliseconds since epoch (allow 1 second tolerance)
        expect(
          cert.expiration.millisecondsSinceEpoch,
          closeTo(expiration.millisecondsSinceEpoch, 1000),
        );

        cert.dispose();
      });
    });

    group('serialize() / deserialize()', () {
      test('round-trip preserves certificate', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final original = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          senderE164: '+1234567890',
          deviceId: 42,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        final serialized = original.serialize();
        expect(serialized, isNotEmpty);

        final restored = SenderCertificate.deserialize(serialized);

        expect(restored.senderUuid, equals(original.senderUuid));
        expect(restored.senderE164, equals(original.senderE164));
        expect(restored.deviceId, equals(original.deviceId));
        expect(restored.signature, equals(original.signature));
        expect(restored.certificate, equals(original.certificate));

        final origKey = original.getKey();
        final restoredKey = restored.getKey();
        expect(restoredKey.equals(origKey), isTrue);

        original.dispose();
        restored.dispose();
        origKey.dispose();
        restoredKey.dispose();
      });

      test('round-trip preserves certificate without E164', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final original = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          senderE164: null,
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        final serialized = original.serialize();
        final restored = SenderCertificate.deserialize(serialized);

        expect(restored.senderE164, isNull);

        original.dispose();
        restored.dispose();
      });

      test('deserialize rejects empty data', () {
        expect(
          () => SenderCertificate.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects invalid data', () {
        final invalidData = Uint8List.fromList([1, 2, 3, 4, 5]);
        expect(
          () => SenderCertificate.deserialize(invalidData),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects garbage data', () {
        final garbage = randomBytes(100);
        expect(
          () => SenderCertificate.deserialize(garbage),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('getKey()', () {
      test('returns valid public key', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        final key = cert.getKey();

        expect(key, isNotNull);
        expect(key.isDisposed, isFalse);
        expect(key.serialize().length, equals(33));
        expect(key.equals(senderKey), isTrue);

        key.dispose();
        cert.dispose();
      });

      test('multiple calls return equivalent keys', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        final key1 = cert.getKey();
        final key2 = cert.getKey();

        expect(key1.equals(key2), isTrue);

        key1.dispose();
        key2.dispose();
        cert.dispose();
      });
    });

    group('getServerCertificate()', () {
      test('returns server certificate', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        final serverCertRetrieved = cert.getServerCertificate();

        expect(serverCertRetrieved, isNotNull);
        expect(serverCertRetrieved.isDisposed, isFalse);
        expect(serverCertRetrieved.keyId, equals(serverCert.keyId));

        serverCertRetrieved.dispose();
        cert.dispose();
      });
    });

    group('validate()', () {
      test('valid certificate validates successfully', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        final isValid = cert.validate(trustRootPublic);
        expect(isValid, isTrue);

        cert.dispose();
      });

      test('expired certificate fails validation', () {
        // Create a certificate that expired in the past
        final expiration = DateTime.now().subtract(const Duration(days: 1));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        final isValid = cert.validate(trustRootPublic);
        expect(isValid, isFalse);

        cert.dispose();
      });

      test('validation with custom time works', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        // Check with time before expiration
        final isValidBefore = cert.validate(
          trustRootPublic,
          now: DateTime.now().add(const Duration(days: 15)),
        );
        expect(isValidBefore, isTrue);

        // Check with time after expiration
        final isValidAfter = cert.validate(
          trustRootPublic,
          now: DateTime.now().add(const Duration(days: 60)),
        );
        expect(isValidAfter, isFalse);

        cert.dispose();
      });

      test('validation fails with wrong trust root', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        final wrongTrustRoot = PrivateKey.generate().getPublicKey();
        final isValid = cert.validate(wrongTrustRoot);
        expect(isValid, isFalse);

        wrongTrustRoot.dispose();
        cert.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final original = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          senderE164: '+1234567890',
          deviceId: 42,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        final cloned = original.clone();

        expect(cloned.senderUuid, equals(original.senderUuid));
        expect(cloned.senderE164, equals(original.senderE164));
        expect(cloned.deviceId, equals(original.deviceId));
        expect(cloned.serialize(), equals(original.serialize()));

        original.dispose();

        // Cloned should still work
        expect(cloned.isDisposed, isFalse);
        expect(cloned.senderUuid, equals('test-uuid-1234'));

        cloned.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        expect(cert.isDisposed, isFalse);
        cert.dispose();
      });

      test('isDisposed is true after dispose', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        cert.dispose();
        expect(cert.isDisposed, isTrue);
      });

      test('double dispose is safe', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        cert.dispose();
        expect(() => cert.dispose(), returnsNormally);
      });

      test('senderUuid throws after dispose', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        cert.dispose();
        expect(() => cert.senderUuid, throwsStateError);
      });

      test('senderE164 throws after dispose', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        cert.dispose();
        expect(() => cert.senderE164, throwsStateError);
      });

      test('deviceId throws after dispose', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        cert.dispose();
        expect(() => cert.deviceId, throwsStateError);
      });

      test('expiration throws after dispose', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        cert.dispose();
        expect(() => cert.expiration, throwsStateError);
      });

      test('serialize throws after dispose', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        cert.dispose();
        expect(() => cert.serialize(), throwsStateError);
      });

      test('getKey throws after dispose', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        cert.dispose();
        expect(() => cert.getKey(), throwsStateError);
      });

      test('getServerCertificate throws after dispose', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        cert.dispose();
        expect(() => cert.getServerCertificate(), throwsStateError);
      });

      test('validate throws after dispose', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        cert.dispose();
        expect(() => cert.validate(trustRootPublic), throwsStateError);
      });

      test('certificate throws after dispose', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        cert.dispose();
        expect(() => cert.certificate, throwsStateError);
      });

      test('signature throws after dispose', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        cert.dispose();
        expect(() => cert.signature, throwsStateError);
      });

      test('clone throws after dispose', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        cert.dispose();
        expect(() => cert.clone(), throwsStateError);
      });

      test('pointer throws after dispose', () {
        final expiration = DateTime.now().add(const Duration(days: 30));
        final cert = SenderCertificate.create(
          senderUuid: 'test-uuid-1234',
          deviceId: 1,
          senderKey: senderKey,
          expiration: expiration,
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        cert.dispose();
        expect(() => cert.pointer, throwsStateError);
      });
    });
  });
}
