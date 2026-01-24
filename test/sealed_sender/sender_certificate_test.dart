import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });
  tearDownAll(() => LibSignal.cleanup());

  group('Sender Certificate', () {
    late PrivateKey trustRootPrivate;
    late PublicKey trustRootPublic;
    late PrivateKey serverPrivate;
    late PublicKey serverPublic;
    late List<int> serverCertificate;
    late IdentityKeyPair senderIdentity;

    setUp(() {
      // Generate trust root key pair
      trustRootPrivate = PrivateKey.generate();
      trustRootPublic = trustRootPrivate.getPublicKey();

      // Generate server key pair
      serverPrivate = PrivateKey.generate();
      serverPublic = serverPrivate.getPublicKey();

      // Create server certificate
      serverCertificate = createServerCertificate(
        keyId: 1,
        serverPublicKey: serverPublic.serialize().toList(),
        trustRootPrivateKey: trustRootPrivate.serialize().toList(),
      ).toList();

      // Generate sender identity
      senderIdentity = IdentityKeyPair.generate();
    });

    group('createSenderCertificate()', () {
      test('creates valid sender certificate', () {
        final expiration = BigInt.from(
          DateTime.now().add(const Duration(days: 1)).millisecondsSinceEpoch,
        );

        final cert = createSenderCertificate(
          senderUuid: 'alice-uuid',
          senderDeviceId: 1,
          senderIdentityKey: senderIdentity.publicKey.toList(),
          expiration: expiration,
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivate.serialize().toList(),
        );

        expect(cert, isNotEmpty);
        expect(cert.length, greaterThan(10));
      });

      test('certificate contains correct sender name', () {
        final expiration = BigInt.from(
          DateTime.now().add(const Duration(days: 1)).millisecondsSinceEpoch,
        );

        final cert = createSenderCertificate(
          senderUuid: 'alice-uuid',
          senderDeviceId: 1,
          senderIdentityKey: senderIdentity.publicKey.toList(),
          expiration: expiration,
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivate.serialize().toList(),
        );

        final name = senderCertificateGetSenderName(certificate: cert.toList());
        expect(name, equals('alice-uuid'));
      });

      test('certificate contains correct device ID', () {
        final expiration = BigInt.from(
          DateTime.now().add(const Duration(days: 1)).millisecondsSinceEpoch,
        );

        final cert = createSenderCertificate(
          senderUuid: 'alice-uuid',
          senderDeviceId: 42,
          senderIdentityKey: senderIdentity.publicKey.toList(),
          expiration: expiration,
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivate.serialize().toList(),
        );

        final deviceId = senderCertificateGetSenderDeviceId(
          certificate: cert.toList(),
        );
        expect(deviceId, equals(42));
      });

      test('certificate contains correct identity key', () {
        final expiration = BigInt.from(
          DateTime.now().add(const Duration(days: 1)).millisecondsSinceEpoch,
        );

        final cert = createSenderCertificate(
          senderUuid: 'alice-uuid',
          senderDeviceId: 1,
          senderIdentityKey: senderIdentity.publicKey.toList(),
          expiration: expiration,
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivate.serialize().toList(),
        );

        final key = senderCertificateGetKey(certificate: cert.toList());
        expect(key, equals(senderIdentity.publicKey));
      });

      test('certificate contains correct expiration', () {
        final expiration = BigInt.from(
          DateTime.now().add(const Duration(days: 1)).millisecondsSinceEpoch,
        );

        final cert = createSenderCertificate(
          senderUuid: 'alice-uuid',
          senderDeviceId: 1,
          senderIdentityKey: senderIdentity.publicKey.toList(),
          expiration: expiration,
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivate.serialize().toList(),
        );

        final certExpiration = senderCertificateGetExpiration(
          certificate: cert.toList(),
        );
        expect(certExpiration, equals(expiration));
      });
    });

    group('validateSenderCertificate()', () {
      test('validates certificate with correct trust root', () {
        final expiration = BigInt.from(
          DateTime.now().add(const Duration(days: 1)).millisecondsSinceEpoch,
        );
        final timestamp = BigInt.from(DateTime.now().millisecondsSinceEpoch);

        final cert = createSenderCertificate(
          senderUuid: 'alice-uuid',
          senderDeviceId: 1,
          senderIdentityKey: senderIdentity.publicKey.toList(),
          expiration: expiration,
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivate.serialize().toList(),
        );

        final isValid = validateSenderCertificate(
          certificate: cert.toList(),
          trustRoot: trustRootPublic.serialize().toList(),
          timestamp: timestamp,
        );

        expect(isValid, isTrue);
      });

      test('rejects certificate with wrong trust root', () {
        final expiration = BigInt.from(
          DateTime.now().add(const Duration(days: 1)).millisecondsSinceEpoch,
        );
        final timestamp = BigInt.from(DateTime.now().millisecondsSinceEpoch);

        final cert = createSenderCertificate(
          senderUuid: 'alice-uuid',
          senderDeviceId: 1,
          senderIdentityKey: senderIdentity.publicKey.toList(),
          expiration: expiration,
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivate.serialize().toList(),
        );

        // Use a different trust root
        final wrongTrustRoot = PrivateKey.generate().getPublicKey();

        expect(
          () => validateSenderCertificate(
            certificate: cert.toList(),
            trustRoot: wrongTrustRoot.serialize().toList(),
            timestamp: timestamp,
          ),
          throwsA(anything),
        );
      });

      test('rejects expired certificate', () {
        // Certificate expired yesterday
        final expiration = BigInt.from(
          DateTime.now()
              .subtract(const Duration(days: 1))
              .millisecondsSinceEpoch,
        );
        final timestamp = BigInt.from(DateTime.now().millisecondsSinceEpoch);

        final cert = createSenderCertificate(
          senderUuid: 'alice-uuid',
          senderDeviceId: 1,
          senderIdentityKey: senderIdentity.publicKey.toList(),
          expiration: expiration,
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivate.serialize().toList(),
        );

        expect(
          () => validateSenderCertificate(
            certificate: cert.toList(),
            trustRoot: trustRootPublic.serialize().toList(),
            timestamp: timestamp,
          ),
          throwsA(anything),
        );
      });

      test('rejects empty certificate', () {
        expect(
          () => validateSenderCertificate(
            certificate: [],
            trustRoot: [],
            timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
          ),
          throwsA(anything),
        );
      });

      test('rejects garbage data', () {
        final garbage = [0x99, 0x88, 0x77, 0x66, 0x55];
        expect(
          () => validateSenderCertificate(
            certificate: garbage,
            trustRoot: garbage,
            timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
          ),
          throwsA(anything),
        );
      });
    });

    group('getter functions', () {
      test('senderCertificateGetSenderName rejects empty certificate', () {
        expect(
          () => senderCertificateGetSenderName(certificate: []),
          throwsA(anything),
        );
      });

      test('senderCertificateGetSenderDeviceId rejects empty certificate', () {
        expect(
          () => senderCertificateGetSenderDeviceId(certificate: []),
          throwsA(anything),
        );
      });

      test('senderCertificateGetKey rejects empty certificate', () {
        expect(
          () => senderCertificateGetKey(certificate: []),
          throwsA(anything),
        );
      });

      test('senderCertificateGetExpiration rejects empty certificate', () {
        expect(
          () => senderCertificateGetExpiration(certificate: []),
          throwsA(anything),
        );
      });
    });
  });
}
