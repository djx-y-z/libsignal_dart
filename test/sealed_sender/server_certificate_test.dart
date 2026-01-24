import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });
  tearDownAll(() => LibSignal.cleanup());

  group('Server Certificate', () {
    late PrivateKey trustRootPrivate;
    late PrivateKey serverPrivate;
    late PublicKey serverPublic;

    setUp(() {
      // Generate trust root key pair
      trustRootPrivate = PrivateKey.generate();

      // Generate server key pair
      serverPrivate = PrivateKey.generate();
      serverPublic = serverPrivate.getPublicKey();
    });

    group('createServerCertificate()', () {
      test('creates valid server certificate', () {
        final cert = createServerCertificate(
          keyId: 1,
          serverPublicKey: serverPublic.serialize().toList(),
          trustRootPrivateKey: trustRootPrivate.serialize().toList(),
        );

        expect(cert, isNotEmpty);
        // Certificate should be a valid protobuf
        expect(cert.length, greaterThan(10));
      });

      test('creates certificates with different key IDs', () {
        final cert1 = createServerCertificate(
          keyId: 1,
          serverPublicKey: serverPublic.serialize().toList(),
          trustRootPrivateKey: trustRootPrivate.serialize().toList(),
        );

        final cert2 = createServerCertificate(
          keyId: 2,
          serverPublicKey: serverPublic.serialize().toList(),
          trustRootPrivateKey: trustRootPrivate.serialize().toList(),
        );

        // Different key IDs should produce different certificates
        expect(cert1, isNot(equals(cert2)));
      });

      test('creates certificates with different server keys', () {
        final otherServerPrivate = PrivateKey.generate();
        final otherServerPublic = otherServerPrivate.getPublicKey();

        final cert1 = createServerCertificate(
          keyId: 1,
          serverPublicKey: serverPublic.serialize().toList(),
          trustRootPrivateKey: trustRootPrivate.serialize().toList(),
        );

        final cert2 = createServerCertificate(
          keyId: 1,
          serverPublicKey: otherServerPublic.serialize().toList(),
          trustRootPrivateKey: trustRootPrivate.serialize().toList(),
        );

        // Different server keys should produce different certificates
        expect(cert1, isNot(equals(cert2)));
      });

      test('rejects invalid server public key', () {
        expect(
          () => createServerCertificate(
            keyId: 1,
            serverPublicKey: [1, 2, 3], // Invalid key
            trustRootPrivateKey: trustRootPrivate.serialize().toList(),
          ),
          throwsA(anything),
        );
      });

      test('rejects invalid trust root private key', () {
        expect(
          () => createServerCertificate(
            keyId: 1,
            serverPublicKey: serverPublic.serialize().toList(),
            trustRootPrivateKey: [1, 2, 3], // Invalid key
          ),
          throwsA(anything),
        );
      });
    });

    group('certificate validation', () {
      test('validateSenderCertificate rejects empty certificate', () {
        expect(
          () => validateSenderCertificate(
            certificate: [],
            trustRoot: [],
            timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
          ),
          throwsA(anything),
        );
      });

      test('validateSenderCertificate rejects garbage data', () {
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
  });
}
