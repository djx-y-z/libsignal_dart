import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  // Note: UnidentifiedSenderMessageContent is an internal type used by the
  // sealed sender protocol. The public API exposes high-level functions
  // instead of the raw message content type.
  //
  // Sealed sender encryption/decryption is tested in:
  // - sealed_session_cipher_test.dart (via SealedSenderCipher)
  //
  // Certificate functions are tested in:
  // - sender_certificate_test.dart
  // - server_certificate_test.dart

  group('Sealed Sender API', () {
    group('certificate getter functions', () {
      test('senderCertificateGetSenderName rejects invalid data', () {
        expect(
          () => senderCertificateGetSenderName(certificate: []),
          throwsA(anything),
        );
        expect(
          () => senderCertificateGetSenderName(certificate: [1, 2, 3]),
          throwsA(anything),
        );
      });

      test('senderCertificateGetSenderDeviceId rejects invalid data', () {
        expect(
          () => senderCertificateGetSenderDeviceId(certificate: []),
          throwsA(anything),
        );
      });

      test('senderCertificateGetKey rejects invalid data', () {
        expect(
          () => senderCertificateGetKey(certificate: []),
          throwsA(anything),
        );
      });

      test('senderCertificateGetExpiration rejects invalid data', () {
        expect(
          () => senderCertificateGetExpiration(certificate: []),
          throwsA(anything),
        );
      });
    });

    group('certificate validation', () {
      test('validateSenderCertificate rejects empty inputs', () {
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
