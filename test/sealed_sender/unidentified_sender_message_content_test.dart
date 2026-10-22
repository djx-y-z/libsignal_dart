import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/error_matchers.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  // Note: this file covers the certificate helpers only.
  // `UnidentifiedSenderMessageContent` itself — construction, accessors, and
  // the encryptFromUsmc / decryptToUsmc round trip — is covered in
  // `usmc_and_multi_recipient_test.dart`.
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
          failsWith(LibSignalErrorCode.protobufError),
        );
        expect(
          () => senderCertificateGetSenderName(certificate: [1, 2, 3]),
          failsWith(LibSignalErrorCode.protobufError),
        );
      });

      test('senderCertificateGetSenderDeviceId rejects invalid data', () {
        expect(
          () => senderCertificateGetSenderDeviceId(certificate: []),
          failsWith(LibSignalErrorCode.protobufError),
        );
      });

      test('senderCertificateGetKey rejects invalid data', () {
        expect(
          () => senderCertificateGetKey(certificate: []),
          failsWith(LibSignalErrorCode.protobufError),
        );
      });

      test('senderCertificateGetExpiration rejects invalid data', () {
        expect(
          () => senderCertificateGetExpiration(certificate: []),
          failsWith(LibSignalErrorCode.protobufError),
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
          failsWith(LibSignalErrorCode.protobufError),
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
          failsWith(LibSignalErrorCode.protobufError),
        );
      });
    });
  });
}
