import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:libsignal/src/serialization_validator.dart';
import 'package:test/test.dart';

void main() {
  group('KeyType', () {
    test('djb constant is 0x05', () {
      expect(KeyType.djb, equals(0x05));
    });

    test('identityKeyPair constant is 0x0a', () {
      expect(KeyType.identityKeyPair, equals(0x0a));
    });

    test('kyber1024 constant is 0x08', () {
      expect(KeyType.kyber1024, equals(0x08));
    });
  });

  group('KeySize', () {
    test('publicKey is 33', () {
      expect(KeySize.publicKey, equals(33));
    });

    test('privateKey is 32', () {
      expect(KeySize.privateKey, equals(32));
    });

    test('identityKeyPair is 69', () {
      expect(KeySize.identityKeyPair, equals(69));
    });

    test('kyberPublicKey is 1569', () {
      expect(KeySize.kyberPublicKey, equals(1569));
    });

    test('kyberSecretKey is 3169', () {
      expect(KeySize.kyberSecretKey, equals(3169));
    });
  });

  group('RecordSize', () {
    test('all minimum sizes are positive', () {
      expect(RecordSize.preKeyRecordMin, greaterThan(0));
      expect(RecordSize.signedPreKeyRecordMin, greaterThan(0));
      expect(RecordSize.kyberPreKeyRecordMin, greaterThan(0));
      expect(RecordSize.sessionRecordMin, greaterThan(0));
      expect(RecordSize.senderKeyRecordMin, greaterThan(0));
      expect(RecordSize.senderCertificateMin, greaterThan(0));
      expect(RecordSize.serverCertificateMin, greaterThan(0));
      expect(RecordSize.signalMessageMin, greaterThan(0));
      expect(RecordSize.decryptionErrorMessageMin, greaterThan(0));
      expect(RecordSize.senderKeyMessageMin, greaterThan(0));
      expect(RecordSize.senderKeyDistributionMessageMin, greaterThan(0));
    });
  });

  group('SerializationValidator', () {
    group('validatePublicKey', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validatePublicKey(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on wrong length', () {
        expect(
          () => SerializationValidator.validatePublicKey(Uint8List(10)),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('Invalid length'),
            ),
          ),
        );
      });

      test('throws on invalid key type', () {
        final data = Uint8List(33);
        data[0] = 0x99; // Invalid type
        expect(
          () => SerializationValidator.validatePublicKey(data),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('Invalid key type'),
            ),
          ),
        );
      });

      test('throws on low-order point (all zeros)', () {
        final data = Uint8List(33);
        data[0] = KeyType.djb;
        // Bytes 1-32 are all zeros (low-order point)
        expect(
          () => SerializationValidator.validatePublicKey(data),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('Low-order point'),
            ),
          ),
        );
      });

      test('throws on low-order point (1)', () {
        final data = Uint8List(33);
        data[0] = KeyType.djb;
        data[1] = 0x01; // Low-order point: 1
        expect(
          () => SerializationValidator.validatePublicKey(data),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('Low-order point'),
            ),
          ),
        );
      });

      test('passes for valid public key', () {
        // Generate a real key and use its bytes
        LibSignal.ensureInitialized();
        final key = PrivateKey.generate().getPublicKey();
        final data = key.serialize();
        key.dispose();

        expect(
          () => SerializationValidator.validatePublicKey(data),
          returnsNormally,
        );
      });
    });

    group('validatePrivateKey', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validatePrivateKey(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on wrong length', () {
        expect(
          () => SerializationValidator.validatePrivateKey(Uint8List(10)),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('Invalid length'),
            ),
          ),
        );
      });

      test('passes for correct length', () {
        expect(
          () => SerializationValidator.validatePrivateKey(Uint8List(32)),
          returnsNormally,
        );
      });
    });

    group('validateIdentityKeyPair', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validateIdentityKeyPair(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on wrong length', () {
        expect(
          () => SerializationValidator.validateIdentityKeyPair(Uint8List(10)),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('Invalid length'),
            ),
          ),
        );
      });

      test('throws on invalid key type', () {
        final data = Uint8List(69);
        data[0] = 0x99; // Invalid type
        expect(
          () => SerializationValidator.validateIdentityKeyPair(data),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('Invalid key type'),
            ),
          ),
        );
      });

      test('passes for valid structure', () {
        final data = Uint8List(69);
        data[0] = KeyType.identityKeyPair;
        expect(
          () => SerializationValidator.validateIdentityKeyPair(data),
          returnsNormally,
        );
      });
    });

    group('validateKyberPublicKey', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validateKyberPublicKey(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on wrong length', () {
        expect(
          () => SerializationValidator.validateKyberPublicKey(Uint8List(100)),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('Invalid length'),
            ),
          ),
        );
      });

      test('throws on invalid key type', () {
        final data = Uint8List(1569);
        data[0] = 0x99; // Invalid type
        expect(
          () => SerializationValidator.validateKyberPublicKey(data),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('Invalid key type'),
            ),
          ),
        );
      });

      test('passes for valid structure', () {
        final data = Uint8List(1569);
        data[0] = KeyType.kyber1024;
        expect(
          () => SerializationValidator.validateKyberPublicKey(data),
          returnsNormally,
        );
      });
    });

    group('validateKyberSecretKey', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validateKyberSecretKey(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on wrong length', () {
        expect(
          () => SerializationValidator.validateKyberSecretKey(Uint8List(100)),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('Invalid length'),
            ),
          ),
        );
      });

      test('passes for correct length', () {
        expect(
          () => SerializationValidator.validateKyberSecretKey(Uint8List(3169)),
          returnsNormally,
        );
      });
    });

    group('validateMinLength', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validateMinLength(
            Uint8List(0),
            10,
            'test',
          ),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws when data too short', () {
        expect(
          () => SerializationValidator.validateMinLength(
            Uint8List(5),
            10,
            'test',
          ),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('too short'),
            ),
          ),
        );
      });

      test('passes when data equals minimum', () {
        expect(
          () => SerializationValidator.validateMinLength(
            Uint8List(10),
            10,
            'test',
          ),
          returnsNormally,
        );
      });

      test('passes when data exceeds minimum', () {
        expect(
          () => SerializationValidator.validateMinLength(
            Uint8List(20),
            10,
            'test',
          ),
          returnsNormally,
        );
      });
    });

    group('validatePreKeyRecord', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validatePreKeyRecord(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on too short data', () {
        expect(
          () => SerializationValidator.validatePreKeyRecord(Uint8List(10)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on invalid protobuf tag', () {
        final data = Uint8List(RecordSize.preKeyRecordMin);
        data[0] = 0x99; // Invalid tag
        expect(
          () => SerializationValidator.validatePreKeyRecord(data),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('Invalid protobuf'),
            ),
          ),
        );
      });

      test('passes for field 1 (0x08)', () {
        final data = Uint8List(RecordSize.preKeyRecordMin);
        data[0] = 0x08;
        expect(
          () => SerializationValidator.validatePreKeyRecord(data),
          returnsNormally,
        );
      });

      test('passes for field 2 (0x12)', () {
        final data = Uint8List(RecordSize.preKeyRecordMin);
        data[0] = 0x12;
        expect(
          () => SerializationValidator.validatePreKeyRecord(data),
          returnsNormally,
        );
      });
    });

    group('validateSignedPreKeyRecord', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validateSignedPreKeyRecord(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on invalid protobuf tag', () {
        final data = Uint8List(RecordSize.signedPreKeyRecordMin);
        data[0] = 0x99;
        expect(
          () => SerializationValidator.validateSignedPreKeyRecord(data),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('passes for valid tags', () {
        for (final tag in [0x08, 0x10, 0x12]) {
          final data = Uint8List(RecordSize.signedPreKeyRecordMin);
          data[0] = tag;
          expect(
            () => SerializationValidator.validateSignedPreKeyRecord(data),
            returnsNormally,
          );
        }
      });
    });

    group('validateKyberPreKeyRecord', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validateKyberPreKeyRecord(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on invalid protobuf tag', () {
        final data = Uint8List(RecordSize.kyberPreKeyRecordMin);
        data[0] = 0x99;
        expect(
          () => SerializationValidator.validateKyberPreKeyRecord(data),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('passes for valid tags', () {
        for (final tag in [0x08, 0x10, 0x12]) {
          final data = Uint8List(RecordSize.kyberPreKeyRecordMin);
          data[0] = tag;
          expect(
            () => SerializationValidator.validateKyberPreKeyRecord(data),
            returnsNormally,
          );
        }
      });
    });

    group('validateSessionRecord', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validateSessionRecord(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on invalid protobuf tag', () {
        final data = Uint8List(RecordSize.sessionRecordMin);
        data[0] = 0x99;
        expect(
          () => SerializationValidator.validateSessionRecord(data),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('passes for field 0x0a', () {
        final data = Uint8List(RecordSize.sessionRecordMin);
        data[0] = 0x0a;
        expect(
          () => SerializationValidator.validateSessionRecord(data),
          returnsNormally,
        );
      });

      test('passes for field 0x12', () {
        final data = Uint8List(RecordSize.sessionRecordMin);
        data[0] = 0x12;
        expect(
          () => SerializationValidator.validateSessionRecord(data),
          returnsNormally,
        );
      });
    });

    group('validateSenderKeyRecord', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validateSenderKeyRecord(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on invalid protobuf tag', () {
        final data = Uint8List(RecordSize.senderKeyRecordMin);
        data[0] = 0x99;
        expect(
          () => SerializationValidator.validateSenderKeyRecord(data),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('passes for 0x0a', () {
        final data = Uint8List(RecordSize.senderKeyRecordMin);
        data[0] = 0x0a;
        expect(
          () => SerializationValidator.validateSenderKeyRecord(data),
          returnsNormally,
        );
      });
    });

    group('validateSenderCertificate', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validateSenderCertificate(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on invalid protobuf tag', () {
        final data = Uint8List(RecordSize.senderCertificateMin);
        data[0] = 0x99;
        expect(
          () => SerializationValidator.validateSenderCertificate(data),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('passes for 0x0a', () {
        final data = Uint8List(RecordSize.senderCertificateMin);
        data[0] = 0x0a;
        expect(
          () => SerializationValidator.validateSenderCertificate(data),
          returnsNormally,
        );
      });
    });

    group('validateServerCertificate', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validateServerCertificate(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on invalid protobuf tag', () {
        final data = Uint8List(RecordSize.serverCertificateMin);
        data[0] = 0x99;
        expect(
          () => SerializationValidator.validateServerCertificate(data),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('passes for 0x0a', () {
        final data = Uint8List(RecordSize.serverCertificateMin);
        data[0] = 0x0a;
        expect(
          () => SerializationValidator.validateServerCertificate(data),
          returnsNormally,
        );
      });
    });

    group('validateSignalMessage', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validateSignalMessage(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on invalid version (0)', () {
        final data = Uint8List(RecordSize.signalMessageMin);
        data[0] = 0x00; // version 0 in high nibble
        expect(
          () => SerializationValidator.validateSignalMessage(data),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('Invalid message version'),
            ),
          ),
        );
      });

      test('throws on invalid version (5)', () {
        final data = Uint8List(RecordSize.signalMessageMin);
        data[0] = 0x50; // version 5 in high nibble
        expect(
          () => SerializationValidator.validateSignalMessage(data),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('passes for version 3', () {
        final data = Uint8List(RecordSize.signalMessageMin);
        data[0] = 0x33; // version 3 in high nibble
        expect(
          () => SerializationValidator.validateSignalMessage(data),
          returnsNormally,
        );
      });

      test('passes for version 4', () {
        final data = Uint8List(RecordSize.signalMessageMin);
        data[0] = 0x43; // version 4 in high nibble
        expect(
          () => SerializationValidator.validateSignalMessage(data),
          returnsNormally,
        );
      });
    });

    group('validateDecryptionErrorMessage', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validateDecryptionErrorMessage(
            Uint8List(0),
          ),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on invalid wire type', () {
        final data = Uint8List(RecordSize.decryptionErrorMessageMin);
        data[0] = 0x0F; // wire type 7 (invalid)
        expect(
          () => SerializationValidator.validateDecryptionErrorMessage(data),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('Invalid protobuf wire type'),
            ),
          ),
        );
      });

      test('passes for valid wire types', () {
        for (var wireType = 0; wireType <= 5; wireType++) {
          final data = Uint8List(RecordSize.decryptionErrorMessageMin);
          data[0] = wireType; // field 0 with different wire types
          expect(
            () => SerializationValidator.validateDecryptionErrorMessage(data),
            returnsNormally,
          );
        }
      });
    });

    group('validateSenderKeyMessage', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validateSenderKeyMessage(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on invalid version', () {
        final data = Uint8List(RecordSize.senderKeyMessageMin);
        data[0] = 0x00; // version 0
        expect(
          () => SerializationValidator.validateSenderKeyMessage(data),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('passes for version 3', () {
        final data = Uint8List(RecordSize.senderKeyMessageMin);
        data[0] = 0x33;
        expect(
          () => SerializationValidator.validateSenderKeyMessage(data),
          returnsNormally,
        );
      });
    });

    group('validateSenderKeyDistributionMessage', () {
      test('throws on empty data', () {
        expect(
          () => SerializationValidator.validateSenderKeyDistributionMessage(
            Uint8List(0),
          ),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws on invalid version', () {
        final data = Uint8List(RecordSize.senderKeyDistributionMessageMin);
        data[0] = 0x00; // version 0
        expect(
          () => SerializationValidator.validateSenderKeyDistributionMessage(
            data,
          ),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('passes for version 3', () {
        final data = Uint8List(RecordSize.senderKeyDistributionMessageMin);
        data[0] = 0x33;
        expect(
          () => SerializationValidator.validateSenderKeyDistributionMessage(
            data,
          ),
          returnsNormally,
        );
      });
    });
  });
}
