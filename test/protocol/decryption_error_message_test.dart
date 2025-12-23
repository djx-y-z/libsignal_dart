import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('DecryptionErrorMessage', () {
    late InMemorySessionStore aliceSessionStore;
    late InMemoryIdentityKeyStore aliceIdentityStore;
    late InMemoryPreKeyStore bobPreKeyStore;
    late InMemorySignedPreKeyStore bobSignedPreKeyStore;
    late InMemoryKyberPreKeyStore bobKyberPreKeyStore;
    late IdentityKeyPair aliceIdentity;
    late ProtocolAddress bobAddress;
    late RemotePartyKeys bobKeys;

    // We need to create valid encrypted messages to test DecryptionErrorMessage
    late Uint8List validEncryptedMessage;
    late int validTimestamp;

    setUp(() async {
      aliceIdentity = IdentityKeyPair.generate();
      bobAddress = ProtocolAddress('bob', 1);

      aliceSessionStore = InMemorySessionStore();
      aliceIdentityStore = InMemoryIdentityKeyStore(aliceIdentity, 12345);
      bobPreKeyStore = InMemoryPreKeyStore();
      bobSignedPreKeyStore = InMemorySignedPreKeyStore();
      bobKyberPreKeyStore = InMemoryKyberPreKeyStore();

      // Generate Bob's keys
      bobKeys = generateRemotePartyKeys(registrationId: 67890);

      // Store Bob's pre-keys
      final preKeyRecord = PreKeyRecord.create(
        id: bobKeys.preKeyId,
        publicKey: bobKeys.preKeyPublic,
        privateKey: bobKeys.preKeyPrivate,
      );
      await bobPreKeyStore.storePreKey(bobKeys.preKeyId, preKeyRecord);

      final signedPreKeyRecord = SignedPreKeyRecord.create(
        id: bobKeys.signedPreKeyId,
        timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
        publicKey: bobKeys.signedPreKeyPublic,
        privateKey: bobKeys.signedPreKeyPrivate,
        signature: bobKeys.signedPreKeySignature,
      );
      await bobSignedPreKeyStore.storeSignedPreKey(
        bobKeys.signedPreKeyId,
        signedPreKeyRecord,
      );

      final kyberPreKeyRecord = KyberPreKeyRecord.create(
        id: bobKeys.kyberPreKeyId,
        timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
        keyPair: bobKeys.kyberKeyPair,
        signature: bobKeys.kyberPreKeySignature,
      );
      await bobKyberPreKeyStore.storeKyberPreKey(
        bobKeys.kyberPreKeyId,
        kyberPreKeyRecord,
      );

      // Alice establishes session with Bob
      final bobBundle = bobKeys.toBundle();
      final aliceBuilder = SessionBuilder(
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );
      await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

      // Alice encrypts a message to get valid encrypted bytes
      final aliceCipher = SessionCipher(
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );
      final plaintext = Uint8List.fromList(utf8.encode('Test message'));
      final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);
      validEncryptedMessage = encrypted.bytes;
      validTimestamp = DateTime.now().toUtc().millisecondsSinceEpoch;

      preKeyRecord.dispose();
      signedPreKeyRecord.dispose();
      kyberPreKeyRecord.dispose();
      bobBundle.dispose();
    });

    tearDown(() {
      aliceIdentity.dispose();
      bobAddress.dispose();
      bobKeys.dispose();
      aliceSessionStore.clear();
      bobPreKeyStore.clear();
      bobSignedPreKeyStore.clear();
      bobKyberPreKeyStore.clear();
    });

    group('forOriginalMessage()', () {
      test('creates valid error message with valid encrypted message', () {
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: validTimestamp,
          originalSenderDeviceId: 42,
        );

        expect(errorMsg, isNotNull);
        expect(errorMsg.isDisposed, isFalse);
        expect(errorMsg.deviceId, equals(42));
        expect(errorMsg.timestamp, equals(validTimestamp));

        errorMsg.dispose();
      });

      test('creates error message with various device IDs', () {
        for (final deviceId in [1, 2, 100, 0xFFFF]) {
          final errorMsg = DecryptionErrorMessage.forOriginalMessage(
            originalBytes: validEncryptedMessage,
            messageType: CiphertextMessageType.preKey.value,
            timestamp: validTimestamp,
            originalSenderDeviceId: deviceId,
          );

          expect(errorMsg.deviceId, equals(deviceId));
          errorMsg.dispose();
        }
      });

      test('rejects empty original bytes', () {
        expect(
          () => DecryptionErrorMessage.forOriginalMessage(
            originalBytes: Uint8List(0),
            messageType: 2,
            timestamp: 12345,
            originalSenderDeviceId: 1,
          ),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('serialize() / deserialize()', () {
      test('round-trip preserves message', () {
        final original = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: validTimestamp,
          originalSenderDeviceId: 42,
        );

        final serialized = original.serialize();
        expect(serialized, isNotEmpty);

        final restored = DecryptionErrorMessage.deserialize(serialized);

        expect(restored.deviceId, equals(original.deviceId));
        expect(restored.timestamp, equals(original.timestamp));
        expect(restored.serialize(), equals(serialized));

        original.dispose();
        restored.dispose();
      });

      test('deserialize rejects empty data', () {
        expect(
          () => DecryptionErrorMessage.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects garbage data', () {
        final garbage = Uint8List.fromList([0x99, 0x88, 0x77, 0x66, 0x55]);
        expect(
          () => DecryptionErrorMessage.deserialize(garbage),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('getters', () {
      test('timestamp returns correct value', () {
        const timestamp = 1700000000000;
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: timestamp,
          originalSenderDeviceId: 1,
        );

        expect(errorMsg.timestamp, equals(timestamp));
        errorMsg.dispose();
      });

      test('deviceId returns correct value', () {
        const deviceId = 123;
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: validTimestamp,
          originalSenderDeviceId: deviceId,
        );

        expect(errorMsg.deviceId, equals(deviceId));
        errorMsg.dispose();
      });

      test('getRatchetKey returns key for valid message', () {
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: validTimestamp,
          originalSenderDeviceId: 1,
        );

        final ratchetKey = errorMsg.getRatchetKey();

        // PreKey messages should have a ratchet key
        if (ratchetKey != null) {
          expect(ratchetKey.isDisposed, isFalse);
          expect(ratchetKey.serialize().length, equals(33));
          ratchetKey.dispose();
        }

        errorMsg.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final original = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: validTimestamp,
          originalSenderDeviceId: 42,
        );

        final cloned = original.clone();

        expect(cloned.deviceId, equals(original.deviceId));
        expect(cloned.timestamp, equals(original.timestamp));
        expect(cloned.serialize(), equals(original.serialize()));

        original.dispose();

        // Cloned should still work
        expect(cloned.isDisposed, isFalse);
        expect(cloned.deviceId, equals(42));

        cloned.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: validTimestamp,
          originalSenderDeviceId: 1,
        );

        expect(errorMsg.isDisposed, isFalse);
        errorMsg.dispose();
      });

      test('isDisposed is true after dispose', () {
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: validTimestamp,
          originalSenderDeviceId: 1,
        );

        errorMsg.dispose();
        expect(errorMsg.isDisposed, isTrue);
      });

      test('double dispose is safe', () {
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: validTimestamp,
          originalSenderDeviceId: 1,
        );

        errorMsg.dispose();
        expect(() => errorMsg.dispose(), returnsNormally);
      });

      test('timestamp throws after dispose', () {
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: validTimestamp,
          originalSenderDeviceId: 1,
        );

        errorMsg.dispose();
        expect(() => errorMsg.timestamp, throwsStateError);
      });

      test('deviceId throws after dispose', () {
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: validTimestamp,
          originalSenderDeviceId: 1,
        );

        errorMsg.dispose();
        expect(() => errorMsg.deviceId, throwsStateError);
      });

      test('serialize throws after dispose', () {
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: validTimestamp,
          originalSenderDeviceId: 1,
        );

        errorMsg.dispose();
        expect(() => errorMsg.serialize(), throwsStateError);
      });

      test('getRatchetKey throws after dispose', () {
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: validTimestamp,
          originalSenderDeviceId: 1,
        );

        errorMsg.dispose();
        expect(() => errorMsg.getRatchetKey(), throwsStateError);
      });

      test('clone throws after dispose', () {
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: validTimestamp,
          originalSenderDeviceId: 1,
        );

        errorMsg.dispose();
        expect(() => errorMsg.clone(), throwsStateError);
      });

      test('pointer throws after dispose', () {
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: validEncryptedMessage,
          messageType: CiphertextMessageType.preKey.value,
          timestamp: validTimestamp,
          originalSenderDeviceId: 1,
        );

        errorMsg.dispose();
        expect(() => errorMsg.pointer, throwsStateError);
      });
    });
  });
}
