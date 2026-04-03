// ignore_for_file: avoid_redundant_argument_values, unnecessary_lambdas
import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/session_helpers.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('DecryptionErrorMessage', () {
    group('extractFromSerializedContent()', () {
      test('rejects empty data', () {
        expect(
          () => DecryptionErrorMessage.extractFromSerializedContent(bytes: []),
          throwsA(anything),
        );
      });

      test('rejects garbage data', () {
        final garbage = [0x12, 0x34, 0x56, 0x78];
        expect(
          () => DecryptionErrorMessage.extractFromSerializedContent(
            bytes: garbage,
          ),
          throwsA(anything),
        );
      });
    });

    group('deserialize()', () {
      test('rejects empty data', () {
        expect(
          () => DecryptionErrorMessage.deserialize(bytes: []),
          throwsA(anything),
        );
      });

      test('rejects garbage data', () {
        final garbage = [0x99, 0x88, 0x77, 0x66, 0x55];
        expect(
          () => DecryptionErrorMessage.deserialize(bytes: garbage),
          throwsA(anything),
        );
      });
    });

    group('forOriginalMessage()', () {
      test('creates error message from encrypted bytes', () async {
        // Setup Alice and Bob
        final aliceIdentity = IdentityKeyPair.generate();
        final aliceSessionStorage = <String, Uint8List>{};
        final aliceIdentityStorage = <String, Uint8List>{};

        final bobKeys = generateRemotePartyKeys(
          registrationId: 222,
          deviceId: 1,
        );
        final bobBundle = bobKeys.toBundle();

        // Alice processes Bob's bundle
        await processPrekeyBundleWithCallbacks(
          remoteName: 'bob',
          remoteDeviceId: 1,
          bundle: bobBundle,
          loadSession: (name, deviceId) =>
              aliceSessionStorage['$name:$deviceId'],
          storeSession: (name, deviceId, data) =>
              aliceSessionStorage['$name:$deviceId'] = data,
          getIdentityKeyPair: () => aliceIdentity.serialize(),
          getLocalRegistrationId: () => 111,
          saveIdentity: (name, deviceId, key) =>
              aliceIdentityStorage['$name:$deviceId'] = key,
        );

        // Alice encrypts a message
        const message = 'Hello Bob!';
        final encrypted = await messageEncryptWithCallbacks(
          remoteName: 'bob',
          remoteDeviceId: 1,
          localName: 'alice',
          localDeviceId: 1,
          plaintext: utf8.encode(message),
          loadSession: (name, deviceId) =>
              aliceSessionStorage['$name:$deviceId'],
          storeSession: (name, deviceId, data) =>
              aliceSessionStorage['$name:$deviceId'] = data,
          getIdentityKeyPair: () => aliceIdentity.serialize(),
          getLocalRegistrationId: () => 111,
        );

        // Create a DecryptionErrorMessage from the encrypted bytes
        final timestamp = BigInt.from(DateTime.now().millisecondsSinceEpoch);
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: encrypted.ciphertext.toList(),
          messageType: encrypted.messageType,
          timestamp: timestamp,
          originalSenderDeviceId: 1,
        );

        expect(errorMsg, isNotNull);
        expect(errorMsg.timestamp(), equals(timestamp));
        expect(errorMsg.deviceId(), equals(1));
      });
    });

    group('serialize() / deserialize() round-trip', () {
      test('preserves error message', () async {
        // Setup and encrypt
        final aliceIdentity = IdentityKeyPair.generate();
        final aliceSessionStorage = <String, Uint8List>{};
        final aliceIdentityStorage = <String, Uint8List>{};

        final bobKeys = generateRemotePartyKeys();
        final bobBundle = bobKeys.toBundle();

        await processPrekeyBundleWithCallbacks(
          remoteName: 'bob',
          remoteDeviceId: 1,
          bundle: bobBundle,
          loadSession: (name, deviceId) =>
              aliceSessionStorage['$name:$deviceId'],
          storeSession: (name, deviceId, data) =>
              aliceSessionStorage['$name:$deviceId'] = data,
          getIdentityKeyPair: () => aliceIdentity.serialize(),
          getLocalRegistrationId: () => 111,
          saveIdentity: (name, deviceId, key) =>
              aliceIdentityStorage['$name:$deviceId'] = key,
        );

        final encrypted = await messageEncryptWithCallbacks(
          remoteName: 'bob',
          remoteDeviceId: 1,
          localName: 'alice',
          localDeviceId: 1,
          plaintext: utf8.encode('Test message'),
          loadSession: (name, deviceId) =>
              aliceSessionStorage['$name:$deviceId'],
          storeSession: (name, deviceId, data) =>
              aliceSessionStorage['$name:$deviceId'] = data,
          getIdentityKeyPair: () => aliceIdentity.serialize(),
          getLocalRegistrationId: () => 111,
        );

        final timestamp = BigInt.from(DateTime.now().millisecondsSinceEpoch);
        final original = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: encrypted.ciphertext.toList(),
          messageType: encrypted.messageType,
          timestamp: timestamp,
          originalSenderDeviceId: 42,
        );

        // Serialize and deserialize
        final serialized = original.serialize();
        final restored = DecryptionErrorMessage.deserialize(
          bytes: serialized.toList(),
        );

        // Verify fields are preserved
        expect(restored.timestamp(), equals(original.timestamp()));
        expect(restored.deviceId(), equals(original.deviceId()));
        expect(restored.serialize(), equals(serialized));
      });
    });

    group('getters', () {
      test('timestamp returns correct value', () async {
        final aliceIdentity = IdentityKeyPair.generate();
        final aliceSessionStorage = <String, Uint8List>{};
        final aliceIdentityStorage = <String, Uint8List>{};

        final bobKeys = generateRemotePartyKeys();
        final bobBundle = bobKeys.toBundle();

        await processPrekeyBundleWithCallbacks(
          remoteName: 'bob',
          remoteDeviceId: 1,
          bundle: bobBundle,
          loadSession: (name, deviceId) =>
              aliceSessionStorage['$name:$deviceId'],
          storeSession: (name, deviceId, data) =>
              aliceSessionStorage['$name:$deviceId'] = data,
          getIdentityKeyPair: () => aliceIdentity.serialize(),
          getLocalRegistrationId: () => 111,
          saveIdentity: (name, deviceId, key) =>
              aliceIdentityStorage['$name:$deviceId'] = key,
        );

        final encrypted = await messageEncryptWithCallbacks(
          remoteName: 'bob',
          remoteDeviceId: 1,
          localName: 'alice',
          localDeviceId: 1,
          plaintext: utf8.encode('Test'),
          loadSession: (name, deviceId) =>
              aliceSessionStorage['$name:$deviceId'],
          storeSession: (name, deviceId, data) =>
              aliceSessionStorage['$name:$deviceId'] = data,
          getIdentityKeyPair: () => aliceIdentity.serialize(),
          getLocalRegistrationId: () => 111,
        );

        final timestamp = BigInt.from(1234567890000);
        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: encrypted.ciphertext.toList(),
          messageType: encrypted.messageType,
          timestamp: timestamp,
          originalSenderDeviceId: 1,
        );

        expect(errorMsg.timestamp(), equals(timestamp));
      });

      test('deviceId returns correct value', () async {
        final aliceIdentity = IdentityKeyPair.generate();
        final aliceSessionStorage = <String, Uint8List>{};
        final aliceIdentityStorage = <String, Uint8List>{};

        final bobKeys = generateRemotePartyKeys();
        final bobBundle = bobKeys.toBundle();

        await processPrekeyBundleWithCallbacks(
          remoteName: 'bob',
          remoteDeviceId: 1,
          bundle: bobBundle,
          loadSession: (name, deviceId) =>
              aliceSessionStorage['$name:$deviceId'],
          storeSession: (name, deviceId, data) =>
              aliceSessionStorage['$name:$deviceId'] = data,
          getIdentityKeyPair: () => aliceIdentity.serialize(),
          getLocalRegistrationId: () => 111,
          saveIdentity: (name, deviceId, key) =>
              aliceIdentityStorage['$name:$deviceId'] = key,
        );

        final encrypted = await messageEncryptWithCallbacks(
          remoteName: 'bob',
          remoteDeviceId: 1,
          localName: 'alice',
          localDeviceId: 1,
          plaintext: utf8.encode('Test'),
          loadSession: (name, deviceId) =>
              aliceSessionStorage['$name:$deviceId'],
          storeSession: (name, deviceId, data) =>
              aliceSessionStorage['$name:$deviceId'] = data,
          getIdentityKeyPair: () => aliceIdentity.serialize(),
          getLocalRegistrationId: () => 111,
        );

        final errorMsg = DecryptionErrorMessage.forOriginalMessage(
          originalBytes: encrypted.ciphertext.toList(),
          messageType: encrypted.messageType,
          timestamp: BigInt.from(0),
          originalSenderDeviceId: 99,
        );

        expect(errorMsg.deviceId(), equals(99));
      });
    });
  });
}
