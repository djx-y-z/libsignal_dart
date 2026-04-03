// ignore_for_file: avoid_redundant_argument_values, unnecessary_await_in_return
import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:libsignal/src/rust/api/sealed_sender.dart' as ss;
import 'package:test/test.dart';

import '../test_helpers/session_helpers.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('Sealed Sender', () {
    // Trust root key pair (simulates server's root key)
    late PrivateKey trustRootPrivateKey;
    late PublicKey trustRootPublicKey;

    // Server key pair (simulates server certificate key)
    late PrivateKey serverPrivateKey;
    late PublicKey serverPublicKey;

    // Server certificate
    late Uint8List serverCertificate;

    // Alice's stores and identity
    late InMemorySessionStore aliceSessionStore;
    late InMemoryIdentityKeyStore aliceIdentityStore;
    late InMemoryPreKeyStore alicePreKeyStore;
    late InMemorySignedPreKeyStore aliceSignedPreKeyStore;
    late InMemoryKyberPreKeyStore aliceKyberPreKeyStore;
    late IdentityKeyPair aliceIdentity;
    late ProtocolAddress aliceAddress;

    // Bob's stores and identity
    late InMemorySessionStore bobSessionStore;
    late InMemoryIdentityKeyStore bobIdentityStore;
    late InMemoryPreKeyStore bobPreKeyStore;
    late InMemorySignedPreKeyStore bobSignedPreKeyStore;
    late InMemoryKyberPreKeyStore bobKyberPreKeyStore;
    late ProtocolAddress bobAddress;
    late RemotePartyKeys bobKeys;

    // Pre-key IDs
    const preKeyId = 31337;
    const signedPreKeyId = 22;
    const kyberPreKeyId = 1;

    setUp(() async {
      // Create trust root and server keys
      trustRootPrivateKey = PrivateKey.generate();
      trustRootPublicKey = trustRootPrivateKey.getPublicKey();

      serverPrivateKey = PrivateKey.generate();
      serverPublicKey = serverPrivateKey.getPublicKey();

      // Create server certificate
      serverCertificate = createServerCertificate(
        keyId: 1,
        serverPublicKey: serverPublicKey.serialize(),
        trustRootPrivateKey: trustRootPrivateKey.serialize(),
      );

      // Setup Alice
      aliceIdentity = IdentityKeyPair.generate();
      aliceAddress = ProtocolAddress(name: 'alice-uuid', deviceId: 1);
      aliceSessionStore = InMemorySessionStore();
      aliceIdentityStore = InMemoryIdentityKeyStore(aliceIdentity, 11111);
      alicePreKeyStore = InMemoryPreKeyStore();
      aliceSignedPreKeyStore = InMemorySignedPreKeyStore();
      aliceKyberPreKeyStore = InMemoryKyberPreKeyStore();

      // Setup Bob
      bobAddress = ProtocolAddress(name: 'bob-uuid', deviceId: 1);
      bobKeys = generateRemotePartyKeys(
        registrationId: 22222,
        deviceId: 1,
        preKeyId: preKeyId,
        signedPreKeyId: signedPreKeyId,
        kyberPreKeyId: kyberPreKeyId,
      );
      bobSessionStore = InMemorySessionStore();
      bobIdentityStore = InMemoryIdentityKeyStore(
        bobKeys.identityKeyPair,
        22222,
      );
      bobPreKeyStore = InMemoryPreKeyStore();
      bobSignedPreKeyStore = InMemorySignedPreKeyStore();
      bobKyberPreKeyStore = InMemoryKyberPreKeyStore();

      // Store Bob's pre-keys
      final bobPreKey = PreKeyRecord(
        id: preKeyId,
        publicKey: bobKeys.preKeyPublic,
        privateKey: bobKeys.preKeyPrivate,
      );
      await bobPreKeyStore.storePreKey(preKeyId, bobPreKey);

      final bobSignedPreKey = SignedPreKeyRecord(
        id: signedPreKeyId,
        timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
        publicKey: bobKeys.signedPreKeyPublic,
        privateKey: bobKeys.signedPreKeyPrivate,
        signature: bobKeys.signedPreKeySignature,
      );
      await bobSignedPreKeyStore.storeSignedPreKey(
        signedPreKeyId,
        bobSignedPreKey,
      );

      final bobKyberPreKey = KyberPreKeyRecord.create(
        id: kyberPreKeyId,
        timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
        keyPair: bobKeys.kyberKeyPair,
        signature: bobKeys.kyberPreKeySignature,
      );
      await bobKyberPreKeyStore.storeKyberPreKey(kyberPreKeyId, bobKyberPreKey);

      // Create Bob's pre-key bundle
      final bobBundle = bobKeys.toBundle();

      // Alice establishes session with Bob
      final aliceBuilder = SessionBuilder(
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );
      await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);
    });

    group('SealedSenderCipher', () {
      test('encrypts and decrypts message using SealedSenderCipher', () async {
        // Create valid sender certificate for Alice
        final expiration = DateTime.now()
            .add(const Duration(hours: 1))
            .millisecondsSinceEpoch;
        final aliceSenderCertificate = createSenderCertificate(
          senderUuid: aliceAddress.name(),
          senderDeviceId: aliceAddress.deviceId(),
          senderIdentityKey: aliceIdentity.publicKey,
          expiration: BigInt.from(expiration),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivateKey.serialize(),
        );

        // Create cipher for Alice
        final aliceCipher = SealedSenderCipher(
          localAddress: aliceAddress,
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
          preKeyStore: alicePreKeyStore,
          signedPreKeyStore: aliceSignedPreKeyStore,
          kyberPreKeyStore: aliceKyberPreKeyStore,
        );

        // Alice encrypts message to Bob
        const message = 'Hello Bob, this is a sealed sender message!';
        final ciphertext = await aliceCipher.encrypt(
          recipientAddress: bobAddress,
          plaintext: Uint8List.fromList(utf8.encode(message)),
          senderCertificate: aliceSenderCertificate,
        );

        expect(ciphertext, isNotEmpty);
        expect(ciphertext.length, greaterThan(message.length));

        // Create cipher for Bob
        final bobCipher = SealedSenderCipher(
          localAddress: bobAddress,
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
          preKeyStore: bobPreKeyStore,
          signedPreKeyStore: bobSignedPreKeyStore,
          kyberPreKeyStore: bobKyberPreKeyStore,
        );

        // Bob decrypts using SealedSenderCipher.decrypt()
        final result = await bobCipher.decrypt(
          ciphertext: ciphertext,
          trustRoot: trustRootPublicKey.serialize(),
          timestamp: DateTime.now().millisecondsSinceEpoch,
        );

        // Verify decrypted content
        expect(utf8.decode(result.plaintext), equals(message));
        expect(result.senderAddress.name(), equals(aliceAddress.name()));
        expect(
          result.senderAddress.deviceId(),
          equals(aliceAddress.deviceId()),
        );
        // Compare serialized bytes since aliceIdentity.publicKey returns Uint8List
        final expectedKey = PublicKey.deserialize(
          bytes: aliceIdentity.publicKey.toList(),
        );
        expect(result.senderIdentityKey.equals(other: expectedKey), isTrue);

        // Verify pre-key was removed after first message (session establishment)
        expect(await bobPreKeyStore.loadPreKey(preKeyId), isNull);
      });

      test('encrypts and decrypts using raw callbacks', () async {
        // Create valid sender certificate for Alice
        final expiration = DateTime.now()
            .add(const Duration(hours: 1))
            .millisecondsSinceEpoch;
        final aliceSenderCertificate = createSenderCertificate(
          senderUuid: aliceAddress.name(),
          senderDeviceId: aliceAddress.deviceId(),
          senderIdentityKey: aliceIdentity.publicKey,
          expiration: BigInt.from(expiration),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivateKey.serialize(),
        );

        // Create cipher for Alice
        final aliceCipher = SealedSenderCipher(
          localAddress: aliceAddress,
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
          preKeyStore: alicePreKeyStore,
          signedPreKeyStore: aliceSignedPreKeyStore,
          kyberPreKeyStore: aliceKyberPreKeyStore,
        );

        // Alice encrypts message to Bob
        const message = 'Hello Bob, this is a sealed sender message!';
        final ciphertext = await aliceCipher.encrypt(
          recipientAddress: bobAddress,
          plaintext: Uint8List.fromList(utf8.encode(message)),
          senderCertificate: aliceSenderCertificate,
        );

        expect(ciphertext, isNotEmpty);
        expect(ciphertext.length, greaterThan(message.length));

        // Bob decrypts using sealed sender with callbacks
        final rawResult = await ss.sealedSenderDecryptWithCallbacks(
          ciphertext: ciphertext.toList(),
          trustRoot: trustRootPublicKey.serialize().toList(),
          timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
          localName: bobAddress.name(),
          localDeviceId: bobAddress.deviceId(),
          loadSession: (name, deviceId) async {
            final addr = ProtocolAddress(name: name, deviceId: deviceId);
            final session = await bobSessionStore.loadSession(addr);
            return session?.serialize();
          },
          storeSession: (name, deviceId, bytes) async {
            final addr = ProtocolAddress(name: name, deviceId: deviceId);
            final record = SessionRecord.deserialize(bytes: bytes);
            await bobSessionStore.storeSession(addr, record);
          },
          getIdentityKeyPair: () async {
            final pair = await bobIdentityStore.getIdentityKeyPair();
            return pair.serialize();
          },
          getLocalRegistrationId: () async {
            return await bobIdentityStore.getLocalRegistrationId();
          },
          saveIdentity: (name, deviceId, identityBytes) async {
            final addr = ProtocolAddress(name: name, deviceId: deviceId);
            final identityKey = PublicKey.deserialize(bytes: identityBytes);
            await bobIdentityStore.saveIdentity(addr, identityKey);
          },
          loadSignedPreKey: (id) async {
            final preKey = await bobSignedPreKeyStore.loadSignedPreKey(id);
            if (preKey == null) {
              throw StateError('Signed pre-key $id not found');
            }
            return preKey.serialize();
          },
          loadPreKey: (id) async {
            final preKey = await bobPreKeyStore.loadPreKey(id);
            return preKey?.serialize();
          },
          loadKyberPreKey: (id) async {
            final preKey = await bobKyberPreKeyStore.loadKyberPreKey(id);
            return preKey?.serialize();
          },
        );

        // Verify decrypted content
        expect(utf8.decode(rawResult.plaintext), equals(message));
        expect(rawResult.senderName, equals(aliceAddress.name()));
        expect(rawResult.senderDeviceId, equals(aliceAddress.deviceId()));
      });

      test('decryption reveals sender information', () async {
        // Create valid sender certificate for Alice
        final expiration = DateTime.now()
            .add(const Duration(hours: 1))
            .millisecondsSinceEpoch;
        final aliceSenderCertificate = createSenderCertificate(
          senderUuid: aliceAddress.name(),
          senderDeviceId: aliceAddress.deviceId(),
          senderIdentityKey: aliceIdentity.publicKey,
          expiration: BigInt.from(expiration),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivateKey.serialize(),
        );

        // Create cipher for Alice
        final aliceCipher = SealedSenderCipher(
          localAddress: aliceAddress,
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
          preKeyStore: alicePreKeyStore,
          signedPreKeyStore: aliceSignedPreKeyStore,
          kyberPreKeyStore: aliceKyberPreKeyStore,
        );

        // Alice encrypts message to Bob
        final ciphertext = await aliceCipher.encrypt(
          recipientAddress: bobAddress,
          plaintext: Uint8List.fromList(utf8.encode('Secret message')),
          senderCertificate: aliceSenderCertificate,
        );

        // Bob decrypts and verifies sender info
        final rawResult = await ss.sealedSenderDecryptWithCallbacks(
          ciphertext: ciphertext.toList(),
          trustRoot: trustRootPublicKey.serialize().toList(),
          timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
          localName: bobAddress.name(),
          localDeviceId: bobAddress.deviceId(),
          loadSession: (name, deviceId) async {
            final addr = ProtocolAddress(name: name, deviceId: deviceId);
            final session = await bobSessionStore.loadSession(addr);
            return session?.serialize();
          },
          storeSession: (name, deviceId, bytes) async {
            final addr = ProtocolAddress(name: name, deviceId: deviceId);
            final record = SessionRecord.deserialize(bytes: bytes);
            await bobSessionStore.storeSession(addr, record);
          },
          getIdentityKeyPair: () async {
            final pair = await bobIdentityStore.getIdentityKeyPair();
            return pair.serialize();
          },
          getLocalRegistrationId: () async {
            return await bobIdentityStore.getLocalRegistrationId();
          },
          saveIdentity: (name, deviceId, identityBytes) async {
            final addr = ProtocolAddress(name: name, deviceId: deviceId);
            final identityKey = PublicKey.deserialize(bytes: identityBytes);
            await bobIdentityStore.saveIdentity(addr, identityKey);
          },
          loadSignedPreKey: (id) async {
            final preKey = await bobSignedPreKeyStore.loadSignedPreKey(id);
            if (preKey == null) {
              throw StateError('Signed pre-key $id not found');
            }
            return preKey.serialize();
          },
          loadPreKey: (id) async {
            final preKey = await bobPreKeyStore.loadPreKey(id);
            return preKey?.serialize();
          },
          loadKyberPreKey: (id) async {
            final preKey = await bobKyberPreKeyStore.loadKyberPreKey(id);
            return preKey?.serialize();
          },
        );

        // Verify sender information is revealed after decryption
        expect(rawResult.senderName, equals(aliceAddress.name()));
        expect(rawResult.senderDeviceId, equals(aliceAddress.deviceId()));
        expect(rawResult.senderIdentityKey.length, equals(33));
      });

      test('fails with expired certificate', () async {
        // Create expired certificate (1 hour in the past)
        final expiration = DateTime.now()
            .subtract(const Duration(hours: 1))
            .millisecondsSinceEpoch;
        final expiredCertificate = createSenderCertificate(
          senderUuid: aliceAddress.name(),
          senderDeviceId: aliceAddress.deviceId(),
          senderIdentityKey: aliceIdentity.publicKey,
          expiration: BigInt.from(expiration),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivateKey.serialize(),
        );

        final aliceCipher = SealedSenderCipher(
          localAddress: aliceAddress,
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
          preKeyStore: alicePreKeyStore,
          signedPreKeyStore: aliceSignedPreKeyStore,
          kyberPreKeyStore: aliceKyberPreKeyStore,
        );

        final ciphertext = await aliceCipher.encrypt(
          recipientAddress: bobAddress,
          plaintext: Uint8List.fromList(utf8.encode('Test')),
          senderCertificate: expiredCertificate,
        );

        final bobCipher = SealedSenderCipher(
          localAddress: bobAddress,
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
          preKeyStore: bobPreKeyStore,
          signedPreKeyStore: bobSignedPreKeyStore,
          kyberPreKeyStore: bobKyberPreKeyStore,
        );

        expect(
          () => bobCipher.decrypt(
            ciphertext: ciphertext,
            trustRoot: trustRootPublicKey.serialize(),
            timestamp: DateTime.now().millisecondsSinceEpoch,
          ),
          throwsA(anything),
        );
      });

      test('fails with wrong trust root', () async {
        final expiration = DateTime.now()
            .add(const Duration(hours: 1))
            .millisecondsSinceEpoch;
        final aliceSenderCertificate = createSenderCertificate(
          senderUuid: aliceAddress.name(),
          senderDeviceId: aliceAddress.deviceId(),
          senderIdentityKey: aliceIdentity.publicKey,
          expiration: BigInt.from(expiration),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivateKey.serialize(),
        );

        final aliceCipher = SealedSenderCipher(
          localAddress: aliceAddress,
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
          preKeyStore: alicePreKeyStore,
          signedPreKeyStore: aliceSignedPreKeyStore,
          kyberPreKeyStore: aliceKyberPreKeyStore,
        );

        final ciphertext = await aliceCipher.encrypt(
          recipientAddress: bobAddress,
          plaintext: Uint8List.fromList(utf8.encode('Test')),
          senderCertificate: aliceSenderCertificate,
        );

        // Use wrong trust root
        final wrongTrustRoot = PrivateKey.generate().getPublicKey();

        final bobCipher = SealedSenderCipher(
          localAddress: bobAddress,
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
          preKeyStore: bobPreKeyStore,
          signedPreKeyStore: bobSignedPreKeyStore,
          kyberPreKeyStore: bobKyberPreKeyStore,
        );

        expect(
          () => bobCipher.decrypt(
            ciphertext: ciphertext,
            trustRoot: wrongTrustRoot.serialize(),
            timestamp: DateTime.now().millisecondsSinceEpoch,
          ),
          throwsA(anything),
        );
      });

      test('fails with garbage ciphertext', () async {
        final bobCipher = SealedSenderCipher(
          localAddress: bobAddress,
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
          preKeyStore: bobPreKeyStore,
          signedPreKeyStore: bobSignedPreKeyStore,
          kyberPreKeyStore: bobKyberPreKeyStore,
        );

        expect(
          () => bobCipher.decrypt(
            ciphertext: Uint8List.fromList([0x12, 0x34, 0x56, 0x78]),
            trustRoot: trustRootPublicKey.serialize(),
            timestamp: DateTime.now().millisecondsSinceEpoch,
          ),
          throwsA(anything),
        );
      });
    });

    group('Certificate functions', () {
      test('validateSenderCertificate returns true for valid certificate', () {
        final expiration = DateTime.now()
            .add(const Duration(hours: 1))
            .millisecondsSinceEpoch;
        final cert = createSenderCertificate(
          senderUuid: 'test-uuid',
          senderDeviceId: 1,
          senderIdentityKey: aliceIdentity.publicKey,
          expiration: BigInt.from(expiration),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivateKey.serialize(),
        );

        final isValid = validateSenderCertificate(
          certificate: cert,
          trustRoot: trustRootPublicKey.serialize(),
          timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
        );

        expect(isValid, isTrue);
      });

      test('validateSenderCertificate throws for expired certificate', () {
        final expiration = DateTime.now()
            .subtract(const Duration(hours: 1))
            .millisecondsSinceEpoch;
        final cert = createSenderCertificate(
          senderUuid: 'test-uuid',
          senderDeviceId: 1,
          senderIdentityKey: aliceIdentity.publicKey,
          expiration: BigInt.from(expiration),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivateKey.serialize(),
        );

        expect(
          () => validateSenderCertificate(
            certificate: cert,
            trustRoot: trustRootPublicKey.serialize(),
            timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
          ),
          throwsA(anything),
        );
      });

      test('senderCertificateGetSenderName returns correct name', () {
        final cert = createSenderCertificate(
          senderUuid: 'my-uuid-123',
          senderDeviceId: 1,
          senderIdentityKey: aliceIdentity.publicKey,
          expiration: BigInt.from(
            DateTime.now().add(const Duration(hours: 1)).millisecondsSinceEpoch,
          ),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivateKey.serialize(),
        );

        final name = senderCertificateGetSenderName(certificate: cert);
        expect(name, equals('my-uuid-123'));
      });

      test('senderCertificateGetSenderDeviceId returns correct device ID', () {
        final cert = createSenderCertificate(
          senderUuid: 'test-uuid',
          senderDeviceId: 42,
          senderIdentityKey: aliceIdentity.publicKey,
          expiration: BigInt.from(
            DateTime.now().add(const Duration(hours: 1)).millisecondsSinceEpoch,
          ),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivateKey.serialize(),
        );

        final deviceId = senderCertificateGetSenderDeviceId(certificate: cert);
        expect(deviceId, equals(42));
      });

      test('senderCertificateGetExpiration returns correct expiration', () {
        final expiration = DateTime.now()
            .add(const Duration(hours: 1))
            .millisecondsSinceEpoch;
        final cert = createSenderCertificate(
          senderUuid: 'test-uuid',
          senderDeviceId: 1,
          senderIdentityKey: aliceIdentity.publicKey,
          expiration: BigInt.from(expiration),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivateKey.serialize(),
        );

        final gotExpiration = senderCertificateGetExpiration(certificate: cert);
        expect(gotExpiration.toInt(), equals(expiration));
      });

      test('senderCertificateGetKey returns correct identity key', () {
        final cert = createSenderCertificate(
          senderUuid: 'test-uuid',
          senderDeviceId: 1,
          senderIdentityKey: aliceIdentity.publicKey,
          expiration: BigInt.from(
            DateTime.now().add(const Duration(hours: 1)).millisecondsSinceEpoch,
          ),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivateKey.serialize(),
        );

        final key = senderCertificateGetKey(certificate: cert);
        expect(key, equals(aliceIdentity.publicKey));
      });
    });

    group('result class equality', () {
      test('SealedSenderDecryptResult equality', () {
        final plaintext = Uint8List.fromList([1, 2, 3]);
        final identityKey = Uint8List.fromList([4, 5, 6]);
        final sessionRecord = Uint8List.fromList([7, 8, 9]);

        final result1 = ss.SealedSenderDecryptResult(
          plaintext: plaintext,
          senderName: 'alice',
          senderDeviceId: 1,
          senderIdentityKey: identityKey,
          sessionRecord: sessionRecord,
          preKeyToRemove: 42,
        );
        final result2 = ss.SealedSenderDecryptResult(
          plaintext: plaintext,
          senderName: 'alice',
          senderDeviceId: 1,
          senderIdentityKey: identityKey,
          sessionRecord: sessionRecord,
          preKeyToRemove: 42,
        );

        expect(result1, equals(result2));
        expect(result1.hashCode, equals(result2.hashCode));

        // Test inequality with different sender name
        final result3 = ss.SealedSenderDecryptResult(
          plaintext: plaintext,
          senderName: 'bob',
          senderDeviceId: 1,
          senderIdentityKey: identityKey,
          sessionRecord: sessionRecord,
          preKeyToRemove: 42,
        );
        expect(result1, isNot(equals(result3)));

        // Test self-equality
        expect(result1, equals(result1));

        // Test with null preKeyToRemove
        final result4 = ss.SealedSenderDecryptResult(
          plaintext: plaintext,
          senderName: 'alice',
          senderDeviceId: 1,
          senderIdentityKey: identityKey,
          sessionRecord: sessionRecord,
        );
        expect(result4.preKeyToRemove, isNull);
        expect(result4.hashCode, isA<int>());
      });

      test('SealedSenderEncryptResult equality', () {
        final ciphertext = Uint8List.fromList([1, 2, 3]);
        final sessionRecord = Uint8List.fromList([4, 5, 6]);

        final result1 = ss.SealedSenderEncryptResult(
          ciphertext: ciphertext,
          sessionRecord: sessionRecord,
        );
        final result2 = ss.SealedSenderEncryptResult(
          ciphertext: ciphertext,
          sessionRecord: sessionRecord,
        );

        expect(result1, equals(result2));
        expect(result1.hashCode, equals(result2.hashCode));

        // Test inequality with different ciphertext
        final result3 = ss.SealedSenderEncryptResult(
          ciphertext: Uint8List.fromList([7, 8, 9]),
          sessionRecord: sessionRecord,
        );
        expect(result1, isNot(equals(result3)));

        // Test self-equality
        expect(result1, equals(result1));
      });

      test('equality returns false for wrong types', () {
        final result1 = ss.SealedSenderDecryptResult(
          plaintext: Uint8List.fromList([1, 2, 3]),
          senderName: 'alice',
          senderDeviceId: 1,
          senderIdentityKey: Uint8List.fromList([4, 5, 6]),
          sessionRecord: Uint8List.fromList([7, 8, 9]),
        );
        // ignore: unrelated_type_equality_checks
        expect(result1 == 'not a result', isFalse);
        // ignore: unrelated_type_equality_checks
        expect(result1 == 42, isFalse);

        final result2 = ss.SealedSenderEncryptResult(
          ciphertext: Uint8List.fromList([1, 2, 3]),
          sessionRecord: Uint8List.fromList([4, 5, 6]),
        );
        // ignore: unrelated_type_equality_checks
        expect(result2 == 'not a result', isFalse);
        // ignore: unrelated_type_equality_checks
        expect(result2 == 42, isFalse);
      });
    });
  });
}
