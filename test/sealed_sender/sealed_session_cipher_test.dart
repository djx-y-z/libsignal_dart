import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/session_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('SealedSessionCipher', () {
    late InMemorySessionStore aliceSessionStore;
    late InMemoryIdentityKeyStore aliceIdentityStore;
    late InMemoryPreKeyStore alicePreKeyStore;
    late InMemorySignedPreKeyStore aliceSignedPreKeyStore;
    late InMemoryKyberPreKeyStore aliceKyberPreKeyStore;

    late InMemorySessionStore bobSessionStore;
    late InMemoryPreKeyStore bobPreKeyStore;
    late InMemorySignedPreKeyStore bobSignedPreKeyStore;
    late InMemoryKyberPreKeyStore bobKyberPreKeyStore;

    late IdentityKeyPair aliceIdentity;
    late ProtocolAddress aliceAddress;
    late ProtocolAddress bobAddress;

    late PrivateKey trustRootPrivate;
    late PublicKey trustRootPublic;
    late PrivateKey serverPrivate;
    late ServerCertificate serverCert;

    setUp(() {
      // Generate identity keys
      aliceIdentity = IdentityKeyPair.generate();

      // Create addresses
      aliceAddress = ProtocolAddress('alice', 1);
      bobAddress = ProtocolAddress('bob', 1);

      // Create stores for Alice
      aliceSessionStore = InMemorySessionStore();
      aliceIdentityStore = InMemoryIdentityKeyStore(aliceIdentity, 12345);
      alicePreKeyStore = InMemoryPreKeyStore();
      aliceSignedPreKeyStore = InMemorySignedPreKeyStore();
      aliceKyberPreKeyStore = InMemoryKyberPreKeyStore();

      // Create stores for Bob (will be populated per test)
      bobSessionStore = InMemorySessionStore();
      bobPreKeyStore = InMemoryPreKeyStore();
      bobSignedPreKeyStore = InMemorySignedPreKeyStore();
      bobKyberPreKeyStore = InMemoryKyberPreKeyStore();

      // Create trust root and server certificate
      trustRootPrivate = PrivateKey.generate();
      trustRootPublic = trustRootPrivate.getPublicKey();

      serverPrivate = PrivateKey.generate();
      final serverKey = serverPrivate.getPublicKey();

      serverCert = ServerCertificate.create(
        keyId: 1,
        serverKey: serverKey,
        trustRoot: trustRootPrivate,
      );

      serverKey.dispose();
    });

    tearDown(() {
      aliceIdentity.dispose();
      aliceAddress.dispose();
      bobAddress.dispose();
      trustRootPrivate.dispose();
      trustRootPublic.dispose();
      serverPrivate.dispose();
      serverCert.dispose();

      // Clear stores
      aliceSessionStore.clear();
      bobSessionStore.clear();
      alicePreKeyStore.clear();
      bobPreKeyStore.clear();
      aliceSignedPreKeyStore.clear();
      bobSignedPreKeyStore.clear();
      aliceKyberPreKeyStore.clear();
      bobKyberPreKeyStore.clear();
    });

    group('constructor', () {
      test('creates cipher with all stores', () {
        final cipher = SealedSessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        expect(cipher, isNotNull);
      });

      test('creates cipher with required stores only', () {
        final cipher = SealedSessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        expect(cipher, isNotNull);
      });
    });

    group('encrypt()', () {
      test('throws when no session exists', () async {
        final cipher = SealedSessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        // Create sender certificate
        final serverPrivate = PrivateKey.generate();
        final senderCert = SenderCertificate.create(
          senderUuid: 'alice-uuid',
          deviceId: 1,
          senderKey: aliceIdentity.publicKey,
          expiration: DateTime.now().toUtc().add(const Duration(days: 30)),
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        final plaintext = Uint8List.fromList(utf8.encode('Hello!'));

        await expectLater(
          () => cipher.encrypt(bobAddress, plaintext, senderCert),
          throwsA(isA<LibSignalException>()),
        );

        serverPrivate.dispose();
        senderCert.dispose();
      });

      test('encrypts message when session exists', () async {
        // Generate Bob's keys and establish session
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);

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

        // Create sender certificate for Alice
        final serverPrivate = PrivateKey.generate();
        final senderCert = SenderCertificate.create(
          senderUuid: 'alice-uuid',
          deviceId: 1,
          senderKey: aliceIdentity.publicKey,
          expiration: DateTime.now().toUtc().add(const Duration(days: 30)),
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        // Create sealed session cipher
        final cipher = SealedSessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        // Encrypt
        final plaintext = Uint8List.fromList(utf8.encode('Hello, Bob!'));
        final sealed = await cipher.encrypt(bobAddress, plaintext, senderCert);

        expect(sealed, isNotEmpty);
        // Sealed sender messages are larger than regular encrypted messages
        expect(sealed.length, greaterThan(plaintext.length));

        // Cleanup
        preKeyRecord.dispose();
        signedPreKeyRecord.dispose();
        kyberPreKeyRecord.dispose();
        bobBundle.dispose();
        serverPrivate.dispose();
        senderCert.dispose();
        bobKeys.dispose();
      });

      test('encrypts message with group ID', () async {
        // Generate Bob's keys and establish session
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);

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

        // Create sender certificate
        final serverPrivate = PrivateKey.generate();
        final senderCert = SenderCertificate.create(
          senderUuid: 'alice-uuid',
          deviceId: 1,
          senderKey: aliceIdentity.publicKey,
          expiration: DateTime.now().toUtc().add(const Duration(days: 30)),
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        final cipher = SealedSessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        // Encrypt with group ID
        final groupId = Uint8List.fromList(utf8.encode('group-123'));
        final plaintext = Uint8List.fromList(utf8.encode('Hello group!'));
        final sealed = await cipher.encrypt(
          bobAddress,
          plaintext,
          senderCert,
          groupId: groupId,
        );

        expect(sealed, isNotEmpty);

        // Cleanup
        preKeyRecord.dispose();
        signedPreKeyRecord.dispose();
        kyberPreKeyRecord.dispose();
        bobBundle.dispose();
        serverPrivate.dispose();
        senderCert.dispose();
        bobKeys.dispose();
      });

      test('encrypts message with different content hints', () async {
        // Generate Bob's keys and establish session
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);

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

        // Create sender certificate
        final serverPrivate = PrivateKey.generate();
        final senderCert = SenderCertificate.create(
          senderUuid: 'alice-uuid',
          deviceId: 1,
          senderKey: aliceIdentity.publicKey,
          expiration: DateTime.now().toUtc().add(const Duration(days: 30)),
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        final cipher = SealedSessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        final plaintext = Uint8List.fromList(utf8.encode('Test message'));

        // Test with different content hints
        for (final hint in [
          ContentHint.none,
          ContentHint.resendable,
          ContentHint.implicit,
        ]) {
          final sealed = await cipher.encrypt(
            bobAddress,
            plaintext,
            senderCert,
            contentHint: hint,
          );

          expect(sealed, isNotEmpty);
        }

        // Cleanup
        preKeyRecord.dispose();
        signedPreKeyRecord.dispose();
        kyberPreKeyRecord.dispose();
        bobBundle.dispose();
        serverPrivate.dispose();
        senderCert.dispose();
        bobKeys.dispose();
      });
    });


    // Round-trip tests use a two-step decryption approach because
    // libsignal C FFI (v0.67.3) doesn't pass Kyber pre-key store to
    // signal_sealed_session_cipher_decrypt. We use:
    // 1. decryptToUsmc() to unwrap sealed sender layer
    // 2. SessionCipher.decryptPreKeySignalMessage() to decrypt the inner message
    group('round-trip encrypt/decrypt', () {
      test('encrypts and decrypts message successfully', () async {
        // Setup Bob's keys and stores (with Kyber)
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        final bobIdentityStore =
            InMemoryIdentityKeyStore(bobKeys.identityKeyPair, 67890);

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

        // Create sender certificate for Alice
        final senderCert = SenderCertificate.create(
          senderUuid: 'alice-uuid',
          senderE164: '+1234567890',
          deviceId: 1,
          senderKey: aliceIdentity.publicKey,
          expiration: DateTime.now().toUtc().add(const Duration(days: 30)),
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        // Alice encrypts with sealed sender
        final aliceCipher = SealedSessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        final plaintext = Uint8List.fromList(utf8.encode('Hello, Bob!'));
        final sealed =
            await aliceCipher.encrypt(bobAddress, plaintext, senderCert);

        // Bob decrypts using two-step approach:
        // 1. Unwrap sealed sender to get USMC
        final bobCipher = SealedSessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
        );
        final usmc = await bobCipher.decryptToUsmc(sealed);

        // Verify the sender certificate (trust root validation)
        final usmcSenderCert = usmc.getSenderCertificate();
        expect(
          usmcSenderCert.validate(trustRootPublic, now: DateTime.now().toUtc()),
          isTrue,
        );

        // 2. Decrypt the inner message using SessionCipher
        final encryptedContent = usmc.contents;
        final senderAddress =
            ProtocolAddress(usmcSenderCert.senderUuid, usmcSenderCert.deviceId);

        final bobSessionCipher = SessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
          preKeyStore: bobPreKeyStore,
          signedPreKeyStore: bobSignedPreKeyStore,
          kyberPreKeyStore: bobKyberPreKeyStore,
        );

        final decryptedPlaintext = await bobSessionCipher
            .decryptPreKeySignalMessage(senderAddress, encryptedContent);

        // Verify plaintext
        expect(decryptedPlaintext, equals(plaintext));

        // Cleanup
        preKeyRecord.dispose();
        signedPreKeyRecord.dispose();
        kyberPreKeyRecord.dispose();
        bobBundle.dispose();
        senderCert.dispose();
        usmc.dispose();
        usmcSenderCert.dispose();
        senderAddress.dispose();
        bobKeys.dispose();
      });

      test('decrypted message contains correct sender info', () async {
        // Setup Bob's keys and stores (with Kyber)
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        final bobIdentityStore =
            InMemoryIdentityKeyStore(bobKeys.identityKeyPair, 67890);

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

        // Create sender certificate for Alice
        final senderCert = SenderCertificate.create(
          senderUuid: 'alice-uuid',
          senderE164: '+1234567890',
          deviceId: 1,
          senderKey: aliceIdentity.publicKey,
          expiration: DateTime.now().toUtc().add(const Duration(days: 30)),
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        // Alice encrypts with sealed sender
        final aliceCipher = SealedSessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        final plaintext = Uint8List.fromList(utf8.encode('Hello, Bob!'));
        final sealed =
            await aliceCipher.encrypt(bobAddress, plaintext, senderCert);

        // Bob decrypts using two-step approach
        final bobCipher = SealedSessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
        );
        final usmc = await bobCipher.decryptToUsmc(sealed);

        // Get sender info from USMC's sender certificate
        final usmcSenderCert = usmc.getSenderCertificate();

        // Verify sender info
        expect(usmcSenderCert.senderUuid, equals('alice-uuid'));
        expect(usmcSenderCert.deviceId, equals(1));
        expect(usmcSenderCert.senderE164, equals('+1234567890'));

        // Cleanup
        preKeyRecord.dispose();
        signedPreKeyRecord.dispose();
        kyberPreKeyRecord.dispose();
        bobBundle.dispose();
        senderCert.dispose();
        usmc.dispose();
        usmcSenderCert.dispose();
        bobKeys.dispose();
      });

      test('works without senderE164', () async {
        // Setup Bob's keys and stores (with Kyber)
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        final bobIdentityStore =
            InMemoryIdentityKeyStore(bobKeys.identityKeyPair, 67890);

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

        // Create sender certificate WITHOUT e164
        final senderCert = SenderCertificate.create(
          senderUuid: 'alice-uuid',
          senderE164: null,
          deviceId: 1,
          senderKey: aliceIdentity.publicKey,
          expiration: DateTime.now().toUtc().add(const Duration(days: 30)),
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        // Alice encrypts
        final aliceCipher = SealedSessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        final plaintext = Uint8List.fromList(utf8.encode('Hello, Bob!'));
        final sealed =
            await aliceCipher.encrypt(bobAddress, plaintext, senderCert);

        // Bob decrypts using two-step approach
        final bobCipher = SealedSessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
        );
        final usmc = await bobCipher.decryptToUsmc(sealed);
        final usmcSenderCert = usmc.getSenderCertificate();

        // Verify e164 is null but other sender info is correct
        expect(usmcSenderCert.senderE164, isNull);
        expect(usmcSenderCert.senderUuid, equals('alice-uuid'));

        // Decrypt the inner message
        final senderAddress =
            ProtocolAddress(usmcSenderCert.senderUuid, usmcSenderCert.deviceId);
        final bobSessionCipher = SessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
          preKeyStore: bobPreKeyStore,
          signedPreKeyStore: bobSignedPreKeyStore,
          kyberPreKeyStore: bobKyberPreKeyStore,
        );
        final decryptedPlaintext = await bobSessionCipher
            .decryptPreKeySignalMessage(senderAddress, usmc.contents);
        expect(decryptedPlaintext, equals(plaintext));

        // Cleanup
        preKeyRecord.dispose();
        signedPreKeyRecord.dispose();
        kyberPreKeyRecord.dispose();
        bobBundle.dispose();
        senderCert.dispose();
        usmc.dispose();
        usmcSenderCert.dispose();
        senderAddress.dispose();
        bobKeys.dispose();
      });

      test('works with group ID', () async {
        // Setup Bob's keys and stores (with Kyber)
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        final bobIdentityStore =
            InMemoryIdentityKeyStore(bobKeys.identityKeyPair, 67890);

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

        // Create sender certificate
        final senderCert = SenderCertificate.create(
          senderUuid: 'alice-uuid',
          senderE164: '+1234567890',
          deviceId: 1,
          senderKey: aliceIdentity.publicKey,
          expiration: DateTime.now().toUtc().add(const Duration(days: 30)),
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        // Alice encrypts with group ID
        final aliceCipher = SealedSessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        final groupId = Uint8List.fromList(utf8.encode('group-123'));
        final plaintext = Uint8List.fromList(utf8.encode('Hello group!'));
        final sealed = await aliceCipher.encrypt(
          bobAddress,
          plaintext,
          senderCert,
          groupId: groupId,
        );

        // Bob decrypts using two-step approach
        final bobCipher = SealedSessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
        );
        final usmc = await bobCipher.decryptToUsmc(sealed);

        // Verify group ID is present
        expect(usmc.groupId, equals(groupId));

        // Decrypt the inner message
        final usmcSenderCert = usmc.getSenderCertificate();
        final senderAddress =
            ProtocolAddress(usmcSenderCert.senderUuid, usmcSenderCert.deviceId);
        final bobSessionCipher = SessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
          preKeyStore: bobPreKeyStore,
          signedPreKeyStore: bobSignedPreKeyStore,
          kyberPreKeyStore: bobKyberPreKeyStore,
        );
        final decryptedPlaintext = await bobSessionCipher
            .decryptPreKeySignalMessage(senderAddress, usmc.contents);

        // Verify plaintext
        expect(decryptedPlaintext, equals(plaintext));

        // Cleanup
        preKeyRecord.dispose();
        signedPreKeyRecord.dispose();
        kyberPreKeyRecord.dispose();
        bobBundle.dispose();
        senderCert.dispose();
        usmc.dispose();
        usmcSenderCert.dispose();
        senderAddress.dispose();
        bobKeys.dispose();
      });

      test('fails with wrong trust root', () async {
        // Setup Bob's keys and stores (with Kyber)
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        final bobIdentityStore =
            InMemoryIdentityKeyStore(bobKeys.identityKeyPair, 67890);

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

        // Create sender certificate
        final senderCert = SenderCertificate.create(
          senderUuid: 'alice-uuid',
          senderE164: '+1234567890',
          deviceId: 1,
          senderKey: aliceIdentity.publicKey,
          expiration: DateTime.now().toUtc().add(const Duration(days: 30)),
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        // Alice encrypts
        final aliceCipher = SealedSessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        final plaintext = Uint8List.fromList(utf8.encode('Hello, Bob!'));
        final sealed =
            await aliceCipher.encrypt(bobAddress, plaintext, senderCert);

        // Bob decrypts to USMC and validates with WRONG trust root
        final wrongTrustRootPrivate = PrivateKey.generate();
        final wrongTrustRoot = wrongTrustRootPrivate.getPublicKey();

        final bobCipher = SealedSessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
        );

        // decryptToUsmc succeeds (no trust root validation in unwrap)
        final usmc = await bobCipher.decryptToUsmc(sealed);
        final usmcSenderCert = usmc.getSenderCertificate();

        // But validation with wrong trust root should fail
        expect(
          usmcSenderCert.validate(wrongTrustRoot, now: DateTime.now().toUtc()),
          isFalse,
        );

        // Cleanup
        wrongTrustRootPrivate.dispose();
        wrongTrustRoot.dispose();
        preKeyRecord.dispose();
        signedPreKeyRecord.dispose();
        kyberPreKeyRecord.dispose();
        bobBundle.dispose();
        senderCert.dispose();
        usmc.dispose();
        usmcSenderCert.dispose();
        bobKeys.dispose();
      });

      test('fails with expired certificate', () async {
        // Setup Bob's keys and stores (with Kyber)
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        final bobIdentityStore =
            InMemoryIdentityKeyStore(bobKeys.identityKeyPair, 67890);

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

        // Create EXPIRED sender certificate
        final expiredCert = SenderCertificate.create(
          senderUuid: 'alice-uuid',
          senderE164: '+1234567890',
          deviceId: 1,
          senderKey: aliceIdentity.publicKey,
          expiration: DateTime.now().toUtc().subtract(const Duration(days: 1)),
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        // Alice encrypts with expired cert
        final aliceCipher = SealedSessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        final plaintext = Uint8List.fromList(utf8.encode('Hello, Bob!'));
        final sealed =
            await aliceCipher.encrypt(bobAddress, plaintext, expiredCert);

        // Bob decrypts to USMC and validates the expired cert
        final bobCipher = SealedSessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
        );

        // decryptToUsmc succeeds (expiration not checked in unwrap)
        final usmc = await bobCipher.decryptToUsmc(sealed);
        final usmcSenderCert = usmc.getSenderCertificate();

        // But validation should fail due to expiration
        expect(
          usmcSenderCert.validate(trustRootPublic, now: DateTime.now().toUtc()),
          isFalse,
        );

        // Cleanup
        preKeyRecord.dispose();
        signedPreKeyRecord.dispose();
        kyberPreKeyRecord.dispose();
        bobBundle.dispose();
        expiredCert.dispose();
        usmc.dispose();
        usmcSenderCert.dispose();
        bobKeys.dispose();
      });

      test('fails with tampered message', () async {
        // Setup Bob's keys and stores (with Kyber)
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        final bobIdentityStore =
            InMemoryIdentityKeyStore(bobKeys.identityKeyPair, 67890);

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

        // Create sender certificate
        final senderCert = SenderCertificate.create(
          senderUuid: 'alice-uuid',
          senderE164: '+1234567890',
          deviceId: 1,
          senderKey: aliceIdentity.publicKey,
          expiration: DateTime.now().toUtc().add(const Duration(days: 30)),
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        // Alice encrypts
        final aliceCipher = SealedSessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        final plaintext = Uint8List.fromList(utf8.encode('Hello, Bob!'));
        final sealed =
            await aliceCipher.encrypt(bobAddress, plaintext, senderCert);

        // Tamper with the message
        final tampered = Uint8List.fromList(sealed);
        tampered[tampered.length ~/ 2] ^= 0xFF;

        // Bob tries to decrypt tampered message - decryptToUsmc should fail
        final bobCipher = SealedSessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
        );

        await expectLater(
          () => bobCipher.decryptToUsmc(tampered),
          throwsA(isA<LibSignalException>()),
        );

        // Cleanup
        preKeyRecord.dispose();
        signedPreKeyRecord.dispose();
        kyberPreKeyRecord.dispose();
        bobBundle.dispose();
        senderCert.dispose();
        bobKeys.dispose();
      });
    });
  });
}
