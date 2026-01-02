import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/session_helpers.dart';

void main() {
  setUpAll(() {
    LibSignal.ensureInitialized();
  });

  group('SessionBuilder', () {
    late InMemorySessionStore aliceSessionStore;
    late InMemoryIdentityKeyStore aliceIdentityStore;
    late InMemorySessionStore bobSessionStore;
    late InMemoryPreKeyStore bobPreKeyStore;
    late InMemorySignedPreKeyStore bobSignedPreKeyStore;
    late InMemoryKyberPreKeyStore bobKyberPreKeyStore;

    late IdentityKeyPair aliceIdentity;
    late ProtocolAddress aliceAddress;
    late ProtocolAddress bobAddress;

    setUp(() {
      // Generate identity keys
      aliceIdentity = IdentityKeyPair.generate();

      // Create addresses
      aliceAddress = ProtocolAddress('alice', 1);
      bobAddress = ProtocolAddress('bob', 1);

      // Create stores for Alice
      aliceSessionStore = InMemorySessionStore();
      aliceIdentityStore = InMemoryIdentityKeyStore(aliceIdentity, 12345);

      // Create stores for Bob (will be populated per test)
      bobSessionStore = InMemorySessionStore();
      bobPreKeyStore = InMemoryPreKeyStore();
      bobSignedPreKeyStore = InMemorySignedPreKeyStore();
      bobKyberPreKeyStore = InMemoryKyberPreKeyStore();
    });

    tearDown(() {
      aliceIdentity.dispose();
      aliceAddress.dispose();
      bobAddress.dispose();

      // Clear stores to avoid cross-test contamination
      aliceSessionStore.clear();
      bobSessionStore.clear();
      bobPreKeyStore.clear();
      bobSignedPreKeyStore.clear();
      bobKyberPreKeyStore.clear();
    });

    test('processes pre-key bundle and establishes session', () async {
      // Generate Bob's keys
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

      // Create Bob's pre-key bundle
      final bobBundle = bobKeys.toBundle();

      // Alice processes Bob's bundle
      final aliceBuilder = SessionBuilder(
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );

      await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

      // Verify session was created
      final aliceSession = await aliceSessionStore.loadSession(bobAddress);
      expect(aliceSession, isNotNull);
      expect(aliceSession!.remoteRegistrationId, equals(67890));

      // Cleanup
      preKeyRecord.dispose();
      signedPreKeyRecord.dispose();
      kyberPreKeyRecord.dispose();
      bobBundle.dispose();
      aliceSession.dispose();
      bobKeys.dispose();
    });

    test('session encryption after bundle processing', () async {
      // Generate Bob's keys
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

      // Create Bob's pre-key bundle
      final bobBundle = bobKeys.toBundle();

      // Alice establishes session with Bob
      final aliceBuilder = SessionBuilder(
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );
      await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

      // Alice encrypts a message
      final aliceCipher = SessionCipher(
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );

      final plaintext = Uint8List.fromList(utf8.encode('Hello, Bob!'));
      final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

      // The first message should be a PreKeySignalMessage
      expect(encrypted.type, equals(CiphertextMessageType.preKey));
      expect(encrypted.bytes.isNotEmpty, isTrue);

      // Cleanup
      preKeyRecord.dispose();
      signedPreKeyRecord.dispose();
      kyberPreKeyRecord.dispose();
      bobBundle.dispose();
      bobKeys.dispose();
    });

    test('establishes session with existing identity', () async {
      // Generate Bob's keys
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

      // Pre-save Bob's identity to Alice's store
      await aliceIdentityStore.saveIdentity(
        bobAddress,
        bobKeys.identityKeyPair.publicKey,
      );

      // Create Bob's pre-key bundle
      final bobBundle = bobKeys.toBundle();

      // Alice processes Bob's bundle (with existing identity)
      final aliceBuilder = SessionBuilder(
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );

      await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

      // Verify session was created
      final aliceSession = await aliceSessionStore.loadSession(bobAddress);
      expect(aliceSession, isNotNull);
      expect(aliceSession!.remoteRegistrationId, equals(67890));

      // Cleanup
      preKeyRecord.dispose();
      signedPreKeyRecord.dispose();
      kyberPreKeyRecord.dispose();
      bobBundle.dispose();
      aliceSession.dispose();
      bobKeys.dispose();
    });

    test('replaces existing session with new bundle', () async {
      // Generate Bob's first set of keys
      final bobKeys1 = generateRemotePartyKeys(registrationId: 67890);

      // Store Bob's first pre-keys
      var preKeyRecord = PreKeyRecord.create(
        id: bobKeys1.preKeyId,
        publicKey: bobKeys1.preKeyPublic,
        privateKey: bobKeys1.preKeyPrivate,
      );
      await bobPreKeyStore.storePreKey(bobKeys1.preKeyId, preKeyRecord);
      preKeyRecord.dispose();

      var signedPreKeyRecord = SignedPreKeyRecord.create(
        id: bobKeys1.signedPreKeyId,
        timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
        publicKey: bobKeys1.signedPreKeyPublic,
        privateKey: bobKeys1.signedPreKeyPrivate,
        signature: bobKeys1.signedPreKeySignature,
      );
      await bobSignedPreKeyStore.storeSignedPreKey(
        bobKeys1.signedPreKeyId,
        signedPreKeyRecord,
      );
      signedPreKeyRecord.dispose();

      var kyberPreKeyRecord = KyberPreKeyRecord.create(
        id: bobKeys1.kyberPreKeyId,
        timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
        keyPair: bobKeys1.kyberKeyPair,
        signature: bobKeys1.kyberPreKeySignature,
      );
      await bobKyberPreKeyStore.storeKyberPreKey(
        bobKeys1.kyberPreKeyId,
        kyberPreKeyRecord,
      );
      kyberPreKeyRecord.dispose();

      // First session establishment
      var bobBundle = bobKeys1.toBundle();
      final aliceBuilder = SessionBuilder(
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );
      await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);
      bobBundle.dispose();

      // Verify first session
      var aliceSession = await aliceSessionStore.loadSession(bobAddress);
      expect(aliceSession, isNotNull);
      aliceSession!.dispose();

      // Generate Bob's second set of keys with different pre-key IDs
      final bobKeys2 = generateRemotePartyKeys(
        registrationId: 67890,
        preKeyId: 2,
        signedPreKeyId: 2,
        kyberPreKeyId: 2,
      );

      // Store Bob's second pre-keys
      preKeyRecord = PreKeyRecord.create(
        id: bobKeys2.preKeyId,
        publicKey: bobKeys2.preKeyPublic,
        privateKey: bobKeys2.preKeyPrivate,
      );
      await bobPreKeyStore.storePreKey(bobKeys2.preKeyId, preKeyRecord);
      preKeyRecord.dispose();

      signedPreKeyRecord = SignedPreKeyRecord.create(
        id: bobKeys2.signedPreKeyId,
        timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
        publicKey: bobKeys2.signedPreKeyPublic,
        privateKey: bobKeys2.signedPreKeyPrivate,
        signature: bobKeys2.signedPreKeySignature,
      );
      await bobSignedPreKeyStore.storeSignedPreKey(
        bobKeys2.signedPreKeyId,
        signedPreKeyRecord,
      );
      signedPreKeyRecord.dispose();

      kyberPreKeyRecord = KyberPreKeyRecord.create(
        id: bobKeys2.kyberPreKeyId,
        timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
        keyPair: bobKeys2.kyberKeyPair,
        signature: bobKeys2.kyberPreKeySignature,
      );
      await bobKyberPreKeyStore.storeKyberPreKey(
        bobKeys2.kyberPreKeyId,
        kyberPreKeyRecord,
      );
      kyberPreKeyRecord.dispose();

      // Save new identity to enable trust (TOFU check)
      await aliceIdentityStore.saveIdentity(
        bobAddress,
        bobKeys2.identityKeyPair.publicKey,
      );

      // Second session establishment (replaces first)
      final bobBundle2 = bobKeys2.toBundle();
      await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle2);
      bobBundle2.dispose();

      // Verify session was replaced
      aliceSession = await aliceSessionStore.loadSession(bobAddress);
      expect(aliceSession, isNotNull);
      aliceSession!.dispose();

      // Cleanup
      bobKeys1.dispose();
      bobKeys2.dispose();
    });

    test('establishes sessions with multiple addresses', () async {
      // Generate Bob's keys
      final bobKeys = generateRemotePartyKeys(registrationId: 67890);

      // Store Bob's pre-keys
      var preKeyRecord = PreKeyRecord.create(
        id: bobKeys.preKeyId,
        publicKey: bobKeys.preKeyPublic,
        privateKey: bobKeys.preKeyPrivate,
      );
      await bobPreKeyStore.storePreKey(bobKeys.preKeyId, preKeyRecord);
      preKeyRecord.dispose();

      var signedPreKeyRecord = SignedPreKeyRecord.create(
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
      signedPreKeyRecord.dispose();

      var kyberPreKeyRecord = KyberPreKeyRecord.create(
        id: bobKeys.kyberPreKeyId,
        timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
        keyPair: bobKeys.kyberKeyPair,
        signature: bobKeys.kyberPreKeySignature,
      );
      await bobKyberPreKeyStore.storeKyberPreKey(
        bobKeys.kyberPreKeyId,
        kyberPreKeyRecord,
      );
      kyberPreKeyRecord.dispose();

      // Generate Carol's keys
      final carolKeys = generateRemotePartyKeys(registrationId: 11111);
      final carolAddress = ProtocolAddress('carol', 1);

      // Store Carol's pre-keys
      preKeyRecord = PreKeyRecord.create(
        id: carolKeys.preKeyId,
        publicKey: carolKeys.preKeyPublic,
        privateKey: carolKeys.preKeyPrivate,
      );
      await bobPreKeyStore.storePreKey(carolKeys.preKeyId, preKeyRecord);
      preKeyRecord.dispose();

      signedPreKeyRecord = SignedPreKeyRecord.create(
        id: carolKeys.signedPreKeyId,
        timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
        publicKey: carolKeys.signedPreKeyPublic,
        privateKey: carolKeys.signedPreKeyPrivate,
        signature: carolKeys.signedPreKeySignature,
      );
      await bobSignedPreKeyStore.storeSignedPreKey(
        carolKeys.signedPreKeyId,
        signedPreKeyRecord,
      );
      signedPreKeyRecord.dispose();

      kyberPreKeyRecord = KyberPreKeyRecord.create(
        id: carolKeys.kyberPreKeyId,
        timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
        keyPair: carolKeys.kyberKeyPair,
        signature: carolKeys.kyberPreKeySignature,
      );
      await bobKyberPreKeyStore.storeKyberPreKey(
        carolKeys.kyberPreKeyId,
        kyberPreKeyRecord,
      );
      kyberPreKeyRecord.dispose();

      final aliceBuilder = SessionBuilder(
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );

      // Establish session with Bob
      final bobBundle = bobKeys.toBundle();
      await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);
      bobBundle.dispose();

      // Establish session with Carol
      final carolBundle = carolKeys.toBundle();
      await aliceBuilder.processPreKeyBundle(carolAddress, carolBundle);
      carolBundle.dispose();

      // Verify both sessions exist independently
      final bobSession = await aliceSessionStore.loadSession(bobAddress);
      final carolSession = await aliceSessionStore.loadSession(carolAddress);

      expect(bobSession, isNotNull);
      expect(carolSession, isNotNull);
      expect(bobSession!.remoteRegistrationId, equals(67890));
      expect(carolSession!.remoteRegistrationId, equals(11111));

      // Cleanup
      bobSession.dispose();
      carolSession.dispose();
      carolAddress.dispose();
      bobKeys.dispose();
      carolKeys.dispose();
    });

    test('encrypts and decrypts after session establishment', () async {
      // Generate Bob's keys
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

      // Create Bob's pre-key bundle
      final bobBundle = bobKeys.toBundle();

      // Alice establishes session with Bob
      final aliceBuilder = SessionBuilder(
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );
      await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

      // Alice encrypts a message
      final aliceCipher = SessionCipher(
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );

      final plaintext = Uint8List.fromList(utf8.encode('Hello from Alice!'));
      final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

      // Bob decrypts the message
      final bobIdentityStore = InMemoryIdentityKeyStore(
        bobKeys.identityKeyPair,
        67890,
      );
      final bobCipher = SessionCipher(
        sessionStore: bobSessionStore,
        identityKeyStore: bobIdentityStore,
        preKeyStore: bobPreKeyStore,
        signedPreKeyStore: bobSignedPreKeyStore,
        kyberPreKeyStore: bobKyberPreKeyStore,
      );

      final decrypted = await bobCipher.decryptPreKeySignalMessage(
        aliceAddress,
        encrypted.bytes,
      );

      expect(decrypted, equals(plaintext));

      // Cleanup
      preKeyRecord.dispose();
      signedPreKeyRecord.dispose();
      kyberPreKeyRecord.dispose();
      bobBundle.dispose();
      bobKeys.dispose();
    });
  });
}
