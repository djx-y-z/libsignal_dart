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
    late InMemoryIdentityKeyStore bobIdentityStore;
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
      bobIdentityStore = InMemoryIdentityKeyStore(
        bobKeys.identityKeyPair,
        67890,
      );

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
  });
}
