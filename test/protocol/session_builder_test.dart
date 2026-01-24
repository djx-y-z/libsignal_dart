import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/session_helpers.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });

  group('SessionBuilder', () {
    group('processPreKeyBundle', () {
      test('establishes session with valid bundle', () async {
        // Setup Alice (initiator)
        final aliceIdentity = IdentityKeyPair.generate();
        const aliceRegistrationId = 111;
        final aliceSessionStore = InMemorySessionStore();
        final aliceIdentityStore = InMemoryIdentityKeyStore(
          aliceIdentity,
          aliceRegistrationId,
        );

        // Setup Bob (responder) with pre-keys
        final bobKeys = generateRemotePartyKeys(
          registrationId: 222,
          deviceId: 1,
          preKeyId: 42,
          signedPreKeyId: 7,
          kyberPreKeyId: 1,
        );

        // Create Bob's address
        final bobAddress = ProtocolAddress(name: 'bob', deviceId: 1);

        // Create SessionBuilder for Alice
        final builder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        // Process Bob's bundle
        await builder.processPreKeyBundle(bobAddress, bobKeys.toBundle());

        // Verify session was created
        expect(await aliceSessionStore.containsSession(bobAddress), isTrue);

        // Verify identity was saved
        final savedIdentity = await aliceIdentityStore.getIdentity(bobAddress);
        expect(savedIdentity, isNotNull);
      });

      test('creates valid session that can encrypt messages', () async {
        // Setup Alice (initiator)
        final aliceIdentity = IdentityKeyPair.generate();
        const aliceRegistrationId = 111;
        final aliceSessionStore = InMemorySessionStore();
        final aliceIdentityStore = InMemoryIdentityKeyStore(
          aliceIdentity,
          aliceRegistrationId,
        );

        // Setup Bob (responder) with pre-keys
        final bobKeys = generateRemotePartyKeys(
          registrationId: 222,
          deviceId: 1,
          preKeyId: 42,
          signedPreKeyId: 7,
          kyberPreKeyId: 1,
        );
        final bobAddress = ProtocolAddress(name: 'bob', deviceId: 1);

        // Create session
        final builder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await builder.processPreKeyBundle(bobAddress, bobKeys.toBundle());

        // Verify we can load the session and it's valid
        final session = await aliceSessionStore.loadSession(bobAddress);
        expect(session, isNotNull);

        // Session should have a valid structure (not empty)
        final serialized = session!.serialize();
        expect(serialized.length, greaterThan(0));
      });

      test('updates existing session when processing new bundle', () async {
        // Setup Alice
        final aliceIdentity = IdentityKeyPair.generate();
        const aliceRegistrationId = 111;
        final aliceSessionStore = InMemorySessionStore();
        final aliceIdentityStore = InMemoryIdentityKeyStore(
          aliceIdentity,
          aliceRegistrationId,
        );

        // Setup Bob with first set of pre-keys
        final bobKeys1 = generateRemotePartyKeys(
          registrationId: 222,
          deviceId: 1,
          preKeyId: 1,
          signedPreKeyId: 1,
          kyberPreKeyId: 1,
        );
        final bobAddress = ProtocolAddress(name: 'bob', deviceId: 1);

        // Create first session
        final builder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await builder.processPreKeyBundle(bobAddress, bobKeys1.toBundle());

        final session1 = await aliceSessionStore.loadSession(bobAddress);
        expect(session1, isNotNull);
        final serialized1 = session1!.serialize();

        // Create new bundle with same identity (simulating key rotation)
        final bobKeys2 = generateRemotePartyKeysWithIdentity(
          identityKeyPair: bobKeys1.identityKeyPair,
          registrationId: 222,
          deviceId: 1,
          preKeyId: 2,
          signedPreKeyId: 2,
          kyberPreKeyId: 2,
        );

        // Process new bundle
        await builder.processPreKeyBundle(bobAddress, bobKeys2.toBundle());

        final session2 = await aliceSessionStore.loadSession(bobAddress);
        expect(session2, isNotNull);
        final serialized2 = session2!.serialize();

        // Sessions should be different (new ratchet keys)
        expect(serialized2, isNot(equals(serialized1)));
      });

      test('throws on invalid bundle signature', () async {
        // Setup Alice
        final aliceIdentity = IdentityKeyPair.generate();
        const aliceRegistrationId = 111;
        final aliceSessionStore = InMemorySessionStore();
        final aliceIdentityStore = InMemoryIdentityKeyStore(
          aliceIdentity,
          aliceRegistrationId,
        );

        // Create invalid bundle with mismatched signature
        final bobIdentity = IdentityKeyPair.generate();
        final wrongIdentity = IdentityKeyPair.generate();
        final signedPreKeyPrivate = PrivateKey.generate();
        final signedPreKeyPublic = signedPreKeyPrivate.getPublicKey();

        // Sign with wrong identity
        final wrongPrivate = PrivateKey.deserialize(
          bytes: wrongIdentity.privateKey.toList(),
        );
        final signature = wrongPrivate.sign(
          message: signedPreKeyPublic.serialize().toList(),
        );

        final kyberKeyPair = KyberKeyPair.generate();
        final kyberSignature = wrongPrivate.sign(
          message: kyberKeyPair.getPublicKey().serialize().toList(),
        );

        final invalidBundle = PreKeyBundle(
          registrationId: 222,
          deviceId: 1,
          preKeyId: 1,
          preKeyPublic: PrivateKey.generate().getPublicKey().serialize(),
          signedPreKeyId: 1,
          signedPreKeyPublic: signedPreKeyPublic.serialize().toList(),
          signedPreKeySignature: signature.toList(),
          identityKey: bobIdentity.publicKey.toList(), // Different identity
          kyberPreKeyId: 1,
          kyberPreKeyPublic: kyberKeyPair.getPublicKey().serialize().toList(),
          kyberPreKeySignature: kyberSignature.toList(),
        );

        final builder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        final bobAddress = ProtocolAddress(name: 'bob', deviceId: 1);

        // Should throw due to invalid signature
        expect(
          () => builder.processPreKeyBundle(bobAddress, invalidBundle),
          throwsA(anything),
        );
      });
    });
  });
}
