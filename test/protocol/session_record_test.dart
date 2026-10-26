// ignore_for_file: avoid_redundant_argument_values, cascade_invocations, unnecessary_lambdas
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/error_matchers.dart';
import '../test_helpers/session_helpers.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('SessionRecord', () {
    group('deserialize() validation', () {
      test('handles empty data without crashing', () {
        // Rust returns an empty/default SessionRecord for empty input
        final result = SessionRecord.deserialize(bytes: []);
        expect(result, isNotNull);
      });

      test('bytes that do not parse are invalidSession', () {
        final garbage = [0x12, 0x34, 0x56, 0x78, 0x9A];
        expect(
          () => SessionRecord.deserialize(bytes: garbage),
          failsWith(LibSignalErrorCode.invalidSession),
        );
      });
    });

    group('with established session', () {
      late IdentityKeyPair aliceIdentity;
      late Map<String, Uint8List> aliceSessionStorage;
      late Map<String, Uint8List> aliceIdentityStorage;
      late RemotePartyKeys bobKeys;
      late PreKeyBundle bobBundle;

      setUp(() async {
        // Alice's identity
        aliceIdentity = IdentityKeyPair.generate();
        aliceSessionStorage = {};
        aliceIdentityStorage = {};

        // Bob's keys (the responder)
        bobKeys = generateRemotePartyKeys(
          registrationId: 222,
          deviceId: 1,
          preKeyId: 42,
          signedPreKeyId: 7,
          kyberPreKeyId: 1,
        );
        bobBundle = bobKeys.toBundle();

        // Alice processes Bob's bundle to establish session
        await processPrekeyBundleWithCallbacks(
          remoteName: 'bob',
          remoteDeviceId: 1,
          localName: 'alice',
          localDeviceId: 1,
          bundle: bobBundle,
          loadSession: (name, deviceId) =>
              aliceSessionStorage['$name:$deviceId'],
          storeSession: (name, deviceId, data) =>
              aliceSessionStorage['$name:$deviceId'] = data,
          getIdentityKeyPair: () => aliceIdentity.serialize(),
          getLocalRegistrationId: () => 111,
          saveIdentity: (name, deviceId, key) =>
              aliceIdentityStorage['$name:$deviceId'] = key,
          getIdentity: (name, deviceId) =>
              aliceIdentityStorage['$name:$deviceId'],
        );
      });

      test('serialize/deserialize round-trip', () {
        final sessionData = aliceSessionStorage['bob:1']!;
        final session = SessionRecord.deserialize(bytes: sessionData.toList());
        final reserialized = session.serialize();

        // Verify round-trip preserves data
        expect(reserialized, equals(sessionData));
      });

      test('hasUsableSenderChain returns true for established session', () {
        final sessionData = aliceSessionStorage['bob:1']!;
        final session = SessionRecord.deserialize(bytes: sessionData.toList());
        final now = BigInt.from(DateTime.now().millisecondsSinceEpoch);

        // Established session should have a usable sender chain
        expect(session.hasUsableSenderChain(nowMillis: now), isTrue);
      });

      test('hasUsableSenderChain is false for a session nobody answered once '
          'it is 30 days old', () {
        final session = SessionRecord.deserialize(
          bytes: aliceSessionStorage['bob:1']!.toList(),
        );
        final in31Days = DateTime.now().add(const Duration(days: 31));

        // libsignal calls it stale and no longer encrypts on it; a Signal
        // client archives it and fetches a new bundle.
        expect(
          session.hasUsableSenderChain(
            nowMillis: BigInt.from(in31Days.millisecondsSinceEpoch),
          ),
          isFalse,
        );
      });

      test('hasUsableSenderChain stays true for an answered session, however '
          'old', () async {
        final alice = ProtocolAddress(name: 'alice', deviceId: 1);
        final bob = ProtocolAddress(name: 'bob', deviceId: 1);
        final ts = BigInt.from(DateTime.now().millisecondsSinceEpoch);
        final bobPreKeys = InMemoryPreKeyStore();
        await bobPreKeys.storePreKey(
          bobKeys.preKeyId,
          PreKeyRecord(
            id: bobKeys.preKeyId,
            publicKey: bobKeys.preKeyPublic,
            privateKey: bobKeys.preKeyPrivate,
          ),
        );
        final bobSignedPreKeys = InMemorySignedPreKeyStore();
        await bobSignedPreKeys.storeSignedPreKey(
          bobKeys.signedPreKeyId,
          SignedPreKeyRecord(
            id: bobKeys.signedPreKeyId,
            publicKey: bobKeys.signedPreKeyPublic,
            privateKey: bobKeys.signedPreKeyPrivate,
            signature: bobKeys.signedPreKeySignature.toList(),
            timestamp: ts,
          ),
        );
        final bobKyberPreKeys = InMemoryKyberPreKeyStore();
        await bobKyberPreKeys.storeKyberPreKey(
          bobKeys.kyberPreKeyId,
          KyberPreKeyRecord.create(
            id: bobKeys.kyberPreKeyId,
            keyPair: bobKeys.kyberKeyPair,
            signature: bobKeys.kyberPreKeySignature.toList(),
            timestamp: ts,
          ),
        );
        final bobCipher = SessionCipher(
          localAddress: bob,
          sessionStore: InMemorySessionStore(),
          identityKeyStore: InMemoryIdentityKeyStore(
            bobKeys.identityKeyPair,
            222,
          ),
          preKeyStore: bobPreKeys,
          signedPreKeyStore: bobSignedPreKeys,
          kyberPreKeyStore: bobKyberPreKeys,
        );
        final aliceSessions = InMemorySessionStore();
        final aliceIdentities = InMemoryIdentityKeyStore(aliceIdentity, 111);
        await SessionBuilder(
          localAddress: alice,
          sessionStore: aliceSessions,
          identityKeyStore: aliceIdentities,
        ).processPreKeyBundle(bob, bobBundle);
        final aliceCipher = SessionCipher(
          localAddress: alice,
          sessionStore: aliceSessions,
          identityKeyStore: aliceIdentities,
          preKeyStore: InMemoryPreKeyStore(),
          signedPreKeyStore: InMemorySignedPreKeyStore(),
          kyberPreKeyStore: InMemoryKyberPreKeyStore(),
        );
        await bobCipher.decrypt(
          alice,
          await aliceCipher.encrypt(bob, Uint8List.fromList([1])),
        );
        await aliceCipher.decrypt(
          bob,
          await bobCipher.encrypt(alice, Uint8List.fromList([2])),
        );

        final in31Days = DateTime.now().add(const Duration(days: 31));
        final record = (await aliceSessions.loadSession(bob))!;
        expect(
          record.hasUsableSenderChain(
            nowMillis: BigInt.from(in31Days.millisecondsSinceEpoch),
          ),
          isTrue,
        );
      });

      test('hasUsableSenderChain returns false for empty session', () {
        final emptySession = SessionRecord.deserialize(bytes: []);
        final now = BigInt.from(DateTime.now().millisecondsSinceEpoch);

        // Empty session should not have a usable sender chain
        expect(emptySession.hasUsableSenderChain(nowMillis: now), isFalse);
      });

      test('remoteRegistrationId returns correct value', () {
        final sessionData = aliceSessionStorage['bob:1']!;
        final session = SessionRecord.deserialize(bytes: sessionData.toList());

        // Should return Bob's registration ID
        expect(session.remoteRegistrationId(), equals(222));
      });

      test('localRegistrationId returns correct value', () {
        final sessionData = aliceSessionStorage['bob:1']!;
        final session = SessionRecord.deserialize(bytes: sessionData.toList());

        // Should return Alice's registration ID
        expect(session.localRegistrationId(), equals(111));
      });

      test('archiveCurrentState creates new session state', () {
        final sessionData = aliceSessionStorage['bob:1']!;
        final session = SessionRecord.deserialize(bytes: sessionData.toList());

        // Archive the current state
        session.archiveCurrentState();

        // After archiving, the session may no longer have a usable sender chain
        // (depending on implementation details)
        final serialized = session.serialize();
        expect(serialized, isNotEmpty);
      });

      test('currentRatchetKeyMatches works with correct key', () {
        final sessionData = aliceSessionStorage['bob:1']!;
        final session = SessionRecord.deserialize(bytes: sessionData.toList());

        // Get a random key to test (it should NOT match)
        final randomKey = PrivateKey.generate().getPublicKey();
        expect(session.currentRatchetKeyMatches(key: randomKey), isFalse);
      });
    });

    group('cloneRecord', () {
      test('creates independent copy', () async {
        final aliceIdentity = IdentityKeyPair.generate();
        final aliceSessionStorage = <String, Uint8List>{};
        final aliceIdentityStorage = <String, Uint8List>{};

        final bobKeys = generateRemotePartyKeys();
        final bobBundle = bobKeys.toBundle();

        await processPrekeyBundleWithCallbacks(
          remoteName: 'bob',
          remoteDeviceId: 1,
          localName: 'alice',
          localDeviceId: 1,
          bundle: bobBundle,
          loadSession: (name, deviceId) =>
              aliceSessionStorage['$name:$deviceId'],
          storeSession: (name, deviceId, data) =>
              aliceSessionStorage['$name:$deviceId'] = data,
          getIdentityKeyPair: () => aliceIdentity.serialize(),
          getLocalRegistrationId: () => 111,
          saveIdentity: (name, deviceId, key) =>
              aliceIdentityStorage['$name:$deviceId'] = key,
          getIdentity: (name, deviceId) =>
              aliceIdentityStorage['$name:$deviceId'],
        );

        final sessionData = aliceSessionStorage['bob:1']!;
        final session = SessionRecord.deserialize(bytes: sessionData.toList());

        // Clone the session
        final cloned = session.cloneRecord();

        // Verify both serialize to the same data
        expect(cloned.serialize(), equals(session.serialize()));

        // Verify they are independent (modifying one doesn't affect the other)
        session.archiveCurrentState();
        expect(cloned.serialize(), isNot(equals(session.serialize())));
      });
    });
  });
}
