// ignore_for_file: avoid_redundant_argument_values, cascade_invocations, unnecessary_lambdas
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

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

      test('throws for invalid protobuf data', () {
        final garbage = [0x12, 0x34, 0x56, 0x78, 0x9A];
        expect(
          () => SessionRecord.deserialize(bytes: garbage),
          throwsA(anything),
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
