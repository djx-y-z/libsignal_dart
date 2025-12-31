import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/session_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('SessionRecord', () {
    late IdentityKeyPair aliceIdentity;
    late ProtocolAddress aliceAddress;
    late ProtocolAddress bobAddress;
    late InMemorySessionStore aliceSessionStore;
    late InMemoryIdentityKeyStore aliceIdentityStore;

    const aliceRegistrationId = 12345;
    const bobRegistrationId = 67890;

    setUp(() {
      aliceIdentity = IdentityKeyPair.generate();
      aliceAddress = ProtocolAddress('alice', 1);
      bobAddress = ProtocolAddress('bob', 1);
      aliceSessionStore = InMemorySessionStore();
      aliceIdentityStore = InMemoryIdentityKeyStore(
        aliceIdentity,
        aliceRegistrationId,
      );
    });

    tearDown(() {
      aliceIdentity.dispose();
      aliceAddress.dispose();
      bobAddress.dispose();
      aliceSessionStore.clear();
    });

    /// Helper to create a valid session by processing a PreKeyBundle
    Future<SessionRecord> createTestSession() async {
      final bobKeys = generateRemotePartyKeys(registrationId: bobRegistrationId);
      final bobBundle = bobKeys.toBundle();

      final builder = SessionBuilder(
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );

      await builder.processPreKeyBundle(bobAddress, bobBundle);

      final session = await aliceSessionStore.loadSession(bobAddress);
      bobBundle.dispose();
      bobKeys.dispose();

      return session!;
    }

    group('deserialize() validation', () {
      test('rejects empty data', () {
        expect(
          () => SessionRecord.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects garbage data', () {
        final garbage = Uint8List.fromList([0x99, 0x88, 0x77, 0x66, 0x55]);
        expect(
          () => SessionRecord.deserialize(garbage),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects truncated data', () {
        final truncated = Uint8List.fromList([0x0a, 0x10, 0x01, 0x02]);
        expect(
          () => SessionRecord.deserialize(truncated),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('serialize() / deserialize()', () {
      test('round-trip preserves session', () async {
        final session = await createTestSession();
        final serialized = session.serialize();
        final restored = SessionRecord.deserialize(serialized);

        expect(
          restored.localRegistrationId,
          equals(session.localRegistrationId),
        );
        expect(
          restored.remoteRegistrationId,
          equals(session.remoteRegistrationId),
        );

        restored.dispose();
        session.dispose();
      });

      test('serialized data is non-empty', () async {
        final session = await createTestSession();
        final serialized = session.serialize();

        expect(serialized, isNotEmpty);

        session.dispose();
      });
    });

    group('archiveCurrentState()', () {
      test('archives without error', () async {
        final session = await createTestSession();
        expect(() => session.archiveCurrentState(), returnsNormally);
        session.dispose();
      });

      test('archived session can still be serialized', () async {
        final session = await createTestSession();
        session.archiveCurrentState();

        expect(() => session.serialize(), returnsNormally);

        session.dispose();
      });
    });

    group('hasUsableSenderChain()', () {
      test('returns true for new session', () async {
        final session = await createTestSession();
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        expect(session.hasUsableSenderChain(now), isTrue);
        session.dispose();
      });

      test('accepts timestamp parameter', () async {
        final session = await createTestSession();
        // Just verify it doesn't throw with different timestamp values
        expect(() => session.hasUsableSenderChain(0), returnsNormally);
        expect(
          () => session.hasUsableSenderChain(
            DateTime.now().millisecondsSinceEpoch ~/ 1000,
          ),
          returnsNormally,
        );
        session.dispose();
      });
    });

    group('currentRatchetKeyMatches()', () {
      test('returns false for random key', () async {
        final session = await createTestSession();
        final randomKey = PrivateKey.generate().getPublicKey();

        expect(session.currentRatchetKeyMatches(randomKey), isFalse);

        randomKey.dispose();
        session.dispose();
      });
    });

    group('localRegistrationId', () {
      test('returns correct local registration ID', () async {
        final session = await createTestSession();
        expect(session.localRegistrationId, equals(aliceRegistrationId));
        session.dispose();
      });
    });

    group('remoteRegistrationId', () {
      test('returns correct remote registration ID', () async {
        final session = await createTestSession();
        expect(session.remoteRegistrationId, equals(bobRegistrationId));
        session.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () async {
        final session = await createTestSession();
        final cloned = session.clone();

        expect(
          cloned.localRegistrationId,
          equals(session.localRegistrationId),
        );
        expect(
          cloned.remoteRegistrationId,
          equals(session.remoteRegistrationId),
        );

        session.dispose();
        expect(cloned.isDisposed, isFalse);
        cloned.dispose();
      });

      test('clone has own lifecycle', () async {
        final session = await createTestSession();
        final cloned = session.clone();

        cloned.dispose();
        expect(cloned.isDisposed, isTrue);
        expect(session.isDisposed, isFalse);

        session.dispose();
      });

      test('modifying clone does not affect original', () async {
        final session = await createTestSession();
        final cloned = session.clone();

        // Archive the cloned session
        cloned.archiveCurrentState();

        // Original should still have usable sender chain
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        expect(session.hasUsableSenderChain(now), isTrue);

        cloned.dispose();
        session.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () async {
        final session = await createTestSession();
        expect(session.isDisposed, isFalse);
        session.dispose();
      });

      test('isDisposed is true after dispose', () async {
        final session = await createTestSession();
        session.dispose();
        expect(session.isDisposed, isTrue);
      });

      test('double dispose is safe', () async {
        final session = await createTestSession();
        session.dispose();
        expect(() => session.dispose(), returnsNormally);
      });

      test('serialize throws after dispose', () async {
        final session = await createTestSession();
        session.dispose();
        expect(
          () => session.serialize(),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('archiveCurrentState throws after dispose', () async {
        final session = await createTestSession();
        session.dispose();
        expect(
          () => session.archiveCurrentState(),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('hasUsableSenderChain throws after dispose', () async {
        final session = await createTestSession();
        session.dispose();
        expect(
          () => session.hasUsableSenderChain(0),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('currentRatchetKeyMatches throws after dispose', () async {
        final session = await createTestSession();
        final key = PrivateKey.generate().getPublicKey();
        session.dispose();
        expect(
          () => session.currentRatchetKeyMatches(key),
          throwsA(isA<LibSignalException>()),
        );
        key.dispose();
      });

      test('localRegistrationId throws after dispose', () async {
        final session = await createTestSession();
        session.dispose();
        expect(
          () => session.localRegistrationId,
          throwsA(isA<LibSignalException>()),
        );
      });

      test('remoteRegistrationId throws after dispose', () async {
        final session = await createTestSession();
        session.dispose();
        expect(
          () => session.remoteRegistrationId,
          throwsA(isA<LibSignalException>()),
        );
      });

      test('clone throws after dispose', () async {
        final session = await createTestSession();
        session.dispose();
        expect(
          () => session.clone(),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('pointer throws after dispose', () async {
        final session = await createTestSession();
        session.dispose();
        expect(
          () => session.pointer,
          throwsA(isA<LibSignalException>()),
        );
      });
    });
  });
}
