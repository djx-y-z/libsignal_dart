import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('SessionRecord', () {
    // Note: SessionRecord requires a valid serialized session to be created.
    // Full testing requires the session establishment protocol (X3DH)
    // which processes a PreKeyBundle to create a session.
    //
    // Once signal_process_prekey_bundle is wrapped, these tests can be
    // expanded to test the full session lifecycle.
    //
    // PreKeyBundle tests are located in test/prekeys/pre_key_bundle_test.dart

    group('deserialize()', () {
      test('rejects empty data', () {
        expect(
          () => SessionRecord.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects invalid data', () {
        final invalidData = Uint8List.fromList([1, 2, 3, 4, 5]);

        expect(
          () => SessionRecord.deserialize(invalidData),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects random bytes', () {
        // Random bytes shouldn't deserialize as valid session
        final randomData = Uint8List.fromList(
          List.generate(100, (i) => i % 256),
        );

        expect(
          () => SessionRecord.deserialize(randomData),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects truncated data', () {
        // Create some bytes that might look like a header but are incomplete
        final truncatedData = Uint8List.fromList([0x0A, 0x10, 0x01, 0x02]);

        expect(
          () => SessionRecord.deserialize(truncatedData),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects very large random data', () {
        // Large random data should still fail
        final largeData = Uint8List.fromList(
          List.generate(10000, (i) => i % 256),
        );

        expect(
          () => SessionRecord.deserialize(largeData),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    // Note: The following tests require a valid session.
    // They are documented here as placeholders for when
    // signal_process_prekey_bundle is implemented.
    //
    // group('serialize() / deserialize()', () {
    //   test('round-trip preserves session', () async {
    //     final session = await createTestSession();
    //     final serialized = session.serialize();
    //     final restored = SessionRecord.deserialize(serialized);
    //
    //     expect(restored.localRegistrationId, equals(session.localRegistrationId));
    //     expect(restored.remoteRegistrationId, equals(session.remoteRegistrationId));
    //
    //     restored.dispose();
    //     session.dispose();
    //   });
    // });
    //
    // group('archiveCurrentState()', () {
    //   test('archives without error', () async {
    //     final session = await createTestSession();
    //     expect(() => session.archiveCurrentState(), returnsNormally);
    //     session.dispose();
    //   });
    // });
    //
    // group('hasUsableSenderChain()', () {
    //   test('returns true for new session', () async {
    //     final session = await createTestSession();
    //     final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    //     expect(session.hasUsableSenderChain(now), isTrue);
    //     session.dispose();
    //   });
    // });
    //
    // group('currentRatchetKeyMatches()', () {
    //   test('matches current ratchet key', () async {
    //     final session = await createTestSession();
    //     // Would need to extract the current ratchet key...
    //     session.dispose();
    //   });
    // });
    //
    // group('registration IDs', () {
    //   test('returns local registration ID', () async {
    //     final session = await createTestSession();
    //     expect(session.localRegistrationId, isPositive);
    //     session.dispose();
    //   });
    //
    //   test('returns remote registration ID', () async {
    //     final session = await createTestSession();
    //     expect(session.remoteRegistrationId, isPositive);
    //     session.dispose();
    //   });
    // });
    //
    // group('clone()', () {
    //   test('creates independent copy', () async {
    //     final session = await createTestSession();
    //     final cloned = session.clone();
    //
    //     expect(cloned.localRegistrationId, equals(session.localRegistrationId));
    //
    //     session.dispose();
    //     expect(cloned.isDisposed, isFalse);
    //     cloned.dispose();
    //   });
    // });
    //
    // group('disposal', () {
    //   test('isDisposed is false initially', () async {
    //     final session = await createTestSession();
    //     expect(session.isDisposed, isFalse);
    //     session.dispose();
    //   });
    //
    //   test('isDisposed is true after dispose', () async {
    //     final session = await createTestSession();
    //     session.dispose();
    //     expect(session.isDisposed, isTrue);
    //   });
    //
    //   test('serialize throws after dispose', () async {
    //     final session = await createTestSession();
    //     session.dispose();
    //     expect(() => session.serialize(), throwsStateError);
    //   });
    // });
  });
}
