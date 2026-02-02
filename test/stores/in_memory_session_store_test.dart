import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('InMemorySessionStore', () {
    late InMemorySessionStore store;
    late ProtocolAddress aliceAddress;

    setUp(() {
      store = InMemorySessionStore();
      aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
    });

    group('initial state', () {
      test('is empty initially', () {
        expect(store.length, equals(0));
      });

      test('loadSession returns null for non-existent session', () async {
        final session = await store.loadSession(aliceAddress);
        expect(session, isNull);
      });

      test('containsSession returns false for non-existent session', () async {
        final contains = await store.containsSession(aliceAddress);
        expect(contains, isFalse);
      });
    });

    group('deleteSession()', () {
      test('deleting non-existent session is safe', () async {
        await expectLater(store.deleteSession(aliceAddress), completes);
      });
    });

    group('deleteAllSessions()', () {
      test('deleting sessions for non-existent user is safe', () async {
        await expectLater(store.deleteAllSessions('unknown'), completes);
      });
    });

    group('getSubDeviceSessions()', () {
      test('returns empty list for non-existent user', () async {
        final devices = await store.getSubDeviceSessions('unknown');
        expect(devices, isEmpty);
      });
    });

    group('clear()', () {
      test('clear on empty store is safe', () {
        expect(() => store.clear(), returnsNormally);
        expect(store.length, equals(0));
      });
    });

    // Note: Full session store tests require valid SessionRecords,
    // which can only be created through actual protocol session
    // establishment. See integration tests for full coverage.
  });
}
