import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('InMemorySessionStore', () {
    late InMemorySessionStore store;
    late ProtocolAddress aliceAddress;
    late ProtocolAddress bobAddress;

    setUp(() {
      store = InMemorySessionStore();
      aliceAddress = ProtocolAddress('alice', 1);
      bobAddress = ProtocolAddress('bob', 1);
    });

    tearDown(() {
      aliceAddress.dispose();
      bobAddress.dispose();
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
    //
    // The following tests are documented but skipped:
    //
    // group('storeSession() / loadSession()', () {
    //   test('stores and loads session', () async { ... });
    //   test('overwrites existing session', () async { ... });
    // });
    //
    // group('multiple devices', () {
    //   test('stores sessions for multiple devices', () async { ... });
    //   test('getSubDeviceSessions returns all device IDs', () async { ... });
    //   test('deleteAllSessions removes all devices', () async { ... });
    // });
  });
}
