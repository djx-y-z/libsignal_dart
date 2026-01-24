import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });
  tearDownAll(() => LibSignal.cleanup());

  group('InMemoryPreKeyStore', () {
    late InMemoryPreKeyStore store;
    late PreKeyRecord record1;
    late PreKeyRecord record2;

    /// Helper to create a pre-key record
    PreKeyRecord createPreKey(int id) {
      final privateKey = PrivateKey.generate();
      final publicKey = privateKey.getPublicKey();
      return PreKeyRecord(id: id, publicKey: publicKey, privateKey: privateKey);
    }

    setUp(() {
      store = InMemoryPreKeyStore();
      record1 = createPreKey(1);
      record2 = createPreKey(2);
    });

    group('initial state', () {
      test('is empty initially', () {
        expect(store.length, equals(0));
      });

      test('loadPreKey returns null for non-existent key', () async {
        final record = await store.loadPreKey(1);
        expect(record, isNull);
      });

      test('containsPreKey returns false for non-existent key', () async {
        final contains = await store.containsPreKey(1);
        expect(contains, isFalse);
      });

      test('getAllPreKeyIds returns empty list', () async {
        final ids = await store.getAllPreKeyIds();
        expect(ids, isEmpty);
      });
    });

    group('storePreKey() / loadPreKey()', () {
      test('stores and loads pre-key', () async {
        await store.storePreKey(1, record1);

        final loaded = await store.loadPreKey(1);
        expect(loaded, isNotNull);
        expect(loaded!.id(), equals(1));
      });

      test('stores multiple pre-keys', () async {
        await store.storePreKey(1, record1);
        await store.storePreKey(2, record2);

        final loaded1 = await store.loadPreKey(1);
        final loaded2 = await store.loadPreKey(2);

        expect(loaded1, isNotNull);
        expect(loaded2, isNotNull);
        expect(loaded1!.id(), equals(1));
        expect(loaded2!.id(), equals(2));
      });

      test('overwrites existing pre-key', () async {
        await store.storePreKey(1, record1);

        final newRecord = createPreKey(1);
        await store.storePreKey(1, newRecord);

        final loaded = await store.loadPreKey(1);
        expect(loaded, isNotNull);
        expect(loaded!.id(), equals(1));

        // Verify it's the new record by checking serialization matches
        expect(loaded.serialize(), equals(newRecord.serialize()));
      });
    });

    group('containsPreKey()', () {
      test('returns true for stored key', () async {
        await store.storePreKey(1, record1);

        final contains = await store.containsPreKey(1);
        expect(contains, isTrue);
      });

      test('returns false after removal', () async {
        await store.storePreKey(1, record1);
        await store.removePreKey(1);

        final contains = await store.containsPreKey(1);
        expect(contains, isFalse);
      });
    });

    group('removePreKey()', () {
      test('removes stored key', () async {
        await store.storePreKey(1, record1);
        await store.removePreKey(1);

        final loaded = await store.loadPreKey(1);
        expect(loaded, isNull);
        expect(store.length, equals(0));
      });

      test('removing non-existent key is safe', () async {
        await expectLater(store.removePreKey(999), completes);
      });

      test('removes only specified key', () async {
        await store.storePreKey(1, record1);
        await store.storePreKey(2, record2);
        await store.removePreKey(1);

        expect(await store.loadPreKey(1), isNull);
        expect(await store.loadPreKey(2), isNotNull);
      });
    });

    group('getAllPreKeyIds()', () {
      test('returns all stored IDs', () async {
        await store.storePreKey(1, record1);
        await store.storePreKey(2, record2);

        final ids = await store.getAllPreKeyIds();
        expect(ids, containsAll([1, 2]));
        expect(ids.length, equals(2));
      });

      test('updates after removals', () async {
        await store.storePreKey(1, record1);
        await store.storePreKey(2, record2);
        await store.removePreKey(1);

        final ids = await store.getAllPreKeyIds();
        expect(ids, contains(2));
        expect(ids, isNot(contains(1)));
      });
    });

    group('clear()', () {
      test('clears all pre-keys', () async {
        await store.storePreKey(1, record1);
        await store.storePreKey(2, record2);

        store.clear();

        expect(store.length, equals(0));
        expect(await store.loadPreKey(1), isNull);
        expect(await store.loadPreKey(2), isNull);
      });

      test('clear on empty store is safe', () {
        expect(() => store.clear(), returnsNormally);
        expect(store.length, equals(0));
      });
    });

    group('length', () {
      test('tracks number of stored pre-keys', () async {
        expect(store.length, equals(0));

        await store.storePreKey(1, record1);
        expect(store.length, equals(1));

        await store.storePreKey(2, record2);
        expect(store.length, equals(2));
      });

      test('updates after removal', () async {
        await store.storePreKey(1, record1);
        await store.storePreKey(2, record2);
        await store.removePreKey(1);

        expect(store.length, equals(1));
      });

      test('does not change for overwrites', () async {
        await store.storePreKey(1, record1);
        expect(store.length, equals(1));

        await store.storePreKey(1, record2);
        expect(store.length, equals(1));
      });
    });

    group('various key IDs', () {
      test('handles ID 0', () async {
        final record = createPreKey(0);

        await store.storePreKey(0, record);
        expect(await store.containsPreKey(0), isTrue);

        final loaded = await store.loadPreKey(0);
        expect(loaded, isNotNull);
        expect(loaded!.id(), equals(0));
      });

      test('handles large IDs', () async {
        final record = createPreKey(0xFFFFFF);

        await store.storePreKey(0xFFFFFF, record);
        expect(await store.containsPreKey(0xFFFFFF), isTrue);

        final loaded = await store.loadPreKey(0xFFFFFF);
        expect(loaded, isNotNull);
        expect(loaded!.id(), equals(0xFFFFFF));
      });
    });
  });
}
