import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('InMemoryPreKeyStore', () {
    late InMemoryPreKeyStore store;
    late PrivateKey privateKey1;
    late PrivateKey privateKey2;
    late PublicKey publicKey1;
    late PublicKey publicKey2;
    late PreKeyRecord record1;
    late PreKeyRecord record2;

    setUp(() {
      store = InMemoryPreKeyStore();
      privateKey1 = PrivateKey.generate();
      privateKey2 = PrivateKey.generate();
      publicKey1 = privateKey1.getPublicKey();
      publicKey2 = privateKey2.getPublicKey();
      record1 = PreKeyRecord.create(
        id: 1,
        publicKey: publicKey1,
        privateKey: privateKey1,
      );
      record2 = PreKeyRecord.create(
        id: 2,
        publicKey: publicKey2,
        privateKey: privateKey2,
      );
    });

    tearDown(() {
      privateKey1.dispose();
      privateKey2.dispose();
      publicKey1.dispose();
      publicKey2.dispose();
      record1.dispose();
      record2.dispose();
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
        expect(loaded!.id, equals(1));

        loaded.dispose();
      });

      test('stores multiple pre-keys', () async {
        await store.storePreKey(1, record1);
        await store.storePreKey(2, record2);

        final loaded1 = await store.loadPreKey(1);
        final loaded2 = await store.loadPreKey(2);

        expect(loaded1, isNotNull);
        expect(loaded2, isNotNull);
        expect(loaded1!.id, equals(1));
        expect(loaded2!.id, equals(2));

        loaded1.dispose();
        loaded2.dispose();
      });

      test('overwrites existing pre-key', () async {
        await store.storePreKey(1, record1);

        final newKey = PrivateKey.generate();
        final newPubKey = newKey.getPublicKey();
        final newRecord = PreKeyRecord.create(
          id: 1,
          publicKey: newPubKey,
          privateKey: newKey,
        );
        await store.storePreKey(1, newRecord);

        final loaded = await store.loadPreKey(1);
        expect(loaded, isNotNull);
        expect(loaded!.id, equals(1));

        // Verify it's the new record by checking serialization differs
        expect(
          loaded.serialize(),
          equals(newRecord.serialize()),
        );

        loaded.dispose();
        newRecord.dispose();
        newPubKey.dispose();
        newKey.dispose();
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
        await expectLater(
          store.removePreKey(999),
          completes,
        );
      });

      test('removes only specified key', () async {
        await store.storePreKey(1, record1);
        await store.storePreKey(2, record2);
        await store.removePreKey(1);

        expect(await store.loadPreKey(1), isNull);
        expect(await store.loadPreKey(2), isNotNull);

        final loaded2 = await store.loadPreKey(2);
        loaded2?.dispose();
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
        final key = PrivateKey.generate();
        final pubKey = key.getPublicKey();
        final record = PreKeyRecord.create(
          id: 0,
          publicKey: pubKey,
          privateKey: key,
        );

        await store.storePreKey(0, record);
        expect(await store.containsPreKey(0), isTrue);

        final loaded = await store.loadPreKey(0);
        expect(loaded, isNotNull);
        expect(loaded!.id, equals(0));

        loaded.dispose();
        record.dispose();
        pubKey.dispose();
        key.dispose();
      });

      test('handles large IDs', () async {
        final key = PrivateKey.generate();
        final pubKey = key.getPublicKey();
        final record = PreKeyRecord.create(
          id: 0xFFFFFF,
          publicKey: pubKey,
          privateKey: key,
        );

        await store.storePreKey(0xFFFFFF, record);
        expect(await store.containsPreKey(0xFFFFFF), isTrue);

        final loaded = await store.loadPreKey(0xFFFFFF);
        expect(loaded, isNotNull);
        expect(loaded!.id, equals(0xFFFFFF));

        loaded.dispose();
        record.dispose();
        pubKey.dispose();
        key.dispose();
      });
    });
  });
}
