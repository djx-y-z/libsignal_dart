import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('InMemoryKyberPreKeyStore', () {
    late InMemoryKyberPreKeyStore store;
    late IdentityKeyPair identityKeyPair;
    late KyberPreKeyRecord record1;
    late KyberPreKeyRecord record2;

    /// Helper to create a Kyber pre-key record with valid signature
    KyberPreKeyRecord createKyberPreKey({
      required int id,
      required int timestamp,
      required IdentityKeyPair identityKeyPair,
    }) {
      final kyberKeyPair = KyberKeyPair.generate();
      final publicKey = kyberKeyPair.getPublicKey();
      final signature = identityKeyPair.privateKey.sign(publicKey.serialize());

      final record = KyberPreKeyRecord.create(
        id: id,
        timestamp: timestamp,
        keyPair: kyberKeyPair,
        signature: signature,
      );

      kyberKeyPair.dispose();
      publicKey.dispose();

      return record;
    }

    setUp(() {
      store = InMemoryKyberPreKeyStore();
      identityKeyPair = IdentityKeyPair.generate();

      final timestamp = DateTime.now().toUtc().millisecondsSinceEpoch;
      record1 = createKyberPreKey(
        id: 1,
        timestamp: timestamp,
        identityKeyPair: identityKeyPair,
      );
      record2 = createKyberPreKey(
        id: 2,
        timestamp: timestamp,
        identityKeyPair: identityKeyPair,
      );
    });

    tearDown(() {
      identityKeyPair.dispose();
      record1.dispose();
      record2.dispose();
    });

    group('initial state', () {
      test('is empty initially', () {
        expect(store.length, equals(0));
      });

      test('loadKyberPreKey returns null for non-existent key', () async {
        final record = await store.loadKyberPreKey(1);
        expect(record, isNull);
      });

      test('containsKyberPreKey returns false for non-existent key', () async {
        final contains = await store.containsKyberPreKey(1);
        expect(contains, isFalse);
      });

      test('getAllKyberPreKeyIds returns empty list', () async {
        final ids = await store.getAllKyberPreKeyIds();
        expect(ids, isEmpty);
      });
    });

    group('storeKyberPreKey() / loadKyberPreKey()', () {
      test('stores and loads Kyber pre-key', () async {
        await store.storeKyberPreKey(1, record1);

        final loaded = await store.loadKyberPreKey(1);
        expect(loaded, isNotNull);
        expect(loaded!.id, equals(1));

        loaded.dispose();
      });

      test('stores multiple Kyber pre-keys', () async {
        await store.storeKyberPreKey(1, record1);
        await store.storeKyberPreKey(2, record2);

        final loaded1 = await store.loadKyberPreKey(1);
        final loaded2 = await store.loadKyberPreKey(2);

        expect(loaded1, isNotNull);
        expect(loaded2, isNotNull);
        expect(loaded1!.id, equals(1));
        expect(loaded2!.id, equals(2));

        loaded1.dispose();
        loaded2.dispose();
      });

      test('overwrites existing Kyber pre-key', () async {
        await store.storeKyberPreKey(1, record1);

        final newRecord = createKyberPreKey(
          id: 1,
          timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
          identityKeyPair: identityKeyPair,
        );
        await store.storeKyberPreKey(1, newRecord);

        final loaded = await store.loadKyberPreKey(1);
        expect(loaded, isNotNull);
        expect(loaded!.id, equals(1));
        expect(loaded.serialize(), equals(newRecord.serialize()));

        loaded.dispose();
        newRecord.dispose();
      });
    });

    group('containsKyberPreKey()', () {
      test('returns true for stored key', () async {
        await store.storeKyberPreKey(1, record1);

        final contains = await store.containsKyberPreKey(1);
        expect(contains, isTrue);
      });

      test('returns false after removal', () async {
        await store.storeKyberPreKey(1, record1);
        await store.removeKyberPreKey(1);

        final contains = await store.containsKyberPreKey(1);
        expect(contains, isFalse);
      });
    });

    group('markKyberPreKeyUsed()', () {
      test('marks key as used', () async {
        await store.storeKyberPreKey(1, record1);
        await store.markKyberPreKeyUsed(1);

        expect(store.isKyberPreKeyUsed(1), isTrue);
      });

      test('marking non-existent key is safe', () async {
        await expectLater(store.markKyberPreKeyUsed(999), completes);
      });

      test('key is not used before marking', () async {
        await store.storeKyberPreKey(1, record1);

        expect(store.isKyberPreKeyUsed(1), isFalse);
      });

      test('used status is cleared when key is removed', () async {
        await store.storeKyberPreKey(1, record1);
        await store.markKyberPreKeyUsed(1);
        await store.removeKyberPreKey(1);

        expect(store.isKyberPreKeyUsed(1), isFalse);
      });
    });

    group('removeKyberPreKey()', () {
      test('removes stored key', () async {
        await store.storeKyberPreKey(1, record1);
        await store.removeKyberPreKey(1);

        final loaded = await store.loadKyberPreKey(1);
        expect(loaded, isNull);
        expect(store.length, equals(0));
      });

      test('removing non-existent key is safe', () async {
        await expectLater(store.removeKyberPreKey(999), completes);
      });

      test('removes only specified key', () async {
        await store.storeKyberPreKey(1, record1);
        await store.storeKyberPreKey(2, record2);
        await store.removeKyberPreKey(1);

        expect(await store.loadKyberPreKey(1), isNull);
        expect(await store.loadKyberPreKey(2), isNotNull);

        final loaded2 = await store.loadKyberPreKey(2);
        loaded2?.dispose();
      });
    });

    group('getAllKyberPreKeyIds()', () {
      test('returns all stored IDs', () async {
        await store.storeKyberPreKey(1, record1);
        await store.storeKyberPreKey(2, record2);

        final ids = await store.getAllKyberPreKeyIds();
        expect(ids, containsAll([1, 2]));
        expect(ids.length, equals(2));
      });

      test('updates after removals', () async {
        await store.storeKyberPreKey(1, record1);
        await store.storeKyberPreKey(2, record2);
        await store.removeKyberPreKey(1);

        final ids = await store.getAllKyberPreKeyIds();
        expect(ids, contains(2));
        expect(ids, isNot(contains(1)));
      });
    });

    group('clear()', () {
      test('clears all Kyber pre-keys', () async {
        await store.storeKyberPreKey(1, record1);
        await store.storeKyberPreKey(2, record2);

        store.clear();

        expect(store.length, equals(0));
        expect(await store.loadKyberPreKey(1), isNull);
        expect(await store.loadKyberPreKey(2), isNull);
      });

      test('clears used status tracking', () async {
        await store.storeKyberPreKey(1, record1);
        await store.markKyberPreKeyUsed(1);

        store.clear();

        expect(store.isKyberPreKeyUsed(1), isFalse);
      });

      test('clear on empty store is safe', () {
        expect(() => store.clear(), returnsNormally);
        expect(store.length, equals(0));
      });
    });

    group('length', () {
      test('tracks number of stored Kyber pre-keys', () async {
        expect(store.length, equals(0));

        await store.storeKyberPreKey(1, record1);
        expect(store.length, equals(1));

        await store.storeKyberPreKey(2, record2);
        expect(store.length, equals(2));
      });

      test('updates after removal', () async {
        await store.storeKyberPreKey(1, record1);
        await store.storeKyberPreKey(2, record2);
        await store.removeKyberPreKey(1);

        expect(store.length, equals(1));
      });

      test('does not change for overwrites', () async {
        await store.storeKyberPreKey(1, record1);
        expect(store.length, equals(1));

        await store.storeKyberPreKey(1, record2);
        expect(store.length, equals(1));
      });
    });

    group('various key IDs', () {
      test('handles ID 0', () async {
        final record = createKyberPreKey(
          id: 0,
          timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
          identityKeyPair: identityKeyPair,
        );

        await store.storeKyberPreKey(0, record);
        expect(await store.containsKyberPreKey(0), isTrue);

        final loaded = await store.loadKyberPreKey(0);
        expect(loaded, isNotNull);
        expect(loaded!.id, equals(0));

        loaded.dispose();
        record.dispose();
      });

      test('handles large IDs', () async {
        final record = createKyberPreKey(
          id: 0xFFFFFF,
          timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
          identityKeyPair: identityKeyPair,
        );

        await store.storeKyberPreKey(0xFFFFFF, record);
        expect(await store.containsKyberPreKey(0xFFFFFF), isTrue);

        final loaded = await store.loadKyberPreKey(0xFFFFFF);
        expect(loaded, isNotNull);
        expect(loaded!.id, equals(0xFFFFFF));

        loaded.dispose();
        record.dispose();
      });
    });
  });
}
