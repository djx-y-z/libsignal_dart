import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('InMemorySignedPreKeyStore', () {
    late InMemorySignedPreKeyStore store;
    late IdentityKeyPair identityKeyPair;
    late SignedPreKeyRecord record1;
    late SignedPreKeyRecord record2;

    /// Helper to create a signed pre-key record with valid signature
    SignedPreKeyRecord createSignedPreKey({
      required int id,
      required int timestamp,
      required IdentityKeyPair identityKeyPair,
    }) {
      final privateKey = PrivateKey.generate();
      final publicKey = privateKey.getPublicKey();
      final signature = identityKeyPair.privateKey.sign(publicKey.serialize());

      final signedPreKey = SignedPreKeyRecord.create(
        id: id,
        timestamp: timestamp,
        publicKey: publicKey,
        privateKey: privateKey,
        signature: signature,
      );

      privateKey.dispose();
      publicKey.dispose();

      return signedPreKey;
    }

    setUp(() {
      store = InMemorySignedPreKeyStore();
      identityKeyPair = IdentityKeyPair.generate();

      final timestamp = DateTime.now().toUtc().millisecondsSinceEpoch;
      record1 = createSignedPreKey(
        id: 1,
        timestamp: timestamp,
        identityKeyPair: identityKeyPair,
      );
      record2 = createSignedPreKey(
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

      test('loadSignedPreKey returns null for non-existent key', () async {
        final record = await store.loadSignedPreKey(1);
        expect(record, isNull);
      });

      test('containsSignedPreKey returns false for non-existent key', () async {
        final contains = await store.containsSignedPreKey(1);
        expect(contains, isFalse);
      });

      test('getAllSignedPreKeyIds returns empty list', () async {
        final ids = await store.getAllSignedPreKeyIds();
        expect(ids, isEmpty);
      });
    });

    group('storeSignedPreKey() / loadSignedPreKey()', () {
      test('stores and loads signed pre-key', () async {
        await store.storeSignedPreKey(1, record1);

        final loaded = await store.loadSignedPreKey(1);
        expect(loaded, isNotNull);
        expect(loaded!.id, equals(1));

        loaded.dispose();
      });

      test('stores multiple signed pre-keys', () async {
        await store.storeSignedPreKey(1, record1);
        await store.storeSignedPreKey(2, record2);

        final loaded1 = await store.loadSignedPreKey(1);
        final loaded2 = await store.loadSignedPreKey(2);

        expect(loaded1, isNotNull);
        expect(loaded2, isNotNull);
        expect(loaded1!.id, equals(1));
        expect(loaded2!.id, equals(2));

        loaded1.dispose();
        loaded2.dispose();
      });

      test('overwrites existing signed pre-key', () async {
        await store.storeSignedPreKey(1, record1);

        final newRecord = createSignedPreKey(
          id: 1,
          timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
          identityKeyPair: identityKeyPair,
        );
        await store.storeSignedPreKey(1, newRecord);

        final loaded = await store.loadSignedPreKey(1);
        expect(loaded, isNotNull);
        expect(loaded!.id, equals(1));
        expect(
          loaded.serialize(),
          equals(newRecord.serialize()),
        );

        loaded.dispose();
        newRecord.dispose();
      });
    });

    group('containsSignedPreKey()', () {
      test('returns true for stored key', () async {
        await store.storeSignedPreKey(1, record1);

        final contains = await store.containsSignedPreKey(1);
        expect(contains, isTrue);
      });

      test('returns false after removal', () async {
        await store.storeSignedPreKey(1, record1);
        await store.removeSignedPreKey(1);

        final contains = await store.containsSignedPreKey(1);
        expect(contains, isFalse);
      });
    });

    group('removeSignedPreKey()', () {
      test('removes stored key', () async {
        await store.storeSignedPreKey(1, record1);
        await store.removeSignedPreKey(1);

        final loaded = await store.loadSignedPreKey(1);
        expect(loaded, isNull);
        expect(store.length, equals(0));
      });

      test('removing non-existent key is safe', () async {
        await expectLater(
          store.removeSignedPreKey(999),
          completes,
        );
      });

      test('removes only specified key', () async {
        await store.storeSignedPreKey(1, record1);
        await store.storeSignedPreKey(2, record2);
        await store.removeSignedPreKey(1);

        expect(await store.loadSignedPreKey(1), isNull);
        expect(await store.loadSignedPreKey(2), isNotNull);

        final loaded2 = await store.loadSignedPreKey(2);
        loaded2?.dispose();
      });
    });

    group('getAllSignedPreKeyIds()', () {
      test('returns all stored IDs', () async {
        await store.storeSignedPreKey(1, record1);
        await store.storeSignedPreKey(2, record2);

        final ids = await store.getAllSignedPreKeyIds();
        expect(ids, containsAll([1, 2]));
        expect(ids.length, equals(2));
      });

      test('updates after removals', () async {
        await store.storeSignedPreKey(1, record1);
        await store.storeSignedPreKey(2, record2);
        await store.removeSignedPreKey(1);

        final ids = await store.getAllSignedPreKeyIds();
        expect(ids, contains(2));
        expect(ids, isNot(contains(1)));
      });
    });

    group('clear()', () {
      test('clears all signed pre-keys', () async {
        await store.storeSignedPreKey(1, record1);
        await store.storeSignedPreKey(2, record2);

        store.clear();

        expect(store.length, equals(0));
        expect(await store.loadSignedPreKey(1), isNull);
        expect(await store.loadSignedPreKey(2), isNull);
      });

      test('clear on empty store is safe', () {
        expect(() => store.clear(), returnsNormally);
        expect(store.length, equals(0));
      });
    });

    group('length', () {
      test('tracks number of stored signed pre-keys', () async {
        expect(store.length, equals(0));

        await store.storeSignedPreKey(1, record1);
        expect(store.length, equals(1));

        await store.storeSignedPreKey(2, record2);
        expect(store.length, equals(2));
      });

      test('updates after removal', () async {
        await store.storeSignedPreKey(1, record1);
        await store.storeSignedPreKey(2, record2);
        await store.removeSignedPreKey(1);

        expect(store.length, equals(1));
      });

      test('does not change for overwrites', () async {
        await store.storeSignedPreKey(1, record1);
        expect(store.length, equals(1));

        await store.storeSignedPreKey(1, record2);
        expect(store.length, equals(1));
      });
    });

    group('various key IDs', () {
      test('handles ID 0', () async {
        final record = createSignedPreKey(
          id: 0,
          timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
          identityKeyPair: identityKeyPair,
        );

        await store.storeSignedPreKey(0, record);
        expect(await store.containsSignedPreKey(0), isTrue);

        final loaded = await store.loadSignedPreKey(0);
        expect(loaded, isNotNull);
        expect(loaded!.id, equals(0));

        loaded.dispose();
        record.dispose();
      });

      test('handles large IDs', () async {
        final record = createSignedPreKey(
          id: 0xFFFFFF,
          timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
          identityKeyPair: identityKeyPair,
        );

        await store.storeSignedPreKey(0xFFFFFF, record);
        expect(await store.containsSignedPreKey(0xFFFFFF), isTrue);

        final loaded = await store.loadSignedPreKey(0xFFFFFF);
        expect(loaded, isNotNull);
        expect(loaded!.id, equals(0xFFFFFF));

        loaded.dispose();
        record.dispose();
      });
    });
  });
}
