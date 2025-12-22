import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('InMemorySenderKeyStore', () {
    late InMemorySenderKeyStore store;
    late ProtocolAddress aliceAddress;
    late ProtocolAddress bobAddress;
    late SenderKeyName aliceSenderKey1;
    late SenderKeyName aliceSenderKey2;
    late SenderKeyName bobSenderKey;
    late Uint8List record1;
    late Uint8List record2;

    setUp(() {
      store = InMemorySenderKeyStore();
      aliceAddress = ProtocolAddress('alice', 1);
      bobAddress = ProtocolAddress('bob', 1);
      aliceSenderKey1 = SenderKeyName(aliceAddress, 'group-1');
      aliceSenderKey2 = SenderKeyName(aliceAddress, 'group-2');
      bobSenderKey = SenderKeyName(bobAddress, 'group-1');
      record1 = randomBytes(100);
      record2 = randomBytes(100);
    });

    tearDown(() {
      aliceAddress.dispose();
      bobAddress.dispose();
    });

    group('initial state', () {
      test('is empty initially', () {
        expect(store.length, equals(0));
      });

      test('loadSenderKey returns null for non-existent key', () async {
        final record = await store.loadSenderKey(aliceSenderKey1);
        expect(record, isNull);
      });
    });

    group('storeSenderKey() / loadSenderKey()', () {
      test('stores and loads sender key', () async {
        await store.storeSenderKey(aliceSenderKey1, record1);

        final loaded = await store.loadSenderKey(aliceSenderKey1);
        expect(loaded, isNotNull);
        expect(loaded, equals(record1));
      });

      test('stores sender keys for same user different groups', () async {
        await store.storeSenderKey(aliceSenderKey1, record1);
        await store.storeSenderKey(aliceSenderKey2, record2);

        final loaded1 = await store.loadSenderKey(aliceSenderKey1);
        final loaded2 = await store.loadSenderKey(aliceSenderKey2);

        expect(loaded1, equals(record1));
        expect(loaded2, equals(record2));
      });

      test('stores sender keys for different users same group', () async {
        await store.storeSenderKey(aliceSenderKey1, record1);
        await store.storeSenderKey(bobSenderKey, record2);

        final loaded1 = await store.loadSenderKey(aliceSenderKey1);
        final loaded2 = await store.loadSenderKey(bobSenderKey);

        expect(loaded1, equals(record1));
        expect(loaded2, equals(record2));
      });

      test('overwrites existing sender key', () async {
        await store.storeSenderKey(aliceSenderKey1, record1);
        await store.storeSenderKey(aliceSenderKey1, record2);

        final loaded = await store.loadSenderKey(aliceSenderKey1);
        expect(loaded, equals(record2));
      });
    });

    group('clear()', () {
      test('clears all sender keys', () async {
        await store.storeSenderKey(aliceSenderKey1, record1);
        await store.storeSenderKey(bobSenderKey, record2);

        store.clear();

        expect(store.length, equals(0));
        expect(await store.loadSenderKey(aliceSenderKey1), isNull);
        expect(await store.loadSenderKey(bobSenderKey), isNull);
      });

      test('clear on empty store is safe', () {
        expect(() => store.clear(), returnsNormally);
        expect(store.length, equals(0));
      });
    });

    group('length', () {
      test('tracks number of stored sender keys', () async {
        expect(store.length, equals(0));

        await store.storeSenderKey(aliceSenderKey1, record1);
        expect(store.length, equals(1));

        await store.storeSenderKey(aliceSenderKey2, record2);
        expect(store.length, equals(2));

        await store.storeSenderKey(bobSenderKey, randomBytes(50));
        expect(store.length, equals(3));
      });

      test('does not change for overwrites', () async {
        await store.storeSenderKey(aliceSenderKey1, record1);
        expect(store.length, equals(1));

        await store.storeSenderKey(aliceSenderKey1, record2);
        expect(store.length, equals(1));
      });
    });

    group('SenderKeyName', () {
      test('equals works correctly', () {
        final addr1 = ProtocolAddress('alice', 1);
        final addr2 = ProtocolAddress('alice', 1);
        final addr3 = ProtocolAddress('bob', 1);

        final name1 = SenderKeyName(addr1, 'group-1');
        final name2 = SenderKeyName(addr2, 'group-1');
        final name3 = SenderKeyName(addr1, 'group-2');
        final name4 = SenderKeyName(addr3, 'group-1');

        expect(name1, equals(name2));
        expect(name1, isNot(equals(name3)));
        expect(name1, isNot(equals(name4)));

        addr1.dispose();
        addr2.dispose();
        addr3.dispose();
      });

      test('hashCode is consistent with equals', () {
        final addr1 = ProtocolAddress('alice', 1);
        final addr2 = ProtocolAddress('alice', 1);

        final name1 = SenderKeyName(addr1, 'group-1');
        final name2 = SenderKeyName(addr2, 'group-1');

        expect(name1.hashCode, equals(name2.hashCode));

        addr1.dispose();
        addr2.dispose();
      });

      test('toString returns readable representation', () {
        final addr = ProtocolAddress('alice', 1);
        final name = SenderKeyName(addr, 'group-1');

        final str = name.toString();
        // ProtocolAddress now redacts names longer than 4 chars
        expect(str, contains('alic')); // First 4 chars visible
        expect(str, contains('group-1'));

        addr.dispose();
      });
    });

    group('different device IDs', () {
      test('treats different device IDs as separate keys', () async {
        final alice1 = ProtocolAddress('alice', 1);
        final alice2 = ProtocolAddress('alice', 2);

        final name1 = SenderKeyName(alice1, 'group-1');
        final name2 = SenderKeyName(alice2, 'group-1');

        await store.storeSenderKey(name1, record1);
        await store.storeSenderKey(name2, record2);

        expect(await store.loadSenderKey(name1), equals(record1));
        expect(await store.loadSenderKey(name2), equals(record2));
        expect(store.length, equals(2));

        alice1.dispose();
        alice2.dispose();
      });
    });

    group('edge cases', () {
      test('handles empty distribution ID', () async {
        final name = SenderKeyName(aliceAddress, '');

        await store.storeSenderKey(name, record1);

        final loaded = await store.loadSenderKey(name);
        expect(loaded, equals(record1));
      });

      test('handles empty record', () async {
        final emptyRecord = Uint8List(0);

        await store.storeSenderKey(aliceSenderKey1, emptyRecord);

        final loaded = await store.loadSenderKey(aliceSenderKey1);
        expect(loaded, equals(emptyRecord));
        expect(loaded!.isEmpty, isTrue);
      });

      test('handles large records', () async {
        final largeRecord = randomBytes(10000);

        await store.storeSenderKey(aliceSenderKey1, largeRecord);

        final loaded = await store.loadSenderKey(aliceSenderKey1);
        expect(loaded, equals(largeRecord));
      });
    });
  });
}
