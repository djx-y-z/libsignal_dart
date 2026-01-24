import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });
  tearDownAll(() => LibSignal.cleanup());

  // Note: The FRB API manages sender key records as raw byte arrays
  // through the SenderKeyStore interface. The SenderKeyRecord class
  // from the old Dart wrapper API no longer exists.

  group('Sender Key Record', () {
    group('InMemorySenderKeyStore usage', () {
      test('stores and retrieves sender key data', () async {
        final store = InMemorySenderKeyStore();
        final address = ProtocolAddress(name: 'sender', deviceId: 1);
        final senderKeyName = SenderKeyName(address, 'group-123');
        final recordData = Uint8List.fromList([1, 2, 3, 4, 5]);

        await store.storeSenderKey(senderKeyName, recordData);
        final loaded = await store.loadSenderKey(senderKeyName);

        expect(loaded, equals(recordData));
      });

      test('returns null for non-existent sender key', () async {
        final store = InMemorySenderKeyStore();
        final address = ProtocolAddress(name: 'unknown', deviceId: 1);
        final senderKeyName = SenderKeyName(address, 'group-123');

        final loaded = await store.loadSenderKey(senderKeyName);
        expect(loaded, isNull);
      });

      test('overwrites existing sender key', () async {
        final store = InMemorySenderKeyStore();
        final address = ProtocolAddress(name: 'sender', deviceId: 1);
        final senderKeyName = SenderKeyName(address, 'group-123');

        final data1 = Uint8List.fromList([1, 2, 3]);
        final data2 = Uint8List.fromList([4, 5, 6, 7]);

        await store.storeSenderKey(senderKeyName, data1);
        await store.storeSenderKey(senderKeyName, data2);

        final loaded = await store.loadSenderKey(senderKeyName);
        expect(loaded, equals(data2));
      });

      test('different groups have separate sender keys', () async {
        final store = InMemorySenderKeyStore();
        final address = ProtocolAddress(name: 'sender', deviceId: 1);
        final group1 = SenderKeyName(address, 'group-1');
        final group2 = SenderKeyName(address, 'group-2');

        final data1 = Uint8List.fromList([1, 1, 1]);
        final data2 = Uint8List.fromList([2, 2, 2]);

        await store.storeSenderKey(group1, data1);
        await store.storeSenderKey(group2, data2);

        expect(await store.loadSenderKey(group1), equals(data1));
        expect(await store.loadSenderKey(group2), equals(data2));
      });

      test('different senders have separate sender keys', () async {
        final store = InMemorySenderKeyStore();
        final address1 = ProtocolAddress(name: 'sender1', deviceId: 1);
        final address2 = ProtocolAddress(name: 'sender2', deviceId: 1);
        final senderKey1 = SenderKeyName(address1, 'group-123');
        final senderKey2 = SenderKeyName(address2, 'group-123');

        final data1 = Uint8List.fromList([1, 1, 1]);
        final data2 = Uint8List.fromList([2, 2, 2]);

        await store.storeSenderKey(senderKey1, data1);
        await store.storeSenderKey(senderKey2, data2);

        expect(await store.loadSenderKey(senderKey1), equals(data1));
        expect(await store.loadSenderKey(senderKey2), equals(data2));
      });
    });
  });
}
