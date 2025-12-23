import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('SenderKeyRecord', () {
    late ProtocolAddress senderAddress;
    late InMemorySenderKeyStore store;
    late Uint8List distributionId;
    late GroupSession session;
    late Uint8List recordBytes;

    setUp(() async {
      senderAddress = ProtocolAddress('sender', 1);
      store = InMemorySenderKeyStore();
      distributionId = GroupSession.uuidFromString(
        '01234567-89ab-cdef-0123-456789abcdef',
      );
      session = GroupSession(senderAddress, distributionId, store);

      // Create a distribution message to populate the store with a record
      final distMessage = await session.createDistributionMessage();
      distMessage.dispose();

      // Get the serialized record from the store
      final senderKeyName = SenderKeyName(
        senderAddress,
        GroupSession.uuidToString(distributionId),
      );
      recordBytes = (await store.loadSenderKey(senderKeyName))!;
    });

    tearDown(() {
      senderAddress.dispose();
    });

    group('deserialize()', () {
      test('rejects empty data', () {
        expect(
          () => SenderKeyRecord.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects garbage data', () {
        final garbage = Uint8List.fromList([0x99, 0x88, 0x77, 0x66, 0x55]);
        expect(
          () => SenderKeyRecord.deserialize(garbage),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('accepts valid record bytes', () {
        final record = SenderKeyRecord.deserialize(recordBytes);

        expect(record, isNotNull);
        expect(record.isDisposed, isFalse);

        record.dispose();
      });
    });

    group('serialize() / deserialize()', () {
      test('serializes to non-empty bytes', () {
        final record = SenderKeyRecord.deserialize(recordBytes);
        final serialized = record.serialize();

        expect(serialized, isNotEmpty);

        record.dispose();
      });

      test('round-trip preserves record', () {
        final original = SenderKeyRecord.deserialize(recordBytes);
        final serialized = original.serialize();
        final restored = SenderKeyRecord.deserialize(serialized);

        // Both should serialize to the same bytes
        expect(restored.serialize(), equals(original.serialize()));

        original.dispose();
        restored.dispose();
      });

      test('multiple round-trips are stable', () {
        var record = SenderKeyRecord.deserialize(recordBytes);

        for (var i = 0; i < 5; i++) {
          final serialized = record.serialize();
          record.dispose();
          record = SenderKeyRecord.deserialize(serialized);
        }

        // Should still be valid after multiple round-trips
        expect(record.serialize(), isNotEmpty);

        record.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final original = SenderKeyRecord.deserialize(recordBytes);
        final cloned = original.clone();

        expect(cloned, isNotNull);
        expect(cloned.isDisposed, isFalse);

        // Original should still be usable after disposing clone
        cloned.dispose();
        expect(cloned.isDisposed, isTrue);
        expect(original.isDisposed, isFalse);
        expect(original.serialize(), isNotEmpty);

        original.dispose();
      });

      test('cloned record serializes to same bytes', () {
        final original = SenderKeyRecord.deserialize(recordBytes);
        final cloned = original.clone();

        expect(cloned.serialize(), equals(original.serialize()));

        original.dispose();
        cloned.dispose();
      });

      test('modifications to clone do not affect original', () {
        final original = SenderKeyRecord.deserialize(recordBytes);
        final originalSerialized = original.serialize();
        final cloned = original.clone();

        // Dispose the clone
        cloned.dispose();

        // Original should still serialize the same
        expect(original.serialize(), equals(originalSerialized));

        original.dispose();
      });
    });

    group('dispose()', () {
      test('marks record as disposed', () {
        final record = SenderKeyRecord.deserialize(recordBytes);
        expect(record.isDisposed, isFalse);

        record.dispose();

        expect(record.isDisposed, isTrue);
      });

      test('accessing disposed record throws StateError', () {
        final record = SenderKeyRecord.deserialize(recordBytes);
        record.dispose();

        expect(() => record.serialize(), throwsA(isA<LibSignalException>()));
        expect(() => record.clone(), throwsA(isA<LibSignalException>()));
        expect(() => record.pointer, throwsA(isA<LibSignalException>()));
      });

      test('double dispose is safe', () {
        final record = SenderKeyRecord.deserialize(recordBytes);

        record.dispose();
        expect(() => record.dispose(), returnsNormally);
      });
    });

    group('usage with GroupSession', () {
      test('record is updated after encryption', () async {
        // Get initial record
        final senderKeyName = SenderKeyName(
          senderAddress,
          GroupSession.uuidToString(distributionId),
        );
        final initialBytes = await store.loadSenderKey(senderKeyName);

        // Encrypt a message
        final plaintext = Uint8List.fromList([1, 2, 3, 4, 5]);
        await session.encrypt(plaintext);

        // Get updated record
        final updatedBytes = await store.loadSenderKey(senderKeyName);

        // Record should have changed (chain advanced)
        expect(updatedBytes, isNot(equals(initialBytes)));
      });

      test('record can be restored to continue encryption', () async {
        // Create a new session with the saved record
        final newStore = InMemorySenderKeyStore();
        final senderKeyName = SenderKeyName(
          senderAddress,
          GroupSession.uuidToString(distributionId),
        );

        // Copy the record to the new store
        await newStore.storeSenderKey(senderKeyName, recordBytes);

        // Create a new session using the new store
        final newSession = GroupSession(
          senderAddress,
          distributionId,
          newStore,
        );

        // Should be able to encrypt with the restored state
        final plaintext = Uint8List.fromList([1, 2, 3, 4, 5]);
        final ciphertext = await newSession.encrypt(plaintext);

        expect(ciphertext, isNotEmpty);
      });
    });
  });
}
