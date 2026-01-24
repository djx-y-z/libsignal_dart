import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });
  tearDownAll(() => LibSignal.cleanup());

  group('GroupCipher', () {
    late InMemorySenderKeyStore aliceSenderKeyStore;
    late InMemoryIdentityKeyStore aliceIdentityKeyStore;
    late InMemorySenderKeyStore bobSenderKeyStore;
    late InMemoryIdentityKeyStore bobIdentityKeyStore;
    late GroupCipher aliceCipher;
    late GroupCipher bobCipher;
    late ProtocolAddress aliceAddress;
    late ProtocolAddress bobAddress;
    const distributionId = '00000000-0000-0000-0000-000000000001';

    setUp(() {
      // Create Alice's stores and cipher
      final aliceIdentityKeyPair = IdentityKeyPair.generate();
      aliceSenderKeyStore = InMemorySenderKeyStore();
      aliceIdentityKeyStore = InMemoryIdentityKeyStore(
        aliceIdentityKeyPair,
        11111,
      );
      aliceCipher = GroupCipher(
        senderKeyStore: aliceSenderKeyStore,
        identityKeyStore: aliceIdentityKeyStore,
      );
      aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);

      // Create Bob's stores and cipher
      final bobIdentityKeyPair = IdentityKeyPair.generate();
      bobSenderKeyStore = InMemorySenderKeyStore();
      bobIdentityKeyStore = InMemoryIdentityKeyStore(bobIdentityKeyPair, 22222);
      bobCipher = GroupCipher(
        senderKeyStore: bobSenderKeyStore,
        identityKeyStore: bobIdentityKeyStore,
      );
      bobAddress = ProtocolAddress(name: 'bob', deviceId: 1);
    });

    group('createDistributionMessage', () {
      test('creates distribution message', () async {
        final distMessage = await aliceCipher.createDistributionMessage(
          aliceAddress,
          distributionId,
        );

        expect(distMessage, isNotEmpty);
        // Distribution message should have reasonable size
        expect(distMessage.length, greaterThan(50));
      });

      test('creates consistent messages for same group', () async {
        // First distribution message
        final distMessage1 = await aliceCipher.createDistributionMessage(
          aliceAddress,
          distributionId,
        );

        // Second call should work (key exists now)
        final distMessage2 = await aliceCipher.createDistributionMessage(
          aliceAddress,
          distributionId,
        );

        // Messages may differ due to chain key ratcheting
        expect(distMessage1, isNotEmpty);
        expect(distMessage2, isNotEmpty);
      });
    });

    group('processDistributionMessage', () {
      test('processes distribution message', () async {
        // Alice creates distribution message
        final distMessage = await aliceCipher.createDistributionMessage(
          aliceAddress,
          distributionId,
        );

        // Bob processes it
        await bobCipher.processDistributionMessage(
          aliceAddress,
          distributionId,
          distMessage,
        );

        // Bob should now have Alice's sender key stored
        final senderKeyName = SenderKeyName(aliceAddress, distributionId);
        final storedKey = await bobSenderKeyStore.loadSenderKey(senderKeyName);
        expect(storedKey, isNotNull);
      });
    });

    group('encrypt / decrypt', () {
      test('encrypts and decrypts message', () async {
        // Alice creates distribution message
        final distMessage = await aliceCipher.createDistributionMessage(
          aliceAddress,
          distributionId,
        );

        // Bob processes it
        await bobCipher.processDistributionMessage(
          aliceAddress,
          distributionId,
          distMessage,
        );

        // Alice encrypts message
        const plaintext = 'Hello group!';
        final ciphertext = await aliceCipher.encrypt(
          aliceAddress,
          distributionId,
          utf8.encode(plaintext),
        );

        expect(ciphertext, isNotEmpty);
        expect(ciphertext.length, greaterThan(plaintext.length));

        // Bob decrypts message
        final decrypted = await bobCipher.decrypt(
          aliceAddress,
          distributionId,
          ciphertext,
        );

        expect(utf8.decode(decrypted), equals(plaintext));
      });

      test('handles multiple messages', () async {
        // Setup distribution
        final distMessage = await aliceCipher.createDistributionMessage(
          aliceAddress,
          distributionId,
        );
        await bobCipher.processDistributionMessage(
          aliceAddress,
          distributionId,
          distMessage,
        );

        // Send multiple messages
        final messages = ['First message', 'Second message', 'Third message'];
        for (final msg in messages) {
          final ciphertext = await aliceCipher.encrypt(
            aliceAddress,
            distributionId,
            utf8.encode(msg),
          );

          final decrypted = await bobCipher.decrypt(
            aliceAddress,
            distributionId,
            ciphertext,
          );

          expect(utf8.decode(decrypted), equals(msg));
        }
      });

      test('handles empty message', () async {
        final distMessage = await aliceCipher.createDistributionMessage(
          aliceAddress,
          distributionId,
        );
        await bobCipher.processDistributionMessage(
          aliceAddress,
          distributionId,
          distMessage,
        );

        final ciphertext = await aliceCipher.encrypt(
          aliceAddress,
          distributionId,
          [],
        );

        final decrypted = await bobCipher.decrypt(
          aliceAddress,
          distributionId,
          ciphertext,
        );

        expect(decrypted, isEmpty);
      });

      test('throws without distribution message', () async {
        // Try to decrypt without processing distribution message
        expect(
          () => bobCipher.decrypt(aliceAddress, distributionId, [
            0x12,
            0x34,
            0x56,
          ]),
          throwsA(anything),
        );
      });

      test('throws with garbage ciphertext', () async {
        final distMessage = await aliceCipher.createDistributionMessage(
          aliceAddress,
          distributionId,
        );
        await bobCipher.processDistributionMessage(
          aliceAddress,
          distributionId,
          distMessage,
        );

        expect(
          () => bobCipher.decrypt(aliceAddress, distributionId, [
            0x12,
            0x34,
            0x56,
          ]),
          throwsA(anything),
        );
      });
    });

    group('bidirectional communication', () {
      test('both parties can send and receive', () async {
        // Alice creates and shares her distribution message
        final aliceDistMessage = await aliceCipher.createDistributionMessage(
          aliceAddress,
          distributionId,
        );
        await bobCipher.processDistributionMessage(
          aliceAddress,
          distributionId,
          aliceDistMessage,
        );

        // Bob creates and shares his distribution message
        final bobDistMessage = await bobCipher.createDistributionMessage(
          bobAddress,
          distributionId,
        );
        await aliceCipher.processDistributionMessage(
          bobAddress,
          distributionId,
          bobDistMessage,
        );

        // Alice sends to Bob
        const aliceMessage = 'Hello Bob!';
        final aliceCiphertext = await aliceCipher.encrypt(
          aliceAddress,
          distributionId,
          utf8.encode(aliceMessage),
        );
        final decrypted1 = await bobCipher.decrypt(
          aliceAddress,
          distributionId,
          aliceCiphertext,
        );
        expect(utf8.decode(decrypted1), equals(aliceMessage));

        // Bob sends to Alice
        const bobMessage = 'Hello Alice!';
        final bobCiphertext = await bobCipher.encrypt(
          bobAddress,
          distributionId,
          utf8.encode(bobMessage),
        );
        final decrypted2 = await aliceCipher.decrypt(
          bobAddress,
          distributionId,
          bobCiphertext,
        );
        expect(utf8.decode(decrypted2), equals(bobMessage));
      });
    });

    group('multi-member scenario', () {
      late InMemorySenderKeyStore carolSenderKeyStore;
      late InMemoryIdentityKeyStore carolIdentityKeyStore;
      late GroupCipher carolCipher;
      late ProtocolAddress carolAddress;

      setUp(() {
        // Create Carol's stores and cipher
        final carolIdentityKeyPair = IdentityKeyPair.generate();
        carolSenderKeyStore = InMemorySenderKeyStore();
        carolIdentityKeyStore = InMemoryIdentityKeyStore(
          carolIdentityKeyPair,
          33333,
        );
        carolCipher = GroupCipher(
          senderKeyStore: carolSenderKeyStore,
          identityKeyStore: carolIdentityKeyStore,
        );
        carolAddress = ProtocolAddress(name: 'carol', deviceId: 1);
      });

      test('three members can communicate', () async {
        // Each member creates their distribution message
        final aliceDistMessage = await aliceCipher.createDistributionMessage(
          aliceAddress,
          distributionId,
        );
        final bobDistMessage = await bobCipher.createDistributionMessage(
          bobAddress,
          distributionId,
        );
        final carolDistMessage = await carolCipher.createDistributionMessage(
          carolAddress,
          distributionId,
        );

        // Each member processes others' distribution messages
        // Alice gets Bob's and Carol's keys
        await aliceCipher.processDistributionMessage(
          bobAddress,
          distributionId,
          bobDistMessage,
        );
        await aliceCipher.processDistributionMessage(
          carolAddress,
          distributionId,
          carolDistMessage,
        );

        // Bob gets Alice's and Carol's keys
        await bobCipher.processDistributionMessage(
          aliceAddress,
          distributionId,
          aliceDistMessage,
        );
        await bobCipher.processDistributionMessage(
          carolAddress,
          distributionId,
          carolDistMessage,
        );

        // Carol gets Alice's and Bob's keys
        await carolCipher.processDistributionMessage(
          aliceAddress,
          distributionId,
          aliceDistMessage,
        );
        await carolCipher.processDistributionMessage(
          bobAddress,
          distributionId,
          bobDistMessage,
        );

        // Alice sends a message
        const aliceMessage = 'Hello everyone!';
        final aliceCiphertext = await aliceCipher.encrypt(
          aliceAddress,
          distributionId,
          utf8.encode(aliceMessage),
        );

        // Bob and Carol both decrypt it
        final bobDecrypted = await bobCipher.decrypt(
          aliceAddress,
          distributionId,
          aliceCiphertext,
        );
        final carolDecrypted = await carolCipher.decrypt(
          aliceAddress,
          distributionId,
          aliceCiphertext,
        );

        expect(utf8.decode(bobDecrypted), equals(aliceMessage));
        expect(utf8.decode(carolDecrypted), equals(aliceMessage));

        // Bob sends a message
        const bobMessage = 'Hi from Bob!';
        final bobCiphertext = await bobCipher.encrypt(
          bobAddress,
          distributionId,
          utf8.encode(bobMessage),
        );

        // Alice and Carol both decrypt it
        final aliceDecrypted = await aliceCipher.decrypt(
          bobAddress,
          distributionId,
          bobCiphertext,
        );
        final carolDecrypted2 = await carolCipher.decrypt(
          bobAddress,
          distributionId,
          bobCiphertext,
        );

        expect(utf8.decode(aliceDecrypted), equals(bobMessage));
        expect(utf8.decode(carolDecrypted2), equals(bobMessage));
      });
    });

    group('result class equality', () {
      test('CreateSenderKeyDistributionResult equality', () {
        final dist1 = Uint8List.fromList([1, 2, 3]);
        final record1 = Uint8List.fromList([4, 5, 6]);

        final result1 = CreateSenderKeyDistributionResult(
          distributionMessage: dist1,
          senderKeyRecord: record1,
        );
        final result2 = CreateSenderKeyDistributionResult(
          distributionMessage: dist1,
          senderKeyRecord: record1,
        );

        expect(result1, equals(result2));
        expect(result1.hashCode, equals(result2.hashCode));

        // Test inequality with different distribution message
        final result3 = CreateSenderKeyDistributionResult(
          distributionMessage: Uint8List.fromList([7, 8, 9]),
          senderKeyRecord: record1,
        );
        expect(result1, isNot(equals(result3)));

        // Test self-equality
        expect(result1, equals(result1));
      });

      test('GroupDecryptResult equality', () {
        final plaintext1 = Uint8List.fromList([1, 2, 3]);
        final record1 = Uint8List.fromList([4, 5, 6]);

        final result1 = GroupDecryptResult(
          plaintext: plaintext1,
          senderKeyRecord: record1,
        );
        final result2 = GroupDecryptResult(
          plaintext: plaintext1,
          senderKeyRecord: record1,
        );

        expect(result1, equals(result2));
        expect(result1.hashCode, equals(result2.hashCode));

        // Test inequality with different plaintext
        final result3 = GroupDecryptResult(
          plaintext: Uint8List.fromList([7, 8, 9]),
          senderKeyRecord: record1,
        );
        expect(result1, isNot(equals(result3)));

        // Test self-equality
        expect(result1, equals(result1));
      });

      test('GroupEncryptResult equality', () {
        final ciphertext1 = Uint8List.fromList([1, 2, 3]);
        final record1 = Uint8List.fromList([4, 5, 6]);

        final result1 = GroupEncryptResult(
          ciphertext: ciphertext1,
          senderKeyRecord: record1,
        );
        final result2 = GroupEncryptResult(
          ciphertext: ciphertext1,
          senderKeyRecord: record1,
        );

        expect(result1, equals(result2));
        expect(result1.hashCode, equals(result2.hashCode));

        // Test inequality with different ciphertext
        final result3 = GroupEncryptResult(
          ciphertext: Uint8List.fromList([7, 8, 9]),
          senderKeyRecord: record1,
        );
        expect(result1, isNot(equals(result3)));

        // Test self-equality
        expect(result1, equals(result1));
      });

      test('equality returns false for wrong types', () {
        final result1 = CreateSenderKeyDistributionResult(
          distributionMessage: Uint8List.fromList([1, 2, 3]),
          senderKeyRecord: Uint8List.fromList([4, 5, 6]),
        );
        // ignore: unrelated_type_equality_checks
        expect(result1 == 'not a result', isFalse);
        // ignore: unrelated_type_equality_checks
        expect(result1 == 42, isFalse);

        final result2 = GroupDecryptResult(
          plaintext: Uint8List.fromList([1, 2, 3]),
          senderKeyRecord: Uint8List.fromList([4, 5, 6]),
        );
        // ignore: unrelated_type_equality_checks
        expect(result2 == 'not a result', isFalse);

        final result3 = GroupEncryptResult(
          ciphertext: Uint8List.fromList([1, 2, 3]),
          senderKeyRecord: Uint8List.fromList([4, 5, 6]),
        );
        // ignore: unrelated_type_equality_checks
        expect(result3 == 'not a result', isFalse);
      });
    });
  });
}
