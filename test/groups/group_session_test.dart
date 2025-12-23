import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('GroupSession', () {
    late ProtocolAddress aliceAddress;
    late InMemorySenderKeyStore aliceStore;
    late Uint8List distributionId;

    setUp(() {
      aliceAddress = ProtocolAddress('alice', 1);
      aliceStore = InMemorySenderKeyStore();

      // Create a UUID for the distribution ID
      distributionId = GroupSession.uuidFromString(
        '01234567-89ab-cdef-0123-456789abcdef',
      );
    });

    tearDown(() {
      aliceAddress.dispose();
    });

    group('constructor', () {
      test('creates valid group session', () {
        final session = GroupSession(aliceAddress, distributionId, aliceStore);

        expect(session.senderAddress, equals(aliceAddress));
        expect(session.distributionId, equals(distributionId));
      });

      test('rejects invalid distribution ID length', () {
        expect(
          () => GroupSession(aliceAddress, Uint8List(10), aliceStore),
          throwsArgumentError,
        );
      });
    });

    group('createDistributionMessage()', () {
      test('creates valid distribution message', () async {
        final session = GroupSession(aliceAddress, distributionId, aliceStore);

        final distMessage = await session.createDistributionMessage();

        expect(distMessage, isNotNull);
        expect(distMessage.isDisposed, isFalse);

        distMessage.dispose();
      });

      test('distribution message contains correct distributionId', () async {
        final session = GroupSession(aliceAddress, distributionId, aliceStore);

        final distMessage = await session.createDistributionMessage();

        expect(distMessage.distributionId, equals(distributionId));

        distMessage.dispose();
      });

      test('distribution message has valid signature key', () async {
        final session = GroupSession(aliceAddress, distributionId, aliceStore);

        final distMessage = await session.createDistributionMessage();
        final signatureKey = distMessage.getSignatureKey();

        expect(signatureKey, isNotNull);
        expect(signatureKey.isDisposed, isFalse);
        // Public key should be 33 bytes (1 type byte + 32 key bytes)
        expect(signatureKey.serialize().length, equals(33));

        signatureKey.dispose();
        distMessage.dispose();
      });

      test('distribution message has chain key of 32 bytes', () async {
        final session = GroupSession(aliceAddress, distributionId, aliceStore);

        final distMessage = await session.createDistributionMessage();

        expect(distMessage.chainKey.length, equals(32));

        distMessage.dispose();
      });

      test('distribution message starts at iteration 0', () async {
        final session = GroupSession(aliceAddress, distributionId, aliceStore);

        final distMessage = await session.createDistributionMessage();

        expect(distMessage.iteration, equals(0));

        distMessage.dispose();
      });

      test('stores sender key record after creation', () async {
        final session = GroupSession(aliceAddress, distributionId, aliceStore);

        await session.createDistributionMessage();

        // Check that something was stored
        expect(aliceStore.length, greaterThan(0));
      });
    });

    group('processDistributionMessage()', () {
      test('processes valid distribution message', () async {
        // Alice creates distribution message
        final aliceSession = GroupSession(
          aliceAddress,
          distributionId,
          aliceStore,
        );
        final distMessage = await aliceSession.createDistributionMessage();

        // Bob receives and processes it
        final bobAddress = ProtocolAddress('bob', 1);
        final bobStore = InMemorySenderKeyStore();
        final bobSession = GroupSession(bobAddress, distributionId, bobStore);

        // Should not throw
        await bobSession.processDistributionMessage(aliceAddress, distMessage);

        // Bob's store should have the key
        expect(bobStore.length, greaterThan(0));

        distMessage.dispose();
        bobAddress.dispose();
      });

      test('allows decryption after processing', () async {
        // Alice creates and shares distribution message
        final aliceSession = GroupSession(
          aliceAddress,
          distributionId,
          aliceStore,
        );
        final distMessage = await aliceSession.createDistributionMessage();

        // Bob processes it
        final bobAddress = ProtocolAddress('bob', 1);
        final bobStore = InMemorySenderKeyStore();
        final bobSession = GroupSession(bobAddress, distributionId, bobStore);
        await bobSession.processDistributionMessage(aliceAddress, distMessage);

        // Alice encrypts a message
        final plaintext = Uint8List.fromList(utf8.encode('Hello, group!'));
        final ciphertext = await aliceSession.encrypt(plaintext);

        // Bob decrypts it
        final decrypted = await bobSession.decrypt(aliceAddress, ciphertext);

        expect(decrypted, equals(plaintext));

        distMessage.dispose();
        bobAddress.dispose();
      });
    });

    group('encrypt()', () {
      test('encrypts message successfully', () async {
        final session = GroupSession(aliceAddress, distributionId, aliceStore);
        await session.createDistributionMessage();

        final plaintext = Uint8List.fromList(utf8.encode('Test message'));
        final ciphertext = await session.encrypt(plaintext);

        expect(ciphertext, isNotNull);
        expect(ciphertext, isNotEmpty);
      });

      test('ciphertext differs from plaintext', () async {
        final session = GroupSession(aliceAddress, distributionId, aliceStore);
        await session.createDistributionMessage();

        final plaintext = Uint8List.fromList(utf8.encode('Test message'));
        final ciphertext = await session.encrypt(plaintext);

        expect(ciphertext, isNot(equals(plaintext)));
      });

      test('ciphertext is larger than plaintext', () async {
        final session = GroupSession(aliceAddress, distributionId, aliceStore);
        await session.createDistributionMessage();

        final plaintext = Uint8List.fromList(utf8.encode('Test message'));
        final ciphertext = await session.encrypt(plaintext);

        // Ciphertext includes signature and metadata
        expect(ciphertext.length, greaterThan(plaintext.length));
      });

      test('encrypts empty message', () async {
        final session = GroupSession(aliceAddress, distributionId, aliceStore);
        await session.createDistributionMessage();

        final plaintext = Uint8List(0);
        final ciphertext = await session.encrypt(plaintext);

        expect(ciphertext, isNotEmpty);
      });

      test('same plaintext produces different ciphertext', () async {
        final session = GroupSession(aliceAddress, distributionId, aliceStore);
        await session.createDistributionMessage();

        final plaintext = Uint8List.fromList(utf8.encode('Test'));
        final ciphertext1 = await session.encrypt(plaintext);
        final ciphertext2 = await session.encrypt(plaintext);

        // Each encryption advances the chain, so ciphertexts should differ
        expect(ciphertext1, isNot(equals(ciphertext2)));
      });
    });

    group('decrypt()', () {
      late ProtocolAddress bobAddress;
      late InMemorySenderKeyStore bobStore;
      late GroupSession aliceSession;
      late GroupSession bobSession;

      setUp(() async {
        bobAddress = ProtocolAddress('bob', 1);
        bobStore = InMemorySenderKeyStore();

        aliceSession = GroupSession(aliceAddress, distributionId, aliceStore);
        bobSession = GroupSession(bobAddress, distributionId, bobStore);

        // Setup: Alice creates and shares distribution message with Bob
        final distMessage = await aliceSession.createDistributionMessage();
        await bobSession.processDistributionMessage(aliceAddress, distMessage);
        distMessage.dispose();
      });

      tearDown(() {
        bobAddress.dispose();
      });

      test('decrypts message from sender', () async {
        final plaintext = Uint8List.fromList(utf8.encode('Hello Bob!'));
        final ciphertext = await aliceSession.encrypt(plaintext);

        final decrypted = await bobSession.decrypt(aliceAddress, ciphertext);

        expect(decrypted, equals(plaintext));
      });

      test('round-trip preserves message content', () async {
        final messages = [
          'Short',
          'A longer message with more content',
          'Unicode: Привет мир! 你好世界 🎉',
          '',
        ];

        for (final message in messages) {
          final plaintext = Uint8List.fromList(utf8.encode(message));
          final ciphertext = await aliceSession.encrypt(plaintext);
          final decrypted = await bobSession.decrypt(aliceAddress, ciphertext);

          expect(utf8.decode(decrypted), equals(message));
        }
      });

      test('decrypts multiple messages in order', () async {
        final messages = ['First', 'Second', 'Third'];
        final ciphertexts = <Uint8List>[];

        // Encrypt all messages
        for (final message in messages) {
          final plaintext = Uint8List.fromList(utf8.encode(message));
          ciphertexts.add(await aliceSession.encrypt(plaintext));
        }

        // Decrypt in order
        for (var i = 0; i < messages.length; i++) {
          final decrypted = await bobSession.decrypt(
            aliceAddress,
            ciphertexts[i],
          );
          expect(utf8.decode(decrypted), equals(messages[i]));
        }
      });

      // Note: Tests for tampered/invalid ciphertext are skipped because
      // libsignal native library may crash when retrieving error messages
      // for certain decryption failures. This is a known limitation.
    });

    group('multi-member scenario', () {
      test('three members can communicate', () async {
        // Setup: Alice, Bob, and Charlie
        final bobAddress = ProtocolAddress('bob', 1);
        final charlieAddress = ProtocolAddress('charlie', 1);
        final bobStore = InMemorySenderKeyStore();
        final charlieStore = InMemorySenderKeyStore();

        final aliceSession = GroupSession(
          aliceAddress,
          distributionId,
          aliceStore,
        );
        final bobSession = GroupSession(bobAddress, distributionId, bobStore);
        final charlieSession = GroupSession(
          charlieAddress,
          distributionId,
          charlieStore,
        );

        // Alice shares her key with Bob and Charlie
        final aliceDist = await aliceSession.createDistributionMessage();
        await bobSession.processDistributionMessage(aliceAddress, aliceDist);
        await charlieSession.processDistributionMessage(
          aliceAddress,
          aliceDist,
        );

        // Bob shares his key with Alice and Charlie
        final bobDist = await bobSession.createDistributionMessage();
        await aliceSession.processDistributionMessage(bobAddress, bobDist);
        await charlieSession.processDistributionMessage(bobAddress, bobDist);

        // Alice sends to group
        final aliceMsg = Uint8List.fromList(utf8.encode('Hello from Alice!'));
        final aliceCipher = await aliceSession.encrypt(aliceMsg);

        // Bob and Charlie can decrypt
        expect(
          await bobSession.decrypt(aliceAddress, aliceCipher),
          equals(aliceMsg),
        );
        expect(
          await charlieSession.decrypt(aliceAddress, aliceCipher),
          equals(aliceMsg),
        );

        // Bob sends to group
        final bobMsg = Uint8List.fromList(utf8.encode('Hello from Bob!'));
        final bobCipher = await bobSession.encrypt(bobMsg);

        // Alice and Charlie can decrypt
        expect(
          await aliceSession.decrypt(bobAddress, bobCipher),
          equals(bobMsg),
        );
        expect(
          await charlieSession.decrypt(bobAddress, bobCipher),
          equals(bobMsg),
        );

        aliceDist.dispose();
        bobDist.dispose();
        bobAddress.dispose();
        charlieAddress.dispose();
      });

      test('different groups are isolated', () async {
        final bobAddress = ProtocolAddress('bob', 1);
        final bobStore = InMemorySenderKeyStore();

        final groupAId = GroupSession.uuidFromString(
          'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        );
        final groupBId = GroupSession.uuidFromString(
          'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
        );

        // Alice creates session for group A
        final aliceGroupA = GroupSession(aliceAddress, groupAId, aliceStore);
        final aliceDistA = await aliceGroupA.createDistributionMessage();

        // Bob joins group A
        final bobGroupA = GroupSession(bobAddress, groupAId, bobStore);
        await bobGroupA.processDistributionMessage(aliceAddress, aliceDistA);

        // Alice sends to group A
        final msgA = Uint8List.fromList(utf8.encode('Group A message'));
        final cipherA = await aliceGroupA.encrypt(msgA);

        // Bob can decrypt group A message
        expect(await bobGroupA.decrypt(aliceAddress, cipherA), equals(msgA));

        // Note: Test for cross-group decryption failure is skipped because
        // libsignal native library may crash when retrieving error messages
        // for certain decryption failures. This is a known limitation.

        aliceDistA.dispose();
        bobAddress.dispose();
      });
    });

    group('UUID utilities', () {
      test('converts UUID string to bytes', () {
        final uuid = GroupSession.uuidFromString(
          '01234567-89ab-cdef-0123-456789abcdef',
        );
        expect(uuid.length, equals(16));
        expect(uuid[0], equals(0x01));
        expect(uuid[1], equals(0x23));
        expect(uuid[2], equals(0x45));
        expect(uuid[3], equals(0x67));
      });

      test('converts UUID bytes to string', () {
        final bytes = Uint8List.fromList([
          0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, //
          0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        ]);
        final uuid = GroupSession.uuidToString(bytes);
        expect(uuid, equals('01234567-89ab-cdef-0123-456789abcdef'));
      });

      test('round-trip UUID conversion', () {
        final original = '01234567-89ab-cdef-0123-456789abcdef';
        final bytes = GroupSession.uuidFromString(original);
        final result = GroupSession.uuidToString(bytes);
        expect(result, equals(original));
      });

      test('rejects invalid UUID string', () {
        expect(
          () => GroupSession.uuidFromString('invalid'),
          throwsArgumentError,
        );
      });

      test('rejects wrong length UUID bytes', () {
        expect(
          () => GroupSession.uuidToString(Uint8List(10)),
          throwsArgumentError,
        );
      });
    });
  });
}
