import 'dart:convert';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('Sender Key Message', () {
    late InMemorySenderKeyStore aliceSenderKeyStore;
    late InMemoryIdentityKeyStore aliceIdentityKeyStore;
    late InMemorySenderKeyStore bobSenderKeyStore;
    late InMemoryIdentityKeyStore bobIdentityKeyStore;
    late GroupCipher aliceCipher;
    late GroupCipher bobCipher;
    late ProtocolAddress aliceAddress;
    const distributionId = '00000000-0000-0000-0000-000000000001';

    setUp(() async {
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

      // Setup: Alice creates distribution message and Bob processes it
      final distMessage = await aliceCipher.createDistributionMessage(
        aliceAddress,
        distributionId,
      );
      await bobCipher.processDistributionMessage(
        aliceAddress,
        distributionId,
        distMessage,
      );
    });

    group('GroupCipher.encrypt', () {
      test('encrypts message', () async {
        const plaintext = 'Hello group!';
        final ciphertext = await aliceCipher.encrypt(
          aliceAddress,
          distributionId,
          utf8.encode(plaintext),
        );

        expect(ciphertext, isNotEmpty);
        expect(ciphertext.length, greaterThan(plaintext.length));
      });

      test('encrypted messages are different each time', () async {
        const plaintext = 'Same message';
        final ciphertext1 = await aliceCipher.encrypt(
          aliceAddress,
          distributionId,
          utf8.encode(plaintext),
        );
        final ciphertext2 = await aliceCipher.encrypt(
          aliceAddress,
          distributionId,
          utf8.encode(plaintext),
        );

        // Due to chain key ratcheting, same plaintext produces different ciphertext
        expect(ciphertext1, isNot(equals(ciphertext2)));
      });
    });

    group('GroupCipher.decrypt', () {
      test('decrypts message', () async {
        const plaintext = 'Hello from Alice!';
        final ciphertext = await aliceCipher.encrypt(
          aliceAddress,
          distributionId,
          utf8.encode(plaintext),
        );

        final decrypted = await bobCipher.decrypt(
          aliceAddress,
          distributionId,
          ciphertext,
        );

        expect(utf8.decode(decrypted), equals(plaintext));
      });

      test('decrypts multiple messages in order', () async {
        final messages = ['First', 'Second', 'Third'];
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
    });
  });
}
