import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';

import '../support/harness.dart';
import '../support/party.dart';

void messageCapabilities() {
  group('messages', () {
    capability('PreKeySignalMessage parses', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await establish(alice, bob);
      final sent = await alice.cipher.encrypt(bob.address, bytesOf('hello'));

      final message = PreKeySignalMessage.deserialize(data: sent.ciphertext);
      expect(message.serialize(), sent.ciphertext);
      expect(message.cloneMessage().serialize(), sent.ciphertext);
      expect(message.registrationId(), 1111);
      expect(message.identityKey(), alice.identity.publicKey);
      expect(message.preKeyId(), 42);
      expect(message.signedPreKeyId(), 7);
      expect(message.kyberPreKeyId(), 3);
      expect(message.kyberCiphertext(), isNotEmpty);
      expect(message.baseKey(), hasLength(33));
      expect(message.messageVersion(), greaterThanOrEqualTo(4));
      expect(message.message().body(), isNotEmpty);
    });

    capability('SignalMessage parses', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await converse(alice, bob);
      final sent = await alice.cipher.encrypt(bob.address, bytesOf('hello'));

      final message = SignalMessage.deserialize(data: sent.ciphertext);
      expect(message.serialize(), sent.ciphertext);
      expect(message.cloneMessage().serialize(), sent.ciphertext);
      expect(message.body(), isNotEmpty);
      expect(message.counter(), isNonNegative);
      expect(message.messageVersion(), greaterThanOrEqualTo(4));
      expect(message.senderRatchetKey(), hasLength(33));
      expect(
        message.verifyMac(
          senderAddressName: 'alice',
          senderAddressDeviceId: 1,
          recipientAddressName: 'bob',
          recipientAddressDeviceId: 1,
          senderIdentityKey: alice.identity.publicKey,
          receiverIdentityKey: bob.identity.publicKey,
          macKey: List.filled(32, 7),
        ),
        isFalse,
        reason: 'not the key this message was authenticated with',
      );
    });

    capability('DecryptionErrorMessage carries a resend request', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await converse(alice, bob);
      final sent = await alice.cipher.encrypt(bob.address, bytesOf('lost'));

      final timestamp = nowMillis();
      final request = DecryptionErrorMessage.forOriginalMessage(
        originalBytes: sent.ciphertext,
        messageType: CiphertextMessageType.signal.value,
        timestamp: timestamp,
        originalSenderDeviceId: 1,
      );
      expect(request.timestamp(), timestamp);
      expect(request.deviceId(), 1);
      expect(
        request.ratchetKey(),
        SignalMessage.deserialize(data: sent.ciphertext).senderRatchetKey(),
      );
      expect(
        DecryptionErrorMessage.deserialize(
          bytes: request.serialize(),
        ).serialize(),
        request.serialize(),
      );
      expect(request.cloneMessage().serialize(), request.serialize());

      final content = PlaintextContent.fromDecryptionErrorMessage(
        message: request,
      );
      expect(content.cloneMessage().serialize(), content.serialize());
      expect(
        PlaintextContent.deserialize(data: content.serialize()).body(),
        content.body(),
      );
      expect(
        DecryptionErrorMessage.extractFromSerializedContent(
          bytes: content.body(),
        ).serialize(),
        request.serialize(),
      );
    });

    capability('CiphertextMessage reads the wire types', () async {
      final message = CiphertextMessage.fromRaw(
        messageType: 3,
        ciphertext: bytesOf('body'),
      );
      expect(message.type, CiphertextMessageType.preKey);
      expect(message.isPreKeyMessage, isTrue);
      expect(
        CiphertextMessageType.fromValue(7),
        CiphertextMessageType.senderKey,
      );
      expect(
        CiphertextMessageType.fromValue(8),
        CiphertextMessageType.plaintextContent,
      );
      expect(() => CiphertextMessageType.fromValue(99), throwsArgumentError);
    });
  });
}
