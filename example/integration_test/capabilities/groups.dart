import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';

import '../support/harness.dart';
import '../support/party.dart';

const _distributionId = '01234567-89ab-cdef-0123-456789abcdef';

void groupCapabilities() {
  group('groups', () {
    capability('GroupCipher delivers to every member', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      final carol = Party('carol', 3333);

      final distribution = await alice.group.createDistributionMessage(
        alice.address,
        _distributionId,
      );
      for (final member in [bob, carol]) {
        await member.group.processDistributionMessage(
          alice.address,
          _distributionId,
          distribution,
        );
      }

      for (var i = 0; i < 3; i++) {
        final sent = await alice.group.encrypt(
          alice.address,
          _distributionId,
          bytesOf('message $i'),
        );
        for (final member in [bob, carol]) {
          expect(
            utf8.decode(
              await member.group.decrypt(alice.address, _distributionId, sent),
            ),
            'message $i',
          );
        }
      }
    });

    capability('a stranger cannot read the group', () async {
      final alice = Party('alice', 1111);
      final mallory = Party('mallory', 4444);
      await alice.group.createDistributionMessage(
        alice.address,
        _distributionId,
      );
      final sent = await alice.group.encrypt(
        alice.address,
        _distributionId,
        bytesOf('private'),
      );

      await expectLater(
        mallory.group.decrypt(alice.address, _distributionId, sent),
        throwsA(isA<LibSignalException>()),
      );
    });

    capability('the group messages parse', () async {
      final alice = Party('alice', 1111);
      final distribution = await alice.group.createDistributionMessage(
        alice.address,
        _distributionId,
      );

      final parsedDistribution = SenderKeyDistributionMessage.deserialize(
        data: distribution,
      );
      expect(parsedDistribution.distributionId(), _distributionId);
      expect(parsedDistribution.iteration(), 0);
      expect(parsedDistribution.chainId(), isNonNegative);
      expect(parsedDistribution.messageVersion(), isPositive);
      expect(parsedDistribution.signingKey(), hasLength(33));
      expect(parsedDistribution.serialize(), distribution);
      expect(parsedDistribution.cloneMessage().serialize(), distribution);

      final sent = await alice.group.encrypt(
        alice.address,
        _distributionId,
        bytesOf('signed'),
      );
      final parsed = SenderKeyMessage.deserialize(data: sent);
      expect(parsed.distributionId(), _distributionId);
      expect(parsed.chainId(), parsedDistribution.chainId());
      expect(parsed.iteration(), 0);
      expect(parsed.messageVersion(), isPositive);
      expect(parsed.ciphertext(), isNotEmpty);
      expect(parsed.serialize(), sent);
      expect(parsed.cloneMessage().serialize(), sent);
      expect(
        parsed.verifySignature(signatureKey: parsedDistribution.signingKey()),
        isTrue,
      );
      expect(
        parsed.verifySignature(
          signatureKey: PrivateKey.generate().getPublicKey().serialize(),
        ),
        isFalse,
      );
    });

    capability('the callback API hands back the records it wrote', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      final name = alice.name;
      final device = alice.deviceId;

      Future<Uint8List?> load(
        InMemorySenderKeyStore store,
        String sender,
        int deviceId,
        String distributionId,
      ) => store.loadSenderKey(
        SenderKeyName(
          ProtocolAddress(name: sender, deviceId: deviceId),
          distributionId,
        ),
      );

      final created = await createSenderKeyDistributionMessageWithCallbacks(
        senderName: name,
        senderDeviceId: device,
        distributionId: _distributionId,
        loadSenderKey: (n, d, i) => load(alice.senderKeys, n, d, i),
        storeSenderKey: (n, d, i, r) => alice.senderKeys.storeSenderKey(
          SenderKeyName(ProtocolAddress(name: n, deviceId: d), i),
          r,
        ),
        getIdentityKeyPair: () async => alice.identity.serialize(),
      );
      expect(created.senderKeyRecord, isNotEmpty);

      final processed = await processSenderKeyDistributionMessageWithCallbacks(
        senderName: name,
        senderDeviceId: device,
        distributionId: _distributionId,
        distributionMessage: created.distributionMessage,
        loadSenderKey: (n, d, i) => load(bob.senderKeys, n, d, i),
        storeSenderKey: (n, d, i, r) => bob.senderKeys.storeSenderKey(
          SenderKeyName(ProtocolAddress(name: n, deviceId: d), i),
          r,
        ),
      );
      expect(processed, isNotEmpty);

      final encrypted = await groupEncryptWithCallbacks(
        senderName: name,
        senderDeviceId: device,
        distributionId: _distributionId,
        plaintext: bytesOf('callbacks'),
        loadSenderKey: (n, d, i) => load(alice.senderKeys, n, d, i),
        storeSenderKey: (n, d, i, r) => alice.senderKeys.storeSenderKey(
          SenderKeyName(ProtocolAddress(name: n, deviceId: d), i),
          r,
        ),
        getIdentityKeyPair: () async => alice.identity.serialize(),
      );
      expect(encrypted.senderKeyRecord, isNotEmpty);

      final decrypted = await groupDecryptWithCallbacks(
        senderName: name,
        senderDeviceId: device,
        distributionId: _distributionId,
        ciphertext: encrypted.ciphertext,
        loadSenderKey: (n, d, i) => load(bob.senderKeys, n, d, i),
        storeSenderKey: (n, d, i, r) => bob.senderKeys.storeSenderKey(
          SenderKeyName(ProtocolAddress(name: n, deviceId: d), i),
          r,
        ),
      );
      expect(utf8.decode(decrypted.plaintext), 'callbacks');
      expect(decrypted.senderKeyRecord, isNotEmpty);
    });
  });
}
