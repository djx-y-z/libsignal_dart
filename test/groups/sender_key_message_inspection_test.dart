import 'dart:convert';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

const _distributionId = '33333333-3333-3333-3333-333333333333';

void main() {
  setUpAll(LibSignal.init);

  group('sender key message inspection', () {
    late GroupCipher alice;
    late GroupCipher bob;
    late ProtocolAddress aliceAddress;

    setUp(() {
      alice = GroupCipher(
        senderKeyStore: InMemorySenderKeyStore(),
        identityKeyStore: InMemoryIdentityKeyStore(
          IdentityKeyPair.generate(),
          111,
        ),
      );
      bob = GroupCipher(
        senderKeyStore: InMemorySenderKeyStore(),
        identityKeyStore: InMemoryIdentityKeyStore(
          IdentityKeyPair.generate(),
          222,
        ),
      );
      aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
    });

    test(
      'SenderKeyDistributionMessage exposes the group it establishes',
      () async {
        final bytes = await alice.createDistributionMessage(
          aliceAddress,
          _distributionId,
        );
        final skdm = SenderKeyDistributionMessage.deserialize(data: bytes);

        // The whole point: the id no longer has to be known out-of-band.
        expect(skdm.distributionId(), equals(_distributionId));
        expect(skdm.serialize(), equals(bytes));
        expect(skdm.messageVersion(), equals(3));
        expect(skdm.iteration(), equals(0));
        expect(skdm.signingKey(), hasLength(33));
        expect(skdm.chainId(), isNonNegative);
      },
    );

    test(
      'SenderKeyMessage exposes the routing fields of a group ciphertext',
      () async {
        final skdm = await alice.createDistributionMessage(
          aliceAddress,
          _distributionId,
        );
        await bob.processDistributionMessage(
          aliceAddress,
          _distributionId,
          skdm,
        );

        final ciphertext = await alice.encrypt(
          aliceAddress,
          _distributionId,
          utf8.encode('hello group'),
        );
        final msg = SenderKeyMessage.deserialize(data: ciphertext);

        expect(msg.distributionId(), equals(_distributionId));
        expect(
          msg.chainId(),
          equals(
            SenderKeyDistributionMessage.deserialize(data: skdm).chainId(),
          ),
        );
        expect(msg.iteration(), equals(0));
        expect(msg.messageVersion(), equals(3));
        expect(msg.ciphertext(), isNotEmpty);
        expect(msg.serialize(), equals(ciphertext));

        // A recipient can now derive the argument groupDecrypt demands.
        expect(
          utf8.decode(
            await bob.decrypt(aliceAddress, msg.distributionId(), ciphertext),
          ),
          equals('hello group'),
        );
      },
    );

    test('iteration advances with each message in the chain', () async {
      final skdm = await alice.createDistributionMessage(
        aliceAddress,
        _distributionId,
      );
      await bob.processDistributionMessage(aliceAddress, _distributionId, skdm);

      for (var i = 0; i < 3; i++) {
        final ct = await alice.encrypt(
          aliceAddress,
          _distributionId,
          utf8.encode('msg $i'),
        );
        expect(SenderKeyMessage.deserialize(data: ct).iteration(), equals(i));
      }
    });

    test(
      'verifySignature accepts the sender key and rejects a stranger',
      () async {
        final skdmBytes = await alice.createDistributionMessage(
          aliceAddress,
          _distributionId,
        );
        final signingKey = SenderKeyDistributionMessage.deserialize(
          data: skdmBytes,
        ).signingKey();

        final ciphertext = await alice.encrypt(
          aliceAddress,
          _distributionId,
          utf8.encode('signed'),
        );
        final msg = SenderKeyMessage.deserialize(data: ciphertext);

        expect(msg.verifySignature(signatureKey: signingKey), isTrue);
        expect(
          msg.verifySignature(
            signatureKey: PrivateKey.generate().getPublicKey().serialize(),
          ),
          isFalse,
        );
      },
    );

    test('cloneMessage and malformed input', () async {
      final skdmBytes = await alice.createDistributionMessage(
        aliceAddress,
        _distributionId,
      );
      final skdm = SenderKeyDistributionMessage.deserialize(data: skdmBytes);
      expect(skdm.cloneMessage().serialize(), equals(skdm.serialize()));

      expect(
        () => SenderKeyMessage.deserialize(data: <int>[9, 9, 9]),
        throwsA(anything),
      );
      expect(
        () => SenderKeyDistributionMessage.deserialize(data: <int>[9, 9, 9]),
        throwsA(anything),
      );
    });
  });
}
