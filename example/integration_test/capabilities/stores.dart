import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';

import '../support/harness.dart';
import '../support/party.dart';

void storeCapabilities() {
  group('stores', () {
    capability('the session store keeps sessions per device', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await establish(alice, bob);
      final store = alice.sessions;
      final record = (await store.loadSession(bob.address))!;
      final other = ProtocolAddress(name: 'bob', deviceId: 2);
      await store.storeSession(other, record);

      expect(await store.containsSession(bob.address), isTrue);
      expect(await store.getSubDeviceSessions('bob'), unorderedEquals([1, 2]));
      expect(store.length, 2);

      await store.deleteSession(other);
      expect(await store.containsSession(other), isFalse);
      await store.deleteAllSessions('bob');
      expect(await store.loadSession(bob.address), isNull);
      store.clear();
      expect(store.length, 0);
    });

    capability('the identity store remembers and judges identities', () async {
      final party = Party('alice', 1111);
      final store = party.identities;
      final bob = ProtocolAddress(name: 'bob', deviceId: 1);
      final key = PrivateKey.generate().getPublicKey();
      final changed = PrivateKey.generate().getPublicKey();

      expect(
        (await store.getIdentityKeyPair()).serialize(),
        party.identity.serialize(),
      );
      expect(await store.getLocalRegistrationId(), 1111);
      expect(await store.getIdentity(bob), isNull);
      expect(
        await store.isTrustedIdentity(bob, key, Direction.sending),
        isTrue,
        reason: 'trust on first use',
      );

      expect(await store.saveIdentity(bob, key), isTrue, reason: 'it is new');
      expect(await store.saveIdentity(bob, key), isFalse, reason: 'unchanged');
      expect((await store.getIdentity(bob))!.equals(other: key), isTrue);
      expect(
        await store.isTrustedIdentity(bob, key, Direction.receiving),
        isTrue,
      );
      expect(
        await store.isTrustedIdentity(bob, changed, Direction.sending),
        isFalse,
      );
      expect(await store.saveIdentity(bob, changed), isTrue, reason: 'changed');
      expect(store.length, 1);
      store.clear();
      expect(store.length, 0);
    });

    capability('the pre-key stores keep and hand out records', () async {
      final party = Party('alice', 1111);
      await party.publishBundle();

      expect(await party.preKeys.getAllPreKeyIds(), [42]);
      expect(await party.preKeys.containsPreKey(42), isTrue);
      expect((await party.preKeys.loadPreKey(42))!.id(), 42);
      expect(party.preKeys.length, 1);
      await party.preKeys.removePreKey(42);
      expect(await party.preKeys.loadPreKey(42), isNull);
      party.preKeys.clear();

      expect(await party.signedPreKeys.getAllSignedPreKeyIds(), [7]);
      expect(await party.signedPreKeys.containsSignedPreKey(7), isTrue);
      expect((await party.signedPreKeys.loadSignedPreKey(7))!.id(), 7);
      expect(party.signedPreKeys.length, 1);
      await party.signedPreKeys.removeSignedPreKey(7);
      expect(await party.signedPreKeys.loadSignedPreKey(7), isNull);
      party.signedPreKeys.clear();

      final kyber = party.kyberPreKeys;
      expect(await kyber.getAllKyberPreKeyIds(), [3]);
      expect(await kyber.containsKyberPreKey(3), isTrue);
      expect((await kyber.loadKyberPreKey(3))!.id(), 3);
      expect(kyber.length, 1);
      await kyber.removeKyberPreKey(3);
      expect(await kyber.loadKyberPreKey(3), isNull);
      kyber.clear();
    });

    capability('the Kyber store refuses an agreement it has seen', () async {
      final party = Party('alice', 1111);
      await party.publishBundle();
      final baseKey = PrivateKey.generate().getPublicKey();

      expect(
        await party.kyberPreKeys.markKyberPreKeyUsed(3, 7, baseKey),
        isTrue,
      );
      expect(
        await party.kyberPreKeys.markKyberPreKeyUsed(3, 7, baseKey),
        isFalse,
      );
      expect(party.kyberPreKeys.isKyberPreKeyUsed(3), isTrue);
      expect(party.kyberPreKeys.wasAgreementSeen(3, 7, baseKey), isTrue);
    });

    capability('the sender key store keys by sender and id', () async {
      final store = InMemorySenderKeyStore();
      final name = SenderKeyName(
        ProtocolAddress(name: 'alice', deviceId: 1),
        'the-distribution',
      );

      expect(await store.loadSenderKey(name), isNull);
      await store.storeSenderKey(name, bytesOf('record'));
      expect(
        await store.loadSenderKey(
          SenderKeyName(
            ProtocolAddress(name: 'alice', deviceId: 1),
            'the-distribution',
          ),
        ),
        bytesOf('record'),
      );
      expect(store.length, 1);
      expect(name.toString(), contains('alice:1'));
      final sameName = SenderKeyName(
        ProtocolAddress(name: 'alice', deviceId: 1),
        'the-distribution',
      );
      expect(name, sameName);
      expect(name.hashCode, sameName.hashCode);
      expect(
        name,
        isNot(
          SenderKeyName(
            ProtocolAddress(name: 'alice', deviceId: 2),
            'the-distribution',
          ),
        ),
      );
      store.clear();
      expect(store.length, 0);
    });
  });
}
