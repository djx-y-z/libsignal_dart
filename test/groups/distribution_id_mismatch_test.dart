// A sender key distribution message carries its own distribution id, but the
// store callbacks are keyed by the id the caller passes in. When the two
// disagree libsignal writes the new state under the message's id while this
// wrapper reads back under the caller's — so the message has to be refused
// rather than processed into a key nobody will ever read.
import 'dart:convert';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

const _idA = '11111111-1111-1111-1111-111111111111';
const _idB = '22222222-2222-2222-2222-222222222222';

GroupCipher _cipher(int registrationId) => GroupCipher(
  senderKeyStore: InMemorySenderKeyStore(),
  identityKeyStore: InMemoryIdentityKeyStore(
    IdentityKeyPair.generate(),
    registrationId,
  ),
);

void main() {
  setUpAll(LibSignal.init);

  group('processDistributionMessage distribution id', () {
    late GroupCipher alice;
    late GroupCipher bob;
    late ProtocolAddress aliceAddress;

    setUp(() {
      alice = _cipher(111);
      bob = _cipher(222);
      aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
    });

    test('rejects a message whose id differs from the one passed in', () async {
      final skdmB = await alice.createDistributionMessage(aliceAddress, _idB);

      await expectLater(
        bob.processDistributionMessage(aliceAddress, _idA, skdmB),
        throwsA(
          predicate(
            (Object e) => e.toString().contains('Distribution ID mismatch'),
            'throws a distribution id mismatch error',
          ),
        ),
      );
    });

    test(
      'rejects the mismatch even when a key for that id already exists',
      () async {
        // The regression: with a record already stored under the caller's id, the
        // read-back used to return that stale record, so the call succeeded and
        // silently discarded the distribution message.
        final skdmA = await alice.createDistributionMessage(aliceAddress, _idA);
        await bob.processDistributionMessage(aliceAddress, _idA, skdmA);

        final skdmB = await alice.createDistributionMessage(aliceAddress, _idB);
        await expectLater(
          bob.processDistributionMessage(aliceAddress, _idA, skdmB),
          throwsA(
            predicate(
              (Object e) => e.toString().contains('Distribution ID mismatch'),
              'throws a distribution id mismatch error',
            ),
          ),
        );
      },
    );

    test('the refused message leaves the existing key untouched', () async {
      // Refusing is only worth anything if it is a clean no-op: the record
      // already stored under the caller's id must still work afterwards.
      final skdmA = await alice.createDistributionMessage(aliceAddress, _idA);
      await bob.processDistributionMessage(aliceAddress, _idA, skdmA);

      final skdmB = await alice.createDistributionMessage(aliceAddress, _idB);
      await expectLater(
        bob.processDistributionMessage(aliceAddress, _idA, skdmB),
        throwsA(anything),
      );

      final ciphertext = await alice.encrypt(
        aliceAddress,
        _idA,
        utf8.encode('group A still works'),
      );
      expect(
        utf8.decode(await bob.decrypt(aliceAddress, _idA, ciphertext)),
        equals('group A still works'),
      );
    });

    test('decrypt also refuses a ciphertext from another group', () async {
      // decrypt was already fail-closed before the fix; pin it so a future
      // change to the seed/read-back pattern cannot quietly open it.
      for (final id in [_idA, _idB]) {
        final skdm = await alice.createDistributionMessage(aliceAddress, id);
        await bob.processDistributionMessage(aliceAddress, id, skdm);
      }
      final ciphertextB = await alice.encrypt(
        aliceAddress,
        _idB,
        utf8.encode('group B'),
      );

      // Both groups are known to bob, so this is a genuine routing mistake
      // rather than a missing key.
      await expectLater(
        bob.decrypt(aliceAddress, _idA, ciphertextB),
        throwsA(anything),
      );
      // And the id is now readable off the message, so the caller need not
      // guess in the first place.
      expect(
        SenderKeyMessage.deserialize(data: ciphertextB).distributionId(),
        equals(_idB),
      );
    });

    test('the matching id still round-trips two independent groups', () async {
      for (final id in [_idA, _idB]) {
        final skdm = await alice.createDistributionMessage(aliceAddress, id);
        await bob.processDistributionMessage(aliceAddress, id, skdm);

        final ciphertext = await alice.encrypt(
          aliceAddress,
          id,
          utf8.encode('hello $id'),
        );
        expect(
          utf8.decode(await bob.decrypt(aliceAddress, id, ciphertext)),
          equals('hello $id'),
        );
      }
    });
  });
}
