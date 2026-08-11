import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_party.dart';

void main() {
  setUpAll(LibSignal.init);

  group('PreKeySignalMessage', () {
    late TestParty alice;
    late TestParty bob;
    late CiphertextMessage preKeyCiphertext;

    setUp(() async {
      alice = TestParty.create(name: 'alice', registrationId: 111);
      bob = TestParty.create(name: 'bob', registrationId: 222)
        ..generatePreKeys(preKeyId: 42, signedPreKeyId: 7, kyberPreKeyId: 9);

      await alice.sessionBuilder.processPreKeyBundle(
        bob.address,
        bob.getBundle(),
      );
      preKeyCiphertext = await alice.sessionCipher.encrypt(
        bob.address,
        utf8.encode('hello'),
      );
      expect(preKeyCiphertext.isPreKeyMessage, isTrue);
    });

    test('deserialize round-trips the wire bytes', () {
      final msg = PreKeySignalMessage.deserialize(
        data: preKeyCiphertext.ciphertext,
      );
      expect(msg.serialize(), equals(preKeyCiphertext.ciphertext));
    });

    test('exposes the pre-key ids the message references', () {
      final msg = PreKeySignalMessage.deserialize(
        data: preKeyCiphertext.ciphertext,
      );
      expect(msg.preKeyId(), equals(42));
      expect(msg.signedPreKeyId(), equals(7));
      expect(msg.kyberPreKeyId(), equals(9));
      // The sender's registration id, not the recipient's.
      expect(msg.registrationId(), equals(111));
      // Deliberately pins the wire version: upstream moved it 3 → 4 for PQXDH,
      // and a binding library wants that to fail loudly if it moves again.
      expect(msg.messageVersion(), equals(4));
    });

    test('exposes the sender keys', () {
      final msg = PreKeySignalMessage.deserialize(
        data: preKeyCiphertext.ciphertext,
      );
      expect(msg.identityKey(), equals(alice.identityKeyPair.publicKey));
      // Curve25519 public keys are 32 bytes plus a type byte.
      expect(msg.baseKey(), hasLength(33));
      // PQXDH: the bundle carried a Kyber pre-key, so an encapsulation is here.
      expect(msg.kyberCiphertext(), isNotNull);
      expect(msg.kyberCiphertext(), isNotEmpty);
    });

    test('exposes the wrapped SignalMessage and its SPQR payload', () {
      final msg = PreKeySignalMessage.deserialize(
        data: preKeyCiphertext.ciphertext,
      );
      final inner = msg.message();

      expect(inner.messageVersion(), equals(msg.messageVersion()));
      expect(inner.counter(), equals(0));

      // The reason this accessor exists (issue #62): the very first message of
      // a session carries chunk 0 of the initiator's SPQR header, and it was
      // previously unreachable from Dart. Frame layout is
      // [version][epoch][index][type] + [chunk index][32-byte chunk].
      final pq = inner.pqRatchet();
      expect(pq, isNotNull);
      expect(pq, hasLength(37));
      expect(
        pq!.sublist(0, 5),
        equals(Uint8List.fromList([1, 1, 1, 1, 0])),
        reason: 'v1, epoch 1, index 1, type Hdr, chunk index 0',
      );
    });

    test('cloneMessage produces an independent equal copy', () {
      final msg = PreKeySignalMessage.deserialize(
        data: preKeyCiphertext.ciphertext,
      );
      final copy = msg.cloneMessage();
      expect(copy.serialize(), equals(msg.serialize()));
      expect(copy.preKeyId(), equals(msg.preKeyId()));
    });

    test('inspection does not consume the message', () async {
      // Reading a message must not disturb the session state it establishes.
      final msg = PreKeySignalMessage.deserialize(
        data: preKeyCiphertext.ciphertext,
      );
      msg.message().pqRatchet();

      final plaintext = await bob.sessionCipher.decrypt(
        alice.address,
        preKeyCiphertext,
      );
      expect(utf8.decode(plaintext), equals('hello'));
    });

    test('deserialize rejects malformed input', () {
      expect(
        () => PreKeySignalMessage.deserialize(data: <int>[1, 2, 3]),
        throwsA(anything),
      );
      // A plain SignalMessage is not a PreKeySignalMessage.
      expect(
        () => PreKeySignalMessage.deserialize(
          data: PreKeySignalMessage.deserialize(
            data: preKeyCiphertext.ciphertext,
          ).message().serialize(),
        ),
        throwsA(anything),
      );
    });
  });
}
