import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';

import '../support/harness.dart';
import '../support/party.dart';

void sessionCapabilities() {
  group('sessions', () {
    capability('PQXDH and the Double Ratchet, in both directions', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await establish(alice, bob);

      final opening = await alice.cipher.encrypt(bob.address, bytesOf('hello'));
      expect(opening.isPreKeyMessage, isTrue);
      expect(opening.isSignalMessage, isFalse);
      expect(opening.type, CiphertextMessageType.preKey);
      expect(
        utf8.decode(await bob.cipher.decrypt(alice.address, opening)),
        'hello',
      );

      final answer = await bob.cipher.encrypt(alice.address, bytesOf('hi'));
      expect(answer.isSignalMessage, isTrue);
      expect(
        utf8.decode(await alice.cipher.decrypt(bob.address, answer)),
        'hi',
      );

      // Several turns, so that the ratchet actually steps.
      for (var turn = 0; turn < 4; turn++) {
        final there = await alice.cipher.encrypt(
          bob.address,
          bytesOf('there $turn'),
        );
        expect(
          utf8.decode(await bob.cipher.decrypt(alice.address, there)),
          'there $turn',
        );
        final back = await bob.cipher.encrypt(
          alice.address,
          bytesOf('back $turn'),
        );
        expect(
          utf8.decode(await alice.cipher.decrypt(bob.address, back)),
          'back $turn',
        );
      }
    });

    capability('a session starts without a one-time pre-key', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await alice.builder.processPreKeyBundle(
        bob.address,
        await bob.publishBundle(oneTimePreKey: false),
      );

      final opening = await alice.cipher.encrypt(bob.address, bytesOf('hello'));
      final ids = extractPrekeyMessageIds(message: opening.ciphertext);
      expect(ids.preKeyId, isNull);
      expect(ids.signedPreKeyId, 7);
      expect(ids.kyberPreKeyId, 3);
      expect(
        utf8.decode(
          await bob.cipher.decryptPreKeyMessage(
            alice.address,
            opening.ciphertext,
          ),
        ),
        'hello',
      );
    });

    capability('decrypting a pre-key message consumes the pre-keys', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await establish(alice, bob);
      expect(await bob.preKeys.containsPreKey(42), isTrue);

      final opening = await alice.cipher.encrypt(bob.address, bytesOf('hello'));
      final ids = extractPrekeyMessageIds(message: opening.ciphertext);
      expect(ids.preKeyId, 42);
      await bob.cipher.decrypt(alice.address, opening);

      expect(await bob.preKeys.containsPreKey(42), isFalse);
      expect(await bob.sessions.containsSession(alice.address), isTrue);
      expect(await alice.sessions.containsSession(bob.address), isTrue);

      // Until Bob answers, Alice's messages stay pre-key messages. This one
      // lands on the session the first one made, from an identity now known.
      final again = await alice.cipher.encrypt(bob.address, bytesOf('again'));
      expect(again.isPreKeyMessage, isTrue);
      expect(
        utf8.decode(await bob.cipher.decrypt(alice.address, again)),
        'again',
      );
    });

    capability('messages may arrive out of order, but only once', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await converse(alice, bob);

      final first = await alice.cipher.encrypt(bob.address, bytesOf('first'));
      final second = await alice.cipher.encrypt(bob.address, bytesOf('second'));

      expect(
        utf8.decode(
          await bob.cipher.decryptSignalMessage(
            alice.address,
            second.ciphertext,
          ),
        ),
        'second',
      );
      expect(
        utf8.decode(await bob.cipher.decrypt(alice.address, first)),
        'first',
      );
      await expectLater(
        bob.cipher.decrypt(alice.address, first),
        throwsA(
          isA<LibSignalException>().having(
            (e) => e.code,
            'code',
            LibSignalErrorCode.duplicatedMessage,
          ),
        ),
      );
    });

    capability('SessionRecord reports on, and survives, a session', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await converse(alice, bob);

      final record = (await alice.sessions.loadSession(bob.address))!;
      expect(record.localRegistrationId(), 1111);
      expect(record.remoteRegistrationId(), 2222);
      expect(record.hasUsableSenderChain(nowMillis: nowMillis()), isTrue);

      final restored = SessionRecord.deserialize(bytes: record.serialize());
      expect(restored.serialize(), record.serialize());
      expect(record.cloneRecord().serialize(), record.serialize());

      final sent = await alice.cipher.encrypt(bob.address, bytesOf('ratchet'));
      final ratchetKey = PublicKey.deserialize(
        bytes: SignalMessage.deserialize(
          data: sent.ciphertext,
        ).senderRatchetKey(),
      );
      final current = (await alice.sessions.loadSession(bob.address))!;
      expect(current.currentRatchetKeyMatches(key: ratchetKey), isTrue);
      expect(
        current.currentRatchetKeyMatches(
          key: PrivateKey.generate().getPublicKey(),
        ),
        isFalse,
      );

      // A restored session keeps talking.
      await alice.sessions.storeSession(
        bob.address,
        SessionRecord.deserialize(bytes: current.serialize()),
      );
      final next = await alice.cipher.encrypt(bob.address, bytesOf('restored'));
      await bob.cipher.decrypt(alice.address, sent);
      expect(
        utf8.decode(await bob.cipher.decrypt(alice.address, next)),
        'restored',
      );

      final archived = (await alice.sessions.loadSession(bob.address))!
        ..archiveCurrentState();
      expect(archived.hasUsableSenderChain(nowMillis: nowMillis()), isFalse);
    });

    capability('a changed identity is refused, not trusted', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await establish(alice, bob);

      final impostor = Party('bob', 2222);
      await expectLater(
        alice.builder.processPreKeyBundle(
          bob.address,
          await impostor.publishBundle(),
        ),
        throwsA(
          isA<LibSignalException>().having(
            (e) => e.code,
            'code',
            LibSignalErrorCode.untrustedIdentity,
          ),
        ),
      );
    });

    capability('the post-quantum ratchet travels in the messages', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await converse(alice, bob);

      final sent = await alice.cipher.encrypt(bob.address, bytesOf('sparse'));
      expect(
        SignalMessage.deserialize(data: sent.ciphertext).pqRatchet(),
        isNotEmpty,
      );
    });
  });
}
