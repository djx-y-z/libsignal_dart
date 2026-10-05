// Codes as an application meets them: every test here makes a public call fail
// and checks the LibSignalErrorCode it throws, so a call site that loses its
// code fails here even while the variant-to-code table in
// rust/src/api/error.rs is still right.
//
// Every code except internalError is asserted by an exact-code matcher, here or
// next to the feature it belongs to: invalidKeyIdentifier in
// test/protocol/session_cipher_test.dart, sealedSenderSelfSend in
// test/sealed_sender/decrypt_to_usmc_identity_trust_test.dart, invalidSession
// in test/protocol/session_record_test.dart, and invalidRegistrationId and
// invalidState in test/sealed_sender/usmc_and_multi_recipient_test.dart.
// internalError marks a broken invariant; no input produces it.
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_rust_bridge/flutter_rust_bridge.dart'
    show FrbException, PanicException;
import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_party.dart';

/// A LibSignalException whose code is [code].
Matcher _withCode(LibSignalErrorCode code) =>
    isA<LibSignalException>().having((e) => e.code, 'code', code);

/// What [body] threw; the test fails when it throws nothing.
LibSignalException _thrownBy(void Function() body) {
  try {
    body();
  } on LibSignalException catch (thrown) {
    return thrown;
  }
  fail('nothing was thrown');
}

/// Carol and Dave with a session running both ways, so the next message
/// either of them encrypts is a plain Signal message rather than a pre-key
/// message.
Future<(TestParty carol, TestParty dave)> _talkingPair() async {
  final carol = TestParty.create(name: 'carol', registrationId: 4001);
  final dave = TestParty.create(name: 'dave', registrationId: 4002)
    ..generatePreKeys(preKeyId: 21, signedPreKeyId: 22, kyberPreKeyId: 23);
  await carol.sessionBuilder.processPreKeyBundle(
    dave.address,
    dave.getBundle(),
  );
  final opening = await carol.sessionCipher.encrypt(
    dave.address,
    utf8.encode('opening'),
  );
  await dave.sessionCipher.decrypt(carol.address, opening);
  final answer = await dave.sessionCipher.encrypt(
    carol.address,
    utf8.encode('answer'),
  );
  await carol.sessionCipher.decrypt(dave.address, answer);
  return (carol, dave);
}

/// [first] followed by MAC-sized padding: the shortest input a Signal message
/// parser reads past its length check.
List<int> _signalMessageBytes(int first) => [first, ...List.filled(8, 0)];

/// [wire] with one byte in the middle of [part], which it contains, inverted.
/// Given an encrypted body as [part], the result still parses and only
/// authentication can fail.
Uint8List _withByteChangedIn(List<int> wire, List<int> part) {
  final changed = Uint8List.fromList(wire);
  for (var at = 0; at + part.length <= changed.length; at++) {
    var found = true;
    for (var i = 0; i < part.length && found; i++) {
      found = changed[at + i] == part[i];
    }
    if (found) {
      final target = at + part.length ~/ 2;
      changed[target] = ~changed[target] & 0xff;
      return changed;
    }
  }
  fail('the part is not inside the serialized message');
}

/// The encrypted body of a serialized Signal message.
Uint8List _bodyOf(List<int> signalMessage) =>
    SignalMessage.deserialize(data: signalMessage).body();

void main() {
  setUpAll(LibSignal.init);

  group('the exception type', () {
    test('is both an FrbException and an Exception', () {
      final thrown = _thrownBy(() => PublicKey.deserialize(bytes: [9, 9, 9]));
      expect(thrown, isA<FrbException>());
      expect(thrown, isA<Exception>());
    });

    test('toString() names the code before the message', () {
      final thrown = _thrownBy(() => PublicKey.deserialize(bytes: [9, 9, 9]));
      expect(thrown.message, isNotEmpty);
      expect(
        thrown.toString(),
        equals('LibSignalException(invalidKey): ${thrown.message}'),
      );
    });

    test('the codes keep their order, which is how they cross the bridge', () {
      // A code travels as its position in this list. Changing the list is a
      // breaking change, made only in a major release.
      expect(LibSignalErrorCode.values.map((code) => code.name), [
        'invalidArgument',
        'invalidState',
        'internalError',
        'protobufError',
        'legacyCiphertextVersion',
        'unknownCiphertextVersion',
        'unrecognizedMessageVersion',
        'invalidMessage',
        'sealedSenderSelfSend',
        'invalidKey',
        'invalidSignature',
        'fingerprintVersionMismatch',
        'fingerprintParsingError',
        'untrustedIdentity',
        'invalidKeyIdentifier',
        'sessionNotFound',
        'invalidRegistrationId',
        'invalidSession',
        'invalidSenderKeySession',
        'duplicatedMessage',
        'verificationFailure',
      ]);
    });
  });

  group('receiving a Signal message', () {
    late TestParty carol;
    late TestParty dave;

    setUp(() async {
      (carol, dave) = await _talkingPair();
    });

    Future<CiphertextMessage> fromCarol(String text) async {
      final sent = await carol.sessionCipher.encrypt(
        dave.address,
        utf8.encode(text),
      );
      expect(sent.isSignalMessage, isTrue, reason: 'the pair is set up');
      return sent;
    }

    test('decrypting the same message twice is duplicatedMessage', () async {
      final sent = await fromCarol('delivered twice');
      await dave.sessionCipher.decrypt(carol.address, sent);

      await expectLater(
        dave.sessionCipher.decrypt(carol.address, sent),
        throwsA(_withCode(LibSignalErrorCode.duplicatedMessage)),
      );
    });

    test(
      'a receiver that never had a session reports sessionNotFound',
      () async {
        final sent = await fromCarol('to a stranger');
        final newcomer = TestParty.create(name: 'dave', registrationId: 4003);

        await expectLater(
          newcomer.sessionCipher.decrypt(carol.address, sent),
          throwsA(_withCode(LibSignalErrorCode.sessionNotFound)),
        );
      },
    );

    test('a body changed in transit is invalidMessage', () async {
      final sent = await fromCarol('altered on the way');

      await expectLater(
        dave.sessionCipher.decryptSignalMessage(
          carol.address,
          _withByteChangedIn(sent.ciphertext, _bodyOf(sent.ciphertext)),
        ),
        throwsA(_withCode(LibSignalErrorCode.invalidMessage)),
      );
    });

    test('a copy of a message already read is duplicatedMessage even with '
        'its body changed: the code comes before authentication', () async {
      final sent = await fromCarol('read already');
      await dave.sessionCipher.decrypt(carol.address, sent);

      await expectLater(
        dave.sessionCipher.decryptSignalMessage(
          carol.address,
          _withByteChangedIn(sent.ciphertext, _bodyOf(sent.ciphertext)),
        ),
        throwsA(_withCode(LibSignalErrorCode.duplicatedMessage)),
      );
    });

    test('fewer bytes than a MAC is invalidMessage', () async {
      await expectLater(
        dave.sessionCipher.decryptSignalMessage(
          carol.address,
          Uint8List.fromList([0x44, 0x01, 0x02]),
        ),
        throwsA(_withCode(LibSignalErrorCode.invalidMessage)),
      );
    });
  });

  group('receiving a pre-key message', () {
    test('a key other than the stored one is untrustedIdentity before the '
        'message is authenticated, and the stored key stays', () async {
      final (carol, dave) = await _talkingPair();
      dave.generatePreKeys(preKeyId: 31, signedPreKeyId: 32, kyberPreKeyId: 33);
      // Someone else opens a session to Dave. A copy of that first message,
      // with a byte of its body changed so that it cannot authenticate, is
      // delivered as if Carol had sent it.
      final erin = TestParty.create(name: 'erin', registrationId: 4011);
      await erin.sessionBuilder.processPreKeyBundle(
        dave.address,
        dave.getBundle(),
      );
      final first = await erin.sessionCipher.encrypt(
        dave.address,
        utf8.encode('signed, carol'),
      );
      expect(first.isPreKeyMessage, isTrue);
      final changed = _withByteChangedIn(
        first.ciphertext,
        PreKeySignalMessage.deserialize(
          data: first.ciphertext,
        ).message().body(),
      );

      await expectLater(
        dave.sessionCipher.decryptPreKeyMessage(carol.address, changed),
        throwsA(_withCode(LibSignalErrorCode.untrustedIdentity)),
      );
      final stored = await dave.identityKeyStore.getIdentity(carol.address);
      expect(stored!.serialize(), carol.identityKeyPair.publicKey);

      // The control: under Erin's own address, for which nothing is stored,
      // the same bytes get as far as authentication and fail it.
      await expectLater(
        dave.sessionCipher.decryptPreKeyMessage(erin.address, changed),
        throwsA(_withCode(LibSignalErrorCode.invalidMessage)),
      );
      expect(await dave.identityKeyStore.getIdentity(erin.address), isNull);
    });
  });

  group('parsing', () {
    test('a known version with no message inside is protobufError', () {
      expect(
        () => SignalMessage.deserialize(data: _signalMessageBytes(0x44)),
        throwsA(_withCode(LibSignalErrorCode.protobufError)),
      );
    });

    test('version 2 is legacyCiphertextVersion', () {
      expect(
        () => SignalMessage.deserialize(data: _signalMessageBytes(0x24)),
        throwsA(_withCode(LibSignalErrorCode.legacyCiphertextVersion)),
      );
    });

    test('version 5 is unknownCiphertextVersion', () {
      expect(
        () => SignalMessage.deserialize(data: _signalMessageBytes(0x54)),
        throwsA(_withCode(LibSignalErrorCode.unknownCiphertextVersion)),
      );
    });

    test('plaintext content with the wrong marker byte is '
        'unrecognizedMessageVersion', () {
      expect(
        () => PlaintextContent.deserialize(data: [0x01, 0x02]),
        throwsA(_withCode(LibSignalErrorCode.unrecognizedMessageVersion)),
      );
    });
  });

  group('sending without a session', () {
    // Built inside each test: the library is initialized only in setUpAll.
    ProtocolAddress nobody() => ProtocolAddress(name: 'nobody', deviceId: 1);

    test('SessionCipher.encrypt is sessionNotFound', () async {
      final carol = TestParty.create(name: 'carol', registrationId: 4051);

      await expectLater(
        carol.sessionCipher.encrypt(nobody(), utf8.encode('hello?')),
        throwsA(_withCode(LibSignalErrorCode.sessionNotFound)),
      );
    });

    test('SealedSenderCipher.encrypt is sessionNotFound', () async {
      final carol = TestParty.create(name: 'carol', registrationId: 4052);
      final trustRoot = PrivateKey.generate();
      final server = PrivateKey.generate();
      final certificate = createSenderCertificate(
        senderUuid: 'carol-uuid',
        senderDeviceId: 1,
        senderIdentityKey: carol.identityKeyPair.publicKey.toList(),
        expiration: BigInt.from(
          DateTime.now().add(const Duration(days: 1)).millisecondsSinceEpoch,
        ),
        serverCertificate: createServerCertificate(
          keyId: 7,
          serverPublicKey: server.getPublicKey().serialize().toList(),
          trustRootPrivateKey: trustRoot.serialize().toList(),
        ).toList(),
        serverPrivateKey: server.serialize().toList(),
      );
      final sealing = SealedSenderCipher(
        localAddress: carol.address,
        sessionStore: carol.sessionStore,
        identityKeyStore: carol.identityKeyStore,
        preKeyStore: carol.preKeyStore,
        signedPreKeyStore: carol.signedPreKeyStore,
        kyberPreKeyStore: carol.kyberPreKeyStore,
      );

      await expectLater(
        sealing.encrypt(
          recipientAddress: nobody(),
          plaintext: Uint8List.fromList(utf8.encode('hello?')),
          senderCertificate: certificate,
        ),
        throwsA(_withCode(LibSignalErrorCode.sessionNotFound)),
      );
    });
  });

  group('groups', () {
    const groupId = '6f1c0a8e-4b1d-4c2a-9e0f-2b7f6f3d9a11';

    GroupCipher groupCipherOf(TestParty member) => GroupCipher(
      senderKeyStore: InMemorySenderKeyStore(),
      identityKeyStore: member.identityKeyStore,
    );

    test('a group message whose sender key never arrived is '
        'sessionNotFound', () async {
      final carol = TestParty.create(name: 'carol', registrationId: 4101);
      final dave = TestParty.create(name: 'dave', registrationId: 4102);
      final carolGroup = groupCipherOf(carol);
      await carolGroup.createDistributionMessage(carol.address, groupId);
      final sent = await carolGroup.encrypt(
        carol.address,
        groupId,
        utf8.encode('to everyone'),
      );

      await expectLater(
        groupCipherOf(dave).decrypt(carol.address, groupId, sent),
        throwsA(_withCode(LibSignalErrorCode.sessionNotFound)),
      );
    });

    test('a group message whose signature was changed is '
        'invalidSignature', () async {
      final carol = TestParty.create(name: 'carol', registrationId: 4104);
      final dave = TestParty.create(name: 'dave', registrationId: 4105);
      final carolGroup = groupCipherOf(carol);
      final daveGroup = groupCipherOf(dave);
      await daveGroup.processDistributionMessage(
        carol.address,
        groupId,
        await carolGroup.createDistributionMessage(carol.address, groupId),
      );
      final sent = await carolGroup.encrypt(
        carol.address,
        groupId,
        utf8.encode('to the group'),
      );
      // A sender-key message ends with its 64-byte signature.
      final changed = Uint8List.fromList(sent);
      final inSignature = changed.length - 32;
      changed[inSignature] = ~changed[inSignature] & 0xff;

      await expectLater(
        daveGroup.decrypt(carol.address, groupId, changed),
        throwsA(_withCode(LibSignalErrorCode.invalidSignature)),
      );
    });

    test('a stored sender-key record with no state is '
        'invalidSenderKeySession', () async {
      final carol = TestParty.create(name: 'carol', registrationId: 4106);
      final store = InMemorySenderKeyStore();
      await store.storeSenderKey(
        SenderKeyName(carol.address, groupId),
        Uint8List(0),
      );

      await expectLater(
        GroupCipher(
          senderKeyStore: store,
          identityKeyStore: carol.identityKeyStore,
        ).encrypt(carol.address, groupId, utf8.encode('none yet')),
        throwsA(_withCode(LibSignalErrorCode.invalidSenderKeySession)),
      );
    });

    test('encrypting before any distribution message is '
        'sessionNotFound', () async {
      final carol = TestParty.create(name: 'carol', registrationId: 4103);

      await expectLater(
        groupCipherOf(
          carol,
        ).encrypt(carol.address, groupId, utf8.encode('too early')),
        throwsA(_withCode(LibSignalErrorCode.sessionNotFound)),
      );
    });
  });

  group('rejected inputs', () {
    test('a device id outside 1–127 is invalidArgument', () {
      expect(
        () => ProtocolAddress(name: 'carol', deviceId: 0),
        throwsA(_withCode(LibSignalErrorCode.invalidArgument)),
      );
    });

    test('a device id out of range in verifyMac is invalidArgument', () async {
      final (carol, dave) = await _talkingPair();
      final sent = await carol.sessionCipher.encrypt(
        dave.address,
        utf8.encode('mac'),
      );
      final parsed = SignalMessage.deserialize(data: sent.ciphertext);

      expect(
        () => parsed.verifyMac(
          senderAddressName: 'carol',
          senderAddressDeviceId: 0,
          recipientAddressName: 'dave',
          recipientAddressDeviceId: 1,
          senderIdentityKey: carol.identityKeyPair.publicKey.toList(),
          receiverIdentityKey: dave.identityKeyPair.publicKey.toList(),
          macKey: List.filled(32, 0),
        ),
        throwsA(_withCode(LibSignalErrorCode.invalidArgument)),
      );
    });

    test('a malformed public key is invalidKey', () {
      expect(
        () => PublicKey.deserialize(bytes: [9, 9, 9]),
        throwsA(_withCode(LibSignalErrorCode.invalidKey)),
      );
    });

    test('Kyber halves of two different pairs are invalidKey', () {
      final a = KyberKeyPair.generate();
      final b = KyberKeyPair.generate();
      expect(
        () => KyberKeyPair.fromKeys(
          publicKey: a.getPublicKey(),
          secretKey: b.getSecretKey(),
        ),
        throwsA(_withCode(LibSignalErrorCode.invalidKey)),
      );
    });

    test('an AES-GCM-SIV key of the wrong length is invalidArgument, '
        'and the message reports its real length', () {
      final thrown = _thrownBy(() => Aes256GcmSiv(key: List.filled(24, 1)));
      expect(thrown.code, LibSignalErrorCode.invalidArgument);
      expect(thrown.message, contains('got 24 bytes'));
    });

    test('an AES-GCM-SIV ciphertext that does not authenticate is '
        'invalidMessage', () {
      final cipher = Aes256GcmSiv(key: List.filled(32, 3));
      final nonce = List.filled(12, 5);
      final sealed = cipher.encrypt(
        plaintext: utf8.encode('sealed text'),
        nonce: nonce,
        associatedData: const [],
      );
      sealed[0] = ~sealed[0] & 0xff;
      expect(
        () => cipher.decrypt(
          ciphertext: sealed,
          nonce: nonce,
          associatedData: const [],
        ),
        throwsA(_withCode(LibSignalErrorCode.invalidMessage)),
      );
    });

    test('fingerprints of different versions are '
        'fingerprintVersionMismatch', () {
      final local = IdentityKeyPair.generate();
      final remote = IdentityKeyPair.generate();
      Fingerprint fingerprintOf(int version) => Fingerprint(
        iterations: 1024,
        version: version,
        localIdentifier: utf8.encode('carol'),
        localPublicKey: local.publicKey.toList(),
        remoteIdentifier: utf8.encode('dave'),
        remotePublicKey: remote.publicKey.toList(),
      );

      expect(
        () => fingerprintCompare(
          fingerprint1: fingerprintOf(1).scannableEncoding(),
          fingerprint2: fingerprintOf(2).scannableEncoding(),
        ),
        throwsA(_withCode(LibSignalErrorCode.fingerprintVersionMismatch)),
      );
    });

    test('a scannable fingerprint that does not parse is '
        'fingerprintParsingError', () {
      final scannable = Fingerprint(
        iterations: 1024,
        version: 2,
        localIdentifier: utf8.encode('carol'),
        localPublicKey: IdentityKeyPair.generate().publicKey.toList(),
        remoteIdentifier: utf8.encode('dave'),
        remotePublicKey: IdentityKeyPair.generate().publicKey.toList(),
      ).scannableEncoding();
      final unreadable = List<int>.filled(16, 0xff);

      expect(
        () => fingerprintCompare(
          fingerprint1: unreadable,
          fingerprint2: scannable,
        ),
        throwsA(_withCode(LibSignalErrorCode.fingerprintParsingError)),
      );
      expect(
        () => fingerprintCompare(
          fingerprint1: scannable,
          fingerprint2: unreadable,
        ),
        throwsA(_withCode(LibSignalErrorCode.fingerprintParsingError)),
      );
    });

    test('an expired sender certificate is verificationFailure', () {
      final trustRoot = PrivateKey.generate();
      final server = PrivateKey.generate();
      final serverCertificate = createServerCertificate(
        keyId: 1,
        serverPublicKey: server.getPublicKey().serialize().toList(),
        trustRootPrivateKey: trustRoot.serialize().toList(),
      ).toList();
      final now = DateTime.now().millisecondsSinceEpoch;
      final expired = createSenderCertificate(
        senderUuid: 'carol-uuid',
        senderDeviceId: 1,
        senderIdentityKey: IdentityKeyPair.generate().publicKey.toList(),
        expiration: BigInt.from(now - 60000),
        serverCertificate: serverCertificate,
        serverPrivateKey: server.serialize().toList(),
      );

      expect(
        () => validateSenderCertificate(
          certificate: expired.toList(),
          trustRoot: trustRoot.getPublicKey().serialize().toList(),
          timestamp: BigInt.from(now),
        ),
        throwsA(_withCode(LibSignalErrorCode.verificationFailure)),
      );
    });
  });

  group('failures that are not a LibSignalException', () {
    // The store interfaces cannot return an error across the bridge, so a
    // store that throws is reported as a panic. This is the Dart VM; on the
    // web the module traps and the call never completes, which the README
    // documents and nothing here can pin.
    test('on the Dart VM, a store callback that throws surfaces as '
        'PanicException', () async {
      final carol = TestParty.create(name: 'carol', registrationId: 4201);
      final cipher = SessionCipher(
        localAddress: carol.address,
        sessionStore: _FailingSessionStore(),
        identityKeyStore: carol.identityKeyStore,
        preKeyStore: carol.preKeyStore,
        signedPreKeyStore: carol.signedPreKeyStore,
        kyberPreKeyStore: carol.kyberPreKeyStore,
      );

      await expectLater(
        cipher.encrypt(
          ProtocolAddress(name: 'dave', deviceId: 1),
          utf8.encode('x'),
        ),
        throwsA(
          isA<PanicException>().having(
            (e) => e.message,
            'message',
            contains('session store offline'),
          ),
        ),
      );
    });

    // flutter_rust_bridge reports a disposed handle itself, with an exception
    // type it does not export.
    test('a call on an object after dispose() throws an FrbException that '
        'is not a LibSignalException', () {
      final key = PrivateKey.generate()..dispose();
      expect(
        key.serialize,
        throwsA(allOf(isA<FrbException>(), isNot(isA<LibSignalException>()))),
      );
    });
  });
}

class _FailingSessionStore extends InMemorySessionStore {
  @override
  Future<SessionRecord?> loadSession(ProtocolAddress address) async =>
      throw StateError('session store offline');
}
