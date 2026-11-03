import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';

import '../support/harness.dart';
import '../support/party.dart';

// Sealed Sender v2 addresses recipients by service id, so these are real UUIDs.
const _aliceUuid = 'aaaaaaaa-0000-4000-8000-000000000001';
const _bobUuid = 'bbbbbbbb-0000-4000-8000-000000000002';
const _carolUuid = 'cccccccc-0000-4000-8000-000000000003';
const _excludedUuid = 'dddddddd-0000-4000-8000-000000000004';

/// A trust root, a server certificate under it, and a way to issue sender
/// certificates.
class _Authority {
  _Authority() {
    serverCertificate = createServerCertificate(
      keyId: 1,
      serverPublicKey: _server.getPublicKey().serialize(),
      trustRootPrivateKey: _root.serialize(),
    );
  }

  final _root = PrivateKey.generate();
  final _server = PrivateKey.generate();
  late final Uint8List serverCertificate;

  Uint8List get trustRoot => _root.getPublicKey().serialize();

  Uint8List certify(
    Party sender, {
    Duration validFor = const Duration(hours: 1),
  }) => createSenderCertificate(
    senderUuid: sender.name,
    senderDeviceId: sender.deviceId,
    senderIdentityKey: sender.identity.publicKey,
    expiration: BigInt.from(
      DateTime.now().add(validFor).millisecondsSinceEpoch,
    ),
    serverCertificate: serverCertificate,
    serverPrivateKey: _server.serialize(),
  );
}

/// Whether [needle] occurs anywhere in [haystack].
bool _contains(List<int> haystack, List<int> needle) {
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    var j = 0;
    while (j < needle.length && haystack[i + j] == needle[j]) {
      j++;
    }
    if (j == needle.length) return true;
  }
  return false;
}

/// [party]'s identity callbacks, for the entry points that take them directly.
Future<Uint8List?> _identityOf(Party party, String name, int deviceId) async =>
    (await party.identities.getIdentity(
      ProtocolAddress(name: name, deviceId: deviceId),
    ))?.serialize();

/// [sealed], unsealed by [recipient] without touching a session.
Future<UnidentifiedSenderMessageContent> _unseal(
  List<int> sealed,
  Party recipient,
  _Authority authority,
) async => UnidentifiedSenderMessageContent.deserialize(
  data: await sealedSenderDecryptToUsmcWithCallbacks(
    ciphertext: sealed,
    trustRoot: authority.trustRoot,
    timestamp: nowMillis(),
    localName: recipient.name,
    localDeviceId: recipient.deviceId,
    getIdentityKeyPair: () async => recipient.identity.serialize(),
    getLocalRegistrationId: () async => recipient.registrationId,
    getIdentity: (name, deviceId) => _identityOf(recipient, name, deviceId),
  ),
);

void sealedSenderCapabilities() {
  group('sealed sender', () {
    capability('certificates issue, read back and validate', () async {
      final authority = _Authority();
      final alice = Party(_aliceUuid, 1111, deviceId: 2);
      final certificate = authority.certify(alice);

      expect(
        senderCertificateGetSenderName(certificate: certificate),
        _aliceUuid,
      );
      expect(senderCertificateGetSenderDeviceId(certificate: certificate), 2);
      expect(
        senderCertificateGetKey(certificate: certificate),
        alice.identity.publicKey,
      );
      expect(
        senderCertificateGetExpiration(certificate: certificate),
        greaterThan(nowMillis()),
      );
      expect(
        validateSenderCertificate(
          certificate: certificate,
          trustRoot: authority.trustRoot,
          timestamp: nowMillis(),
        ),
        isTrue,
      );

      // A certificate that fails validation is an exception, not a `false`.
      final isRefused = throwsA(
        isA<LibSignalException>().having(
          (e) => e.code,
          'code',
          LibSignalErrorCode.verificationFailure,
        ),
      );
      expect(
        () => validateSenderCertificate(
          certificate: certificate,
          trustRoot: _Authority().trustRoot,
          timestamp: nowMillis(),
        ),
        isRefused,
        reason: 'another authority did not issue it',
      );
      expect(
        () => validateSenderCertificate(
          certificate: authority.certify(
            alice,
            validFor: const Duration(hours: -1),
          ),
          trustRoot: authority.trustRoot,
          timestamp: nowMillis(),
        ),
        isRefused,
        reason: 'it has expired',
      );
    });

    capability(
      'the sender stays hidden until the recipient decrypts',
      () async {
        final authority = _Authority();
        final alice = Party(_aliceUuid, 1111);
        final bob = Party(_bobUuid, 2222);
        await establish(alice, bob);

        final sealed = await alice.sealed.encrypt(
          recipientAddress: bob.address,
          plaintext: bytesOf('from nobody'),
          senderCertificate: authority.certify(alice),
        );
        // Neither who sent it nor their key is in the envelope in the clear,
        // and no one else can open it to find out.
        expect(_contains(sealed, bytesOf(_aliceUuid)), isFalse);
        expect(_contains(sealed, alice.identity.publicKey), isFalse);
        await expectLater(
          _unseal(sealed, Party(_carolUuid, 3333), authority),
          throwsA(isA<LibSignalException>()),
        );

        final opened = await bob.sealed.decrypt(
          ciphertext: sealed,
          trustRoot: authority.trustRoot,
          timestamp: DateTime.now().millisecondsSinceEpoch,
        );

        expect(utf8.decode(opened.plaintext), 'from nobody');
        expect(opened.senderAddress.name(), _aliceUuid);
        expect(opened.senderAddress.deviceId(), 1);
        expect(opened.senderIdentityKey.serialize(), alice.identity.publicKey);

        // The same again, from a sender Bob now knows.
        final again = await bob.sealed.decrypt(
          ciphertext: await alice.sealed.encrypt(
            recipientAddress: bob.address,
            plaintext: bytesOf('still nobody'),
            senderCertificate: authority.certify(alice),
          ),
          trustRoot: authority.trustRoot,
          timestamp: DateTime.now().millisecondsSinceEpoch,
        );
        expect(utf8.decode(again.plaintext), 'still nobody');

        // The session it established works for an ordinary reply.
        final reply = await bob.cipher.encrypt(alice.address, bytesOf('reply'));
        expect(
          utf8.decode(await alice.cipher.decrypt(bob.address, reply)),
          'reply',
        );
      },
    );

    capability('UnidentifiedSenderMessageContent round-trips', () async {
      final authority = _Authority();
      final alice = Party(_aliceUuid, 1111);
      final certificate = authority.certify(alice);

      final usmc = UnidentifiedSenderMessageContent(
        messageType: CiphertextMessageType.senderKey.value,
        senderCertificate: certificate,
        contents: bytesOf('already encrypted'),
        contentHint: ContentHint.resendable.value,
        groupId: bytesOf('the-group'),
      );
      final parsed = UnidentifiedSenderMessageContent.deserialize(
        data: usmc.serialize(),
      );

      expect(parsed.messageType(), CiphertextMessageType.senderKey.value);
      expect(parsed.senderCertificate(), certificate);
      expect(parsed.contents(), bytesOf('already encrypted'));
      expect(parsed.groupId(), bytesOf('the-group'));
      expect(
        ContentHint.fromValue(parsed.contentHint()),
        ContentHint.resendable,
      );
      expect(ContentHint.fromValue(99), isNull);
    });

    capability('a USMC seals to one recipient and unseals intact', () async {
      final authority = _Authority();
      final alice = Party(_aliceUuid, 1111);
      final bob = Party(_bobUuid, 2222);
      await establish(alice, bob);

      final inner = await alice.cipher.encrypt(bob.address, bytesOf('inside'));
      final sealed = await sealedSenderEncryptFromUsmcWithCallbacks(
        recipientName: bob.name,
        recipientDeviceId: bob.deviceId,
        usmc: UnidentifiedSenderMessageContent(
          messageType: inner.type.value,
          senderCertificate: authority.certify(alice),
          contents: inner.ciphertext,
          contentHint: ContentHint.implicit.value,
        ).serialize(),
        getIdentityKeyPair: () async => alice.identity.serialize(),
        getLocalRegistrationId: () async => alice.registrationId,
        getIdentity: (name, deviceId) => _identityOf(alice, name, deviceId),
      );

      final unsealed = await _unseal(sealed, bob, authority);
      expect(unsealed.contents(), inner.ciphertext);
      expect(unsealed.contentHint(), ContentHint.implicit.value);
    });

    capability('a multi-recipient message fans out to each device', () async {
      final authority = _Authority();
      final alice = Party(_aliceUuid, 1111);
      final bob = Party(_bobUuid, 2222);
      final carol = Party(_carolUuid, 3333);
      await establish(alice, bob);
      await establish(alice, carol);

      final sent = await sealedSenderMultiRecipientEncryptWithCallbacks(
        destinations: [
          for (final peer in [bob, carol])
            MultiRecipientDestination(
              name: peer.name,
              deviceId: peer.deviceId,
              sessionRecord: (await alice.sessions.loadSession(
                peer.address,
              ))!.serialize(),
            ),
        ],
        excludedRecipients: [_excludedUuid],
        usmc: UnidentifiedSenderMessageContent(
          messageType: CiphertextMessageType.senderKey.value,
          senderCertificate: authority.certify(alice),
          contents: bytesOf('one body, many recipients'),
          contentHint: ContentHint.resendable.value,
          groupId: bytesOf('the-group'),
        ).serialize(),
        getIdentityKeyPair: () async => alice.identity.serialize(),
        getLocalRegistrationId: () async => alice.registrationId,
        getIdentity: (name, deviceId) => _identityOf(alice, name, deviceId),
      );

      final parsed = await sealedSenderV2ParseSentMessage(data: sent);
      expect(parsed.version, isPositive);
      expect(parsed.receivedMessageVersion, isPositive);
      expect(parsed.parsedLength, sent.length);
      expect(parsed.recipients, hasLength(3));

      final byId = {for (final r in parsed.recipients) r.serviceId: r};
      expect(byId[_excludedUuid]!.devices, isEmpty);
      expect(
        parsed.receivedMessageFor(recipient: byId[_excludedUuid]!, data: sent),
        isEmpty,
      );
      expect(byId[_bobUuid]!.devices.single.deviceId, 1);
      expect(byId[_bobUuid]!.devices.single.registrationId, 2222);
      expect(
        byId[_bobUuid]!.keyMaterialEnd,
        greaterThan(byId[_bobUuid]!.keyMaterialStart),
      );
      expect(parsed.sharedBytesOffset, lessThan(parsed.parsedLength));
      expect(
        () => parsed.receivedMessageFor(
          recipient: byId[_bobUuid]!,
          data: sent.sublist(1),
        ),
        throwsArgumentError,
        reason: 'the offsets index the buffer that was parsed, and no other',
      );

      for (final peer in [bob, carol]) {
        final received = parsed.receivedMessageFor(
          recipient: byId[peer.name]!,
          data: sent,
        );
        final unsealed = await _unseal(received, peer, authority);
        expect(unsealed.contents(), bytesOf('one body, many recipients'));
        expect(unsealed.groupId(), bytesOf('the-group'));
      }
    });

    capability('the callback API hands back the session it wrote', () async {
      final authority = _Authority();
      final alice = Party(_aliceUuid, 1111);
      final bob = Party(_bobUuid, 2222);
      await establish(alice, bob);

      Future<Uint8List?> loadSession(
        Party party,
        String name,
        int device,
      ) async => (await party.sessions.loadSession(
        ProtocolAddress(name: name, deviceId: device),
      ))?.serialize();
      Future<void> storeSession(
        Party party,
        String name,
        int device,
        Uint8List record,
      ) => party.sessions.storeSession(
        ProtocolAddress(name: name, deviceId: device),
        SessionRecord.deserialize(bytes: record),
      );
      Future<void> saveIdentity(
        Party party,
        String name,
        int device,
        Uint8List key,
      ) => party.identities.saveIdentity(
        ProtocolAddress(name: name, deviceId: device),
        PublicKey.deserialize(bytes: key),
      );

      final sealed = await sealedSenderEncryptWithCallbacks(
        recipientName: bob.name,
        recipientDeviceId: bob.deviceId,
        plaintext: bytesOf('callbacks'),
        senderCertificate: authority.certify(alice),
        loadSession: (name, device) => loadSession(alice, name, device),
        storeSession: (name, device, record) =>
            storeSession(alice, name, device, record),
        getIdentityKeyPair: () async => alice.identity.serialize(),
        getLocalRegistrationId: () async => alice.registrationId,
        saveIdentity: (name, device, key) =>
            saveIdentity(alice, name, device, key),
        getIdentity: (name, device) => _identityOf(alice, name, device),
      );
      expect(
        sealed.sessionRecord,
        await loadSession(alice, bob.name, bob.deviceId),
      );

      final opened = await sealedSenderDecryptWithCallbacks(
        ciphertext: sealed.ciphertext,
        trustRoot: authority.trustRoot,
        timestamp: nowMillis(),
        localName: bob.name,
        localDeviceId: bob.deviceId,
        loadSession: (name, device) => loadSession(bob, name, device),
        storeSession: (name, device, record) =>
            storeSession(bob, name, device, record),
        getIdentityKeyPair: () async => bob.identity.serialize(),
        getLocalRegistrationId: () async => bob.registrationId,
        saveIdentity: (name, device, key) =>
            saveIdentity(bob, name, device, key),
        loadSignedPreKey: (id) async =>
            (await bob.signedPreKeys.loadSignedPreKey(id))?.serialize(),
        loadPreKey: (id) async =>
            (await bob.preKeys.loadPreKey(id))?.serialize(),
        removePreKey: bob.preKeys.removePreKey,
        loadKyberPreKey: (id) async =>
            (await bob.kyberPreKeys.loadKyberPreKey(id))?.serialize(),
        markKyberPreKeyUsed: (id, signedId, baseKey) =>
            bob.kyberPreKeys.markKyberPreKeyUsed(
              id,
              signedId,
              PublicKey.deserialize(bytes: baseKey),
            ),
        getIdentity: (name, device) => _identityOf(bob, name, device),
      );
      expect(utf8.decode(opened.plaintext), 'callbacks');
      expect(opened.senderName, _aliceUuid);
      expect(opened.senderDeviceId, 1);
      expect(opened.senderIdentityKey, alice.identity.publicKey);
      expect(
        opened.sessionRecord,
        await loadSession(bob, alice.name, alice.deviceId),
      );
    });

    capability('a replayed sealed pre-key message is refused', () async {
      // As in `sessions`, without a one-time pre-key, so that the Kyber
      // agreement alone tells the second delivery from the first.
      final authority = _Authority();
      final alice = Party(_aliceUuid, 1111);
      final bob = Party(_bobUuid, 2222);
      await alice.builder.processPreKeyBundle(
        bob.address,
        await bob.publishBundle(oneTimePreKey: false),
      );
      final sealed = await alice.sealed.encrypt(
        recipientAddress: bob.address,
        plaintext: bytesOf('once'),
        senderCertificate: authority.certify(alice),
      );
      Future<SealedSenderDecryptionResult> open() => bob.sealed.decrypt(
        ciphertext: sealed,
        trustRoot: authority.trustRoot,
        timestamp: DateTime.now().millisecondsSinceEpoch,
      );
      expect(utf8.decode((await open()).plaintext), 'once');

      await bob.sessions.deleteSession(alice.address);
      await expectLater(
        open(),
        throwsA(
          isA<LibSignalException>().having(
            (e) => e.code,
            'code',
            LibSignalErrorCode.invalidMessage,
          ),
        ),
      );
    });

    capability('a forged certificate is refused', () async {
      final authority = _Authority();
      final alice = Party(_aliceUuid, 1111);
      final bob = Party(_bobUuid, 2222);
      await establish(alice, bob);

      final sealed = await alice.sealed.encrypt(
        recipientAddress: bob.address,
        plaintext: bytesOf('forged'),
        senderCertificate: _Authority().certify(alice),
      );
      await expectLater(
        bob.sealed.decrypt(
          ciphertext: sealed,
          trustRoot: authority.trustRoot,
          timestamp: DateTime.now().millisecondsSinceEpoch,
        ),
        throwsA(
          isA<LibSignalException>().having(
            (e) => e.code,
            'code',
            LibSignalErrorCode.verificationFailure,
          ),
        ),
      );
    });
  });
}
