import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/session_helpers.dart';

// Sealed Sender v2 addresses recipients by service id, so these have to be
// real UUIDs rather than the free-form names the v1 tests use.
const _aliceUuid = 'aaaaaaaa-0000-4000-8000-000000000001';
const _bobUuid = 'bbbbbbbb-0000-4000-8000-000000000002';
const _carolUuid = 'cccccccc-0000-4000-8000-000000000003';
const _excludedUuid = 'dddddddd-0000-4000-8000-000000000004';

/// A recipient with pre-keys published and a session established from alice.
class _Peer {
  _Peer(
    this.uuid,
    this.registrationId, {
    this.deviceId = 1,
    IdentityKeyPair? identity,
  }) : keys = identity == null
           ? generateRemotePartyKeys(
               registrationId: registrationId,
               deviceId: deviceId,
             )
           // Devices of one account must share an identity key — Sealed Sender
           // v2 groups recipients by account and carries one identity per group.
           : generateRemotePartyKeysWithIdentity(
               identityKeyPair: identity,
               registrationId: registrationId,
               deviceId: deviceId,
             );

  final String uuid;
  final int registrationId;
  final int deviceId;
  final RemotePartyKeys keys;

  final preKeyStore = InMemoryPreKeyStore();
  final signedPreKeyStore = InMemorySignedPreKeyStore();
  final kyberPreKeyStore = InMemoryKyberPreKeyStore();

  ProtocolAddress get address =>
      ProtocolAddress(name: uuid, deviceId: deviceId);

  /// Publish this peer's own pre-keys so it can decrypt a PreKey message.
  Future<void> publishPreKeys() async {
    final now = BigInt.from(DateTime.now().millisecondsSinceEpoch);
    await preKeyStore.storePreKey(
      keys.preKeyId,
      PreKeyRecord(
        id: keys.preKeyId,
        publicKey: keys.preKeyPublic,
        privateKey: keys.preKeyPrivate,
      ),
    );
    await signedPreKeyStore.storeSignedPreKey(
      keys.signedPreKeyId,
      SignedPreKeyRecord(
        id: keys.signedPreKeyId,
        timestamp: now,
        publicKey: keys.signedPreKeyPublic,
        privateKey: keys.signedPreKeyPrivate,
        signature: keys.signedPreKeySignature,
      ),
    );
    await kyberPreKeyStore.storeKyberPreKey(
      keys.kyberPreKeyId,
      KyberPreKeyRecord.create(
        id: keys.kyberPreKeyId,
        timestamp: now,
        keyPair: keys.kyberKeyPair,
        signature: keys.kyberPreKeySignature,
      ),
    );
  }
}

void main() {
  setUpAll(LibSignal.init);

  group('USMC and multi-recipient sealed sender', () {
    late PrivateKey trustRootPrivate;
    late PrivateKey serverPrivate;
    late Uint8List serverCertificate;
    late Uint8List aliceCertificate;

    late IdentityKeyPair aliceIdentity;
    late ProtocolAddress aliceAddress;
    late InMemorySessionStore aliceSessions;
    late InMemoryIdentityKeyStore aliceIdentityStore;

    setUp(() async {
      trustRootPrivate = PrivateKey.generate();
      serverPrivate = PrivateKey.generate();
      serverCertificate = createServerCertificate(
        keyId: 1,
        serverPublicKey: serverPrivate.getPublicKey().serialize(),
        trustRootPrivateKey: trustRootPrivate.serialize(),
      );

      aliceIdentity = IdentityKeyPair.generate();
      aliceAddress = ProtocolAddress(name: _aliceUuid, deviceId: 1);
      aliceSessions = InMemorySessionStore();
      aliceIdentityStore = InMemoryIdentityKeyStore(aliceIdentity, 11111);

      aliceCertificate = createSenderCertificate(
        senderUuid: _aliceUuid,
        senderDeviceId: 1,
        senderIdentityKey: aliceIdentity.publicKey,
        expiration: BigInt.from(
          DateTime.now().add(const Duration(hours: 1)).millisecondsSinceEpoch,
        ),
        serverCertificate: serverCertificate,
        serverPrivateKey: serverPrivate.serialize(),
      );
    });

    Future<_Peer> addPeer(
      String uuid,
      int registrationId, {
      int deviceId = 1,
      IdentityKeyPair? identity,
    }) async {
      final peer = _Peer(
        uuid,
        registrationId,
        deviceId: deviceId,
        identity: identity,
      );
      await peer.publishPreKeys();
      await SessionBuilder(
        localAddress: aliceAddress,
        sessionStore: aliceSessions,
        identityKeyStore: aliceIdentityStore,
      ).processPreKeyBundle(peer.address, peer.keys.toBundle());
      return peer;
    }

    group('UnidentifiedSenderMessageContent', () {
      test('carries the content hint and group id through a round trip', () {
        final usmc = UnidentifiedSenderMessageContent(
          messageType: CiphertextMessageType.signal.value,
          senderCertificate: aliceCertificate,
          contents: utf8.encode('already encrypted'),
          contentHint: ContentHint.resendable.value,
          groupId: utf8.encode('group-42'),
        );

        expect(usmc.messageType(), equals(CiphertextMessageType.signal.value));
        expect(usmc.contents(), equals(utf8.encode('already encrypted')));
        expect(usmc.contentHint(), equals(ContentHint.resendable.value));
        expect(usmc.groupId(), equals(utf8.encode('group-42')));
        expect(usmc.senderCertificate(), equals(aliceCertificate));

        final parsed = UnidentifiedSenderMessageContent.deserialize(
          data: usmc.serialize(),
        );
        expect(parsed.contentHint(), equals(ContentHint.resendable.value));
        expect(parsed.groupId(), equals(utf8.encode('group-42')));
      });

      test('defaults: no group id, hint 0', () {
        final usmc = UnidentifiedSenderMessageContent(
          messageType: CiphertextMessageType.senderKey.value,
          senderCertificate: aliceCertificate,
          contents: utf8.encode('body'),
          contentHint: ContentHint.none.value,
        );
        expect(usmc.groupId(), isNull);
        expect(usmc.contentHint(), equals(0));
        expect(ContentHint.fromValue(usmc.contentHint()), ContentHint.none);
      });

      test('an unknown hint value is passed through, not rejected', () {
        final usmc = UnidentifiedSenderMessageContent(
          messageType: CiphertextMessageType.signal.value,
          senderCertificate: aliceCertificate,
          contents: utf8.encode('body'),
          contentHint: 99,
        );
        expect(usmc.contentHint(), equals(99));
        expect(ContentHint.fromValue(99), isNull);
      });

      test('an empty group id is dropped on the wire, not in memory', () {
        // An upstream quirk worth pinning: `new` omits an empty group id from
        // the serialized form but keeps it on the object, so the value only
        // becomes absent after a round trip.
        final usmc = UnidentifiedSenderMessageContent(
          messageType: CiphertextMessageType.signal.value,
          senderCertificate: aliceCertificate,
          contents: utf8.encode('body'),
          contentHint: 0,
          groupId: Uint8List(0),
        );
        expect(usmc.groupId(), isEmpty);
        expect(
          UnidentifiedSenderMessageContent.deserialize(
            data: usmc.serialize(),
          ).groupId(),
          isNull,
        );
      });
    });

    group('encryptFromUsmc / decryptToUsmc', () {
      test('a sealed message unseals to the USMC that built it', () async {
        final bob = await addPeer(_bobUuid, 2222);

        // A real encrypted body, so the recipient could also decrypt it.
        final inner = await SessionCipher(
          localAddress: aliceAddress,
          sessionStore: aliceSessions,
          identityKeyStore: aliceIdentityStore,
          preKeyStore: InMemoryPreKeyStore(),
          signedPreKeyStore: InMemorySignedPreKeyStore(),
          kyberPreKeyStore: InMemoryKyberPreKeyStore(),
        ).encrypt(bob.address, utf8.encode('secret'));

        final usmc = UnidentifiedSenderMessageContent(
          messageType: inner.type.value,
          senderCertificate: aliceCertificate,
          contents: inner.ciphertext,
          contentHint: ContentHint.implicit.value,
          groupId: utf8.encode('the-group'),
        );

        final sealed = await sealedSenderEncryptFromUsmcWithCallbacks(
          recipientName: bob.address.name(),
          recipientDeviceId: bob.address.deviceId(),
          usmc: usmc.serialize(),
          getIdentityKeyPair: () async => aliceIdentity.serialize(),
          getLocalRegistrationId: () async => 11111,
          getIdentity: (name, deviceId) async =>
              (await aliceIdentityStore.getIdentity(
                ProtocolAddress(name: name, deviceId: deviceId),
              ))?.serialize(),
        );

        // Bob unseals without touching his session state.
        final unsealedBytes = await sealedSenderDecryptToUsmcWithCallbacks(
          ciphertext: sealed,
          trustRoot: trustRootPrivate.getPublicKey().serialize(),
          timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
          localName: bob.uuid,
          localDeviceId: bob.deviceId,
          getIdentityKeyPair: () async => bob.keys.identityKeyPair.serialize(),
          getLocalRegistrationId: () async => bob.registrationId,
          getIdentity: (name, deviceId) async => null,
        );
        final unsealed = UnidentifiedSenderMessageContent.deserialize(
          data: unsealedBytes,
        );

        expect(unsealed.contentHint(), equals(ContentHint.implicit.value));
        expect(unsealed.groupId(), equals(utf8.encode('the-group')));
        expect(unsealed.contents(), equals(inner.ciphertext));
        // The certificate came through authenticated, so it validates.
        expect(
          validateSenderCertificate(
            certificate: unsealed.senderCertificate(),
            trustRoot: trustRootPrivate.getPublicKey().serialize(),
            timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
          ),
          isTrue,
        );
      });

      test('encryptFromUsmc does not advance the session', () async {
        // The doc's central claim: no Double Ratchet work, so the sender's
        // session is not advanced. That is what makes it safe to call without
        // holding the per-address lock. (The decrypt side needs no assertion —
        // sealedSenderDecryptToUsmcWithCallbacks takes no session callback at
        // all, so there is no store for it to touch.)
        final bob = await addPeer(_bobUuid, 2222);
        final before = (await aliceSessions.loadSession(
          bob.address,
        ))!.serialize();

        final sealed = await sealedSenderEncryptFromUsmcWithCallbacks(
          recipientName: bob.address.name(),
          recipientDeviceId: bob.address.deviceId(),
          usmc: UnidentifiedSenderMessageContent(
            messageType: CiphertextMessageType.signal.value,
            senderCertificate: aliceCertificate,
            contents: utf8.encode('body'),
            contentHint: 0,
          ).serialize(),
          getIdentityKeyPair: () async => aliceIdentity.serialize(),
          getLocalRegistrationId: () async => 11111,
          getIdentity: (name, deviceId) async =>
              (await aliceIdentityStore.getIdentity(
                ProtocolAddress(name: name, deviceId: deviceId),
              ))?.serialize(),
        );
        expect(
          (await aliceSessions.loadSession(bob.address))!.serialize(),
          equals(before),
          reason: 'encryptFromUsmc must not advance the sender session',
        );

        // Still unsealable afterwards, i.e. the send really was side-effect free.
        await sealedSenderDecryptToUsmcWithCallbacks(
          ciphertext: sealed,
          trustRoot: trustRootPrivate.getPublicKey().serialize(),
          timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
          localName: bob.uuid,
          localDeviceId: bob.deviceId,
          getIdentityKeyPair: () async => bob.keys.identityKeyPair.serialize(),
          getLocalRegistrationId: () async => bob.registrationId,
          getIdentity: (name, deviceId) async => null,
        );
      });

      test('rejects a certificate minted under a foreign trust root', () async {
        // Sealing needs nothing but the recipient's public identity key, so
        // anyone can mint a self-signed certificate naming any sender and any
        // group. Upstream's decrypt_to_usmc only binds the certificate to
        // whoever sealed the blob; the trust-root check is what stops the
        // caller attributing the message — and its resend request — to whoever
        // the attacker chose.
        final bob = await addPeer(_bobUuid, 2222);

        final rogueRoot = PrivateKey.generate();
        final rogueServer = PrivateKey.generate();
        final rogueServerCert = createServerCertificate(
          keyId: 99,
          serverPublicKey: rogueServer.getPublicKey().serialize(),
          trustRootPrivateKey: rogueRoot.serialize(),
        );
        final forgedCert = createSenderCertificate(
          // Impersonating alice.
          senderUuid: _aliceUuid,
          senderDeviceId: 1,
          senderIdentityKey: IdentityKeyPair.generate().publicKey,
          expiration: BigInt.from(
            DateTime.now().add(const Duration(hours: 1)).millisecondsSinceEpoch,
          ),
          serverCertificate: rogueServerCert,
          serverPrivateKey: rogueServer.serialize(),
        );

        final mallory = IdentityKeyPair.generate();
        final sealed = await sealedSenderEncryptFromUsmcWithCallbacks(
          recipientName: bob.address.name(),
          recipientDeviceId: bob.address.deviceId(),
          usmc: UnidentifiedSenderMessageContent(
            messageType: CiphertextMessageType.signal.value,
            senderCertificate: forgedCert,
            contents: utf8.encode('garbage'),
            contentHint: ContentHint.resendable.value,
            groupId: utf8.encode('a-group-mallory-picked'),
          ).serialize(),
          getIdentityKeyPair: () async => mallory.serialize(),
          getLocalRegistrationId: () async => 4444,
          // Mallory needs only bob's public identity key, which is public.
          getIdentity: (name, deviceId) async =>
              bob.keys.identityKeyPair.publicKey,
        );

        await expectLater(
          sealedSenderDecryptToUsmcWithCallbacks(
            ciphertext: sealed,
            trustRoot: trustRootPrivate.getPublicKey().serialize(),
            timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
            localName: bob.uuid,
            localDeviceId: bob.deviceId,
            getIdentityKeyPair: () async =>
                bob.keys.identityKeyPair.serialize(),
            getLocalRegistrationId: () async => bob.registrationId,
            getIdentity: (name, deviceId) async => null,
          ),
          throwsA(anything),
          reason: 'a foreign trust root must not authenticate',
        );
      });

      test('rejects a certificate that has expired', () async {
        final bob = await addPeer(_bobUuid, 2222);
        final expiredCert = createSenderCertificate(
          senderUuid: _aliceUuid,
          senderDeviceId: 1,
          senderIdentityKey: aliceIdentity.publicKey,
          expiration: BigInt.from(
            DateTime.now()
                .subtract(const Duration(hours: 1))
                .millisecondsSinceEpoch,
          ),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivate.serialize(),
        );
        final sealed = await sealedSenderEncryptFromUsmcWithCallbacks(
          recipientName: bob.address.name(),
          recipientDeviceId: bob.address.deviceId(),
          usmc: UnidentifiedSenderMessageContent(
            messageType: CiphertextMessageType.signal.value,
            senderCertificate: expiredCert,
            contents: utf8.encode('body'),
            contentHint: 0,
          ).serialize(),
          getIdentityKeyPair: () async => aliceIdentity.serialize(),
          getLocalRegistrationId: () async => 11111,
          getIdentity: (name, deviceId) async =>
              (await aliceIdentityStore.getIdentity(
                ProtocolAddress(name: name, deviceId: deviceId),
              ))?.serialize(),
        );

        await expectLater(
          sealedSenderDecryptToUsmcWithCallbacks(
            ciphertext: sealed,
            trustRoot: trustRootPrivate.getPublicKey().serialize(),
            timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
            localName: bob.uuid,
            localDeviceId: bob.deviceId,
            getIdentityKeyPair: () async =>
                bob.keys.identityKeyPair.serialize(),
            getLocalRegistrationId: () async => bob.registrationId,
            getIdentity: (name, deviceId) async => null,
          ),
          throwsA(anything),
        );
      });

      test('a stranger cannot unseal it', () async {
        final bob = await addPeer(_bobUuid, 2222);
        final usmc = UnidentifiedSenderMessageContent(
          messageType: CiphertextMessageType.signal.value,
          senderCertificate: aliceCertificate,
          contents: utf8.encode('body'),
          contentHint: 0,
        );
        final sealed = await sealedSenderEncryptFromUsmcWithCallbacks(
          recipientName: bob.address.name(),
          recipientDeviceId: bob.address.deviceId(),
          usmc: usmc.serialize(),
          getIdentityKeyPair: () async => aliceIdentity.serialize(),
          getLocalRegistrationId: () async => 11111,
          getIdentity: (name, deviceId) async =>
              (await aliceIdentityStore.getIdentity(
                ProtocolAddress(name: name, deviceId: deviceId),
              ))?.serialize(),
        );

        final mallory = IdentityKeyPair.generate();
        await expectLater(
          sealedSenderDecryptToUsmcWithCallbacks(
            ciphertext: sealed,
            trustRoot: trustRootPrivate.getPublicKey().serialize(),
            timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
            localName: 'mallory-uuid',
            localDeviceId: 1,
            getIdentityKeyPair: () async => mallory.serialize(),
            getLocalRegistrationId: () async => 99999,
            getIdentity: (name, deviceId) async => null,
          ),
          throwsA(anything),
        );
      });
    });

    group('multi-recipient (Sealed Sender v2)', () {
      test('fans out to each recipient, who can then unseal it', () async {
        final bob = await addPeer(_bobUuid, 2222);
        final carol = await addPeer(_carolUuid, 3333);

        final usmc = UnidentifiedSenderMessageContent(
          messageType: CiphertextMessageType.senderKey.value,
          senderCertificate: aliceCertificate,
          contents: utf8.encode('one body, many recipients'),
          contentHint: ContentHint.implicit.value,
          groupId: utf8.encode('the-group'),
        );

        Future<Uint8List> sessionFor(_Peer p) async =>
            (await aliceSessions.loadSession(p.address))!.serialize();

        final sent = await sealedSenderMultiRecipientEncryptWithCallbacks(
          destinations: [
            MultiRecipientDestination(
              name: bob.address.name(),
              deviceId: bob.address.deviceId(),
              sessionRecord: await sessionFor(bob),
            ),
            MultiRecipientDestination(
              name: carol.address.name(),
              deviceId: carol.address.deviceId(),
              sessionRecord: await sessionFor(carol),
            ),
          ],
          excludedRecipients: [_excludedUuid],
          usmc: usmc.serialize(),
          getIdentityKeyPair: () async => aliceIdentity.serialize(),
          getLocalRegistrationId: () async => 11111,
          getIdentity: (name, deviceId) async =>
              (await aliceIdentityStore.getIdentity(
                ProtocolAddress(name: name, deviceId: deviceId),
              ))?.serialize(),
        );

        final parsed = await sealedSenderV2ParseSentMessage(data: sent);
        expect(parsed.recipients, hasLength(3));

        final byId = {for (final r in parsed.recipients) r.serviceId: r};
        expect(byId.keys, containsAll([_bobUuid, _carolUuid, _excludedUuid]));

        // The excluded recipient is listed but gets nothing to deliver.
        expect(byId[_excludedUuid]!.devices, isEmpty);
        expect(
          parsed.receivedMessageFor(
            recipient: byId[_excludedUuid]!,
            data: sent,
          ),
          isEmpty,
        );

        // Each real recipient gets their own single-recipient message, with the
        // registration id the server needs for routing.
        expect(byId[_bobUuid]!.devices.single.deviceId, equals(1));
        expect(
          byId[_bobUuid]!.devices.single.registrationId,
          equals(bob.registrationId),
        );
        expect(
          byId[_carolUuid]!.devices.single.registrationId,
          equals(carol.registrationId),
        );

        for (final peer in [bob, carol]) {
          final unsealed = UnidentifiedSenderMessageContent.deserialize(
            data: await sealedSenderDecryptToUsmcWithCallbacks(
              ciphertext: parsed.receivedMessageFor(
                recipient: byId[peer.uuid]!,
                data: sent,
              ),
              trustRoot: trustRootPrivate.getPublicKey().serialize(),
              timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
              localName: peer.uuid,
              localDeviceId: peer.deviceId,
              getIdentityKeyPair: () async =>
                  peer.keys.identityKeyPair.serialize(),
              getLocalRegistrationId: () async => peer.registrationId,
              getIdentity: (name, deviceId) async => null,
            ),
          );
          expect(
            unsealed.contents(),
            equals(utf8.encode('one body, many recipients')),
            reason: 'recipient ${peer.uuid}',
          );
          expect(unsealed.groupId(), equals(utf8.encode('the-group')));
        }
      });

      test('each fanned-out message decrypts end to end', () async {
        // The parser's doc promises each fanned-out message is "ready for
        // SealedSenderCipher.decrypt" — assert that, not just that the
        // envelope unseals.
        //
        // Two recipients, deliberately. With one, `keyMaterialEnd` and
        // `sharedBytesOffset` coincide, and a whole class of offset mistakes in
        // `receivedMessageFor` assembles the right bytes anyway. Only from the
        // second recipient onwards do the two diverge.
        final bob = await addPeer(_bobUuid, 2222);
        final carol = await addPeer(_carolUuid, 3333);

        final inner = await SessionCipher(
          localAddress: aliceAddress,
          sessionStore: aliceSessions,
          identityKeyStore: aliceIdentityStore,
          preKeyStore: InMemoryPreKeyStore(),
          signedPreKeyStore: InMemorySignedPreKeyStore(),
          kyberPreKeyStore: InMemoryKyberPreKeyStore(),
        ).encrypt(bob.address, utf8.encode('all the way through'));

        final sent = await sealedSenderMultiRecipientEncryptWithCallbacks(
          destinations: [
            for (final peer in [bob, carol])
              MultiRecipientDestination(
                name: peer.address.name(),
                deviceId: peer.address.deviceId(),
                sessionRecord: (await aliceSessions.loadSession(
                  peer.address,
                ))!.serialize(),
              ),
          ],
          excludedRecipients: [],
          usmc: UnidentifiedSenderMessageContent(
            messageType: inner.type.value,
            senderCertificate: aliceCertificate,
            contents: inner.ciphertext,
            contentHint: ContentHint.resendable.value,
          ).serialize(),
          getIdentityKeyPair: () async => aliceIdentity.serialize(),
          getLocalRegistrationId: () async => 11111,
          getIdentity: (name, deviceId) async =>
              (await aliceIdentityStore.getIdentity(
                ProtocolAddress(name: name, deviceId: deviceId),
              ))?.serialize(),
        );

        final parsed = await sealedSenderV2ParseSentMessage(data: sent);
        expect(parsed.version, isPositive);
        expect(parsed.recipients, hasLength(2));

        // The inner message is Alice's session with Bob, so only Bob's
        // reconstruction can decrypt all the way to plaintext — but Carol's
        // must still be a well-formed sealed sender message addressed to her,
        // which is what unsealing it proves.
        final bobRecipient = parsed.recipients.firstWhere(
          (r) => r.serviceId == _bobUuid,
        );
        expect(
          bobRecipient.keyMaterialEnd,
          lessThan(parsed.sharedBytesOffset),
          reason:
              'with two recipients the two offsets must differ, or this '
              'test is no stronger than the single-recipient one',
        );

        final result =
            await SealedSenderCipher(
              localAddress: bob.address,
              sessionStore: InMemorySessionStore(),
              identityKeyStore: InMemoryIdentityKeyStore(
                bob.keys.identityKeyPair,
                bob.registrationId,
              ),
              preKeyStore: bob.preKeyStore,
              signedPreKeyStore: bob.signedPreKeyStore,
              kyberPreKeyStore: bob.kyberPreKeyStore,
            ).decrypt(
              ciphertext: parsed.receivedMessageFor(
                recipient: bobRecipient,
                data: sent,
              ),
              trustRoot: trustRootPrivate.getPublicKey().serialize(),
              timestamp: DateTime.now().millisecondsSinceEpoch,
            );

        expect(utf8.decode(result.plaintext), equals('all the way through'));
        expect(result.senderAddress.name(), equals(_aliceUuid));

        // Carol's copy: unseals under her identity, and is not Bob's copy.
        final carolRecipient = parsed.recipients.firstWhere(
          (r) => r.serviceId == _carolUuid,
        );
        final carolMessage = parsed.receivedMessageFor(
          recipient: carolRecipient,
          data: sent,
        );
        expect(
          await sealedSenderDecryptToUsmcWithCallbacks(
            ciphertext: carolMessage,
            trustRoot: trustRootPrivate.getPublicKey().serialize(),
            timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
            localName: carol.uuid,
            localDeviceId: carol.deviceId,
            getIdentityKeyPair: () async =>
                carol.keys.identityKeyPair.serialize(),
            getLocalRegistrationId: () async => carol.registrationId,
            getIdentity: (name, deviceId) async => null,
          ),
          isNotEmpty,
        );
        expect(
          carolMessage,
          isNot(
            equals(
              parsed.receivedMessageFor(recipient: bobRecipient, data: sent),
            ),
          ),
        );
      });

      test('rejects a registration id wider than 14 bits', () async {
        // SSv2 packs the registration id into 14 bits (0..=16383).
        final bob = await addPeer(_bobUuid, 20000);
        await expectLater(
          sealedSenderMultiRecipientEncryptWithCallbacks(
            destinations: [
              MultiRecipientDestination(
                name: bob.address.name(),
                deviceId: bob.address.deviceId(),
                sessionRecord: (await aliceSessions.loadSession(
                  bob.address,
                ))!.serialize(),
              ),
            ],
            excludedRecipients: [],
            usmc: UnidentifiedSenderMessageContent(
              messageType: CiphertextMessageType.signal.value,
              senderCertificate: aliceCertificate,
              contents: utf8.encode('body'),
              contentHint: 0,
            ).serialize(),
            getIdentityKeyPair: () async => aliceIdentity.serialize(),
            getLocalRegistrationId: () async => 11111,
            getIdentity: (name, deviceId) async =>
                (await aliceIdentityStore.getIdentity(
                  ProtocolAddress(name: name, deviceId: deviceId),
                ))?.serialize(),
          ),
          throwsA(anything),
        );
      });

      test('rejects a destination name that is not a service id', () async {
        final peer = await addPeer('not-a-service-id', 2222);
        await expectLater(
          sealedSenderMultiRecipientEncryptWithCallbacks(
            destinations: [
              MultiRecipientDestination(
                name: peer.address.name(),
                deviceId: peer.address.deviceId(),
                sessionRecord: (await aliceSessions.loadSession(
                  peer.address,
                ))!.serialize(),
              ),
            ],
            excludedRecipients: [],
            usmc: UnidentifiedSenderMessageContent(
              messageType: CiphertextMessageType.signal.value,
              senderCertificate: aliceCertificate,
              contents: utf8.encode('body'),
              contentHint: 0,
            ).serialize(),
            getIdentityKeyPair: () async => aliceIdentity.serialize(),
            getLocalRegistrationId: () async => 11111,
            getIdentity: (name, deviceId) async =>
                (await aliceIdentityStore.getIdentity(
                  ProtocolAddress(name: name, deviceId: deviceId),
                ))?.serialize(),
          ),
          throwsA(anything),
        );
      });

      test(
        'groups two devices of one recipient under one service id',
        () async {
          final bob1 = await addPeer(_bobUuid, 2222);
          final bob2 = await addPeer(
            _bobUuid,
            2223,
            deviceId: 2,
            identity: bob1.keys.identityKeyPair,
          );

          final sent = await sealedSenderMultiRecipientEncryptWithCallbacks(
            destinations: [
              for (final p in [bob1, bob2])
                MultiRecipientDestination(
                  name: p.address.name(),
                  deviceId: p.address.deviceId(),
                  sessionRecord: (await aliceSessions.loadSession(
                    p.address,
                  ))!.serialize(),
                ),
            ],
            excludedRecipients: [],
            usmc: UnidentifiedSenderMessageContent(
              messageType: CiphertextMessageType.signal.value,
              senderCertificate: aliceCertificate,
              contents: utf8.encode('body'),
              contentHint: 0,
            ).serialize(),
            getIdentityKeyPair: () async => aliceIdentity.serialize(),
            getLocalRegistrationId: () async => 11111,
            getIdentity: (name, deviceId) async =>
                (await aliceIdentityStore.getIdentity(
                  ProtocolAddress(name: name, deviceId: deviceId),
                ))?.serialize(),
          );

          final parsed = await sealedSenderV2ParseSentMessage(data: sent);
          // Both devices belong to one account, so one recipient entry.
          expect(parsed.recipients, hasLength(1));
          final devices = parsed.recipients.single.devices;
          expect(devices.map((d) => d.deviceId), containsAll([1, 2]));
          expect(
            devices.map((d) => d.registrationId),
            containsAll([bob1.registrationId, bob2.registrationId]),
          );
        },
      );

      test('rejects an empty destination list', () async {
        final usmc = UnidentifiedSenderMessageContent(
          messageType: CiphertextMessageType.signal.value,
          senderCertificate: aliceCertificate,
          contents: utf8.encode('body'),
          contentHint: 0,
        );
        await expectLater(
          sealedSenderMultiRecipientEncryptWithCallbacks(
            destinations: [],
            excludedRecipients: [],
            usmc: usmc.serialize(),
            getIdentityKeyPair: () async => aliceIdentity.serialize(),
            getLocalRegistrationId: () async => 11111,
            getIdentity: (name, deviceId) async =>
                (await aliceIdentityStore.getIdentity(
                  ProtocolAddress(name: name, deviceId: deviceId),
                ))?.serialize(),
          ),
          throwsA(anything),
        );
      });

      test('rejects an excluded recipient that is not a service id', () async {
        final bob = await addPeer(_bobUuid, 2222);
        final usmc = UnidentifiedSenderMessageContent(
          messageType: CiphertextMessageType.signal.value,
          senderCertificate: aliceCertificate,
          contents: utf8.encode('body'),
          contentHint: 0,
        );
        await expectLater(
          sealedSenderMultiRecipientEncryptWithCallbacks(
            destinations: [
              MultiRecipientDestination(
                name: bob.address.name(),
                deviceId: bob.address.deviceId(),
                sessionRecord: (await aliceSessions.loadSession(
                  bob.address,
                ))!.serialize(),
              ),
            ],
            excludedRecipients: ['not-a-service-id'],
            usmc: usmc.serialize(),
            getIdentityKeyPair: () async => aliceIdentity.serialize(),
            getLocalRegistrationId: () async => 11111,
            getIdentity: (name, deviceId) async =>
                (await aliceIdentityStore.getIdentity(
                  ProtocolAddress(name: name, deviceId: deviceId),
                ))?.serialize(),
          ),
          throwsA(anything),
        );
      });

      test('refuses a destination whose identity is not trusted', () async {
        // The wrapper seeds each destination's identity from the store rather
        // than trusting on first use, so an unknown recipient is refused
        // instead of being encrypted to.
        final bob = await addPeer(_bobUuid, 2222);
        final usmc = UnidentifiedSenderMessageContent(
          messageType: CiphertextMessageType.signal.value,
          senderCertificate: aliceCertificate,
          contents: utf8.encode('body'),
          contentHint: 0,
        );
        await expectLater(
          sealedSenderMultiRecipientEncryptWithCallbacks(
            destinations: [
              MultiRecipientDestination(
                name: bob.address.name(),
                deviceId: bob.address.deviceId(),
                sessionRecord: (await aliceSessions.loadSession(
                  bob.address,
                ))!.serialize(),
              ),
            ],
            excludedRecipients: [],
            usmc: usmc.serialize(),
            getIdentityKeyPair: () async => aliceIdentity.serialize(),
            getLocalRegistrationId: () async => 11111,
            // An empty identity store: nothing is known about anyone.
            getIdentity: (name, deviceId) async => null,
          ),
          throwsA(anything),
        );
      });

      test('parsing rejects a message that is not Sealed Sender v2', () async {
        await expectLater(
          sealedSenderV2ParseSentMessage(data: <int>[0x11, 0x22]),
          throwsA(anything),
        );
      });

      test('parsing returns offsets, not copies, so its cost does not scale '
          'with the body', () async {
        // The parser used to materialise one full message per recipient, so
        // a large body was copied once each and an N-byte input could
        // produce ~N^2/272 bytes of output. It now hands back ranges into
        // the caller's own buffer.
        final bob = await addPeer(_bobUuid, 2222);
        final carol = await addPeer(_carolUuid, 3333);

        Future<Uint8List> sendBody(int bodyLength) async =>
            sealedSenderMultiRecipientEncryptWithCallbacks(
              destinations: [
                for (final peer in [bob, carol])
                  MultiRecipientDestination(
                    name: peer.uuid,
                    deviceId: peer.deviceId,
                    sessionRecord: (await aliceSessions.loadSession(
                      peer.address,
                    ))!.serialize(),
                  ),
              ],
              excludedRecipients: [],
              usmc: UnidentifiedSenderMessageContent(
                messageType: CiphertextMessageType.signal.value,
                senderCertificate: aliceCertificate,
                contents: List.filled(bodyLength, 7),
                contentHint: 0,
              ).serialize(),
              getIdentityKeyPair: () async => aliceIdentity.serialize(),
              getLocalRegistrationId: () async => 11111,
              getIdentity: (name, deviceId) async =>
                  (await aliceIdentityStore.getIdentity(
                    ProtocolAddress(name: name, deviceId: deviceId),
                  ))?.serialize(),
            );

        final small = await sendBody(64);
        final large = await sendBody(200000);
        final parsedSmall = await sealedSenderV2ParseSentMessage(data: small);
        final parsedLarge = await sealedSenderV2ParseSentMessage(data: large);

        // Same recipient count either way; the ranges are what changes, and
        // key material is a fixed 48 bytes per recipient regardless of body.
        expect(
          parsedLarge.recipients,
          hasLength(parsedSmall.recipients.length),
        );
        for (final recipient in parsedLarge.recipients) {
          expect(
            recipient.keyMaterialEnd - recipient.keyMaterialStart,
            equals(48),
          );
          expect(recipient.keyMaterialEnd, lessThanOrEqualTo(large.length));
        }
        expect(parsedLarge.sharedBytesOffset, lessThan(large.length));
        expect(parsedLarge.receivedMessageVersion, isPositive);
      });

      test(
        'reconstructed messages are exactly what each recipient needs',
        () async {
          final bob = await addPeer(_bobUuid, 2222);
          final carol = await addPeer(_carolUuid, 3333);
          final sent = await sealedSenderMultiRecipientEncryptWithCallbacks(
            destinations: [
              for (final peer in [bob, carol])
                MultiRecipientDestination(
                  name: peer.uuid,
                  deviceId: peer.deviceId,
                  sessionRecord: (await aliceSessions.loadSession(
                    peer.address,
                  ))!.serialize(),
                ),
            ],
            excludedRecipients: [],
            usmc: UnidentifiedSenderMessageContent(
              messageType: CiphertextMessageType.signal.value,
              senderCertificate: aliceCertificate,
              contents: utf8.encode('shared body'),
              contentHint: 0,
            ).serialize(),
            getIdentityKeyPair: () async => aliceIdentity.serialize(),
            getLocalRegistrationId: () async => 11111,
            getIdentity: (name, deviceId) async =>
                (await aliceIdentityStore.getIdentity(
                  ProtocolAddress(name: name, deviceId: deviceId),
                ))?.serialize(),
          );
          final parsed = await sealedSenderV2ParseSentMessage(data: sent);

          for (final recipient in parsed.recipients) {
            final message = parsed.receivedMessageFor(
              recipient: recipient,
              data: sent,
            );
            // [version][48B key material][shared bytes to the end]
            expect(
              message.length,
              equals(1 + 48 + (sent.length - parsed.sharedBytesOffset)),
            );
            expect(message.first, equals(parsed.receivedMessageVersion));
            expect(
              message.sublist(1, 49),
              equals(
                sent.sublist(
                  recipient.keyMaterialStart,
                  recipient.keyMaterialEnd,
                ),
              ),
            );
            expect(
              message.sublist(49),
              equals(sent.sublist(parsed.sharedBytesOffset)),
            );
          }

          // Two recipients of one message share everything but their key material.
          final first = parsed.receivedMessageFor(
            recipient: parsed.recipients.first,
            data: sent,
          );
          final second = parsed.receivedMessageFor(
            recipient: parsed.recipients.last,
            data: sent,
          );
          expect(first.sublist(49), equals(second.sublist(49)));
          expect(first.sublist(1, 49), isNot(equals(second.sublist(1, 49))));
        },
      );

      test(
        'reconstruction refuses a buffer that is not the parsed one',
        () async {
          final bob = await addPeer(_bobUuid, 2222);
          final sent = await sealedSenderMultiRecipientEncryptWithCallbacks(
            destinations: [
              MultiRecipientDestination(
                name: bob.uuid,
                deviceId: bob.deviceId,
                sessionRecord: (await aliceSessions.loadSession(
                  bob.address,
                ))!.serialize(),
              ),
            ],
            excludedRecipients: [],
            usmc: UnidentifiedSenderMessageContent(
              messageType: CiphertextMessageType.signal.value,
              senderCertificate: aliceCertificate,
              contents: utf8.encode('body'),
              contentHint: 0,
            ).serialize(),
            getIdentityKeyPair: () async => aliceIdentity.serialize(),
            getLocalRegistrationId: () async => 11111,
            getIdentity: (name, deviceId) async =>
                (await aliceIdentityStore.getIdentity(
                  ProtocolAddress(name: name, deviceId: deviceId),
                ))?.serialize(),
          );
          final parsed = await sealedSenderV2ParseSentMessage(data: sent);
          expect(parsed.parsedLength, equals(sent.length));

          expect(
            () => parsed.receivedMessageFor(
              recipient: parsed.recipients.single,
              data: Uint8List(4),
            ),
            throwsArgumentError,
          );

          // A buffer that merely *starts* with the parsed message used to slip
          // through the bounds check and silently extend the shared run, so the
          // delivered message grew a tail that was never in the blob. The
          // length is now part of what is checked.
          final longer = Uint8List(sent.length + 100)
            ..setRange(0, sent.length, sent);
          expect(
            () => parsed.receivedMessageFor(
              recipient: parsed.recipients.single,
              data: longer,
            ),
            throwsArgumentError,
          );

          // Truncated by one, likewise.
          expect(
            () => parsed.receivedMessageFor(
              recipient: parsed.recipients.single,
              data: sent.sublist(0, sent.length - 1),
            ),
            throwsArgumentError,
          );

          // A same-length foreign buffer is NOT detectable, and the doc says
          // so. Pin it, so nobody later reads the guard as stronger than it is.
          final foreign = Uint8List(sent.length);
          expect(
            parsed.receivedMessageFor(
              recipient: parsed.recipients.single,
              data: foreign,
            ),
            isNot(
              equals(
                parsed.receivedMessageFor(
                  recipient: parsed.recipients.single,
                  data: sent,
                ),
              ),
            ),
            reason: 'assembles from the wrong bytes; only the AEAD catches it',
          );

          // The excluded-recipient shortcut must not bypass the length check.
          expect(
            () => parsed.receivedMessageFor(
              recipient: SealedSenderV2Recipient(
                serviceId: bob.uuid,
                devices: const [],
                keyMaterialStart: 0,
                keyMaterialEnd: 0,
              ),
              data: Uint8List(4),
            ),
            throwsArgumentError,
          );
        },
      );

      test(
        'an unknown identity is refused per contiguous run, not per device',
        () async {
          // libsignal resolves one identity per contiguous run of destinations
          // sharing an address name, from the run's FIRST destination. So an
          // unknown device is refused or not depending on where it sits — the
          // behaviour SECURITY.md documents. Cryptographically it is sound
          // either way: an accepted device gets material derived from an
          // identity the caller does trust.
          final bob1 = await addPeer(_bobUuid, 2222);
          final bob2 = await addPeer(
            _bobUuid,
            3333,
            deviceId: 2,
            identity: bob1.keys.identityKeyPair,
          );
          final carol = await addPeer(_carolUuid, 4444);

          Future<Object?> send(List<_Peer> order) async {
            try {
              await sealedSenderMultiRecipientEncryptWithCallbacks(
                destinations: [
                  for (final peer in order)
                    MultiRecipientDestination(
                      name: peer.uuid,
                      deviceId: peer.deviceId,
                      sessionRecord: (await aliceSessions.loadSession(
                        peer.address,
                      ))!.serialize(),
                    ),
                ],
                excludedRecipients: [],
                usmc: UnidentifiedSenderMessageContent(
                  messageType: CiphertextMessageType.signal.value,
                  senderCertificate: aliceCertificate,
                  contents: utf8.encode('body'),
                  contentHint: 0,
                ).serialize(),
                getIdentityKeyPair: () async => aliceIdentity.serialize(),
                getLocalRegistrationId: () async => 11111,
                // bob device 2 is the unknown one.
                getIdentity: (name, deviceId) async =>
                    name == _bobUuid && deviceId == 2
                    ? null
                    : (await aliceIdentityStore.getIdentity(
                        ProtocolAddress(name: name, deviceId: deviceId),
                      ))?.serialize(),
              );
              return null;
            } on Object catch (e) {
              return e;
            }
          }

          expect(
            await send([bob1, bob2]),
            isNull,
            reason: 'one run resolved from bob.1, which is known',
          );
          expect(
            await send([bob2, bob1]),
            isNotNull,
            reason: 'one run resolved from bob.2, which is not',
          );
          expect(
            await send([bob1, carol, bob2]),
            isNotNull,
            reason: 'carol splits the run, so bob.2 is looked up on its own',
          );
        },
      );
    });
  });
}
