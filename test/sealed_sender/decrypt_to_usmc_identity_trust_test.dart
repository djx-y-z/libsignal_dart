// ignore_for_file: avoid_redundant_argument_values
// Regression: `sealedSenderDecryptToUsmcWithCallbacks` must run *both* gates
// `SealedSenderCipher.decrypt` runs — certificate chain and identity trust.
//
// It shipped with only the first. A certificate that validly chains to the
// trust root but carries an identity key other than the one stored for that
// sender was unsealed and reported as that sender, silently, while the decrypt
// path refused the very same message with `untrusted identity`. Every test
// below is the pair of calls that made the gap visible.
import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/session_helpers.dart';

/// The name the certificates below claim, and the address Bob has an identity
/// stored for.
const _aliceName = 'alice-uuid';

bool _sameKey(Uint8List a, Uint8List b) =>
    a.length == b.length &&
    List.generate(a.length, (i) => a[i] == b[i]).every((x) => x);

void main() {
  setUpAll(LibSignal.init);

  group('sealedSenderDecryptToUsmc identity trust', () {
    late PrivateKey trustRootPrivate;
    late PrivateKey serverPrivate;
    late Uint8List serverCertificate;
    late BigInt now;

    late RemotePartyKeys bobKeys;
    late ProtocolAddress bobAddress;
    late InMemorySessionStore bobSessions;
    late InMemoryIdentityKeyStore bobIdentities;
    late InMemoryPreKeyStore bobPreKeys;
    late InMemorySignedPreKeyStore bobSignedPreKeys;
    late InMemoryKyberPreKeyStore bobKyberPreKeys;

    late IdentityKeyPair aliceIdentity;
    late ProtocolAddress aliceAddress;

    setUp(() async {
      now = BigInt.from(DateTime.now().millisecondsSinceEpoch);
      trustRootPrivate = PrivateKey.generate();
      serverPrivate = PrivateKey.generate();
      serverCertificate = createServerCertificate(
        keyId: 1,
        serverPublicKey: serverPrivate.getPublicKey().serialize(),
        trustRootPrivateKey: trustRootPrivate.serialize(),
      );

      bobKeys = generateRemotePartyKeys(
        registrationId: 22222,
        deviceId: 1,
        preKeyId: 31337,
        signedPreKeyId: 22,
        kyberPreKeyId: 1,
      );
      bobAddress = ProtocolAddress(name: 'bob-uuid', deviceId: 1);
      bobSessions = InMemorySessionStore();
      bobIdentities = InMemoryIdentityKeyStore(bobKeys.identityKeyPair, 22222);
      bobPreKeys = InMemoryPreKeyStore();
      bobSignedPreKeys = InMemorySignedPreKeyStore();
      bobKyberPreKeys = InMemoryKyberPreKeyStore();
      await bobPreKeys.storePreKey(
        31337,
        PreKeyRecord(
          id: 31337,
          publicKey: bobKeys.preKeyPublic,
          privateKey: bobKeys.preKeyPrivate,
        ),
      );
      await bobSignedPreKeys.storeSignedPreKey(
        22,
        SignedPreKeyRecord(
          id: 22,
          timestamp: now,
          publicKey: bobKeys.signedPreKeyPublic,
          privateKey: bobKeys.signedPreKeyPrivate,
          signature: bobKeys.signedPreKeySignature,
        ),
      );
      await bobKyberPreKeys.storeKyberPreKey(
        1,
        KyberPreKeyRecord.create(
          id: 1,
          timestamp: now,
          keyPair: bobKeys.kyberKeyPair,
          signature: bobKeys.kyberPreKeySignature,
        ),
      );

      // Alice is a peer Bob has already met: her real identity key is stored.
      aliceIdentity = IdentityKeyPair.generate();
      aliceAddress = ProtocolAddress(name: _aliceName, deviceId: 1);
      await bobIdentities.saveIdentity(
        aliceAddress,
        PublicKey.deserialize(bytes: aliceIdentity.publicKey.toList()),
      );
    });

    /// A certificate naming Alice but binding whatever identity key is passed.
    Uint8List certificateFor(Uint8List identityKey) => createSenderCertificate(
      senderUuid: _aliceName,
      senderDeviceId: 1,
      senderIdentityKey: identityKey,
      expiration: now + BigInt.from(3600 * 1000),
      serverCertificate: serverCertificate,
      serverPrivateKey: serverPrivate.serialize(),
    );

    /// Seal a real PreKey message from [sender] to Bob under [certificate].
    Future<Uint8List> sealedFrom(
      IdentityKeyPair sender,
      Uint8List certificate,
    ) async {
      final address = ProtocolAddress(name: 'sender-uuid', deviceId: 1);
      final sessions = InMemorySessionStore();
      final identities = InMemoryIdentityKeyStore(sender, 33333);
      await SessionBuilder(
        localAddress: address,
        sessionStore: sessions,
        identityKeyStore: identities,
      ).processPreKeyBundle(bobAddress, bobKeys.toBundle());
      final inner = await SessionCipher(
        localAddress: address,
        sessionStore: sessions,
        identityKeyStore: identities,
        preKeyStore: InMemoryPreKeyStore(),
        signedPreKeyStore: InMemorySignedPreKeyStore(),
        kyberPreKeyStore: InMemoryKyberPreKeyStore(),
      ).encrypt(bobAddress, Uint8List.fromList(utf8.encode('hello')));

      return sealedSenderEncryptFromUsmcWithCallbacks(
        recipientName: bobAddress.name(),
        recipientDeviceId: bobAddress.deviceId(),
        usmc: UnidentifiedSenderMessageContent(
          messageType: inner.isPreKeyMessage ? 3 : 2,
          senderCertificate: certificate,
          contents: inner.ciphertext,
          contentHint: ContentHint.resendable.value,
          groupId: Uint8List.fromList(utf8.encode('some-group')),
        ).serialize(),
        getIdentityKeyPair: () async => sender.serialize(),
        getLocalRegistrationId: () async => 33333,
        getIdentity: (name, deviceId) async =>
            bobKeys.identityKeyPair.publicKey,
      );
    }

    Future<Uint8List> unseal(Uint8List ciphertext) =>
        sealedSenderDecryptToUsmcWithCallbacks(
          ciphertext: ciphertext,
          trustRoot: trustRootPrivate.getPublicKey().serialize(),
          timestamp: now,
          localName: bobAddress.name(),
          localDeviceId: bobAddress.deviceId(),
          getIdentityKeyPair: () async => bobKeys.identityKeyPair.serialize(),
          getLocalRegistrationId: () async => 22222,
          getIdentity: (name, deviceId) async =>
              (await bobIdentities.getIdentity(
                ProtocolAddress(name: name, deviceId: deviceId),
              ))?.serialize(),
        );

    Future<void> fullDecrypt(Uint8List ciphertext) async {
      await SealedSenderCipher(
        localAddress: bobAddress,
        sessionStore: bobSessions,
        identityKeyStore: bobIdentities,
        preKeyStore: bobPreKeys,
        signedPreKeyStore: bobSignedPreKeys,
        kyberPreKeyStore: bobKyberPreKeys,
      ).decrypt(
        ciphertext: ciphertext,
        trustRoot: trustRootPrivate.getPublicKey().serialize(),
        timestamp: now.toInt(),
      );
    }

    test('a valid certificate carrying a DIFFERENT identity key is refused, '
        'the same way the decrypt path refuses it', () async {
      // Mallory holds a certificate that chains to the trust root and names
      // Alice, but binds Mallory's identity key. Only a hostile or
      // compromised server can mint one — which is exactly the case the
      // identity check exists for.
      final mallory = IdentityKeyPair.generate();
      final sealed = await sealedFrom(
        mallory,
        certificateFor(mallory.publicKey),
      );

      // Both paths must refuse, and for the same stated reason.
      await expectLater(
        fullDecrypt(sealed),
        throwsA(
          predicate(
            (Object e) => e.toString().contains('untrusted identity'),
            'an untrusted identity error',
          ),
        ),
      );
      await expectLater(
        unseal(sealed),
        throwsA(
          predicate(
            (Object e) => e.toString().contains('untrusted identity'),
            'an untrusted identity error',
          ),
        ),
        reason: 'the envelope path must not be the lenient one',
      );
    });

    test(
      'a peer who re-registers is refused — the everyday case, no attacker',
      () async {
        // Nobody hostile here. Alice reinstalls, generates a fresh identity key,
        // and the server issues her a perfectly valid new certificate under her
        // own name. That is a safety-number change, and it is the form of this
        // a real deployment actually hits: without the identity gate the
        // envelope comes back clean and the app never surfaces the change.
        final aliceAfterReinstall = IdentityKeyPair.generate();
        expect(
          _sameKey(aliceAfterReinstall.publicKey, aliceIdentity.publicKey),
          isFalse,
        );

        final sealed = await sealedFrom(
          aliceAfterReinstall,
          certificateFor(aliceAfterReinstall.publicKey),
        );

        await expectLater(
          unseal(sealed),
          throwsA(
            predicate(
              (Object e) => e.toString().contains('untrusted identity'),
              'an untrusted identity error',
            ),
          ),
        );

        // ...and once the user has accepted the change, the same message goes
        // through. The gate reports a change; it does not wedge the session.
        await bobIdentities.saveIdentity(
          aliceAddress,
          PublicKey.deserialize(bytes: aliceAfterReinstall.publicKey.toList()),
        );
        expect(await unseal(sealed), isNotEmpty);
      },
    );

    test(
      'a certificate carrying the stored identity key is accepted',
      () async {
        final sealed = await sealedFrom(
          aliceIdentity,
          certificateFor(aliceIdentity.publicKey),
        );
        final unsealed = UnidentifiedSenderMessageContent.deserialize(
          data: await unseal(sealed),
        );

        expect(
          senderCertificateGetSenderName(
            certificate: unsealed.senderCertificate(),
          ),
          equals(_aliceName),
        );
        expect(unsealed.groupId(), equals(utf8.encode('some-group')));
        expect(unsealed.contentHint(), equals(ContentHint.resendable.value));
        expect(
          _sameKey(
            senderCertificateGetKey(certificate: unsealed.senderCertificate()),
            aliceIdentity.publicKey,
          ),
          isTrue,
        );
      },
    );

    test(
      'an unknown sender is trusted on first use, as everywhere else',
      () async {
        // Same rule as libsignal's is_trusted_identity: nothing stored means
        // first contact. Bob has no identity for `stranger-uuid`.
        final stranger = IdentityKeyPair.generate();
        final certificate = createSenderCertificate(
          senderUuid: 'stranger-uuid',
          senderDeviceId: 1,
          senderIdentityKey: stranger.publicKey,
          expiration: now + BigInt.from(3600 * 1000),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivate.serialize(),
        );
        final sealed = await sealedFrom(stranger, certificate);

        expect(await unseal(sealed), isNotEmpty);
      },
    );

    test(
      'the certificate chain is still checked before the identity is',
      () async {
        // A foreign trust root must fail on gate 1 — and must not have reached
        // gate 2, since an unvalidated certificate's sender name is
        // attacker-chosen and looking it up would probe the caller's store.
        final mallory = IdentityKeyPair.generate();
        final sealed = await sealedFrom(
          mallory,
          certificateFor(mallory.publicKey),
        );

        var identityWasConsulted = false;
        await expectLater(
          sealedSenderDecryptToUsmcWithCallbacks(
            ciphertext: sealed,
            trustRoot: PrivateKey.generate().getPublicKey().serialize(),
            timestamp: now,
            localName: bobAddress.name(),
            localDeviceId: bobAddress.deviceId(),
            getIdentityKeyPair: () async => bobKeys.identityKeyPair.serialize(),
            getLocalRegistrationId: () async => 22222,
            getIdentity: (name, deviceId) async {
              identityWasConsulted = true;
              return null;
            },
          ),
          throwsA(
            predicate(
              (Object e) =>
                  e.toString().contains('certificate validation failed'),
              'a certificate validation failure',
            ),
          ),
        );
        expect(
          identityWasConsulted,
          isFalse,
          reason: 'an unvalidated certificate must not reach the store lookup',
        );
      },
    );

    test(
      'our own message reflected back at us is refused as a self-send',
      () async {
        // A server that echoes your own sealed message back. Without this gate
        // the envelope unseals and names *you* as the sender, and a caller
        // deciding where to send a resend request would aim it at itself.
        // `SealedSenderCipher.decrypt` has refused this since upstream added it;
        // the envelope path must not be the lenient one.
        final selfCertificate = createSenderCertificate(
          senderUuid: bobAddress.name(),
          senderDeviceId: bobAddress.deviceId(),
          senderIdentityKey: bobKeys.identityKeyPair.publicKey,
          expiration: now + BigInt.from(3600 * 1000),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivate.serialize(),
        );
        final reflected = await sealedFrom(
          bobKeys.identityKeyPair,
          selfCertificate,
        );

        await expectLater(
          unseal(reflected),
          throwsA(
            predicate(
              (Object e) => e.toString().contains('self send'),
              'a self-send error',
            ),
          ),
        );
        await expectLater(
          fullDecrypt(reflected),
          throwsA(
            predicate(
              (Object e) => e.toString().contains('self send'),
              'a self-send error',
            ),
          ),
          reason: 'both paths must agree, and on the same string',
        );
      },
    );

    test('another device of our own account is NOT a self-send', () async {
      // The gate compares the device too, exactly as upstream does. Bob's
      // second device is a different peer as far as this check is concerned,
      // and refusing it would break linked-device delivery.
      final otherDeviceCertificate = createSenderCertificate(
        senderUuid: bobAddress.name(),
        senderDeviceId: 2,
        senderIdentityKey: bobKeys.identityKeyPair.publicKey,
        expiration: now + BigInt.from(3600 * 1000),
        serverCertificate: serverCertificate,
        serverPrivateKey: serverPrivate.serialize(),
      );
      final fromOtherDevice = await sealedFrom(
        bobKeys.identityKeyPair,
        otherDeviceCertificate,
      );

      expect(await unseal(fromOtherDevice), isNotEmpty);
    });
  });
}
