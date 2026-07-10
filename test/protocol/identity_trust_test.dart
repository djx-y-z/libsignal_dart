// Identity-trust enforcement (MITM / safety-number-change detection).
//
// These tests guard the fix that wires `getIdentity` into the Rust layer so
// libsignal's `is_trusted_identity` actually runs. Before the fix, the
// high-level ciphers built a fresh empty identity store per call, so a *changed*
// remote identity key was silently accepted (no error). The "rejects a changed
// identity" test below fails (no throw) without the pre-seed — it is the
// regression guard for the whole feature.
// ignore_for_file: avoid_redundant_argument_values
import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/session_helpers.dart';

void main() {
  setUpAll(LibSignal.init);

  group('Identity-trust enforcement', () {
    late IdentityKeyPair aliceIdentity;
    late InMemorySessionStore aliceSessionStore;
    late InMemoryIdentityKeyStore aliceIdentityStore;
    late SessionBuilder builder;
    late ProtocolAddress bobAddress;

    setUp(() {
      // Created in setUp (after setUpAll init), not at group scope, because
      // ProtocolAddress calls into Rust which requires LibSignal.init first.
      bobAddress = ProtocolAddress(name: 'bob', deviceId: 1);
      aliceIdentity = IdentityKeyPair.generate();
      aliceSessionStore = InMemorySessionStore();
      aliceIdentityStore = InMemoryIdentityKeyStore(aliceIdentity, 111);
      builder = SessionBuilder(
        localAddress: ProtocolAddress(name: 'alice', deviceId: 1),
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );
    });

    test('rejects a changed remote identity for the same address', () async {
      // First bundle establishes trust in identity I1 for bob.
      final bobKeys1 = generateRemotePartyKeys(
        registrationId: 222,
        deviceId: 1,
        preKeyId: 1,
        signedPreKeyId: 1,
        kyberPreKeyId: 1,
      );
      await builder.processPreKeyBundle(bobAddress, bobKeys1.toBundle());
      expect(await aliceIdentityStore.getIdentity(bobAddress), isNotNull);

      // A second, self-consistently-signed bundle carrying a DIFFERENT identity
      // (I2) for the SAME address. Its signatures are valid, so the only reason
      // to reject it is the identity change.
      final bobKeys2 = generateRemotePartyKeys(
        registrationId: 222,
        deviceId: 1,
        preKeyId: 2,
        signedPreKeyId: 2,
        kyberPreKeyId: 2,
      );

      await expectLater(
        () => builder.processPreKeyBundle(bobAddress, bobKeys2.toBundle()),
        throwsA(
          predicate<Object>(
            (e) => e.toString().toLowerCase().contains('untrusted identity'),
            'an UntrustedIdentity error (not a signature/session failure)',
          ),
        ),
      );
    });

    test(
      'accepts the same remote identity again (no false rejection)',
      () async {
        final bobKeys1 = generateRemotePartyKeys(
          registrationId: 222,
          deviceId: 1,
          preKeyId: 1,
          signedPreKeyId: 1,
          kyberPreKeyId: 1,
        );
        await builder.processPreKeyBundle(bobAddress, bobKeys1.toBundle());

        // Same identity, rotated pre-keys — must NOT be treated as untrusted.
        final bobKeys2 = generateRemotePartyKeysWithIdentity(
          identityKeyPair: bobKeys1.identityKeyPair,
          registrationId: 222,
          deviceId: 1,
          preKeyId: 2,
          signedPreKeyId: 2,
          kyberPreKeyId: 2,
        );

        await expectLater(
          builder.processPreKeyBundle(bobAddress, bobKeys2.toBundle()),
          completes,
        );
      },
    );
  });

  // Exercises the *pre-key-message decryption* enforcement path (distinct from
  // the bundle path above): Bob decrypting an incoming pre-key message.
  group('Identity-trust on pre-key message decryption', () {
    // Created in setUp (after setUpAll init) — ProtocolAddress calls into Rust.
    late ProtocolAddress aliceAddress;
    setUp(() {
      aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
    });

    // Builds a Bob who can decrypt pre-key messages, and an incoming pre-key
    // message from Alice carrying Alice's real identity. Returns Bob's cipher +
    // identity store (so the test can pre-seed a trusted identity) and the
    // ciphertext.
    Future<(SessionCipher, InMemoryIdentityKeyStore, CiphertextMessage)>
    buildIncomingPreKeyMessage() async {
      // Bob (responder) with pre-keys registered so he can decrypt.
      final bobKeys = generateRemotePartyKeys(
        registrationId: 222,
        deviceId: 1,
        preKeyId: 31,
        signedPreKeyId: 7,
        kyberPreKeyId: 1,
      );
      final bobSessionStore = InMemorySessionStore();
      final bobIdentityStore = InMemoryIdentityKeyStore(
        bobKeys.identityKeyPair,
        222,
      );
      final bobPreKeyStore = InMemoryPreKeyStore();
      final bobSignedPreKeyStore = InMemorySignedPreKeyStore();
      final bobKyberPreKeyStore = InMemoryKyberPreKeyStore();
      final ts = BigInt.from(DateTime.now().millisecondsSinceEpoch);
      await bobPreKeyStore.storePreKey(
        bobKeys.preKeyId,
        PreKeyRecord(
          id: bobKeys.preKeyId,
          publicKey: bobKeys.preKeyPublic,
          privateKey: bobKeys.preKeyPrivate,
        ),
      );
      await bobSignedPreKeyStore.storeSignedPreKey(
        bobKeys.signedPreKeyId,
        SignedPreKeyRecord(
          id: bobKeys.signedPreKeyId,
          publicKey: bobKeys.signedPreKeyPublic,
          privateKey: bobKeys.signedPreKeyPrivate,
          signature: bobKeys.signedPreKeySignature.toList(),
          timestamp: ts,
        ),
      );
      await bobKyberPreKeyStore.storeKyberPreKey(
        bobKeys.kyberPreKeyId,
        KyberPreKeyRecord.create(
          id: bobKeys.kyberPreKeyId,
          keyPair: bobKeys.kyberKeyPair,
          signature: bobKeys.kyberPreKeySignature.toList(),
          timestamp: ts,
        ),
      );
      final bobAddress = ProtocolAddress(name: 'bob', deviceId: 1);
      final bobCipher = SessionCipher(
        localAddress: bobAddress,
        sessionStore: bobSessionStore,
        identityKeyStore: bobIdentityStore,
        preKeyStore: bobPreKeyStore,
        signedPreKeyStore: bobSignedPreKeyStore,
        kyberPreKeyStore: bobKyberPreKeyStore,
      );

      // Alice establishes a session with Bob and encrypts a message. The first
      // message is a pre-key message that carries Alice's identity.
      final alice = IdentityKeyPair.generate();
      final aliceSessionStore = InMemorySessionStore();
      final aliceIdentityStore = InMemoryIdentityKeyStore(alice, 111);
      final aliceBuilder = SessionBuilder(
        localAddress: aliceAddress,
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );
      await aliceBuilder.processPreKeyBundle(bobAddress, bobKeys.toBundle());
      final aliceCipher = SessionCipher(
        localAddress: aliceAddress,
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
        preKeyStore: InMemoryPreKeyStore(),
        signedPreKeyStore: InMemorySignedPreKeyStore(),
        kyberPreKeyStore: InMemoryKyberPreKeyStore(),
      );
      final ciphertext = await aliceCipher.encrypt(
        bobAddress,
        utf8.encode('hello bob'),
      );
      expect(ciphertext.isPreKeyMessage, isTrue);

      return (bobCipher, bobIdentityStore, ciphertext);
    }

    test(
      'rejects a pre-key message whose identity differs from the stored one',
      () async {
        final (bobCipher, bobIdentityStore, ciphertext) =
            await buildIncomingPreKeyMessage();

        // Bob already trusts a DIFFERENT identity for "alice".
        final otherIdentity = IdentityKeyPair.generate();
        await bobIdentityStore.saveIdentity(
          aliceAddress,
          PublicKey.deserialize(bytes: otherIdentity.publicKey.toList()),
        );

        await expectLater(
          () => bobCipher.decrypt(aliceAddress, ciphertext),
          throwsA(
            predicate<Object>(
              (e) => e.toString().toLowerCase().contains('untrusted identity'),
              'an UntrustedIdentity error (not a MAC/prekey failure)',
            ),
          ),
        );
      },
    );

    test('accepts a pre-key message on first contact (control)', () async {
      final (bobCipher, _, ciphertext) = await buildIncomingPreKeyMessage();

      // No prior identity stored for "alice" → trust-on-first-use, decrypts.
      final plaintext = await bobCipher.decrypt(aliceAddress, ciphertext);
      expect(utf8.decode(plaintext), equals('hello bob'));
    });
  });

  // Exercises the *encryption* and *Whisper (established-session) decryption*
  // enforcement paths: libsignal consults is_trusted_identity with
  // Direction::Sending on message_encrypt and Direction::Receiving on
  // message_decrypt_signal, comparing the stored identity against the one bound
  // to the session. A stored identity that differs from the session's must be
  // rejected even though the session itself is intact.
  group('Identity-trust on encryption and Whisper decryption', () {
    late ProtocolAddress aliceAddress;
    late ProtocolAddress bobAddress;
    setUp(() {
      aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
      bobAddress = ProtocolAddress(name: 'bob', deviceId: 1);
    });

    // Establishes a full two-way session between Alice and Bob (bundle →
    // pre-key message → reply), so that subsequent messages in either
    // direction are Whisper messages against an existing session.
    Future<
      ({
        SessionCipher aliceCipher,
        InMemoryIdentityKeyStore aliceIdentityStore,
        SessionCipher bobCipher,
        InMemoryIdentityKeyStore bobIdentityStore,
      })
    >
    buildEstablishedSession() async {
      final bobKeys = generateRemotePartyKeys(
        registrationId: 222,
        deviceId: 1,
        preKeyId: 51,
        signedPreKeyId: 9,
        kyberPreKeyId: 3,
      );
      final bobSessionStore = InMemorySessionStore();
      final bobIdentityStore = InMemoryIdentityKeyStore(
        bobKeys.identityKeyPair,
        222,
      );
      final bobPreKeyStore = InMemoryPreKeyStore();
      final bobSignedPreKeyStore = InMemorySignedPreKeyStore();
      final bobKyberPreKeyStore = InMemoryKyberPreKeyStore();
      final ts = BigInt.from(DateTime.now().millisecondsSinceEpoch);
      await bobPreKeyStore.storePreKey(
        bobKeys.preKeyId,
        PreKeyRecord(
          id: bobKeys.preKeyId,
          publicKey: bobKeys.preKeyPublic,
          privateKey: bobKeys.preKeyPrivate,
        ),
      );
      await bobSignedPreKeyStore.storeSignedPreKey(
        bobKeys.signedPreKeyId,
        SignedPreKeyRecord(
          id: bobKeys.signedPreKeyId,
          publicKey: bobKeys.signedPreKeyPublic,
          privateKey: bobKeys.signedPreKeyPrivate,
          signature: bobKeys.signedPreKeySignature.toList(),
          timestamp: ts,
        ),
      );
      await bobKyberPreKeyStore.storeKyberPreKey(
        bobKeys.kyberPreKeyId,
        KyberPreKeyRecord.create(
          id: bobKeys.kyberPreKeyId,
          keyPair: bobKeys.kyberKeyPair,
          signature: bobKeys.kyberPreKeySignature.toList(),
          timestamp: ts,
        ),
      );
      final bobCipher = SessionCipher(
        localAddress: bobAddress,
        sessionStore: bobSessionStore,
        identityKeyStore: bobIdentityStore,
        preKeyStore: bobPreKeyStore,
        signedPreKeyStore: bobSignedPreKeyStore,
        kyberPreKeyStore: bobKyberPreKeyStore,
      );

      final alice = IdentityKeyPair.generate();
      final aliceSessionStore = InMemorySessionStore();
      final aliceIdentityStore = InMemoryIdentityKeyStore(alice, 111);
      final aliceBuilder = SessionBuilder(
        localAddress: aliceAddress,
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );
      await aliceBuilder.processPreKeyBundle(bobAddress, bobKeys.toBundle());
      final aliceCipher = SessionCipher(
        localAddress: aliceAddress,
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
        preKeyStore: InMemoryPreKeyStore(),
        signedPreKeyStore: InMemorySignedPreKeyStore(),
        kyberPreKeyStore: InMemoryKyberPreKeyStore(),
      );

      // Round-trip: pre-key message to Bob, reply to Alice. After this both
      // sides hold an established session and each other's identity.
      final msg1 = await aliceCipher.encrypt(bobAddress, utf8.encode('hi bob'));
      expect(msg1.isPreKeyMessage, isTrue);
      await bobCipher.decrypt(aliceAddress, msg1);
      final reply = await bobCipher.encrypt(
        aliceAddress,
        utf8.encode('hi alice'),
      );
      expect(reply.isPreKeyMessage, isFalse);
      await aliceCipher.decrypt(bobAddress, reply);

      return (
        aliceCipher: aliceCipher,
        aliceIdentityStore: aliceIdentityStore,
        bobCipher: bobCipher,
        bobIdentityStore: bobIdentityStore,
      );
    }

    test(
      'rejects encryption when the stored recipient identity changed',
      () async {
        final session = await buildEstablishedSession();

        // Control: with the untouched store, encryption succeeds.
        await expectLater(
          session.aliceCipher.encrypt(bobAddress, utf8.encode('control')),
          completes,
        );

        // Alice's store now claims a DIFFERENT identity for bob than the one the
        // session is bound to (e.g. the app re-trusted a new key elsewhere).
        final otherIdentity = IdentityKeyPair.generate();
        await session.aliceIdentityStore.saveIdentity(
          bobAddress,
          PublicKey.deserialize(bytes: otherIdentity.publicKey.toList()),
        );

        await expectLater(
          () => session.aliceCipher.encrypt(bobAddress, utf8.encode('secret')),
          throwsA(
            predicate<Object>(
              (e) => e.toString().toLowerCase().contains('untrusted identity'),
              'an UntrustedIdentity error (not a session failure)',
            ),
          ),
        );
      },
    );

    test(
      'rejects Whisper decryption when the stored sender identity changed',
      () async {
        final session = await buildEstablishedSession();

        // Alice sends a Whisper message over the established session.
        final whisper = await session.aliceCipher.encrypt(
          bobAddress,
          utf8.encode('whisper'),
        );
        expect(whisper.isPreKeyMessage, isFalse);

        // Bob's store now claims a DIFFERENT identity for alice.
        final otherIdentity = IdentityKeyPair.generate();
        await session.bobIdentityStore.saveIdentity(
          aliceAddress,
          PublicKey.deserialize(bytes: otherIdentity.publicKey.toList()),
        );

        await expectLater(
          () => session.bobCipher.decrypt(aliceAddress, whisper),
          throwsA(
            predicate<Object>(
              (e) => e.toString().toLowerCase().contains('untrusted identity'),
              'an UntrustedIdentity error (not a MAC failure)',
            ),
          ),
        );
      },
    );

    test(
      'accepts Whisper decryption with the unchanged identity (control)',
      () async {
        final session = await buildEstablishedSession();

        final whisper = await session.aliceCipher.encrypt(
          bobAddress,
          utf8.encode('whisper'),
        );
        expect(whisper.isPreKeyMessage, isFalse);

        final plaintext = await session.bobCipher.decrypt(
          aliceAddress,
          whisper,
        );
        expect(utf8.decode(plaintext), equals('whisper'));
      },
    );
  });

  // Exercises the *sealed-sender decryption* enforcement path: the identity is
  // seeded against the certificate-derived sender address, so a stored identity
  // that differs from the one in the incoming pre-key message must be rejected.
  group('Identity-trust on sealed-sender decryption', () {
    late ProtocolAddress aliceAddress;
    setUp(() {
      aliceAddress = ProtocolAddress(name: 'alice-uuid', deviceId: 1);
    });

    // Builds a Bob who can decrypt sealed-sender messages and an incoming
    // sealed pre-key message from Alice. Returns Bob's cipher + identity store
    // (so the test can pre-seed a conflicting identity), the ciphertext, and
    // the trust root needed to decrypt.
    Future<(SealedSenderCipher, InMemoryIdentityKeyStore, Uint8List, PublicKey)>
    buildIncomingSealedMessage() async {
      // Server / trust-root keys and certificate chain.
      final trustRootPrivateKey = PrivateKey.generate();
      final trustRootPublicKey = trustRootPrivateKey.getPublicKey();
      final serverPrivateKey = PrivateKey.generate();
      final serverCertificate = createServerCertificate(
        keyId: 1,
        serverPublicKey: serverPrivateKey.getPublicKey().serialize(),
        trustRootPrivateKey: trustRootPrivateKey.serialize(),
      );

      // Bob (responder) with pre-keys registered so he can decrypt.
      final bobKeys = generateRemotePartyKeys(
        registrationId: 222,
        deviceId: 1,
        preKeyId: 41,
        signedPreKeyId: 8,
        kyberPreKeyId: 2,
      );
      final bobSessionStore = InMemorySessionStore();
      final bobIdentityStore = InMemoryIdentityKeyStore(
        bobKeys.identityKeyPair,
        222,
      );
      final bobPreKeyStore = InMemoryPreKeyStore();
      final bobSignedPreKeyStore = InMemorySignedPreKeyStore();
      final bobKyberPreKeyStore = InMemoryKyberPreKeyStore();
      final ts = BigInt.from(DateTime.now().millisecondsSinceEpoch);
      await bobPreKeyStore.storePreKey(
        bobKeys.preKeyId,
        PreKeyRecord(
          id: bobKeys.preKeyId,
          publicKey: bobKeys.preKeyPublic,
          privateKey: bobKeys.preKeyPrivate,
        ),
      );
      await bobSignedPreKeyStore.storeSignedPreKey(
        bobKeys.signedPreKeyId,
        SignedPreKeyRecord(
          id: bobKeys.signedPreKeyId,
          publicKey: bobKeys.signedPreKeyPublic,
          privateKey: bobKeys.signedPreKeyPrivate,
          signature: bobKeys.signedPreKeySignature.toList(),
          timestamp: ts,
        ),
      );
      await bobKyberPreKeyStore.storeKyberPreKey(
        bobKeys.kyberPreKeyId,
        KyberPreKeyRecord.create(
          id: bobKeys.kyberPreKeyId,
          keyPair: bobKeys.kyberKeyPair,
          signature: bobKeys.kyberPreKeySignature.toList(),
          timestamp: ts,
        ),
      );
      final bobAddress = ProtocolAddress(name: 'bob-uuid', deviceId: 1);
      final bobCipher = SealedSenderCipher(
        localAddress: bobAddress,
        sessionStore: bobSessionStore,
        identityKeyStore: bobIdentityStore,
        preKeyStore: bobPreKeyStore,
        signedPreKeyStore: bobSignedPreKeyStore,
        kyberPreKeyStore: bobKyberPreKeyStore,
      );

      // Alice establishes a session with Bob and sends a sealed message. The
      // first message carries a pre-key message with Alice's identity, and the
      // sender certificate binds that identity to 'alice-uuid':1.
      final alice = IdentityKeyPair.generate();
      final aliceSessionStore = InMemorySessionStore();
      final aliceIdentityStore = InMemoryIdentityKeyStore(alice, 111);
      final aliceBuilder = SessionBuilder(
        localAddress: aliceAddress,
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
      );
      await aliceBuilder.processPreKeyBundle(bobAddress, bobKeys.toBundle());

      final expiration = DateTime.now()
          .add(const Duration(hours: 1))
          .millisecondsSinceEpoch;
      final aliceSenderCertificate = createSenderCertificate(
        senderUuid: aliceAddress.name(),
        senderDeviceId: aliceAddress.deviceId(),
        senderIdentityKey: alice.publicKey,
        expiration: BigInt.from(expiration),
        serverCertificate: serverCertificate,
        serverPrivateKey: serverPrivateKey.serialize(),
      );
      final aliceCipher = SealedSenderCipher(
        localAddress: aliceAddress,
        sessionStore: aliceSessionStore,
        identityKeyStore: aliceIdentityStore,
        preKeyStore: InMemoryPreKeyStore(),
        signedPreKeyStore: InMemorySignedPreKeyStore(),
        kyberPreKeyStore: InMemoryKyberPreKeyStore(),
      );
      final ciphertext = await aliceCipher.encrypt(
        recipientAddress: bobAddress,
        plaintext: Uint8List.fromList(utf8.encode('hello bob')),
        senderCertificate: aliceSenderCertificate,
      );

      return (bobCipher, bobIdentityStore, ciphertext, trustRootPublicKey);
    }

    test('rejects a sealed message whose sender identity differs from the '
        'stored one', () async {
      final (bobCipher, bobIdentityStore, ciphertext, trustRoot) =
          await buildIncomingSealedMessage();

      // Bob already trusts a DIFFERENT identity for the cert-derived sender
      // address 'alice-uuid':1.
      final otherIdentity = IdentityKeyPair.generate();
      await bobIdentityStore.saveIdentity(
        aliceAddress,
        PublicKey.deserialize(bytes: otherIdentity.publicKey.toList()),
      );

      await expectLater(
        () => bobCipher.decrypt(
          ciphertext: ciphertext,
          trustRoot: trustRoot.serialize(),
          timestamp: DateTime.now().millisecondsSinceEpoch,
        ),
        throwsA(
          predicate<Object>(
            (e) => e.toString().toLowerCase().contains('untrusted identity'),
            'an UntrustedIdentity error (not a cert/MAC failure)',
          ),
        ),
      );
    });

    test('accepts a sealed message on first contact (control)', () async {
      final (bobCipher, _, ciphertext, trustRoot) =
          await buildIncomingSealedMessage();

      // No prior identity stored for the sender → trust-on-first-use.
      final result = await bobCipher.decrypt(
        ciphertext: ciphertext,
        trustRoot: trustRoot.serialize(),
        timestamp: DateTime.now().millisecondsSinceEpoch,
      );
      expect(utf8.decode(result.plaintext), equals('hello bob'));
      expect(result.senderAddress.name(), equals('alice-uuid'));
    });

    test(
      'rejects sealed encryption when the stored recipient identity changed',
      () async {
        // Minimal sender-side setup: certificate chain + a session with Bob.
        final trustRootPrivateKey = PrivateKey.generate();
        final serverPrivateKey = PrivateKey.generate();
        final serverCertificate = createServerCertificate(
          keyId: 1,
          serverPublicKey: serverPrivateKey.getPublicKey().serialize(),
          trustRootPrivateKey: trustRootPrivateKey.serialize(),
        );
        final bobKeys = generateRemotePartyKeys(
          registrationId: 222,
          deviceId: 1,
          preKeyId: 61,
          signedPreKeyId: 10,
          kyberPreKeyId: 4,
        );
        final bobAddress = ProtocolAddress(name: 'bob-uuid', deviceId: 1);

        final alice = IdentityKeyPair.generate();
        final aliceSessionStore = InMemorySessionStore();
        final aliceIdentityStore = InMemoryIdentityKeyStore(alice, 111);
        final aliceBuilder = SessionBuilder(
          localAddress: aliceAddress,
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await aliceBuilder.processPreKeyBundle(bobAddress, bobKeys.toBundle());
        final expiration = DateTime.now()
            .add(const Duration(hours: 1))
            .millisecondsSinceEpoch;
        final aliceSenderCertificate = createSenderCertificate(
          senderUuid: aliceAddress.name(),
          senderDeviceId: aliceAddress.deviceId(),
          senderIdentityKey: alice.publicKey,
          expiration: BigInt.from(expiration),
          serverCertificate: serverCertificate,
          serverPrivateKey: serverPrivateKey.serialize(),
        );
        final aliceCipher = SealedSenderCipher(
          localAddress: aliceAddress,
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
          preKeyStore: InMemoryPreKeyStore(),
          signedPreKeyStore: InMemorySignedPreKeyStore(),
          kyberPreKeyStore: InMemoryKyberPreKeyStore(),
        );

        // Control: with the identity stored by processPreKeyBundle, sealed
        // encryption succeeds.
        await expectLater(
          aliceCipher.encrypt(
            recipientAddress: bobAddress,
            plaintext: Uint8List.fromList(utf8.encode('control')),
            senderCertificate: aliceSenderCertificate,
          ),
          completes,
        );

        // Alice's store now claims a DIFFERENT identity for bob.
        final otherIdentity = IdentityKeyPair.generate();
        await aliceIdentityStore.saveIdentity(
          bobAddress,
          PublicKey.deserialize(bytes: otherIdentity.publicKey.toList()),
        );

        await expectLater(
          () => aliceCipher.encrypt(
            recipientAddress: bobAddress,
            plaintext: Uint8List.fromList(utf8.encode('secret')),
            senderCertificate: aliceSenderCertificate,
          ),
          throwsA(
            predicate<Object>(
              (e) => e.toString().toLowerCase().contains('untrusted identity'),
              'an UntrustedIdentity error (not a cert/session failure)',
            ),
          ),
        );
      },
    );
  });
}
