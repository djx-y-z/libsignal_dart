// ignore_for_file: unreachable_from_main, sort_constructors_first
/// Which pre-keys a decryption consumes, and what it tells the store.
///
/// Two behaviours are pinned here:
///
/// 1. Consumption follows what libsignal actually did, not what the message
///    referenced. A pre-key message that lands on a session already established
///    by an earlier pre-key message consumes nothing the second time.
/// 2. `markKyberPreKeyUsed` fires on **both** decryption paths, and carries the
///    full `(kyberPreKeyId, signedPreKeyId, baseKey)` triple that libsignal's
///    own `KyberPreKeyStore` receives.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/session_helpers.dart';

/// One `markKyberPreKeyUsed` call.
typedef KyberMark = ({
  int kyberPreKeyId,
  int signedPreKeyId,
  PublicKey baseKey,
});

/// [KyberPreKeyStore] that records every `markKyberPreKeyUsed` call verbatim.
class RecordingKyberPreKeyStore implements KyberPreKeyStore {
  RecordingKyberPreKeyStore(this._inner);

  final InMemoryKyberPreKeyStore _inner;

  final List<KyberMark> marks = [];

  @override
  Future<void> markKyberPreKeyUsed(
    int kyberPreKeyId,
    int signedPreKeyId,
    PublicKey baseKey,
  ) async {
    marks.add((
      kyberPreKeyId: kyberPreKeyId,
      signedPreKeyId: signedPreKeyId,
      baseKey: baseKey,
    ));
    await _inner.markKyberPreKeyUsed(kyberPreKeyId, signedPreKeyId, baseKey);
  }

  @override
  Future<KyberPreKeyRecord?> loadKyberPreKey(int id) =>
      _inner.loadKyberPreKey(id);

  @override
  Future<void> storeKyberPreKey(int id, KyberPreKeyRecord record) =>
      _inner.storeKyberPreKey(id, record);

  @override
  Future<bool> containsKyberPreKey(int id) => _inner.containsKyberPreKey(id);

  @override
  Future<void> removeKyberPreKey(int id) => _inner.removeKyberPreKey(id);

  @override
  Future<List<int>> getAllKyberPreKeyIds() => _inner.getAllKyberPreKeyIds();
}

/// [PreKeyStore] that records every `removePreKey` call.
class RecordingPreKeyStore implements PreKeyStore {
  RecordingPreKeyStore(this._inner);

  final InMemoryPreKeyStore _inner;

  final List<int> removed = [];

  @override
  Future<void> removePreKey(int preKeyId) async {
    removed.add(preKeyId);
    await _inner.removePreKey(preKeyId);
  }

  @override
  Future<PreKeyRecord?> loadPreKey(int id) => _inner.loadPreKey(id);

  @override
  Future<void> storePreKey(int id, PreKeyRecord record) =>
      _inner.storePreKey(id, record);

  @override
  Future<bool> containsPreKey(int id) => _inner.containsPreKey(id);

  @override
  Future<List<int>> getAllPreKeyIds() => _inner.getAllPreKeyIds();
}

/// The receiving side: real stores, wrapped so calls can be counted.
class Recipient {
  Recipient({
    required this.address,
    required this.keys,
    required this.sessionStore,
    required this.identityStore,
    required this.preKeyStore,
    required this.signedPreKeyStore,
    required this.kyberPreKeyStore,
  });

  final ProtocolAddress address;
  final RemotePartyKeys keys;
  final InMemorySessionStore sessionStore;
  final InMemoryIdentityKeyStore identityStore;
  final RecordingPreKeyStore preKeyStore;
  final InMemorySignedPreKeyStore signedPreKeyStore;
  final RecordingKyberPreKeyStore kyberPreKeyStore;

  /// Puts the one-time pre-key back, standing in for a client that published a
  /// fresh bundle after the previous one was consumed.
  Future<void> republishOneTimePreKey(int id) => preKeyStore.storePreKey(
    id,
    PreKeyRecord(
      id: id,
      publicKey: keys.preKeyPublic,
      privateKey: keys.preKeyPrivate,
    ),
  );

  SessionCipher get cipher => SessionCipher(
    localAddress: address,
    sessionStore: sessionStore,
    identityKeyStore: identityStore,
    preKeyStore: preKeyStore,
    signedPreKeyStore: signedPreKeyStore,
    kyberPreKeyStore: kyberPreKeyStore,
  );

  SealedSenderCipher get sealedCipher => SealedSenderCipher(
    localAddress: address,
    sessionStore: sessionStore,
    identityKeyStore: identityStore,
    preKeyStore: preKeyStore,
    signedPreKeyStore: signedPreKeyStore,
    kyberPreKeyStore: kyberPreKeyStore,
  );
}

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  const preKeyId = 31337;
  const signedPreKeyId = 22;
  const kyberPreKeyId = 9;

  /// Builds Bob with pre-keys published and recording stores installed.
  Future<Recipient> createRecipient() async {
    final address = ProtocolAddress(name: 'bob-uuid', deviceId: 1);
    final keys = generateRemotePartyKeys(
      registrationId: 22222,
      preKeyId: preKeyId,
      signedPreKeyId: signedPreKeyId,
      kyberPreKeyId: kyberPreKeyId,
    );

    final preKeyStore = RecordingPreKeyStore(InMemoryPreKeyStore());
    final signedPreKeyStore = InMemorySignedPreKeyStore();
    final kyberPreKeyStore = RecordingKyberPreKeyStore(
      InMemoryKyberPreKeyStore(),
    );
    final timestamp = BigInt.from(DateTime.now().millisecondsSinceEpoch);

    await preKeyStore.storePreKey(
      preKeyId,
      PreKeyRecord(
        id: preKeyId,
        publicKey: keys.preKeyPublic,
        privateKey: keys.preKeyPrivate,
      ),
    );
    await signedPreKeyStore.storeSignedPreKey(
      signedPreKeyId,
      SignedPreKeyRecord(
        id: signedPreKeyId,
        timestamp: timestamp,
        publicKey: keys.signedPreKeyPublic,
        privateKey: keys.signedPreKeyPrivate,
        signature: keys.signedPreKeySignature,
      ),
    );
    await kyberPreKeyStore.storeKyberPreKey(
      kyberPreKeyId,
      KyberPreKeyRecord.create(
        id: kyberPreKeyId,
        timestamp: timestamp,
        keyPair: keys.kyberKeyPair,
        signature: keys.kyberPreKeySignature,
      ),
    );

    return Recipient(
      address: address,
      keys: keys,
      sessionStore: InMemorySessionStore(),
      identityStore: InMemoryIdentityKeyStore(keys.identityKeyPair, 22222),
      preKeyStore: preKeyStore,
      signedPreKeyStore: signedPreKeyStore,
      kyberPreKeyStore: kyberPreKeyStore,
    );
  }

  /// The sending side, with a session to [bob] already established.
  Future<
    ({
      ProtocolAddress address,
      IdentityKeyPair identity,
      SessionCipher cipher,
      InMemorySessionStore sessionStore,
      InMemoryIdentityKeyStore identityStore,
    })
  >
  createSender(Recipient bob, {String name = 'alice-uuid'}) async {
    final address = ProtocolAddress(name: name, deviceId: 1);
    final identity = IdentityKeyPair.generate();
    final sessionStore = InMemorySessionStore();
    final identityStore = InMemoryIdentityKeyStore(identity, 11111);

    await SessionBuilder(
      localAddress: address,
      sessionStore: sessionStore,
      identityKeyStore: identityStore,
    ).processPreKeyBundle(bob.address, bob.keys.toBundle());

    return (
      address: address,
      identity: identity,
      sessionStore: sessionStore,
      identityStore: identityStore,
      cipher: SessionCipher(
        localAddress: address,
        sessionStore: sessionStore,
        identityKeyStore: identityStore,
        preKeyStore: InMemoryPreKeyStore(),
        signedPreKeyStore: InMemorySignedPreKeyStore(),
        kyberPreKeyStore: InMemoryKyberPreKeyStore(),
      ),
    );
  }

  group('SessionCipher.decrypt', () {
    test('marks the Kyber pre-key with the full upstream triple', () async {
      final bob = await createRecipient();
      final alice = await createSender(bob);

      final ciphertext = await alice.cipher.encrypt(
        bob.address,
        utf8.encode('first'),
      );
      expect(ciphertext.isPreKeyMessage, isTrue);

      await bob.cipher.decrypt(alice.address, ciphertext);

      expect(bob.kyberPreKeyStore.marks, hasLength(1));
      final mark = bob.kyberPreKeyStore.marks.single;
      expect(mark.kyberPreKeyId, equals(kyberPreKeyId));
      // The signed EC pre-key the Kyber key was agreed with — this is the
      // argument a store needs for the last-resort replay check, and it must
      // not be confused with the Kyber ID.
      expect(mark.signedPreKeyId, equals(signedPreKeyId));
      // A real curve point, not a placeholder.
      expect(mark.baseKey.serialize(), hasLength(33));

      // The one-time EC pre-key is consumed on the same path.
      expect(bob.preKeyStore.removed, equals([preKeyId]));
    });

    test('base key identifies the agreement, not the recipient', () async {
      final bob = await createRecipient();
      final alice = await createSender(bob);
      final carol = await createSender(bob, name: 'carol-uuid');

      await bob.cipher.decrypt(
        alice.address,
        await alice.cipher.encrypt(bob.address, utf8.encode('from alice')),
      );
      // Alice's message consumed the one-time pre-key Carol's bundle also
      // names; the Kyber and signed pre-keys are reused as designed.
      await bob.republishOneTimePreKey(preKeyId);
      await bob.cipher.decrypt(
        carol.address,
        await carol.cipher.encrypt(bob.address, utf8.encode('from carol')),
      );

      expect(bob.kyberPreKeyStore.marks, hasLength(2));
      final baseKeys = bob.kyberPreKeyStore.marks
          .map((mark) => base64Encode(mark.baseKey.serialize()))
          .toSet();
      // Same Kyber and signed pre-key both times; only the base key separates
      // the two agreements, which is why the triple is what gets recorded.
      expect(baseKeys, hasLength(2));
    });

    test(
      'a second pre-key message on the same session consumes nothing',
      () async {
        final bob = await createRecipient();
        final alice = await createSender(bob);

        // Alice has not heard back yet, so both messages are pre-key messages
        // carrying the same base key.
        final first = await alice.cipher.encrypt(
          bob.address,
          utf8.encode('first'),
        );
        final second = await alice.cipher.encrypt(
          bob.address,
          utf8.encode('second'),
        );
        expect(first.isPreKeyMessage, isTrue);
        expect(second.isPreKeyMessage, isTrue);

        await bob.cipher.decrypt(alice.address, first);
        await bob.cipher.decrypt(alice.address, second);

        // The second message decrypts against the session the first one
        // established: libsignal establishes nothing and consumes nothing, so
        // neither store write is repeated. Deriving consumption from the
        // message fields instead would report both twice.
        expect(bob.kyberPreKeyStore.marks, hasLength(1));
        expect(bob.preKeyStore.removed, equals([preKeyId]));
      },
    );

    test('a genuine replay re-marks the identical triple', () async {
      final bob = await createRecipient();
      final alice = await createSender(bob);

      final ciphertext = await alice.cipher.encrypt(
        bob.address,
        utf8.encode('first'),
      );
      await bob.cipher.decrypt(alice.address, ciphertext);

      // Bob loses the session — a restored backup, the rollback SECURITY.md
      // warns about — and republishes the one-time pre-key. The Kyber key is
      // still served, which is what a last-resort key does by design.
      await bob.sessionStore.deleteSession(alice.address);
      await bob.republishOneTimePreKey(preKeyId);

      // The same message now establishes a session all over again.
      await bob.cipher.decrypt(alice.address, ciphertext);

      // Two marks carrying the *same* triple. That repetition is the only
      // signal a last-resort key gets that a pre-key message was replayed, and
      // it is why the callback carries more than the Kyber ID.
      expect(bob.kyberPreKeyStore.marks, hasLength(2));
      final [first, second] = bob.kyberPreKeyStore.marks;
      expect(second.kyberPreKeyId, equals(first.kyberPreKeyId));
      expect(second.signedPreKeyId, equals(first.signedPreKeyId));
      expect(
        base64Encode(second.baseKey.serialize()),
        equals(base64Encode(first.baseKey.serialize())),
      );
    });

    test('both messages still decrypt correctly', () async {
      final bob = await createRecipient();
      final alice = await createSender(bob);

      final first = await alice.cipher.encrypt(
        bob.address,
        utf8.encode('first'),
      );
      final second = await alice.cipher.encrypt(
        bob.address,
        utf8.encode('second'),
      );

      expect(
        utf8.decode(await bob.cipher.decrypt(alice.address, first)),
        equals('first'),
      );
      expect(
        utf8.decode(await bob.cipher.decrypt(alice.address, second)),
        equals('second'),
      );
    });
  });

  group('SealedSenderCipher.decrypt', () {
    late PrivateKey trustRootPrivateKey;
    late PublicKey trustRootPublicKey;
    late Uint8List serverCertificate;
    late PrivateKey serverPrivateKey;

    setUp(() {
      trustRootPrivateKey = PrivateKey.generate();
      trustRootPublicKey = trustRootPrivateKey.getPublicKey();
      serverPrivateKey = PrivateKey.generate();
      serverCertificate = createServerCertificate(
        keyId: 1,
        serverPublicKey: serverPrivateKey.getPublicKey().serialize(),
        trustRootPrivateKey: trustRootPrivateKey.serialize(),
      );
    });

    Uint8List certificateFor(
      ProtocolAddress address,
      IdentityKeyPair identity,
    ) => createSenderCertificate(
      senderUuid: address.name(),
      senderDeviceId: address.deviceId(),
      senderIdentityKey: identity.publicKey,
      expiration: BigInt.from(
        DateTime.now().add(const Duration(hours: 1)).millisecondsSinceEpoch,
      ),
      serverCertificate: serverCertificate,
      serverPrivateKey: serverPrivateKey.serialize(),
    );

    test('marks the Kyber pre-key it consumed', () async {
      final bob = await createRecipient();
      final alice = await createSender(bob);

      final aliceSealed = SealedSenderCipher(
        localAddress: alice.address,
        sessionStore: alice.sessionStore,
        identityKeyStore: alice.identityStore,
        preKeyStore: InMemoryPreKeyStore(),
        signedPreKeyStore: InMemorySignedPreKeyStore(),
        kyberPreKeyStore: InMemoryKyberPreKeyStore(),
      );

      final ciphertext = await aliceSealed.encrypt(
        recipientAddress: bob.address,
        plaintext: Uint8List.fromList(utf8.encode('sealed hello')),
        senderCertificate: certificateFor(alice.address, alice.identity),
      );

      final result = await bob.sealedCipher.decrypt(
        ciphertext: ciphertext,
        trustRoot: trustRootPublicKey.serialize(),
        timestamp: DateTime.now().millisecondsSinceEpoch,
      );
      expect(utf8.decode(result.plaintext), equals('sealed hello'));

      // The gap this test exists for: sealed sender used to remove the EC
      // pre-key and silently leave the Kyber one unmarked.
      expect(bob.kyberPreKeyStore.marks, hasLength(1));
      final mark = bob.kyberPreKeyStore.marks.single;
      expect(mark.kyberPreKeyId, equals(kyberPreKeyId));
      expect(mark.signedPreKeyId, equals(signedPreKeyId));
      expect(mark.baseKey.serialize(), hasLength(33));

      expect(bob.preKeyStore.removed, equals([preKeyId]));
    });

    test(
      'a second sealed pre-key message on the same session consumes nothing',
      () async {
        final bob = await createRecipient();
        final alice = await createSender(bob);

        final aliceSealed = SealedSenderCipher(
          localAddress: alice.address,
          sessionStore: alice.sessionStore,
          identityKeyStore: alice.identityStore,
          preKeyStore: InMemoryPreKeyStore(),
          signedPreKeyStore: InMemorySignedPreKeyStore(),
          kyberPreKeyStore: InMemoryKyberPreKeyStore(),
        );
        final certificate = certificateFor(alice.address, alice.identity);

        Future<Uint8List> seal(String body) => aliceSealed.encrypt(
          recipientAddress: bob.address,
          plaintext: Uint8List.fromList(utf8.encode(body)),
          senderCertificate: certificate,
        );

        // Bob has not replied, so both wrap pre-key messages sharing a base key.
        final first = await seal('one');
        final second = await seal('two');

        for (final ciphertext in [first, second]) {
          await bob.sealedCipher.decrypt(
            ciphertext: ciphertext,
            trustRoot: trustRootPublicKey.serialize(),
            timestamp: DateTime.now().millisecondsSinceEpoch,
          );
        }

        // Same rule as the SessionCipher path: only the message that actually
        // establishes the session consumes anything.
        expect(bob.kyberPreKeyStore.marks, hasLength(1));
        expect(bob.preKeyStore.removed, equals([preKeyId]));
      },
    );

    test('a plain Whisper message consumes no pre-keys', () async {
      final bob = await createRecipient();
      final alice = await createSender(bob);

      final aliceSealed = SealedSenderCipher(
        localAddress: alice.address,
        sessionStore: alice.sessionStore,
        identityKeyStore: alice.identityStore,
        preKeyStore: InMemoryPreKeyStore(),
        signedPreKeyStore: InMemorySignedPreKeyStore(),
        kyberPreKeyStore: InMemoryKyberPreKeyStore(),
      );
      final certificate = certificateFor(alice.address, alice.identity);

      // First message establishes the session and consumes the pre-keys.
      await bob.sealedCipher.decrypt(
        ciphertext: await aliceSealed.encrypt(
          recipientAddress: bob.address,
          plaintext: Uint8List.fromList(utf8.encode('one')),
          senderCertificate: certificate,
        ),
        trustRoot: trustRootPublicKey.serialize(),
        timestamp: DateTime.now().millisecondsSinceEpoch,
      );

      // Bob replies, which acknowledges the session, so Alice's next message is
      // a Whisper message with nothing to consume.
      final reply = await bob.cipher.encrypt(alice.address, utf8.encode('hi'));
      await alice.cipher.decrypt(bob.address, reply);

      await bob.sealedCipher.decrypt(
        ciphertext: await aliceSealed.encrypt(
          recipientAddress: bob.address,
          plaintext: Uint8List.fromList(utf8.encode('two')),
          senderCertificate: certificate,
        ),
        trustRoot: trustRootPublicKey.serialize(),
        timestamp: DateTime.now().millisecondsSinceEpoch,
      );

      expect(bob.kyberPreKeyStore.marks, hasLength(1));
      expect(bob.preKeyStore.removed, equals([preKeyId]));
    });
  });
}
