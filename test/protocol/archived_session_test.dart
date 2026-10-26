// ignore_for_file: sort_constructors_first
/// What a decryption does when libsignal decrypts on an ARCHIVED session.
///
/// Since libsignal v0.106.0 an archived session still decrypts, but it is never
/// made current again and the identity it carries is not saved. A record can
/// therefore come out of a decryption with no current session at all: after
/// `archiveCurrentState`, or after libsignal archived the current session
/// itself because the conversation kept switching between two sessions.
///
/// Three behaviours are pinned here:
///
/// 1. Such a decryption returns its plaintext and persists the advanced record.
///    The bridge used to read the identity to save off the record's current
///    session, which threw `sessionNotFound` after libsignal had already
///    decrypted, so the message never decrypted at all.
/// 2. Decrypting, `saveIdentity` runs only when libsignal saves the identity:
///    for a message on the current session or one that establishes a session,
///    and not for one on an archived session. That holds for sealed sender too,
///    which used to save the certificate's key on every decryption. Encrypting
///    saves it on every message, as libsignal does, which these tests count
///    apart.
/// 3. With no current session, encrypting throws `sessionNotFound`, and
///    `processPreKeyBundle` is the way back.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/error_matchers.dart';
import '../test_helpers/session_helpers.dart';

/// [IdentityKeyStore] that records every `saveIdentity` call.
class RecordingIdentityKeyStore implements IdentityKeyStore {
  RecordingIdentityKeyStore(this._inner);

  final InMemoryIdentityKeyStore _inner;

  final List<PublicKey> saved = [];

  @override
  Future<bool> saveIdentity(ProtocolAddress address, PublicKey identityKey) {
    saved.add(identityKey);
    return _inner.saveIdentity(address, identityKey);
  }

  @override
  Future<IdentityKeyPair> getIdentityKeyPair() => _inner.getIdentityKeyPair();

  @override
  Future<int> getLocalRegistrationId() => _inner.getLocalRegistrationId();

  @override
  Future<PublicKey?> getIdentity(ProtocolAddress address) =>
      _inner.getIdentity(address);

  @override
  Future<bool> isTrustedIdentity(
    ProtocolAddress address,
    PublicKey identityKey,
    Direction direction,
  ) => _inner.isTrustedIdentity(address, identityKey, direction);
}

/// One side of a conversation: in-memory stores with the identity store
/// recording, and a pre-key bundle published from them.
class Party {
  Party._({
    required this.address,
    required this.keys,
    required this.identityStore,
  });

  final ProtocolAddress address;
  final RemotePartyKeys keys;
  final RecordingIdentityKeyStore identityStore;
  final InMemorySessionStore sessionStore = InMemorySessionStore();
  final InMemoryPreKeyStore preKeyStore = InMemoryPreKeyStore();
  final InMemorySignedPreKeyStore signedPreKeyStore =
      InMemorySignedPreKeyStore();
  final InMemoryKyberPreKeyStore kyberPreKeyStore = InMemoryKyberPreKeyStore();

  static Future<Party> create(String name, int registrationId) async {
    final keys = generateRemotePartyKeys(registrationId: registrationId);
    final party = Party._(
      address: ProtocolAddress(name: name, deviceId: 1),
      keys: keys,
      identityStore: RecordingIdentityKeyStore(
        InMemoryIdentityKeyStore(keys.identityKeyPair, registrationId),
      ),
    );
    final timestamp = BigInt.from(DateTime.now().millisecondsSinceEpoch);
    await party.preKeyStore.storePreKey(
      keys.preKeyId,
      PreKeyRecord(
        id: keys.preKeyId,
        publicKey: keys.preKeyPublic,
        privateKey: keys.preKeyPrivate,
      ),
    );
    await party.signedPreKeyStore.storeSignedPreKey(
      keys.signedPreKeyId,
      SignedPreKeyRecord(
        id: keys.signedPreKeyId,
        timestamp: timestamp,
        publicKey: keys.signedPreKeyPublic,
        privateKey: keys.signedPreKeyPrivate,
        signature: keys.signedPreKeySignature,
      ),
    );
    await party.kyberPreKeyStore.storeKyberPreKey(
      keys.kyberPreKeyId,
      KyberPreKeyRecord.create(
        id: keys.kyberPreKeyId,
        timestamp: timestamp,
        keyPair: keys.kyberKeyPair,
        signature: keys.kyberPreKeySignature,
      ),
    );
    return party;
  }

  PublicKey get identityKey =>
      PublicKey.deserialize(bytes: keys.identityKeyPair.publicKey.toList());

  SessionBuilder get builder => SessionBuilder(
    localAddress: address,
    sessionStore: sessionStore,
    identityKeyStore: identityStore,
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

  /// Encrypts [text] to [to] and has [to] decrypt it.
  Future<String> send(Party to, String text) async {
    final message = await cipher.encrypt(to.address, utf8.encode(text));
    return utf8.decode(await to.cipher.decrypt(address, message));
  }

  /// Whether this side still has a current session to send to [peer] on.
  Future<bool> canSendTo(Party peer) async {
    final record = await sessionStore.loadSession(peer.address);
    return record != null &&
        record.hasUsableSenderChain(
          nowMillis: BigInt.from(DateTime.now().millisecondsSinceEpoch),
        );
  }

  /// Archives this side's current session with [peer], as an application
  /// does on a session reset.
  Future<void> archiveSessionWith(Party peer) async {
    final record = (await sessionStore.loadSession(peer.address))!
      ..archiveCurrentState();
    await sessionStore.storeSession(peer.address, record);
  }
}

/// A sender certificate for [sender], issued under [trustRoot].
Uint8List senderCertificateFor(Party sender, PrivateKey trustRoot) {
  final serverKey = PrivateKey.generate();
  return createSenderCertificate(
    senderUuid: sender.address.name(),
    senderDeviceId: sender.address.deviceId(),
    senderIdentityKey: sender.keys.identityKeyPair.publicKey,
    expiration: BigInt.from(
      DateTime.now().add(const Duration(hours: 1)).millisecondsSinceEpoch,
    ),
    serverCertificate: createServerCertificate(
      keyId: 1,
      serverPublicKey: serverKey.getPublicKey().serialize(),
      trustRootPrivateKey: trustRoot.serialize(),
    ),
    serverPrivateKey: serverKey.serialize(),
  );
}

/// [first] opens a session to [second] and [second] answers on it, so both
/// sides hold it as their current, acknowledged session.
Future<void> establish(Party first, Party second) async {
  await first.builder.processPreKeyBundle(
    second.address,
    second.keys.toBundle(),
  );
  expect(await first.send(second, 'hello'), 'hello');
  expect(await second.send(first, 'hello back'), 'hello back');
}

Matcher isKey(PublicKey key) => isA<PublicKey>().having(
  (k) => k.equals(other: key),
  'equals ${key.serialize()}',
  isTrue,
);

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('A message on an archived session', () {
    late Party alice;
    late Party bob;

    setUp(() async {
      alice = await Party.create('alice', 111);
      bob = await Party.create('bob', 222);
      await establish(alice, bob);
    });

    test('a session the recipient archived still decrypts, and its message '
        'saves no identity', () async {
      // The pre-key message established Bob's session, so libsignal saved
      // Alice's identity, and saved it again for his answer: every message
      // out saves the identity it was checked against.
      expect(bob.identityStore.saved, [
        isKey(alice.identityKey),
        isKey(alice.identityKey),
      ]);
      // Alice saved Bob's identity building the session from his bundle,
      // again for her message, and again for his answer, which decrypted on
      // her current session.
      expect(alice.identityStore.saved, [
        isKey(bob.identityKey),
        isKey(bob.identityKey),
        isKey(bob.identityKey),
      ]);
      bob.identityStore.saved.clear();

      await bob.archiveSessionWith(alice);

      // Alice does not know; she keeps sending on the session she has.
      final message = await alice.cipher.encrypt(
        bob.address,
        utf8.encode('still there?'),
      );
      expect(message.isPreKeyMessage, isFalse);
      expect(
        utf8.decode(await bob.cipher.decrypt(alice.address, message)),
        'still there?',
      );
      expect(bob.identityStore.saved, isEmpty);

      // The advanced record was stored: the same message is a duplicate now.
      await expectLater(
        bob.cipher.decrypt(alice.address, message),
        failsWith(LibSignalErrorCode.duplicatedMessage),
      );
    });

    test('the recipient cannot answer on it until it establishes a new '
        'session', () async {
      await bob.archiveSessionWith(alice);
      expect(await alice.send(bob, 'still there?'), 'still there?');

      // Decrypting did not make the archived session current again, and
      // whatever reads the current session finds none.
      expect(await bob.canSendTo(alice), isFalse);
      await expectLater(
        bob.cipher.encrypt(alice.address, utf8.encode('yes')),
        failsWith(LibSignalErrorCode.sessionNotFound),
      );
      await expectLater(
        bob.sealedCipher.encrypt(
          recipientAddress: alice.address,
          plaintext: Uint8List.fromList(utf8.encode('yes')),
          senderCertificate: senderCertificateFor(bob, PrivateKey.generate()),
        ),
        failsWith(LibSignalErrorCode.sessionNotFound),
      );
      final record = (await bob.sessionStore.loadSession(alice.address))!;
      expect(
        record.remoteRegistrationId,
        failsWith(LibSignalErrorCode.sessionNotFound),
      );
      expect(
        record.localRegistrationId,
        failsWith(LibSignalErrorCode.sessionNotFound),
      );

      await bob.builder.processPreKeyBundle(
        alice.address,
        alice.keys.toBundle(),
      );
      expect(
        await bob.send(alice, 'yes, on a new session'),
        'yes, on a new '
        'session',
      );
      expect(await alice.send(bob, 'got it'), 'got it');
    });

    test('a conversation that keeps switching sessions settles, and every '
        'message on the way decrypts', () async {
      // Bob starts a second session to Alice — say, after refetching her
      // bundle — and his first one is archived. Nothing he sends on it
      // arrives, so Alice keeps sending on the first.
      await bob.builder.processPreKeyBundle(
        alice.address,
        alice.keys.toBundle(),
      );
      // What Bob's store saves while decrypting Alice's messages, which arrive
      // on his archived session. His own messages save the identity they
      // were checked against; that is not what is pinned here.
      final savedDecrypting = <PublicKey>[];

      int? settledAt;
      for (var round = 0; round < 20 && settledAt == null; round++) {
        await bob.cipher.encrypt(alice.address, utf8.encode('bob $round'));
        bob.identityStore.saved.clear();
        expect(
          await alice.send(bob, 'alice $round'),
          'alice $round',
          reason: 'round $round',
        );
        savedDecrypting.addAll(bob.identityStore.saved);
        if (!await bob.canSendTo(alice)) settledAt = round;
      }

      // libsignal archived Bob's current session to break the back-and-forth.
      // This is the case the record comes out of a decryption with no current
      // session; the test needs it to have happened.
      expect(settledAt, isNotNull);
      expect(savedDecrypting, isEmpty);
      expect(await alice.send(bob, 'after'), 'after');
      await expectLater(
        bob.cipher.encrypt(alice.address, utf8.encode('stuck?')),
        failsWith(LibSignalErrorCode.sessionNotFound),
      );

      // A new session from Bob is what settles it: Alice takes it as current.
      await bob.builder.processPreKeyBundle(
        alice.address,
        alice.keys.toBundle(),
      );
      expect(await bob.send(alice, 'new session'), 'new session');
      expect(await alice.send(bob, 'on it'), 'on it');
    });

    test('through sealed sender, it decrypts and saves no identity', () async {
      final trustRoot = PrivateKey.generate();
      await bob.archiveSessionWith(alice);
      bob.identityStore.saved.clear();

      final ciphertext = await alice.sealedCipher.encrypt(
        recipientAddress: bob.address,
        plaintext: Uint8List.fromList(utf8.encode('sealed')),
        senderCertificate: senderCertificateFor(alice, trustRoot),
      );
      final result = await bob.sealedCipher.decrypt(
        ciphertext: ciphertext,
        trustRoot: trustRoot.getPublicKey().serialize(),
        timestamp: DateTime.now().millisecondsSinceEpoch,
      );

      expect(utf8.decode(result.plaintext), 'sealed');
      // The certificate still names the sender's key …
      expect(result.senderIdentityKey, isKey(alice.identityKey));
      // … but libsignal saved nothing, and neither did the bridge.
      expect(bob.identityStore.saved, isEmpty);
    });
  });
}
