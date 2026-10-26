// ignore_for_file: unreachable_from_main
/// The order in which each entry point writes to the stores.
///
/// The order is part of the contract (`SECURITY.md`, "The rule: durable before
/// release"): an application without a transaction around the call is left
/// with whatever landed before a crash. Where libsignal both saves an identity
/// and stores a session it saves the identity first, and the bridge follows; a
/// pre-key message asks `markKyberPreKeyUsed` before anything else, because its
/// answer can refuse the message, and stores its session last, for the reason
/// `SECURITY.md` gives. The differential tests against libsignal compare only
/// what was written, so nothing else pins this.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/error_matchers.dart';
import '../test_helpers/session_helpers.dart';

/// [SessionStore] that logs every `storeSession`.
class LoggingSessionStore implements SessionStore {
  LoggingSessionStore(this._log);

  final List<String> _log;
  final _inner = InMemorySessionStore();

  @override
  Future<void> storeSession(ProtocolAddress address, SessionRecord record) {
    _log.add('storeSession');
    return _inner.storeSession(address, record);
  }

  @override
  Future<SessionRecord?> loadSession(ProtocolAddress address) =>
      _inner.loadSession(address);

  @override
  Future<bool> containsSession(ProtocolAddress address) =>
      _inner.containsSession(address);

  @override
  Future<void> deleteSession(ProtocolAddress address) =>
      _inner.deleteSession(address);

  @override
  Future<void> deleteAllSessions(String name) => _inner.deleteAllSessions(name);

  @override
  Future<List<int>> getSubDeviceSessions(String name) =>
      _inner.getSubDeviceSessions(name);
}

/// [IdentityKeyStore] that logs every `saveIdentity`.
class LoggingIdentityKeyStore implements IdentityKeyStore {
  LoggingIdentityKeyStore(
    this._log,
    IdentityKeyPair identity,
    int registrationId,
  ) : _inner = InMemoryIdentityKeyStore(identity, registrationId);

  final List<String> _log;
  final InMemoryIdentityKeyStore _inner;

  @override
  Future<bool> saveIdentity(ProtocolAddress address, PublicKey identityKey) {
    _log.add('saveIdentity');
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

/// [PreKeyStore] that logs every `removePreKey`.
class LoggingPreKeyStore implements PreKeyStore {
  LoggingPreKeyStore(this._log);

  final List<String> _log;
  final _inner = InMemoryPreKeyStore();

  @override
  Future<void> removePreKey(int preKeyId) {
    _log.add('removePreKey');
    return _inner.removePreKey(preKeyId);
  }

  @override
  Future<PreKeyRecord?> loadPreKey(int preKeyId) => _inner.loadPreKey(preKeyId);

  @override
  Future<void> storePreKey(int preKeyId, PreKeyRecord record) =>
      _inner.storePreKey(preKeyId, record);

  @override
  Future<bool> containsPreKey(int preKeyId) => _inner.containsPreKey(preKeyId);

  @override
  Future<List<int>> getAllPreKeyIds() => _inner.getAllPreKeyIds();
}

/// [KyberPreKeyStore] that logs every `markKyberPreKeyUsed`.
class LoggingKyberPreKeyStore implements KyberPreKeyStore {
  LoggingKyberPreKeyStore(this._log);

  final List<String> _log;
  final _inner = InMemoryKyberPreKeyStore();

  @override
  Future<bool> markKyberPreKeyUsed(
    int kyberPreKeyId,
    int signedPreKeyId,
    PublicKey baseKey,
  ) {
    _log.add('markKyberPreKeyUsed');
    return _inner.markKyberPreKeyUsed(kyberPreKeyId, signedPreKeyId, baseKey);
  }

  @override
  Future<KyberPreKeyRecord?> loadKyberPreKey(int kyberPreKeyId) =>
      _inner.loadKyberPreKey(kyberPreKeyId);

  @override
  Future<void> storeKyberPreKey(int kyberPreKeyId, KyberPreKeyRecord record) =>
      _inner.storeKyberPreKey(kyberPreKeyId, record);

  @override
  Future<bool> containsKyberPreKey(int kyberPreKeyId) =>
      _inner.containsKyberPreKey(kyberPreKeyId);

  @override
  Future<void> removeKyberPreKey(int kyberPreKeyId) =>
      _inner.removeKyberPreKey(kyberPreKeyId);

  @override
  Future<List<int>> getAllKyberPreKeyIds() => _inner.getAllKyberPreKeyIds();
}

/// One party, with every store logging its writes into [log].
class Party {
  Party(this.address, this.identity, int registrationId)
    : log = [],
      _registrationId = registrationId {
    sessionStore = LoggingSessionStore(log);
    identityStore = LoggingIdentityKeyStore(log, identity, _registrationId);
    preKeyStore = LoggingPreKeyStore(log);
    signedPreKeyStore = InMemorySignedPreKeyStore();
    kyberPreKeyStore = LoggingKyberPreKeyStore(log);
  }

  final ProtocolAddress address;
  final IdentityKeyPair identity;
  final int _registrationId;

  /// The writes of the operation under test; cleared by [writesOf].
  final List<String> log;

  late final LoggingSessionStore sessionStore;
  late final LoggingIdentityKeyStore identityStore;
  late final LoggingPreKeyStore preKeyStore;
  late final InMemorySignedPreKeyStore signedPreKeyStore;
  late final LoggingKyberPreKeyStore kyberPreKeyStore;

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

  /// The writes [operation] made, in order.
  Future<List<String>> writesOf(Future<void> Function() operation) async {
    log.clear();
    await operation();
    return List.of(log);
  }
}

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  const preKeyId = 31337;
  const signedPreKeyId = 22;
  const kyberPreKeyId = 9;

  /// libsignal's order wherever it saves an identity and stores a session.
  const identityThenSession = ['saveIdentity', 'storeSession'];

  /// A pre-key message: the check that can refuse it first, the session last.
  const preKeyMessage = [
    'markKyberPreKeyUsed',
    'saveIdentity',
    'removePreKey',
    'storeSession',
  ];

  late RemotePartyKeys bobKeys;
  late Party alice;
  late Party bob;

  late PrivateKey trustRoot;
  late PrivateKey serverKey;
  late Uint8List serverCertificate;

  setUp(() async {
    bobKeys = generateRemotePartyKeys(
      registrationId: 22222,
      preKeyId: preKeyId,
      signedPreKeyId: signedPreKeyId,
      kyberPreKeyId: kyberPreKeyId,
    );
    alice = Party(
      ProtocolAddress(name: 'alice-uuid', deviceId: 1),
      IdentityKeyPair.generate(),
      11111,
    );
    bob = Party(
      ProtocolAddress(name: 'bob-uuid', deviceId: 1),
      bobKeys.identityKeyPair,
      22222,
    );

    final timestamp = BigInt.from(DateTime.now().millisecondsSinceEpoch);
    await bob.preKeyStore.storePreKey(
      preKeyId,
      PreKeyRecord(
        id: preKeyId,
        publicKey: bobKeys.preKeyPublic,
        privateKey: bobKeys.preKeyPrivate,
      ),
    );
    await bob.signedPreKeyStore.storeSignedPreKey(
      signedPreKeyId,
      SignedPreKeyRecord(
        id: signedPreKeyId,
        timestamp: timestamp,
        publicKey: bobKeys.signedPreKeyPublic,
        privateKey: bobKeys.signedPreKeyPrivate,
        signature: bobKeys.signedPreKeySignature,
      ),
    );
    await bob.kyberPreKeyStore.storeKyberPreKey(
      kyberPreKeyId,
      KyberPreKeyRecord.create(
        id: kyberPreKeyId,
        timestamp: timestamp,
        keyPair: bobKeys.kyberKeyPair,
        signature: bobKeys.kyberPreKeySignature,
      ),
    );

    trustRoot = PrivateKey.generate();
    serverKey = PrivateKey.generate();
    serverCertificate = createServerCertificate(
      keyId: 1,
      serverPublicKey: serverKey.getPublicKey().serialize(),
      trustRootPrivateKey: trustRoot.serialize(),
    );
  });

  Uint8List certificateOf(Party party) => createSenderCertificate(
    senderUuid: party.address.name(),
    senderDeviceId: party.address.deviceId(),
    senderIdentityKey: party.identity.publicKey,
    expiration: BigInt.from(
      DateTime.now().add(const Duration(hours: 1)).millisecondsSinceEpoch,
    ),
    serverCertificate: serverCertificate,
    serverPrivateKey: serverKey.serialize(),
  );

  Future<Uint8List> sealedTo(Party to, Party from, String body) =>
      from.sealedCipher.encrypt(
        recipientAddress: to.address,
        plaintext: Uint8List.fromList(utf8.encode(body)),
        senderCertificate: certificateOf(from),
      );

  Future<void> unseal(Party at, Uint8List ciphertext) =>
      at.sealedCipher.decrypt(
        ciphertext: ciphertext,
        trustRoot: trustRoot.getPublicKey().serialize(),
        timestamp: DateTime.now().millisecondsSinceEpoch,
      );

  /// Alice builds a session from Bob's bundle, which carries a one-time
  /// pre-key unless [oneTimePreKey] is false.
  Future<void> fetch({bool oneTimePreKey = true}) =>
      alice.builder.processPreKeyBundle(
        bob.address,
        bobKeys.toBundle(oneTimePreKey: oneTimePreKey),
      );

  /// A session both sides hold as current and acknowledged.
  Future<void> establish() async {
    await fetch();
    await bob.cipher.decrypt(
      alice.address,
      await alice.cipher.encrypt(bob.address, utf8.encode('hello')),
    );
    await alice.cipher.decrypt(
      bob.address,
      await bob.cipher.encrypt(alice.address, utf8.encode('hi')),
    );
  }

  test(
    'processPreKeyBundle saves the identity, then stores the session',
    () async {
      expect(await alice.writesOf(fetch), equals(identityThenSession));
    },
  );

  group('SessionCipher', () {
    test('encrypt saves the identity, then stores the session', () async {
      await fetch();
      expect(
        await alice.writesOf(
          () => alice.cipher.encrypt(bob.address, utf8.encode('hello')),
        ),
        equals(identityThenSession),
      );
    });

    test('decrypting a pre-key message stores the session last', () async {
      await fetch();
      final message = await alice.cipher.encrypt(
        bob.address,
        utf8.encode('hello'),
      );
      expect(message.isPreKeyMessage, isTrue);
      expect(
        await bob.writesOf(() => bob.cipher.decrypt(alice.address, message)),
        equals(preKeyMessage),
      );
    });

    test('a replayed pre-key message writes nothing once refused', () async {
      await fetch(oneTimePreKey: false);
      final message = await alice.cipher.encrypt(
        bob.address,
        utf8.encode('hello'),
      );
      await bob.cipher.decrypt(alice.address, message);
      // The session leaves Bob's record; the same message would build it again.
      await bob.sessionStore.deleteSession(alice.address);
      expect(
        await bob.writesOf(
          () => expectLater(
            bob.cipher.decrypt(alice.address, message),
            failsWith(LibSignalErrorCode.invalidMessage),
          ),
        ),
        equals(['markKyberPreKeyUsed']),
      );
    });

    test('decrypting a Whisper message saves the identity, then stores the '
        'session', () async {
      await establish();
      final message = await bob.cipher.encrypt(
        alice.address,
        utf8.encode('again'),
      );
      expect(message.isPreKeyMessage, isFalse);
      expect(
        await alice.writesOf(() => alice.cipher.decrypt(bob.address, message)),
        equals(identityThenSession),
      );
    });
  });

  group('SealedSenderCipher', () {
    test('encrypt saves the identity, then stores the session', () async {
      await fetch();
      expect(
        await alice.writesOf(() => sealedTo(bob, alice, 'sealed')),
        equals(identityThenSession),
      );
    });

    test('decrypting a pre-key message stores the session last', () async {
      await fetch();
      final ciphertext = await sealedTo(bob, alice, 'sealed');
      expect(
        await bob.writesOf(() => unseal(bob, ciphertext)),
        equals(preKeyMessage),
      );
    });

    test('a replayed pre-key message writes nothing once refused', () async {
      await fetch(oneTimePreKey: false);
      final ciphertext = await sealedTo(bob, alice, 'sealed');
      await unseal(bob, ciphertext);
      await bob.sessionStore.deleteSession(alice.address);
      expect(
        await bob.writesOf(
          () => expectLater(
            unseal(bob, ciphertext),
            failsWith(LibSignalErrorCode.invalidMessage),
          ),
        ),
        equals(['markKyberPreKeyUsed']),
      );
    });

    test('decrypting a Whisper message saves the identity, then stores the '
        'session', () async {
      await establish();
      final ciphertext = await sealedTo(bob, alice, 'sealed again');
      expect(
        await bob.writesOf(() => unseal(bob, ciphertext)),
        equals(identityThenSession),
      );
    });
  });
}
