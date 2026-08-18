/// A test party: identity, in-memory stores, builder and cipher in one bag.
///
/// Shared by the session, pre-key-message and SPQR tests.
library;

import 'dart:async';

import 'package:libsignal/libsignal.dart';

import 'session_helpers.dart';

/// Helper class to manage all stores and keys for a test party.
///
/// Build one with [TestParty.create]. There is deliberately no public
/// generative constructor: `sessionBuilder` and `sessionCipher` are `late
/// final` and are only wired up by `create`, so any other construction path
/// would hand back an object that throws `LateInitializationError` on first
/// use.
class TestParty {
  final String name;
  final int deviceId;
  final int registrationId;
  final IdentityKeyPair identityKeyPair;
  final InMemorySessionStore sessionStore;
  final InMemoryIdentityKeyStore identityKeyStore;
  final InMemoryPreKeyStore preKeyStore;
  final InMemorySignedPreKeyStore signedPreKeyStore;
  final InMemoryKyberPreKeyStore kyberPreKeyStore;

  late final SessionBuilder sessionBuilder;
  late final SessionCipher sessionCipher;
  late final ProtocolAddress address;

  // Pre-keys (for responder role)
  RemotePartyKeys? _preKeys;

  /// Initialize with proper identity store.
  static TestParty create({
    required String name,
    int deviceId = 1,
    required int registrationId,
  }) {
    final identityKeyPair = IdentityKeyPair.generate();
    final sessionStore = InMemorySessionStore();
    final identityKeyStore = InMemoryIdentityKeyStore(
      identityKeyPair,
      registrationId,
    );
    final preKeyStore = InMemoryPreKeyStore();
    final signedPreKeyStore = InMemorySignedPreKeyStore();
    final kyberPreKeyStore = InMemoryKyberPreKeyStore();

    return TestParty._internal(
        name: name,
        deviceId: deviceId,
        registrationId: registrationId,
        identityKeyPair: identityKeyPair,
        sessionStore: sessionStore,
        identityKeyStore: identityKeyStore,
        preKeyStore: preKeyStore,
        signedPreKeyStore: signedPreKeyStore,
        kyberPreKeyStore: kyberPreKeyStore,
      )
      ..sessionBuilder = SessionBuilder(
        localAddress: ProtocolAddress(name: name, deviceId: deviceId),
        sessionStore: sessionStore,
        identityKeyStore: identityKeyStore,
      )
      ..sessionCipher = SessionCipher(
        localAddress: ProtocolAddress(name: name, deviceId: deviceId),
        sessionStore: sessionStore,
        identityKeyStore: identityKeyStore,
        preKeyStore: preKeyStore,
        signedPreKeyStore: signedPreKeyStore,
        kyberPreKeyStore: kyberPreKeyStore,
      );
  }

  // ignore: sort_constructors_first
  TestParty._internal({
    required this.name,
    required this.deviceId,
    required this.registrationId,
    required this.identityKeyPair,
    required this.sessionStore,
    required this.identityKeyStore,
    required this.preKeyStore,
    required this.signedPreKeyStore,
    required this.kyberPreKeyStore,
  }) : address = ProtocolAddress(name: name, deviceId: deviceId);

  /// Generate and store pre-keys for this party.
  void generatePreKeys({
    int preKeyId = 1,
    int signedPreKeyId = 1,
    int kyberPreKeyId = 1,
  }) {
    // Generate keys
    final preKeyPrivate = PrivateKey.generate();
    final preKeyPublic = preKeyPrivate.getPublicKey();

    final signedPreKeyPrivate = PrivateKey.generate();
    final signedPreKeyPublic = signedPreKeyPrivate.getPublicKey();

    // Sign using our identity key
    final identityPrivate = PrivateKey.deserialize(
      bytes: identityKeyPair.privateKey.toList(),
    );
    final signedPreKeySignature = identityPrivate.sign(
      message: signedPreKeyPublic.serialize().toList(),
    );

    final kyberKeyPair = KyberKeyPair.generate();
    final kyberPreKey = kyberKeyPair.getPublicKey();
    final kyberPreKeySignature = identityPrivate.sign(
      message: kyberPreKey.serialize().toList(),
    );

    // Store pre-keys
    final preKeyRecord = PreKeyRecord(
      id: preKeyId,
      publicKey: preKeyPublic,
      privateKey: preKeyPrivate,
    );
    unawaited(preKeyStore.storePreKey(preKeyId, preKeyRecord));

    final timestamp = BigInt.from(DateTime.now().millisecondsSinceEpoch);

    final signedPreKeyRecord = SignedPreKeyRecord(
      id: signedPreKeyId,
      publicKey: signedPreKeyPublic,
      privateKey: signedPreKeyPrivate,
      signature: signedPreKeySignature.toList(),
      timestamp: timestamp,
    );
    unawaited(
      signedPreKeyStore.storeSignedPreKey(signedPreKeyId, signedPreKeyRecord),
    );

    final kyberPreKeyRecord = KyberPreKeyRecord.create(
      id: kyberPreKeyId,
      keyPair: kyberKeyPair,
      signature: kyberPreKeySignature.toList(),
      timestamp: timestamp,
    );
    unawaited(
      kyberPreKeyStore.storeKyberPreKey(kyberPreKeyId, kyberPreKeyRecord),
    );

    // Save for bundle creation
    _preKeys = RemotePartyKeys(
      identityKeyPair: identityKeyPair,
      registrationId: registrationId,
      deviceId: deviceId,
      preKeyPrivate: preKeyPrivate,
      preKeyPublic: preKeyPublic,
      preKeyId: preKeyId,
      signedPreKeyPrivate: signedPreKeyPrivate,
      signedPreKeyPublic: signedPreKeyPublic,
      signedPreKeyId: signedPreKeyId,
      signedPreKeySignature: signedPreKeySignature,
      kyberKeyPair: kyberKeyPair,
      kyberPreKey: kyberPreKey,
      kyberPreKeyId: kyberPreKeyId,
      kyberPreKeySignature: kyberPreKeySignature,
    );
  }

  /// Get a pre-key bundle for this party.
  PreKeyBundle getBundle() {
    if (_preKeys == null) {
      throw StateError('Call generatePreKeys() first');
    }
    return _preKeys!.toBundle();
  }
}
