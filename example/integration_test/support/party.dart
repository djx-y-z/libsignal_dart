import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

/// [text] as the bytes the library takes.
Uint8List bytesOf(String text) => Uint8List.fromList(utf8.encode(text));

/// Lowercase [hex] as bytes.
Uint8List hexBytes(String hex) => Uint8List.fromList([
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
]);

/// Now, as the milliseconds the library takes.
BigInt nowMillis() => BigInt.from(DateTime.now().millisecondsSinceEpoch);

/// One participant: an identity, the six in-memory stores, and what is built
/// from them.
class Party {
  Party(
    this.name,
    this.registrationId, {
    this.deviceId = 1,
    IdentityKeyPair? id,
  }) : identity = id ?? IdentityKeyPair.generate() {
    identities = InMemoryIdentityKeyStore(identity, registrationId);
  }

  final String name;
  final int deviceId;
  final int registrationId;
  final IdentityKeyPair identity;

  late final InMemoryIdentityKeyStore identities;
  final sessions = InMemorySessionStore();
  final preKeys = InMemoryPreKeyStore();
  final signedPreKeys = InMemorySignedPreKeyStore();
  final kyberPreKeys = InMemoryKyberPreKeyStore();
  final senderKeys = InMemorySenderKeyStore();

  ProtocolAddress get address =>
      ProtocolAddress(name: name, deviceId: deviceId);

  SessionBuilder get builder => SessionBuilder(
    localAddress: address,
    sessionStore: sessions,
    identityKeyStore: identities,
  );

  SessionCipher get cipher => SessionCipher(
    localAddress: address,
    sessionStore: sessions,
    identityKeyStore: identities,
    preKeyStore: preKeys,
    signedPreKeyStore: signedPreKeys,
    kyberPreKeyStore: kyberPreKeys,
  );

  SealedSenderCipher get sealed => SealedSenderCipher(
    localAddress: address,
    sessionStore: sessions,
    identityKeyStore: identities,
    preKeyStore: preKeys,
    signedPreKeyStore: signedPreKeys,
    kyberPreKeyStore: kyberPreKeys,
  );

  GroupCipher get group =>
      GroupCipher(senderKeyStore: senderKeys, identityKeyStore: identities);

  /// Generates this party's pre-keys, stores them, and returns what a server
  /// would hand out for it.
  Future<PreKeyBundle> publishBundle({bool oneTimePreKey = true}) async {
    const preKeyId = 42;
    const signedPreKeyId = 7;
    const kyberPreKeyId = 3;
    final timestamp = nowMillis();

    final preKey = PrivateKey.generate();
    await preKeys.storePreKey(
      preKeyId,
      PreKeyRecord(
        id: preKeyId,
        publicKey: preKey.getPublicKey(),
        privateKey: preKey,
      ),
    );

    final signedPreKey = PrivateKey.generate();
    final signedPreKeySignature = identity.sign(
      message: signedPreKey.getPublicKey().serialize(),
    );
    await signedPreKeys.storeSignedPreKey(
      signedPreKeyId,
      SignedPreKeyRecord(
        id: signedPreKeyId,
        timestamp: timestamp,
        publicKey: signedPreKey.getPublicKey(),
        privateKey: signedPreKey,
        signature: signedPreKeySignature,
      ),
    );

    final kyber = KyberKeyPair.generate();
    final kyberSignature = identity.sign(
      message: kyber.getPublicKey().serialize(),
    );
    await kyberPreKeys.storeKyberPreKey(
      kyberPreKeyId,
      KyberPreKeyRecord.create(
        id: kyberPreKeyId,
        timestamp: timestamp,
        keyPair: kyber,
        signature: kyberSignature,
      ),
    );

    return PreKeyBundle(
      registrationId: registrationId,
      deviceId: deviceId,
      preKeyId: oneTimePreKey ? preKeyId : null,
      preKeyPublic: oneTimePreKey ? preKey.getPublicKey().serialize() : null,
      signedPreKeyId: signedPreKeyId,
      signedPreKeyPublic: signedPreKey.getPublicKey().serialize(),
      signedPreKeySignature: signedPreKeySignature,
      identityKey: identity.publicKey,
      kyberPreKeyId: kyberPreKeyId,
      kyberPreKeyPublic: kyber.getPublicKey().serialize(),
      kyberPreKeySignature: kyberSignature,
    );
  }
}

/// [from] takes [to]'s bundle, so that [from] can start the conversation.
Future<void> establish(Party from, Party to) async =>
    from.builder.processPreKeyBundle(to.address, await to.publishBundle());

/// [a] and [b] with a session running both ways, so the next message either of
/// them encrypts is a plain Signal message.
Future<void> converse(Party a, Party b) async {
  await establish(a, b);
  final opening = await a.cipher.encrypt(b.address, bytesOf('opening'));
  await b.cipher.decrypt(a.address, opening);
  final answer = await b.cipher.encrypt(a.address, bytesOf('answer'));
  await a.cipher.decrypt(b.address, answer);
}
