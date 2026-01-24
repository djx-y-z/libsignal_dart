import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

import '../utils.dart';

/// Demonstrates 1-to-1 session establishment and message encryption
/// using the Signal Protocol (Double Ratchet + X3DH/PQXDH).
Future<void> runSessionDemo() async {
  printHeader('Session Demo');

  // 1. Create protocol addresses
  final aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
  final bobAddress = ProtocolAddress(name: 'bob', deviceId: 1);
  printStep(1, 'Protocol addresses created', [
    'Alice: ${aliceAddress.name()}:${aliceAddress.deviceId()}',
    'Bob: ${bobAddress.name()}:${bobAddress.deviceId()}',
  ]);
  print('');

  // 2. Generate Alice's identity and stores
  final aliceIdentity = IdentityKeyPair.generate();
  const aliceRegistrationId = 111;
  final aliceSessionStore = InMemorySessionStore();
  final aliceIdentityStore = InMemoryIdentityKeyStore(
    aliceIdentity,
    aliceRegistrationId,
  );
  final alicePreKeyStore = InMemoryPreKeyStore();
  final aliceSignedPreKeyStore = InMemorySignedPreKeyStore();
  final aliceKyberPreKeyStore = InMemoryKyberPreKeyStore();
  printStep(2, 'Alice setup complete', [
    'Identity: ${bytesToHex(aliceIdentity.publicKey, maxLength: 24)}',
    'Registration ID: $aliceRegistrationId',
  ]);
  print('');

  // 3. Generate Bob's identity and stores
  final bobIdentity = IdentityKeyPair.generate();
  const bobRegistrationId = 222;
  final bobSessionStore = InMemorySessionStore();
  final bobIdentityStore = InMemoryIdentityKeyStore(
    bobIdentity,
    bobRegistrationId,
  );
  final bobPreKeyStore = InMemoryPreKeyStore();
  final bobSignedPreKeyStore = InMemorySignedPreKeyStore();
  final bobKyberPreKeyStore = InMemoryKyberPreKeyStore();
  printStep(3, 'Bob setup complete', [
    'Identity: ${bytesToHex(bobIdentity.publicKey, maxLength: 24)}',
    'Registration ID: $bobRegistrationId',
  ]);
  print('');

  // 4. Generate Bob's pre-keys (required for session establishment)
  const preKeyId = 42;
  const signedPreKeyId = 7;
  const kyberPreKeyId = 1;

  // Pre-key
  final preKeyPrivate = PrivateKey.generate();
  final preKeyPublic = preKeyPrivate.getPublicKey();
  final preKeyRecord = PreKeyRecord(
    id: preKeyId,
    publicKey: preKeyPublic,
    privateKey: preKeyPrivate,
  );
  await bobPreKeyStore.storePreKey(preKeyId, preKeyRecord);

  // Signed pre-key
  final signedPreKeyPrivate = PrivateKey.generate();
  final signedPreKeyPublic = signedPreKeyPrivate.getPublicKey();
  final bobPrivate = PrivateKey.deserialize(
    bytes: bobIdentity.privateKey.toList(),
  );
  final signedPreKeySignature = bobPrivate.sign(
    message: signedPreKeyPublic.serialize().toList(),
  );
  final timestamp = BigInt.from(DateTime.now().millisecondsSinceEpoch);
  final signedPreKeyRecord = SignedPreKeyRecord(
    id: signedPreKeyId,
    publicKey: signedPreKeyPublic,
    privateKey: signedPreKeyPrivate,
    signature: signedPreKeySignature.toList(),
    timestamp: timestamp,
  );
  await bobSignedPreKeyStore.storeSignedPreKey(
    signedPreKeyId,
    signedPreKeyRecord,
  );

  // Kyber pre-key (post-quantum)
  final kyberKeyPair = KyberKeyPair.generate();
  final kyberPreKey = kyberKeyPair.getPublicKey();
  final kyberPreKeySignature = bobPrivate.sign(
    message: kyberPreKey.serialize().toList(),
  );
  final kyberPreKeyRecord = KyberPreKeyRecord.create(
    id: kyberPreKeyId,
    keyPair: kyberKeyPair,
    signature: kyberPreKeySignature.toList(),
    timestamp: timestamp,
  );
  await bobKyberPreKeyStore.storeKyberPreKey(kyberPreKeyId, kyberPreKeyRecord);

  printStep(4, "Bob's pre-keys generated and stored", [
    'Pre-key ID: $preKeyId',
    'Signed pre-key ID: $signedPreKeyId',
    'Kyber pre-key ID: $kyberPreKeyId (post-quantum)',
  ]);
  print('');

  // 5. Create Bob's PreKeyBundle
  final bobBundle = PreKeyBundle(
    registrationId: bobRegistrationId,
    deviceId: bobAddress.deviceId(),
    preKeyId: preKeyId,
    preKeyPublic: preKeyPublic.serialize(),
    signedPreKeyId: signedPreKeyId,
    signedPreKeyPublic: signedPreKeyPublic.serialize().toList(),
    signedPreKeySignature: signedPreKeySignature.toList(),
    identityKey: bobIdentity.publicKey.toList(),
    kyberPreKeyId: kyberPreKeyId,
    kyberPreKeyPublic: kyberPreKey.serialize().toList(),
    kyberPreKeySignature: kyberPreKeySignature.toList(),
  );
  printStep(5, 'PreKeyBundle created for Bob', [
    'Contains: identity + pre-key + signed pre-key + Kyber pre-key',
  ]);
  print('');

  // 6. Alice processes Bob's bundle (X3DH/PQXDH key agreement)
  final aliceBuilder = SessionBuilder(
    sessionStore: aliceSessionStore,
    identityKeyStore: aliceIdentityStore,
  );
  await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);
  printStep(6, 'Alice processed PreKeyBundle (X3DH/PQXDH)', [
    'Session established with Bob',
    'Shared secret derived from key agreement',
  ]);
  print('');

  // 7. Create session ciphers
  final aliceCipher = SessionCipher(
    sessionStore: aliceSessionStore,
    identityKeyStore: aliceIdentityStore,
    preKeyStore: alicePreKeyStore,
    signedPreKeyStore: aliceSignedPreKeyStore,
    kyberPreKeyStore: aliceKyberPreKeyStore,
  );
  final bobCipher = SessionCipher(
    sessionStore: bobSessionStore,
    identityKeyStore: bobIdentityStore,
    preKeyStore: bobPreKeyStore,
    signedPreKeyStore: bobSignedPreKeyStore,
    kyberPreKeyStore: bobKyberPreKeyStore,
  );
  printStep(7, 'SessionCiphers created', [
    'Alice cipher: ready to encrypt',
    'Bob cipher: ready to decrypt',
  ]);
  print('');

  // 8. Alice sends first message to Bob
  const message1 = 'Hello Bob! This is our first encrypted message.';
  final encrypted1 = await aliceCipher.encrypt(
    bobAddress,
    Uint8List.fromList(utf8.encode(message1)),
  );
  printStep(8, 'Alice encrypted first message', [
    'Plaintext: "$message1"',
    'Message type: ${encrypted1.isPreKeyMessage ? "PreKeySignalMessage" : "SignalMessage"}',
    'Ciphertext size: ${encrypted1.ciphertext.length} bytes',
  ]);
  print('');

  // 9. Bob decrypts Alice's message (establishes session on his side)
  final decrypted1 = await bobCipher.decrypt(aliceAddress, encrypted1);
  final decrypted1Text = utf8.decode(decrypted1);
  printStep(9, 'Bob decrypted message', [
    'Decrypted: "$decrypted1Text"',
    'Match: ${decrypted1Text == message1}',
    'Bob now has session with Alice',
  ]);
  print('');

  // 10. Bob replies to Alice
  const message2 = 'Hi Alice! Nice to hear from you.';
  final encrypted2 = await bobCipher.encrypt(
    aliceAddress,
    Uint8List.fromList(utf8.encode(message2)),
  );
  printStep(10, 'Bob encrypted reply', [
    'Plaintext: "$message2"',
    'Message type: ${encrypted2.isPreKeyMessage ? "PreKeySignalMessage" : "SignalMessage"}',
    'Note: Reply uses SignalMessage (not PreKey)',
  ]);
  print('');

  // 11. Alice decrypts Bob's reply
  final decrypted2 = await aliceCipher.decrypt(bobAddress, encrypted2);
  final decrypted2Text = utf8.decode(decrypted2);
  printStep(11, 'Alice decrypted reply', [
    'Decrypted: "$decrypted2Text"',
    'Match: ${decrypted2Text == message2}',
  ]);
  print('');

  // 12. Continue conversation (demonstrates Double Ratchet)
  const message3 = 'How are you doing today?';
  final encrypted3 = await aliceCipher.encrypt(
    bobAddress,
    Uint8List.fromList(utf8.encode(message3)),
  );
  final decrypted3 = await bobCipher.decrypt(aliceAddress, encrypted3);
  final decrypted3Text = utf8.decode(decrypted3);

  const message4 = "I'm doing great, thanks for asking!";
  final encrypted4 = await bobCipher.encrypt(
    aliceAddress,
    Uint8List.fromList(utf8.encode(message4)),
  );
  final decrypted4 = await aliceCipher.decrypt(bobAddress, encrypted4);
  final decrypted4Text = utf8.decode(decrypted4);

  printStep(12, 'Conversation continues (Double Ratchet)', [
    'Alice: "$message3"',
    '  -> Bob decrypted: "$decrypted3Text"',
    'Bob: "$message4"',
    '  -> Alice decrypted: "$decrypted4Text"',
    'All messages use SignalMessage type now',
  ]);

  // No dispose() needed - FRB handles memory automatically
}
