// ignore_for_file: unreachable_from_main, sort_constructors_first, avoid_redundant_argument_values, cascade_invocations
import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import 'test_helpers/session_helpers.dart';

/// Internal helper to store pre-key data.
class PreKeyData {
  final int preKeyId;
  final PrivateKey preKeyPrivate;
  final PublicKey preKeyPublic;
  final int signedPreKeyId;
  final PrivateKey signedPreKeyPrivate;
  final PublicKey signedPreKeyPublic;
  final Uint8List signedPreKeySignature;
  final int kyberPreKeyId;
  final KyberKeyPair kyberKeyPair;
  final KyberPublicKey kyberPreKey;
  final Uint8List kyberPreKeySignature;

  PreKeyData({
    required this.preKeyId,
    required this.preKeyPrivate,
    required this.preKeyPublic,
    required this.signedPreKeyId,
    required this.signedPreKeyPrivate,
    required this.signedPreKeyPublic,
    required this.signedPreKeySignature,
    required this.kyberPreKeyId,
    required this.kyberKeyPair,
    required this.kyberPreKey,
    required this.kyberPreKeySignature,
  });
}

/// Helper class to hold all of a party's keys and provide callbacks.
class PartyState {
  final String name;
  final int deviceId;
  final IdentityKeyPair identityKeyPair;
  final int registrationId;

  // Pre-keys (for the responder)
  PreKeyData? preKeys;

  // Stores
  final sessionStorage = <String, Uint8List>{};
  final identityStorage = <String, Uint8List>{};
  final preKeyStorage = <int, Uint8List>{};
  final signedPreKeyStorage = <int, Uint8List>{};
  final kyberPreKeyStorage = <int, Uint8List>{};

  PartyState({
    required this.name,
    this.deviceId = 1,
    required this.registrationId,
  }) : identityKeyPair = IdentityKeyPair.generate();

  /// Generate pre-keys for this party.
  void generatePreKeys({
    int preKeyId = 1,
    int signedPreKeyId = 1,
    int kyberPreKeyId = 1,
  }) {
    // Generate the key pairs
    final preKeyPrivate = PrivateKey.generate();
    final preKeyPublic = preKeyPrivate.getPublicKey();

    final signedPreKeyPrivate = PrivateKey.generate();
    final signedPreKeyPublic = signedPreKeyPrivate.getPublicKey();

    final kyberKeyPair = KyberKeyPair.generate();
    final kyberPreKey = kyberKeyPair.getPublicKey();

    // Sign using THIS party's identity key
    final identityPrivate = PrivateKey.deserialize(
      bytes: identityKeyPair.privateKey.toList(),
    );

    final signedPreKeySignature = identityPrivate.sign(
      message: signedPreKeyPublic.serialize().toList(),
    );

    final kyberPreKeySignature = identityPrivate.sign(
      message: kyberPreKey.serialize().toList(),
    );

    // Create a RemotePartyKeys-like structure for compatibility
    preKeys = PreKeyData(
      preKeyId: preKeyId,
      preKeyPrivate: preKeyPrivate,
      preKeyPublic: preKeyPublic,
      signedPreKeyId: signedPreKeyId,
      signedPreKeyPrivate: signedPreKeyPrivate,
      signedPreKeyPublic: signedPreKeyPublic,
      signedPreKeySignature: signedPreKeySignature,
      kyberPreKeyId: kyberPreKeyId,
      kyberKeyPair: kyberKeyPair,
      kyberPreKey: kyberPreKey,
      kyberPreKeySignature: kyberPreKeySignature,
    );

    // Store the pre-keys using the correct API
    final pk = PreKeyRecord(
      id: preKeyId,
      publicKey: preKeyPublic,
      privateKey: preKeyPrivate,
    );
    preKeyStorage[preKeyId] = pk.serialize();

    final timestamp = BigInt.from(DateTime.now().millisecondsSinceEpoch);

    final spk = SignedPreKeyRecord(
      id: signedPreKeyId,
      publicKey: signedPreKeyPublic,
      privateKey: signedPreKeyPrivate,
      signature: signedPreKeySignature.toList(),
      timestamp: timestamp,
    );
    signedPreKeyStorage[signedPreKeyId] = spk.serialize();

    final kpk = KyberPreKeyRecord.create(
      id: kyberPreKeyId,
      keyPair: kyberKeyPair,
      signature: kyberPreKeySignature.toList(),
      timestamp: timestamp,
    );
    kyberPreKeyStorage[kyberPreKeyId] = kpk.serialize();
  }

  /// Create a bundle from generated pre-keys.
  PreKeyBundle getBundle() {
    final pk = preKeys;
    if (pk == null) {
      throw StateError('Must call generatePreKeys first');
    }
    // Use THIS party's identity key pair (pre-keys were signed with this key)
    return PreKeyBundle(
      registrationId: registrationId,
      deviceId: deviceId,
      preKeyId: pk.preKeyId,
      preKeyPublic: pk.preKeyPublic.serialize(),
      signedPreKeyId: pk.signedPreKeyId,
      signedPreKeyPublic: pk.signedPreKeyPublic.serialize().toList(),
      signedPreKeySignature: pk.signedPreKeySignature.toList(),
      identityKey: identityKeyPair.publicKey.toList(),
      kyberPreKeyId: pk.kyberPreKeyId,
      kyberPreKeyPublic: pk.kyberPreKey.serialize().toList(),
      kyberPreKeySignature: pk.kyberPreKeySignature.toList(),
    );
  }

  // Callbacks
  Uint8List? loadSession(String name, int deviceId) =>
      sessionStorage['$name:$deviceId'];

  void storeSession(String name, int deviceId, Uint8List data) =>
      sessionStorage['$name:$deviceId'] = data;

  Uint8List getIdentityKeyPair() => identityKeyPair.serialize();

  int getLocalRegistrationId() => registrationId;

  void saveIdentity(String name, int deviceId, Uint8List key) =>
      identityStorage['$name:$deviceId'] = key;

  Uint8List? getIdentity(String name, int deviceId) =>
      identityStorage['$name:$deviceId'];

  Uint8List loadSignedPreKey(int id) {
    final data = signedPreKeyStorage[id];
    if (data == null) throw StateError('Signed pre-key $id not found');
    return data;
  }

  Uint8List? loadPreKey(int id) => preKeyStorage[id];

  Uint8List loadKyberPreKey(int id) {
    final data = kyberPreKeyStorage[id];
    if (data == null) throw StateError('Kyber pre-key $id not found');
    return data;
  }

  void removePreKey(int id) {
    preKeyStorage.remove(id);
  }

  void markKyberPreKeyUsed(int id) {
    // For testing, we don't need to do anything special here
    // In production, you might track which keys have been used
  }
}

void main() {
  setUpAll(LibSignal.init);

  group('Process PreKey Bundle with Callbacks', () {
    test('processPrekeyBundleWithCallbacks creates session', () async {
      // In-memory stores
      final sessionStorage = <String, Uint8List>{};
      final identityStorage = <String, Uint8List>{};

      // Alice's identity (the initiator)
      final aliceIdentity = IdentityKeyPair.generate();
      const aliceRegistrationId = 111;

      // Bob's keys (the responder)
      final bobKeys = generateRemotePartyKeys(
        registrationId: 222,
        deviceId: 1,
        preKeyId: 42,
        signedPreKeyId: 7,
        kyberPreKeyId: 1,
      );
      final bobBundle = bobKeys.toBundle();

      // Define callbacks for Alice's stores
      Uint8List? loadSession(String name, int deviceId) {
        return sessionStorage['$name:$deviceId'];
      }

      void storeSession(String name, int deviceId, Uint8List data) {
        sessionStorage['$name:$deviceId'] = data;
      }

      Uint8List getIdentityKeyPair() {
        return aliceIdentity.serialize();
      }

      int getLocalRegistrationId() {
        return aliceRegistrationId;
      }

      void saveIdentity(String name, int deviceId, Uint8List identityKey) {
        identityStorage['$name:$deviceId'] = identityKey;
      }

      Uint8List? getIdentity(String name, int deviceId) {
        return identityStorage['$name:$deviceId'];
      }

      // Process Bob's bundle (Alice initiates session)
      await processPrekeyBundleWithCallbacks(
        remoteName: 'bob',
        remoteDeviceId: 1,
        localName: 'alice',
        localDeviceId: 1,
        bundle: bobBundle,
        loadSession: loadSession,
        storeSession: storeSession,
        getIdentityKeyPair: getIdentityKeyPair,
        getLocalRegistrationId: getLocalRegistrationId,
        saveIdentity: saveIdentity,
        getIdentity: getIdentity,
      );

      // Verify session was created and stored via callbacks
      expect(sessionStorage.containsKey('bob:1'), isTrue);
      expect(sessionStorage['bob:1'], isNotEmpty);
      expect(identityStorage.containsKey('bob:1'), isTrue);
      expect(identityStorage['bob:1'], isNotEmpty);

      // Verify the remote identity key matches Bob's public key
      final bobPublicKey = Uint8List.fromList(
        bobKeys.identityKeyPair.publicKey,
      );
      expect(identityStorage['bob:1'], equals(bobPublicKey));
    });
  });

  group('Full Message Exchange with Callbacks', () {
    test('Alice and Bob can exchange messages using DartFn callbacks', () async {
      // Setup Alice and Bob
      final alice = PartyState(name: 'alice', registrationId: 111);
      final bob = PartyState(name: 'bob', registrationId: 222);

      // Bob generates pre-keys (Bob is the responder)
      bob.generatePreKeys(preKeyId: 42, signedPreKeyId: 7, kyberPreKeyId: 1);

      // Step 1: Alice processes Bob's pre-key bundle
      final bobBundle = bob.getBundle();
      await processPrekeyBundleWithCallbacks(
        remoteName: 'bob',
        remoteDeviceId: 1,
        localName: 'alice',
        localDeviceId: 1,
        bundle: bobBundle,
        loadSession: alice.loadSession,
        storeSession: alice.storeSession,
        getIdentityKeyPair: alice.getIdentityKeyPair,
        getLocalRegistrationId: alice.getLocalRegistrationId,
        saveIdentity: alice.saveIdentity,
        getIdentity: alice.getIdentity,
      );

      // Verify Alice now has a session with Bob
      expect(alice.sessionStorage.containsKey('bob:1'), isTrue);
      expect(alice.identityStorage.containsKey('bob:1'), isTrue);

      // Step 2: Alice encrypts a message to Bob
      const message1 = 'Hello Bob! This is the first message.';
      final encrypted1 = await messageEncryptWithCallbacks(
        remoteName: 'bob',
        remoteDeviceId: 1,
        localName: 'alice',
        localDeviceId: 1,
        plaintext: utf8.encode(message1),
        loadSession: alice.loadSession,
        storeSession: alice.storeSession,
        getIdentityKeyPair: alice.getIdentityKeyPair,
        getLocalRegistrationId: alice.getLocalRegistrationId,
        getIdentity: alice.getIdentity,
      );

      // First message should be a pre-key message (type 3)
      expect(
        encrypted1.messageType,
        equals(3),
        reason: 'First message should be a pre-key message',
      );
      expect(encrypted1.ciphertext, isNotEmpty);

      // Step 3: Bob decrypts Alice's pre-key message
      final decrypted1 = await messageDecryptPrekeyWithCallbacks(
        remoteName: 'alice',
        remoteDeviceId: 1,
        localName: 'bob',
        localDeviceId: 1,
        ciphertext: encrypted1.ciphertext.toList(),
        loadSession: bob.loadSession,
        storeSession: bob.storeSession,
        getIdentityKeyPair: bob.getIdentityKeyPair,
        getLocalRegistrationId: bob.getLocalRegistrationId,
        saveIdentity: bob.saveIdentity,
        loadSignedPreKey: bob.loadSignedPreKey,
        loadPreKey: bob.loadPreKey,
        removePreKey: bob.removePreKey,
        loadKyberPreKey: bob.loadKyberPreKey,
        markKyberPreKeyUsed: bob.markKyberPreKeyUsed,
        getIdentity: bob.getIdentity,
      );

      // Verify the decrypted message (returns Uint8List directly)
      expect(utf8.decode(decrypted1), equals(message1));

      // Bob should have a session with Alice now
      expect(bob.sessionStorage.containsKey('alice:1'), isTrue);
      expect(bob.identityStorage.containsKey('alice:1'), isTrue);

      // Step 4: Bob sends a reply to Alice
      const message2 = 'Hi Alice! Nice to hear from you.';
      final encrypted2 = await messageEncryptWithCallbacks(
        remoteName: 'alice',
        remoteDeviceId: 1,
        localName: 'bob',
        localDeviceId: 1,
        plaintext: utf8.encode(message2),
        loadSession: bob.loadSession,
        storeSession: bob.storeSession,
        getIdentityKeyPair: bob.getIdentityKeyPair,
        getLocalRegistrationId: bob.getLocalRegistrationId,
        getIdentity: bob.getIdentity,
      );

      // Bob's reply should be a Signal message (type 1) since session is established
      expect(
        encrypted2.messageType,
        equals(1),
        reason: 'Reply should be a Signal message',
      );
      expect(encrypted2.ciphertext, isNotEmpty);

      // Step 5: Alice decrypts Bob's reply
      final decrypted2 = await messageDecryptSignalWithCallbacks(
        remoteName: 'bob',
        remoteDeviceId: 1,
        localName: 'alice',
        localDeviceId: 1,
        ciphertext: encrypted2.ciphertext.toList(),
        loadSession: alice.loadSession,
        storeSession: alice.storeSession,
        getIdentityKeyPair: alice.getIdentityKeyPair,
        getLocalRegistrationId: alice.getLocalRegistrationId,
        saveIdentity: alice.saveIdentity,
        getIdentity: alice.getIdentity,
      );

      // Verify the decrypted message (returns Uint8List directly)
      expect(utf8.decode(decrypted2), equals(message2));

      // Step 6: Alice sends another message (should be Signal message now)
      const message3 = 'How are you doing?';
      final encrypted3 = await messageEncryptWithCallbacks(
        remoteName: 'bob',
        remoteDeviceId: 1,
        localName: 'alice',
        localDeviceId: 1,
        plaintext: utf8.encode(message3),
        loadSession: alice.loadSession,
        storeSession: alice.storeSession,
        getIdentityKeyPair: alice.getIdentityKeyPair,
        getLocalRegistrationId: alice.getLocalRegistrationId,
        getIdentity: alice.getIdentity,
      );

      // Should now be a Signal message since Bob has replied
      expect(
        encrypted3.messageType,
        equals(1),
        reason: 'Second message from Alice should be a Signal message',
      );

      // Bob decrypts
      final decrypted3 = await messageDecryptSignalWithCallbacks(
        remoteName: 'alice',
        remoteDeviceId: 1,
        localName: 'bob',
        localDeviceId: 1,
        ciphertext: encrypted3.ciphertext.toList(),
        loadSession: bob.loadSession,
        storeSession: bob.storeSession,
        getIdentityKeyPair: bob.getIdentityKeyPair,
        getLocalRegistrationId: bob.getLocalRegistrationId,
        saveIdentity: bob.saveIdentity,
        getIdentity: bob.getIdentity,
      );

      expect(utf8.decode(decrypted3), equals(message3));
    });
  });
}
