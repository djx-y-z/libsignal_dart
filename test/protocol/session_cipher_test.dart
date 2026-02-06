// ignore_for_file: cascade_invocations, avoid_redundant_argument_values
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/session_helpers.dart';

/// Helper class to manage all stores and keys for a test party.
// ignore: unreachable_from_main
class TestParty {
  // ignore: unreachable_from_main
  TestParty({
    required this.name,
    this.deviceId = 1,
    required this.registrationId,
  }) : identityKeyPair = IdentityKeyPair.generate(),
       sessionStore = InMemorySessionStore(),
       identityKeyStore = InMemoryIdentityKeyStore(
         IdentityKeyPair.generate(), // placeholder, will be replaced
         0,
       ),
       preKeyStore = InMemoryPreKeyStore(),
       signedPreKeyStore = InMemorySignedPreKeyStore(),
       kyberPreKeyStore = InMemoryKyberPreKeyStore() {
    // Create address
    address = ProtocolAddress(name: name, deviceId: deviceId);
  }

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

    final party = TestParty._internal(
      name: name,
      deviceId: deviceId,
      registrationId: registrationId,
      identityKeyPair: identityKeyPair,
      sessionStore: sessionStore,
      identityKeyStore: identityKeyStore,
      preKeyStore: preKeyStore,
      signedPreKeyStore: signedPreKeyStore,
      kyberPreKeyStore: kyberPreKeyStore,
    );

    party
      ..sessionBuilder = SessionBuilder(
        sessionStore: sessionStore,
        identityKeyStore: identityKeyStore,
      )
      ..sessionCipher = SessionCipher(
        sessionStore: sessionStore,
        identityKeyStore: identityKeyStore,
        preKeyStore: preKeyStore,
        signedPreKeyStore: signedPreKeyStore,
        kyberPreKeyStore: kyberPreKeyStore,
      );

    return party;
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

// Need to make RemotePartyKeys._ accessible or create a different approach
// Since RemotePartyKeys._ is private, let's create our own bundle generation

void main() {
  setUpAll(LibSignal.init);

  group('SessionCipher', () {
    group('encrypt / decrypt', () {
      test('Alice and Bob can exchange messages', () async {
        // Setup Alice
        final alice = TestParty.create(name: 'alice', registrationId: 111);

        // Setup Bob with pre-keys
        final bob = TestParty.create(name: 'bob', registrationId: 222);
        bob.generatePreKeys(preKeyId: 42, signedPreKeyId: 7, kyberPreKeyId: 1);

        // Alice establishes session with Bob
        await alice.sessionBuilder.processPreKeyBundle(
          bob.address,
          bob.getBundle(),
        );

        // Alice encrypts first message to Bob
        const message1 = 'Hello Bob! This is the first message.';
        final encrypted1 = await alice.sessionCipher.encrypt(
          bob.address,
          utf8.encode(message1),
        );

        // First message should be a pre-key message
        expect(encrypted1.isPreKeyMessage, isTrue);

        // Bob decrypts Alice's message (establishes session on his side)
        final aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
        final decrypted1 = await bob.sessionCipher.decrypt(
          aliceAddress,
          encrypted1,
        );

        expect(utf8.decode(decrypted1), equals(message1));

        // Bob should now have a session with Alice
        expect(await bob.sessionStore.containsSession(aliceAddress), isTrue);

        // Bob sends reply to Alice
        const message2 = 'Hi Alice! Nice to hear from you.';
        final encrypted2 = await bob.sessionCipher.encrypt(
          aliceAddress,
          utf8.encode(message2),
        );

        // Reply should be a Signal message (not pre-key)
        expect(encrypted2.isPreKeyMessage, isFalse);

        // Alice decrypts Bob's reply
        final decrypted2 = await alice.sessionCipher.decrypt(
          bob.address,
          encrypted2,
        );

        expect(utf8.decode(decrypted2), equals(message2));

        // Continue conversation - Alice sends another message
        const message3 = 'How are you doing?';
        final encrypted3 = await alice.sessionCipher.encrypt(
          bob.address,
          utf8.encode(message3),
        );

        // Should now be a Signal message
        expect(encrypted3.isPreKeyMessage, isFalse);

        final decrypted3 = await bob.sessionCipher.decrypt(
          aliceAddress,
          encrypted3,
        );

        expect(utf8.decode(decrypted3), equals(message3));
      });

      test('encrypts empty message', () async {
        final alice = TestParty.create(name: 'alice', registrationId: 111);
        final bob = TestParty.create(name: 'bob', registrationId: 222);
        bob.generatePreKeys();

        await alice.sessionBuilder.processPreKeyBundle(
          bob.address,
          bob.getBundle(),
        );

        // Encrypt empty message
        final encrypted = await alice.sessionCipher.encrypt(
          bob.address,
          utf8.encode(''),
        );

        expect(encrypted.ciphertext.isNotEmpty, isTrue);

        // Bob decrypts
        final aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
        final decrypted = await bob.sessionCipher.decrypt(
          aliceAddress,
          encrypted,
        );

        expect(utf8.decode(decrypted), equals(''));
      });

      test('handles large messages', () async {
        final alice = TestParty.create(name: 'alice', registrationId: 111);
        final bob = TestParty.create(name: 'bob', registrationId: 222);
        bob.generatePreKeys();

        await alice.sessionBuilder.processPreKeyBundle(
          bob.address,
          bob.getBundle(),
        );

        // Create large message (100KB)
        final largeMessage = 'x' * 100000;
        final encrypted = await alice.sessionCipher.encrypt(
          bob.address,
          utf8.encode(largeMessage),
        );

        final aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
        final decrypted = await bob.sessionCipher.decrypt(
          aliceAddress,
          encrypted,
        );

        expect(utf8.decode(decrypted), equals(largeMessage));
      });

      test('throws when no session exists', () async {
        final alice = TestParty.create(name: 'alice', registrationId: 111);
        final bob = TestParty.create(name: 'bob', registrationId: 222);

        // Don't establish session - should throw an exception (type varies by implementation)
        expect(
          () => alice.sessionCipher.encrypt(bob.address, utf8.encode('Hello')),
          throwsA(anything),
        );
      });
    });

    group('decryptSignalMessage / decryptPreKeyMessage', () {
      test('decryptPreKeyMessage works for first message', () async {
        final alice = TestParty.create(name: 'alice', registrationId: 111);
        final bob = TestParty.create(name: 'bob', registrationId: 222);
        bob.generatePreKeys();

        await alice.sessionBuilder.processPreKeyBundle(
          bob.address,
          bob.getBundle(),
        );

        const message = 'Test pre-key message';
        final encrypted = await alice.sessionCipher.encrypt(
          bob.address,
          utf8.encode(message),
        );

        expect(encrypted.isPreKeyMessage, isTrue);

        final aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
        final decrypted = await bob.sessionCipher.decryptPreKeyMessage(
          aliceAddress,
          encrypted.ciphertext,
        );

        expect(utf8.decode(decrypted), equals(message));
      });

      test('decryptSignalMessage works for subsequent messages', () async {
        final alice = TestParty.create(name: 'alice', registrationId: 111);
        final bob = TestParty.create(name: 'bob', registrationId: 222);
        bob.generatePreKeys();

        await alice.sessionBuilder.processPreKeyBundle(
          bob.address,
          bob.getBundle(),
        );

        // Exchange first messages to establish bidirectional session
        final aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
        final first = await alice.sessionCipher.encrypt(
          bob.address,
          utf8.encode('First'),
        );
        await bob.sessionCipher.decrypt(aliceAddress, first);

        final reply = await bob.sessionCipher.encrypt(
          aliceAddress,
          utf8.encode('Reply'),
        );
        await alice.sessionCipher.decrypt(bob.address, reply);

        // Now send Signal message (not pre-key)
        const message = 'Test signal message';
        final encrypted = await alice.sessionCipher.encrypt(
          bob.address,
          utf8.encode(message),
        );

        expect(encrypted.isPreKeyMessage, isFalse);

        final decrypted = await bob.sessionCipher.decryptSignalMessage(
          aliceAddress,
          encrypted.ciphertext,
        );

        expect(utf8.decode(decrypted), equals(message));
      });
    });

    group('error handling', () {
      test(
        'throws when signed pre-key is missing during pre-key decryption',
        () async {
          // Setup Alice and Bob
          final alice = TestParty.create(name: 'alice', registrationId: 111);
          final bob = TestParty.create(name: 'bob', registrationId: 222);
          bob.generatePreKeys(
            preKeyId: 1,
            signedPreKeyId: 99,
            kyberPreKeyId: 1,
          );

          // Establish session
          await alice.sessionBuilder.processPreKeyBundle(
            bob.address,
            bob.getBundle(),
          );

          // Alice encrypts a message
          final encrypted = await alice.sessionCipher.encrypt(
            bob.address,
            utf8.encode('Hello'),
          );
          expect(encrypted.isPreKeyMessage, isTrue);

          // Remove the signed pre-key from Bob's store
          await bob.signedPreKeyStore.removeSignedPreKey(99);

          // Bob tries to decrypt - should fail because signed pre-key is missing
          // The error comes from Rust when the callback returns None
          final aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
          expect(
            bob.sessionCipher.decryptPreKeyMessage(
              aliceAddress,
              encrypted.ciphertext,
            ),
            throwsA(
              predicate(
                (e) => e.toString().contains('Signed pre-key 99 not found'),
              ),
            ),
          );
        },
      );

      test('handles missing regular pre-key gracefully', () async {
        // This test verifies that missing regular pre-keys don't cause crashes
        // (they're optional in some protocol versions)
        final alice = TestParty.create(name: 'alice', registrationId: 111);
        final bob = TestParty.create(name: 'bob', registrationId: 222);
        bob.generatePreKeys();

        await alice.sessionBuilder.processPreKeyBundle(
          bob.address,
          bob.getBundle(),
        );

        // First message establishes session and uses pre-keys
        final encrypted1 = await alice.sessionCipher.encrypt(
          bob.address,
          utf8.encode('First message'),
        );

        final aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
        final decrypted1 = await bob.sessionCipher.decrypt(
          aliceAddress,
          encrypted1,
        );
        expect(utf8.decode(decrypted1), equals('First message'));

        // After first message, pre-key should be removed (used up)
        // Subsequent messages should still work without the pre-key
        final reply = await bob.sessionCipher.encrypt(
          aliceAddress,
          utf8.encode('Reply'),
        );
        await alice.sessionCipher.decrypt(bob.address, reply);

        // Continuing the conversation should work
        final encrypted2 = await alice.sessionCipher.encrypt(
          bob.address,
          utf8.encode('Second message'),
        );
        expect(encrypted2.isPreKeyMessage, isFalse);

        final decrypted2 = await bob.sessionCipher.decrypt(
          aliceAddress,
          encrypted2,
        );
        expect(utf8.decode(decrypted2), equals('Second message'));
      });
    });

    group('extractPrekeyMessageIds', () {
      test('extracts pre-key IDs from encrypted pre-key message', () async {
        final alice = TestParty.create(name: 'alice', registrationId: 111);
        final bob = TestParty.create(name: 'bob', registrationId: 222);
        bob.generatePreKeys(preKeyId: 42, signedPreKeyId: 7, kyberPreKeyId: 3);

        await alice.sessionBuilder.processPreKeyBundle(
          bob.address,
          bob.getBundle(),
        );

        // Encrypt a pre-key message
        final encrypted = await alice.sessionCipher.encrypt(
          bob.address,
          utf8.encode('Hello'),
        );
        expect(encrypted.isPreKeyMessage, isTrue);

        // Extract pre-key IDs from the ciphertext
        final ids = extractPrekeyMessageIds(
          message: encrypted.ciphertext.toList(),
        );

        // Verify extracted IDs match what we used
        expect(ids.preKeyId, equals(42));
        expect(ids.signedPreKeyId, equals(7));
        expect(ids.kyberPreKeyId, equals(3));
      });
    });

    group('EncryptResult equality', () {
      test('equals returns true for identical results', () {
        final ciphertext = Uint8List.fromList([1, 2, 3, 4, 5]);
        final result1 = EncryptResult(messageType: 3, ciphertext: ciphertext);
        final result2 = EncryptResult(messageType: 3, ciphertext: ciphertext);

        expect(result1, equals(result2));
        expect(result1.hashCode, equals(result2.hashCode));
      });

      test('equals returns false for different message types', () {
        final ciphertext = Uint8List.fromList([1, 2, 3, 4, 5]);
        final result1 = EncryptResult(messageType: 1, ciphertext: ciphertext);
        final result2 = EncryptResult(messageType: 3, ciphertext: ciphertext);

        expect(result1, isNot(equals(result2)));
      });

      test('equals returns false for different ciphertext', () {
        final result1 = EncryptResult(
          messageType: 3,
          ciphertext: Uint8List.fromList([1, 2, 3]),
        );
        final result2 = EncryptResult(
          messageType: 3,
          ciphertext: Uint8List.fromList([4, 5, 6]),
        );

        expect(result1, isNot(equals(result2)));
      });

      test('identical returns true for same instance', () {
        final result = EncryptResult(
          messageType: 3,
          ciphertext: Uint8List.fromList([1, 2, 3]),
        );

        expect(result, equals(result));
        expect(identical(result, result), isTrue);
      });

      test('equals returns false for non-EncryptResult', () {
        final result = EncryptResult(
          messageType: 3,
          ciphertext: Uint8List.fromList([1, 2, 3]),
        );

        // ignore: unrelated_type_equality_checks
        expect(result == 'not an EncryptResult', isFalse);
        // ignore: unrelated_type_equality_checks
        expect(result == 42, isFalse);
      });
    });

    group('PreKeyMessageIds equality', () {
      test('equals returns true for identical IDs', () {
        const ids1 = PreKeyMessageIds(
          preKeyId: 1,
          signedPreKeyId: 2,
          kyberPreKeyId: 3,
        );
        const ids2 = PreKeyMessageIds(
          preKeyId: 1,
          signedPreKeyId: 2,
          kyberPreKeyId: 3,
        );

        expect(ids1, equals(ids2));
        expect(ids1.hashCode, equals(ids2.hashCode));
      });

      test('equals returns false for different preKeyId', () {
        const ids1 = PreKeyMessageIds(
          preKeyId: 1,
          signedPreKeyId: 2,
          kyberPreKeyId: 3,
        );
        const ids2 = PreKeyMessageIds(
          preKeyId: 10,
          signedPreKeyId: 2,
          kyberPreKeyId: 3,
        );

        expect(ids1, isNot(equals(ids2)));
      });

      test('equals returns false for different signedPreKeyId', () {
        const ids1 = PreKeyMessageIds(
          preKeyId: 1,
          signedPreKeyId: 2,
          kyberPreKeyId: 3,
        );
        const ids2 = PreKeyMessageIds(
          preKeyId: 1,
          signedPreKeyId: 20,
          kyberPreKeyId: 3,
        );

        expect(ids1, isNot(equals(ids2)));
      });

      test('equals returns false for different kyberPreKeyId', () {
        const ids1 = PreKeyMessageIds(
          preKeyId: 1,
          signedPreKeyId: 2,
          kyberPreKeyId: 3,
        );
        const ids2 = PreKeyMessageIds(
          preKeyId: 1,
          signedPreKeyId: 2,
          kyberPreKeyId: 30,
        );

        expect(ids1, isNot(equals(ids2)));
      });

      test('handles null preKeyId', () {
        const ids1 = PreKeyMessageIds(signedPreKeyId: 2);
        const ids2 = PreKeyMessageIds(signedPreKeyId: 2);

        expect(ids1, equals(ids2));
        expect(ids1.preKeyId, isNull);
        expect(ids1.kyberPreKeyId, isNull);
      });

      test('identical returns true for same instance', () {
        const ids = PreKeyMessageIds(
          preKeyId: 1,
          signedPreKeyId: 2,
          kyberPreKeyId: 3,
        );

        expect(ids, equals(ids));
        expect(identical(ids, ids), isTrue);
      });

      test('equals returns false for non-PreKeyMessageIds', () {
        const ids = PreKeyMessageIds(
          preKeyId: 1,
          signedPreKeyId: 2,
          kyberPreKeyId: 3,
        );

        // ignore: unrelated_type_equality_checks
        expect(ids == 'not a PreKeyMessageIds', isFalse);
        // ignore: unrelated_type_equality_checks
        expect(ids == 42, isFalse);
      });
    });
  });
}
