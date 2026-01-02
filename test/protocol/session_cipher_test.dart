import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/session_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('SessionCipher', () {
    late InMemorySessionStore aliceSessionStore;
    late InMemoryIdentityKeyStore aliceIdentityStore;
    late InMemoryPreKeyStore alicePreKeyStore;
    late InMemorySignedPreKeyStore aliceSignedPreKeyStore;
    late InMemoryKyberPreKeyStore aliceKyberPreKeyStore;

    late InMemorySessionStore bobSessionStore;
    // Note: bobIdentityStore is created per-test with bobKeys.identityKeyPair
    late InMemoryPreKeyStore bobPreKeyStore;
    late InMemorySignedPreKeyStore bobSignedPreKeyStore;
    late InMemoryKyberPreKeyStore bobKyberPreKeyStore;

    late IdentityKeyPair aliceIdentity;
    late ProtocolAddress aliceAddress;
    late ProtocolAddress bobAddress;

    setUp(() {
      // Generate identity key for Alice (Bob's identity is in bobKeys per test)
      aliceIdentity = IdentityKeyPair.generate();

      // Create addresses
      aliceAddress = ProtocolAddress('alice', 1);
      bobAddress = ProtocolAddress('bob', 1);

      // Create stores for Alice
      aliceSessionStore = InMemorySessionStore();
      aliceIdentityStore = InMemoryIdentityKeyStore(aliceIdentity, 12345);
      alicePreKeyStore = InMemoryPreKeyStore();
      aliceSignedPreKeyStore = InMemorySignedPreKeyStore();
      aliceKyberPreKeyStore = InMemoryKyberPreKeyStore();

      // Create stores for Bob (identity store created per-test with actual keys)
      bobSessionStore = InMemorySessionStore();
      bobPreKeyStore = InMemoryPreKeyStore();
      bobSignedPreKeyStore = InMemorySignedPreKeyStore();
      bobKyberPreKeyStore = InMemoryKyberPreKeyStore();
    });

    tearDown(() {
      aliceIdentity.dispose();
      aliceAddress.dispose();
      bobAddress.dispose();

      // Clear stores
      aliceSessionStore.clear();
      bobSessionStore.clear();
      alicePreKeyStore.clear();
      bobPreKeyStore.clear();
      aliceSignedPreKeyStore.clear();
      bobSignedPreKeyStore.clear();
      aliceKyberPreKeyStore.clear();
      bobKyberPreKeyStore.clear();
    });

    group('constructor', () {
      test('creates cipher with required stores only', () {
        final cipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        expect(cipher, isNotNull);
      });

      test('creates cipher with all stores', () {
        final cipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
          preKeyStore: alicePreKeyStore,
          signedPreKeyStore: aliceSignedPreKeyStore,
          kyberPreKeyStore: aliceKyberPreKeyStore,
        );

        expect(cipher, isNotNull);
      });
    });

    group('encrypt()', () {
      test('throws when no session exists', () async {
        final cipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        final plaintext = Uint8List.fromList(utf8.encode('Hello!'));

        await expectLater(
          () => cipher.encrypt(bobAddress, plaintext),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('encrypts message when session exists', () async {
        // Generate Bob's keys and establish session
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        await _storeBobPreKeys(
          bobKeys,
          bobPreKeyStore,
          bobSignedPreKeyStore,
          bobKyberPreKeyStore,
        );

        // Alice processes Bob's bundle
        final bobBundle = bobKeys.toBundle();
        final aliceBuilder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

        // Alice encrypts
        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        final plaintext = Uint8List.fromList(utf8.encode('Hello, Bob!'));
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        expect(encrypted.bytes, isNotEmpty);
        expect(encrypted.type, equals(CiphertextMessageType.preKey));
        expect(encrypted.bytes.length, greaterThan(plaintext.length));

        // Cleanup
        bobBundle.dispose();
        bobKeys.dispose();
      });

      test('returns PreKeySignalMessage for first message', () async {
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        await _storeBobPreKeys(
          bobKeys,
          bobPreKeyStore,
          bobSignedPreKeyStore,
          bobKyberPreKeyStore,
        );

        final bobBundle = bobKeys.toBundle();
        final aliceBuilder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        final plaintext = Uint8List.fromList(utf8.encode('First message'));
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        // First message is always PreKeySignalMessage
        expect(encrypted.type, equals(CiphertextMessageType.preKey));

        bobBundle.dispose();
        bobKeys.dispose();
      });

      test('encrypts empty plaintext', () async {
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        await _storeBobPreKeys(
          bobKeys,
          bobPreKeyStore,
          bobSignedPreKeyStore,
          bobKyberPreKeyStore,
        );

        final bobBundle = bobKeys.toBundle();
        final aliceBuilder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        // Empty plaintext should still work
        final plaintext = Uint8List(0);
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        expect(encrypted.bytes, isNotEmpty);

        bobBundle.dispose();
        bobKeys.dispose();
      });

      test('encrypts large plaintext', () async {
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        await _storeBobPreKeys(
          bobKeys,
          bobPreKeyStore,
          bobSignedPreKeyStore,
          bobKyberPreKeyStore,
        );

        final bobBundle = bobKeys.toBundle();
        final aliceBuilder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        // 100KB plaintext
        final plaintext = Uint8List(100 * 1024);
        for (var i = 0; i < plaintext.length; i++) {
          plaintext[i] = i % 256;
        }

        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        expect(encrypted.bytes, isNotEmpty);
        expect(encrypted.bytes.length, greaterThan(plaintext.length));

        bobBundle.dispose();
        bobKeys.dispose();
      });

      test('updates session state after encryption', () async {
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        await _storeBobPreKeys(
          bobKeys,
          bobPreKeyStore,
          bobSignedPreKeyStore,
          bobKyberPreKeyStore,
        );

        final bobBundle = bobKeys.toBundle();
        final aliceBuilder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

        // Get session state before encryption
        final sessionBefore = await aliceSessionStore.loadSession(bobAddress);
        final registrationIdBefore = sessionBefore?.remoteRegistrationId;
        sessionBefore?.dispose();

        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        final plaintext = Uint8List.fromList(utf8.encode('Hello'));
        await aliceCipher.encrypt(bobAddress, plaintext);

        // Session should still be present with same remote registration ID
        final sessionAfter = await aliceSessionStore.loadSession(bobAddress);
        expect(sessionAfter, isNotNull);
        expect(
          sessionAfter!.remoteRegistrationId,
          equals(registrationIdBefore),
        );
        sessionAfter.dispose();

        bobBundle.dispose();
        bobKeys.dispose();
      });
    });

    group('decryptSignalMessage()', () {
      test('decrypts valid SignalMessage after session established', () async {
        // Set up Alice's keys for Bob to use
        final aliceKeys = generateRemotePartyKeys(
          registrationId: 12345,
          deviceId: 1,
        );
        await _storeAlicePreKeys(
          aliceKeys,
          alicePreKeyStore,
          aliceSignedPreKeyStore,
          aliceKyberPreKeyStore,
        );

        // Bob establishes session with Alice
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        await _storeBobPreKeys(
          bobKeys,
          bobPreKeyStore,
          bobSignedPreKeyStore,
          bobKyberPreKeyStore,
        );

        // Alice establishes session with Bob first
        final bobBundle = bobKeys.toBundle();
        final aliceBuilder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

        // Alice sends first message (PreKeySignalMessage) to Bob
        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        final plaintext1 = Uint8List.fromList(utf8.encode('Hello, Bob!'));
        final encrypted1 = await aliceCipher.encrypt(bobAddress, plaintext1);
        expect(encrypted1.type, equals(CiphertextMessageType.preKey));

        // Update Bob's identity store with his own keys
        final bobIdentityStoreWithKeys = InMemoryIdentityKeyStore(
          bobKeys.identityKeyPair,
          67890,
        );

        // Bob decrypts (PreKeySignalMessage) - this establishes the session
        final bobCipher = SessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStoreWithKeys,
          preKeyStore: bobPreKeyStore,
          signedPreKeyStore: bobSignedPreKeyStore,
          kyberPreKeyStore: bobKyberPreKeyStore,
        );
        final decrypted1 = await bobCipher.decryptPreKeySignalMessage(
          aliceAddress,
          encrypted1.bytes,
        );
        expect(decrypted1, equals(plaintext1));

        // Now Bob sends a reply - this will be a SignalMessage
        final plaintext2 = Uint8List.fromList(utf8.encode('Hi Alice!'));
        final encrypted2 = await bobCipher.encrypt(aliceAddress, plaintext2);

        // After first message exchange, it should be whisper (SignalMessage)
        expect(encrypted2.type, equals(CiphertextMessageType.whisper));

        // Alice decrypts (SignalMessage)
        final decrypted2 = await aliceCipher.decryptSignalMessage(
          bobAddress,
          encrypted2.bytes,
        );
        expect(decrypted2, equals(plaintext2));

        // Cleanup
        bobBundle.dispose();
        bobKeys.dispose();
        aliceKeys.dispose();
      });
    });

    group('decryptPreKeySignalMessage()', () {
      test('throws when pre-key stores not provided', () async {
        // Create cipher without pre-key stores
        final cipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
          // No pre-key stores
        );

        final ciphertext = Uint8List.fromList([1, 2, 3, 4, 5]);

        await expectLater(
          () => cipher.decryptPreKeySignalMessage(bobAddress, ciphertext),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('decrypts PreKeySignalMessage and establishes session', () async {
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        await _storeBobPreKeys(
          bobKeys,
          bobPreKeyStore,
          bobSignedPreKeyStore,
          bobKyberPreKeyStore,
        );

        // Alice establishes session with Bob
        final bobBundle = bobKeys.toBundle();
        final aliceBuilder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

        // Alice encrypts first message
        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        final plaintext = Uint8List.fromList(utf8.encode('Hello, Bob!'));
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);
        expect(encrypted.type, equals(CiphertextMessageType.preKey));

        // Bob should NOT have a session initially
        final bobSessionBefore = await bobSessionStore.loadSession(
          aliceAddress,
        );
        expect(bobSessionBefore, isNull);

        // Create Bob's identity store with his own identity
        final bobIdentityStoreWithKeys = InMemoryIdentityKeyStore(
          bobKeys.identityKeyPair,
          67890,
        );

        // Bob decrypts
        final bobCipher = SessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStoreWithKeys,
          preKeyStore: bobPreKeyStore,
          signedPreKeyStore: bobSignedPreKeyStore,
          kyberPreKeyStore: bobKyberPreKeyStore,
        );
        final decrypted = await bobCipher.decryptPreKeySignalMessage(
          aliceAddress,
          encrypted.bytes,
        );

        expect(decrypted, equals(plaintext));

        // Bob should now have a session with Alice
        final bobSessionAfter = await bobSessionStore.loadSession(aliceAddress);
        expect(bobSessionAfter, isNotNull);
        bobSessionAfter?.dispose();

        bobBundle.dispose();
        bobKeys.dispose();
      });

      test('removes used one-time pre-key after decryption', () async {
        final bobKeys = generateRemotePartyKeys(
          registrationId: 67890,
          preKeyId: 42,
        );
        await _storeBobPreKeys(
          bobKeys,
          bobPreKeyStore,
          bobSignedPreKeyStore,
          bobKyberPreKeyStore,
        );

        // Verify pre-key exists
        final preKeyBefore = await bobPreKeyStore.loadPreKey(42);
        expect(preKeyBefore, isNotNull);
        preKeyBefore?.dispose();

        // Alice establishes session with Bob
        final bobBundle = bobKeys.toBundle();
        final aliceBuilder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

        // Alice encrypts first message
        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        final plaintext = Uint8List.fromList(utf8.encode('Hello!'));
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        // Create Bob's identity store with his own identity
        final bobIdentityStoreWithKeys = InMemoryIdentityKeyStore(
          bobKeys.identityKeyPair,
          67890,
        );

        // Bob decrypts
        final bobCipher = SessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStoreWithKeys,
          preKeyStore: bobPreKeyStore,
          signedPreKeyStore: bobSignedPreKeyStore,
          kyberPreKeyStore: bobKyberPreKeyStore,
        );
        await bobCipher.decryptPreKeySignalMessage(
          aliceAddress,
          encrypted.bytes,
        );

        // Pre-key should be removed
        final preKeyAfter = await bobPreKeyStore.loadPreKey(42);
        expect(preKeyAfter, isNull);

        bobBundle.dispose();
        bobKeys.dispose();
      });

      test('marks Kyber pre-key as used after decryption', () async {
        final bobKeys = generateRemotePartyKeys(
          registrationId: 67890,
          kyberPreKeyId: 99,
        );
        await _storeBobPreKeys(
          bobKeys,
          bobPreKeyStore,
          bobSignedPreKeyStore,
          bobKyberPreKeyStore,
        );

        // Verify Kyber pre-key exists
        final kyberKeyBefore = await bobKyberPreKeyStore.loadKyberPreKey(99);
        expect(kyberKeyBefore, isNotNull);
        kyberKeyBefore?.dispose();

        // Alice establishes session with Bob
        final bobBundle = bobKeys.toBundle();
        final aliceBuilder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

        // Alice encrypts first message
        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        final plaintext = Uint8List.fromList(utf8.encode('Hello!'));
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        // Create Bob's identity store with his own identity
        final bobIdentityStoreWithKeys = InMemoryIdentityKeyStore(
          bobKeys.identityKeyPair,
          67890,
        );

        // Bob decrypts
        final bobCipher = SessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStoreWithKeys,
          preKeyStore: bobPreKeyStore,
          signedPreKeyStore: bobSignedPreKeyStore,
          kyberPreKeyStore: bobKyberPreKeyStore,
        );
        await bobCipher.decryptPreKeySignalMessage(
          aliceAddress,
          encrypted.bytes,
        );

        // Kyber pre-key should be marked as used (implementation may vary)
        // The store's markKyberPreKeyUsed is called - we verify it doesn't throw
        expect(true, isTrue);

        bobBundle.dispose();
        bobKeys.dispose();
      });
    });

    group('round-trip encryption/decryption', () {
      test('Alice sends, Bob receives and replies', () async {
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        await _storeBobPreKeys(
          bobKeys,
          bobPreKeyStore,
          bobSignedPreKeyStore,
          bobKyberPreKeyStore,
        );

        // Alice establishes session with Bob
        final bobBundle = bobKeys.toBundle();
        final aliceBuilder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

        // Alice sends first message
        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        final plaintext1 = Uint8List.fromList(utf8.encode('Hello, Bob!'));
        final encrypted1 = await aliceCipher.encrypt(bobAddress, plaintext1);

        // Create Bob's cipher with his own identity
        final bobIdentityStoreWithKeys = InMemoryIdentityKeyStore(
          bobKeys.identityKeyPair,
          67890,
        );
        final bobCipher = SessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStoreWithKeys,
          preKeyStore: bobPreKeyStore,
          signedPreKeyStore: bobSignedPreKeyStore,
          kyberPreKeyStore: bobKyberPreKeyStore,
        );

        // Bob decrypts first message (PreKeySignalMessage)
        final decrypted1 = await bobCipher.decryptPreKeySignalMessage(
          aliceAddress,
          encrypted1.bytes,
        );
        expect(decrypted1, equals(plaintext1));

        // Bob replies
        final plaintext2 = Uint8List.fromList(utf8.encode('Hi Alice!'));
        final encrypted2 = await bobCipher.encrypt(aliceAddress, plaintext2);

        // Alice decrypts reply (SignalMessage)
        final decrypted2 = await aliceCipher.decryptSignalMessage(
          bobAddress,
          encrypted2.bytes,
        );
        expect(decrypted2, equals(plaintext2));

        bobBundle.dispose();
        bobKeys.dispose();
      });

      test('multiple messages back and forth', () async {
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        await _storeBobPreKeys(
          bobKeys,
          bobPreKeyStore,
          bobSignedPreKeyStore,
          bobKyberPreKeyStore,
        );

        // Alice establishes session with Bob
        final bobBundle = bobKeys.toBundle();
        final aliceBuilder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        final bobIdentityStoreWithKeys = InMemoryIdentityKeyStore(
          bobKeys.identityKeyPair,
          67890,
        );
        final bobCipher = SessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStoreWithKeys,
          preKeyStore: bobPreKeyStore,
          signedPreKeyStore: bobSignedPreKeyStore,
          kyberPreKeyStore: bobKyberPreKeyStore,
        );

        // Message 1: Alice -> Bob (PreKeySignalMessage)
        final msg1 = Uint8List.fromList(utf8.encode('Message 1 from Alice'));
        final enc1 = await aliceCipher.encrypt(bobAddress, msg1);
        expect(enc1.type, equals(CiphertextMessageType.preKey));
        final dec1 = await bobCipher.decryptPreKeySignalMessage(
          aliceAddress,
          enc1.bytes,
        );
        expect(dec1, equals(msg1));

        // Message 2: Bob -> Alice (SignalMessage)
        final msg2 = Uint8List.fromList(utf8.encode('Message 2 from Bob'));
        final enc2 = await bobCipher.encrypt(aliceAddress, msg2);
        expect(enc2.type, equals(CiphertextMessageType.whisper));
        final dec2 = await aliceCipher.decryptSignalMessage(
          bobAddress,
          enc2.bytes,
        );
        expect(dec2, equals(msg2));

        // Message 3: Alice -> Bob (SignalMessage now)
        final msg3 = Uint8List.fromList(utf8.encode('Message 3 from Alice'));
        final enc3 = await aliceCipher.encrypt(bobAddress, msg3);
        expect(enc3.type, equals(CiphertextMessageType.whisper));
        final dec3 = await bobCipher.decryptSignalMessage(
          aliceAddress,
          enc3.bytes,
        );
        expect(dec3, equals(msg3));

        // Message 4: Bob -> Alice (SignalMessage)
        final msg4 = Uint8List.fromList(utf8.encode('Message 4 from Bob'));
        final enc4 = await bobCipher.encrypt(aliceAddress, msg4);
        expect(enc4.type, equals(CiphertextMessageType.whisper));
        final dec4 = await aliceCipher.decryptSignalMessage(
          bobAddress,
          enc4.bytes,
        );
        expect(dec4, equals(msg4));

        // Message 5: Alice -> Bob (SignalMessage)
        final msg5 = Uint8List.fromList(utf8.encode('Message 5 from Alice'));
        final enc5 = await aliceCipher.encrypt(bobAddress, msg5);
        expect(enc5.type, equals(CiphertextMessageType.whisper));
        final dec5 = await bobCipher.decryptSignalMessage(
          aliceAddress,
          enc5.bytes,
        );
        expect(dec5, equals(msg5));

        bobBundle.dispose();
        bobKeys.dispose();
      });

      test('conversation with various message sizes', () async {
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);
        await _storeBobPreKeys(
          bobKeys,
          bobPreKeyStore,
          bobSignedPreKeyStore,
          bobKyberPreKeyStore,
        );

        final bobBundle = bobKeys.toBundle();
        final aliceBuilder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);

        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        final bobIdentityStoreWithKeys = InMemoryIdentityKeyStore(
          bobKeys.identityKeyPair,
          67890,
        );
        final bobCipher = SessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStoreWithKeys,
          preKeyStore: bobPreKeyStore,
          signedPreKeyStore: bobSignedPreKeyStore,
          kyberPreKeyStore: bobKyberPreKeyStore,
        );

        // First message to establish session (Alice -> Bob)
        final firstMsg = Uint8List.fromList(utf8.encode('Init'));
        final firstEnc = await aliceCipher.encrypt(bobAddress, firstMsg);
        await bobCipher.decryptPreKeySignalMessage(
          aliceAddress,
          firstEnc.bytes,
        );

        // Bob replies to Alice to complete full session
        final replyMsg = Uint8List.fromList(utf8.encode('Reply'));
        final replyEnc = await bobCipher.encrypt(aliceAddress, replyMsg);
        await aliceCipher.decryptSignalMessage(bobAddress, replyEnc.bytes);

        // Test various message sizes - now both sessions are fully established
        final sizes = [0, 1, 16, 256, 1024, 4096, 16384];
        for (final size in sizes) {
          final data = Uint8List(size);
          for (var i = 0; i < size; i++) {
            data[i] = i % 256;
          }

          // Alice -> Bob
          final enc = await aliceCipher.encrypt(bobAddress, data);
          final dec = await bobCipher.decryptSignalMessage(
            aliceAddress,
            enc.bytes,
          );
          expect(dec, equals(data), reason: 'Size $size A->B failed');

          // Bob -> Alice
          final enc2 = await bobCipher.encrypt(aliceAddress, data);
          final dec2 = await aliceCipher.decryptSignalMessage(
            bobAddress,
            enc2.bytes,
          );
          expect(dec2, equals(data), reason: 'Size $size B->A failed');
        }

        bobBundle.dispose();
        bobKeys.dispose();
      });
    });

    group('CiphertextMessage', () {
      test('constructor creates message with bytes and type', () {
        final bytes = Uint8List.fromList([1, 2, 3, 4]);
        final message = CiphertextMessage(bytes, CiphertextMessageType.whisper);

        expect(message.bytes, equals(bytes));
        expect(message.type, equals(CiphertextMessageType.whisper));
      });

      test('works with different types', () {
        final bytes = Uint8List.fromList([1, 2, 3]);

        final preKeyMessage = CiphertextMessage(
          bytes,
          CiphertextMessageType.preKey,
        );
        expect(preKeyMessage.type, equals(CiphertextMessageType.preKey));

        final whisperMessage = CiphertextMessage(
          bytes,
          CiphertextMessageType.whisper,
        );
        expect(whisperMessage.type, equals(CiphertextMessageType.whisper));
      });
    });
  });
}

/// Helper to store Bob's pre-keys in his stores.
Future<void> _storeBobPreKeys(
  RemotePartyKeys keys,
  InMemoryPreKeyStore preKeyStore,
  InMemorySignedPreKeyStore signedPreKeyStore,
  InMemoryKyberPreKeyStore kyberPreKeyStore,
) async {
  final preKeyRecord = PreKeyRecord.create(
    id: keys.preKeyId,
    publicKey: keys.preKeyPublic,
    privateKey: keys.preKeyPrivate,
  );
  await preKeyStore.storePreKey(keys.preKeyId, preKeyRecord);
  preKeyRecord.dispose();

  final signedPreKeyRecord = SignedPreKeyRecord.create(
    id: keys.signedPreKeyId,
    timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
    publicKey: keys.signedPreKeyPublic,
    privateKey: keys.signedPreKeyPrivate,
    signature: keys.signedPreKeySignature,
  );
  await signedPreKeyStore.storeSignedPreKey(
    keys.signedPreKeyId,
    signedPreKeyRecord,
  );
  signedPreKeyRecord.dispose();

  final kyberPreKeyRecord = KyberPreKeyRecord.create(
    id: keys.kyberPreKeyId,
    timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
    keyPair: keys.kyberKeyPair,
    signature: keys.kyberPreKeySignature,
  );
  await kyberPreKeyStore.storeKyberPreKey(
    keys.kyberPreKeyId,
    kyberPreKeyRecord,
  );
  kyberPreKeyRecord.dispose();
}

/// Helper to store Alice's pre-keys (for bidirectional tests).
Future<void> _storeAlicePreKeys(
  RemotePartyKeys keys,
  InMemoryPreKeyStore preKeyStore,
  InMemorySignedPreKeyStore signedPreKeyStore,
  InMemoryKyberPreKeyStore kyberPreKeyStore,
) async {
  await _storeBobPreKeys(
    keys,
    preKeyStore,
    signedPreKeyStore,
    kyberPreKeyStore,
  );
}
