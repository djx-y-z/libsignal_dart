import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/session_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('UnidentifiedSenderMessageContent', () {
    // Note: Tests for empty/invalid/garbage data deserialization are skipped
    // because libsignal native library may crash when processing invalid data.
    // This is a known limitation documented in HANDOFF.md.

    group('ContentHint constants', () {
      test('none is 0', () {
        expect(ContentHint.none, equals(0));
      });

      test('resendable is 1', () {
        expect(ContentHint.resendable, equals(1));
      });

      test('implicit is 2', () {
        expect(ContentHint.implicit, equals(2));
      });
    });

    // Tests using valid USMC from actual encryption
    group('from valid encryption', () {
      late InMemorySessionStore aliceSessionStore;
      late InMemoryIdentityKeyStore aliceIdentityStore;
      late InMemorySessionStore bobSessionStore;
      late InMemoryPreKeyStore bobPreKeyStore;
      late InMemorySignedPreKeyStore bobSignedPreKeyStore;
      late InMemoryKyberPreKeyStore bobKyberPreKeyStore;

      late IdentityKeyPair aliceIdentity;
      late ProtocolAddress aliceAddress;
      late ProtocolAddress bobAddress;

      late PrivateKey trustRootPrivate;
      late PublicKey trustRootPublic;
      late PrivateKey serverPrivate;
      late ServerCertificate serverCert;

      setUp(() {
        aliceIdentity = IdentityKeyPair.generate();
        aliceAddress = ProtocolAddress('alice', 1);
        bobAddress = ProtocolAddress('bob', 1);

        aliceSessionStore = InMemorySessionStore();
        aliceIdentityStore = InMemoryIdentityKeyStore(aliceIdentity, 12345);

        bobSessionStore = InMemorySessionStore();
        bobPreKeyStore = InMemoryPreKeyStore();
        bobSignedPreKeyStore = InMemorySignedPreKeyStore();
        bobKyberPreKeyStore = InMemoryKyberPreKeyStore();

        trustRootPrivate = PrivateKey.generate();
        trustRootPublic = trustRootPrivate.getPublicKey();

        serverPrivate = PrivateKey.generate();
        final serverKey = serverPrivate.getPublicKey();

        serverCert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        serverKey.dispose();
      });

      tearDown(() {
        aliceIdentity.dispose();
        aliceAddress.dispose();
        bobAddress.dispose();
        trustRootPrivate.dispose();
        trustRootPublic.dispose();
        serverPrivate.dispose();
        serverCert.dispose();

        aliceSessionStore.clear();
        bobSessionStore.clear();
        bobPreKeyStore.clear();
        bobSignedPreKeyStore.clear();
        bobKyberPreKeyStore.clear();
      });

      /// Helper to create a valid USMC by encrypting a message.
      Future<(UnidentifiedSenderMessageContent, RemotePartyKeys)>
          createValidUsmc({
        int contentHint = ContentHint.none,
        Uint8List? groupId,
      }) async {
        // Generate Bob's keys
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);

        // Store Bob's pre-keys
        final preKeyRecord = PreKeyRecord.create(
          id: bobKeys.preKeyId,
          publicKey: bobKeys.preKeyPublic,
          privateKey: bobKeys.preKeyPrivate,
        );
        await bobPreKeyStore.storePreKey(bobKeys.preKeyId, preKeyRecord);
        preKeyRecord.dispose();

        final signedPreKeyRecord = SignedPreKeyRecord.create(
          id: bobKeys.signedPreKeyId,
          timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
          publicKey: bobKeys.signedPreKeyPublic,
          privateKey: bobKeys.signedPreKeyPrivate,
          signature: bobKeys.signedPreKeySignature,
        );
        await bobSignedPreKeyStore.storeSignedPreKey(
          bobKeys.signedPreKeyId,
          signedPreKeyRecord,
        );
        signedPreKeyRecord.dispose();

        final kyberPreKeyRecord = KyberPreKeyRecord.create(
          id: bobKeys.kyberPreKeyId,
          timestamp: DateTime.now().toUtc().millisecondsSinceEpoch,
          keyPair: bobKeys.kyberKeyPair,
          signature: bobKeys.kyberPreKeySignature,
        );
        await bobKyberPreKeyStore.storeKyberPreKey(
          bobKeys.kyberPreKeyId,
          kyberPreKeyRecord,
        );
        kyberPreKeyRecord.dispose();

        // Alice establishes session with Bob
        final bobBundle = bobKeys.toBundle();
        final aliceBuilder = SessionBuilder(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        await aliceBuilder.processPreKeyBundle(bobAddress, bobBundle);
        bobBundle.dispose();

        // Create sender certificate for Alice
        final senderCert = SenderCertificate.create(
          senderUuid: 'alice-uuid',
          senderE164: '+1234567890',
          deviceId: 1,
          senderKey: aliceIdentity.publicKey,
          expiration: DateTime.now().toUtc().add(const Duration(days: 30)),
          signerCertificate: serverCert,
          signerKey: serverPrivate,
        );

        // Alice encrypts with sealed sender
        final aliceCipher = SealedSessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );
        final plaintext = Uint8List.fromList(utf8.encode('Hello, Bob!'));
        final sealed = await aliceCipher.encrypt(
          bobAddress,
          plaintext,
          senderCert,
          contentHint: contentHint,
          groupId: groupId,
        );
        senderCert.dispose();

        // Bob decrypts to get USMC
        final bobIdentityStore = InMemoryIdentityKeyStore(
          bobKeys.identityKeyPair,
          67890,
        );
        final bobCipher = SealedSessionCipher(
          sessionStore: bobSessionStore,
          identityKeyStore: bobIdentityStore,
        );
        final usmc = await bobCipher.decryptToUsmc(sealed);

        return (usmc, bobKeys);
      }

      group('getters', () {
        test('messageType returns correct type', () async {
          final (usmc, bobKeys) = await createValidUsmc();

          // PreKeySignalMessage type is 3
          expect(usmc.messageType, equals(3));

          usmc.dispose();
          bobKeys.dispose();
        });

        test('contentHint returns default value', () async {
          final (usmc, bobKeys) = await createValidUsmc(
            contentHint: ContentHint.none,
          );

          expect(usmc.contentHint, equals(ContentHint.none));

          usmc.dispose();
          bobKeys.dispose();
        });

        test('contentHint returns resendable', () async {
          final (usmc, bobKeys) = await createValidUsmc(
            contentHint: ContentHint.resendable,
          );

          expect(usmc.contentHint, equals(ContentHint.resendable));

          usmc.dispose();
          bobKeys.dispose();
        });

        test('contentHint returns implicit', () async {
          final (usmc, bobKeys) = await createValidUsmc(
            contentHint: ContentHint.implicit,
          );

          expect(usmc.contentHint, equals(ContentHint.implicit));

          usmc.dispose();
          bobKeys.dispose();
        });

        test('groupId returns empty when not set', () async {
          final (usmc, bobKeys) = await createValidUsmc(groupId: null);

          expect(usmc.groupId, isEmpty);

          usmc.dispose();
          bobKeys.dispose();
        });

        test('groupId returns value when set', () async {
          final groupId = Uint8List.fromList(utf8.encode('group-123'));
          final (usmc, bobKeys) = await createValidUsmc(groupId: groupId);

          expect(usmc.groupId, equals(groupId));

          usmc.dispose();
          bobKeys.dispose();
        });

        test('contents returns encrypted message bytes', () async {
          final (usmc, bobKeys) = await createValidUsmc();

          final contents = usmc.contents;
          expect(contents, isNotEmpty);
          // Contents should be the serialized PreKeySignalMessage
          expect(contents.length, greaterThan(10));

          usmc.dispose();
          bobKeys.dispose();
        });

        test('getSenderCertificate returns valid certificate', () async {
          final (usmc, bobKeys) = await createValidUsmc();

          final senderCert = usmc.getSenderCertificate();
          expect(senderCert, isNotNull);
          expect(senderCert.senderUuid, equals('alice-uuid'));
          expect(senderCert.senderE164, equals('+1234567890'));
          expect(senderCert.deviceId, equals(1));

          // Certificate should validate against trust root
          expect(
            senderCert.validate(trustRootPublic, now: DateTime.now().toUtc()),
            isTrue,
          );

          senderCert.dispose();
          usmc.dispose();
          bobKeys.dispose();
        });
      });

      group('serialize()', () {
        test('serializes to bytes', () async {
          final (usmc, bobKeys) = await createValidUsmc();

          final serialized = usmc.serialize();
          expect(serialized, isNotEmpty);
          expect(serialized.length, greaterThan(0));

          usmc.dispose();
          bobKeys.dispose();
        });

        test('round-trip serialization preserves data', () async {
          final groupId = Uint8List.fromList(utf8.encode('test-group'));
          final (usmc, bobKeys) = await createValidUsmc(
            contentHint: ContentHint.resendable,
            groupId: groupId,
          );

          // Serialize
          final serialized = usmc.serialize();

          // Deserialize
          final restored =
              UnidentifiedSenderMessageContent.deserialize(serialized);

          // Verify all properties match
          expect(restored.messageType, equals(usmc.messageType));
          expect(restored.contentHint, equals(usmc.contentHint));
          expect(restored.groupId, equals(usmc.groupId));
          expect(restored.contents, equals(usmc.contents));

          // Get sender certificates and compare
          final origCert = usmc.getSenderCertificate();
          final restoredCert = restored.getSenderCertificate();
          expect(restoredCert.senderUuid, equals(origCert.senderUuid));
          expect(restoredCert.senderE164, equals(origCert.senderE164));
          expect(restoredCert.deviceId, equals(origCert.deviceId));

          origCert.dispose();
          restoredCert.dispose();
          restored.dispose();
          usmc.dispose();
          bobKeys.dispose();
        });
      });

      group('disposal', () {
        test('isDisposed is false initially', () async {
          final (usmc, bobKeys) = await createValidUsmc();

          expect(usmc.isDisposed, isFalse);

          usmc.dispose();
          bobKeys.dispose();
        });

        test('isDisposed is true after dispose', () async {
          final (usmc, bobKeys) = await createValidUsmc();

          usmc.dispose();
          expect(usmc.isDisposed, isTrue);

          bobKeys.dispose();
        });

        test('double dispose is safe', () async {
          final (usmc, bobKeys) = await createValidUsmc();

          usmc.dispose();
          expect(() => usmc.dispose(), returnsNormally);

          bobKeys.dispose();
        });

        test('getters throw after dispose', () async {
          final (usmc, bobKeys) = await createValidUsmc();

          usmc.dispose();

          expect(() => usmc.messageType, throwsA(isA<LibSignalException>()));
          expect(() => usmc.contentHint, throwsA(isA<LibSignalException>()));
          expect(() => usmc.groupId, throwsA(isA<LibSignalException>()));
          expect(() => usmc.contents, throwsA(isA<LibSignalException>()));
          expect(
            () => usmc.getSenderCertificate(),
            throwsA(isA<LibSignalException>()),
          );
          expect(() => usmc.serialize(), throwsA(isA<LibSignalException>()));

          bobKeys.dispose();
        });

        test('pointer throws after dispose', () async {
          final (usmc, bobKeys) = await createValidUsmc();

          usmc.dispose();

          expect(() => usmc.pointer, throwsA(isA<LibSignalException>()));

          bobKeys.dispose();
        });
      });
    });

    group('deserialize()', () {
      test('throws for empty data', () {
        expect(
          () => UnidentifiedSenderMessageContent.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });
    });
  });
}
