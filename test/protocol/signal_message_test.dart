import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:libsignal/libsignal.dart';
import 'package:libsignal/src/bindings/libsignal_bindings.dart' as ffi;
import 'package:libsignal/src/ffi_helpers.dart';
import 'package:test/test.dart';

import '../test_helpers/session_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('SignalMessage', () {
    group('deserialize', () {
      test('throws on empty data', () {
        expect(
          () => SignalMessage.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects garbage data', () {
        final garbage = Uint8List.fromList([0x99, 0x88, 0x77, 0x66, 0x55]);
        expect(
          () => SignalMessage.deserialize(garbage),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('with established session', () {
      late InMemorySessionStore aliceSessionStore;
      late InMemoryIdentityKeyStore aliceIdentityStore;
      late InMemorySessionStore bobSessionStore;
      late InMemoryPreKeyStore bobPreKeyStore;
      late InMemorySignedPreKeyStore bobSignedPreKeyStore;
      late InMemoryKyberPreKeyStore bobKyberPreKeyStore;

      late IdentityKeyPair aliceIdentity;
      late ProtocolAddress aliceAddress;
      late ProtocolAddress bobAddress;
      late RemotePartyKeys bobKeys;

      setUp(() async {
        // Generate identity keys
        aliceIdentity = IdentityKeyPair.generate();

        // Create addresses
        aliceAddress = ProtocolAddress('alice', 1);
        bobAddress = ProtocolAddress('bob', 1);

        // Create stores for Alice
        aliceSessionStore = InMemorySessionStore();
        aliceIdentityStore = InMemoryIdentityKeyStore(aliceIdentity, 12345);

        // Create stores for Bob
        bobSessionStore = InMemorySessionStore();
        bobPreKeyStore = InMemoryPreKeyStore();
        bobSignedPreKeyStore = InMemorySignedPreKeyStore();
        bobKyberPreKeyStore = InMemoryKyberPreKeyStore();

        // Generate Bob's keys
        bobKeys = generateRemotePartyKeys(registrationId: 67890);

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
      });

      tearDown(() {
        aliceIdentity.dispose();
        aliceAddress.dispose();
        bobAddress.dispose();
        bobKeys.dispose();

        aliceSessionStore.clear();
        bobSessionStore.clear();
        bobPreKeyStore.clear();
        bobSignedPreKeyStore.clear();
        bobKyberPreKeyStore.clear();
      });

      /// Helper to extract SignalMessage from PreKeySignalMessage bytes.
      SignalMessage extractSignalMessageFromPreKey(Uint8List preKeyBytes) {
        final dataPtr = calloc<Uint8>(preKeyBytes.length);
        dataPtr.asTypedList(preKeyBytes.length).setAll(0, preKeyBytes);

        final buffer = calloc<ffi.SignalBorrowedBuffer>();
        buffer.ref.base = dataPtr.cast<UnsignedChar>();
        buffer.ref.length = preKeyBytes.length;

        final preKeyMsgPtr = calloc<ffi.SignalMutPointerPreKeySignalMessage>();

        try {
          // Deserialize PreKeySignalMessage
          final error = ffi.signal_pre_key_signal_message_deserialize(
            preKeyMsgPtr,
            buffer.ref,
          );
          FfiHelpers.checkError(
            error,
            'signal_pre_key_signal_message_deserialize',
          );

          // Extract the inner SignalMessage
          final signalMsgPtr = calloc<ffi.SignalMutPointerSignalMessage>();
          final constPreKeyPtr =
              calloc<ffi.SignalConstPointerPreKeySignalMessage>();
          constPreKeyPtr.ref.raw = preKeyMsgPtr.ref.raw;

          try {
            final error2 = ffi.signal_pre_key_signal_message_get_signal_message(
              signalMsgPtr,
              constPreKeyPtr.ref,
            );
            FfiHelpers.checkError(
              error2,
              'signal_pre_key_signal_message_get_signal_message',
            );

            return SignalMessage.fromPointer(signalMsgPtr.ref.raw);
          } finally {
            calloc.free(signalMsgPtr);
            calloc.free(constPreKeyPtr);
          }
        } finally {
          // Destroy the PreKeySignalMessage
          if (preKeyMsgPtr.ref.raw != nullptr) {
            ffi.signal_pre_key_signal_message_destroy(preKeyMsgPtr.ref);
          }
          calloc.free(preKeyMsgPtr);
          calloc.free(dataPtr);
          calloc.free(buffer);
        }
      }

      test('serialize/deserialize round-trip', () async {
        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        final plaintext = Uint8List.fromList([1, 2, 3, 4, 5]);
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        // First message is PreKeySignalMessage
        expect(encrypted.type, equals(CiphertextMessageType.preKey));

        // Extract SignalMessage from PreKeySignalMessage
        final signalMessage = extractSignalMessageFromPreKey(encrypted.bytes);

        // Serialize and deserialize
        final serialized = signalMessage.serialize();
        final deserialized = SignalMessage.deserialize(serialized);

        // Compare properties
        expect(deserialized.counter, equals(signalMessage.counter));
        expect(
          deserialized.messageVersion,
          equals(signalMessage.messageVersion),
        );
        expect(deserialized.body, equals(signalMessage.body));

        // Cleanup
        signalMessage.dispose();
        deserialized.dispose();
      });

      test('body returns encrypted ciphertext', () async {
        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        final plaintext = Uint8List.fromList([1, 2, 3, 4, 5]);
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        final signalMessage = extractSignalMessageFromPreKey(encrypted.bytes);

        // Body should be non-empty ciphertext
        expect(signalMessage.body, isNotEmpty);
        // Body should be different from plaintext (encrypted)
        expect(signalMessage.body, isNot(equals(plaintext)));

        signalMessage.dispose();
      });

      test('counter returns message counter', () async {
        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        final plaintext = Uint8List.fromList([1, 2, 3, 4, 5]);
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        final signalMessage = extractSignalMessageFromPreKey(encrypted.bytes);

        // First message should have counter 0
        expect(signalMessage.counter, equals(0));

        signalMessage.dispose();
      });

      test('messageVersion returns protocol version', () async {
        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        final plaintext = Uint8List.fromList([1, 2, 3, 4, 5]);
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        final signalMessage = extractSignalMessageFromPreKey(encrypted.bytes);

        // Protocol version should be 3 or higher (current is 4 for PQXDH)
        expect(signalMessage.messageVersion, greaterThanOrEqualTo(3));

        signalMessage.dispose();
      });

      // Note: pqRatchet test is skipped because signal_message_get_pq_ratchet
      // is not available in the current version of the native library.

      test('getSenderRatchetKey returns valid PublicKey', () async {
        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        final plaintext = Uint8List.fromList([1, 2, 3, 4, 5]);
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        final signalMessage = extractSignalMessageFromPreKey(encrypted.bytes);

        final ratchetKey = signalMessage.getSenderRatchetKey();

        // Should be a valid public key
        expect(ratchetKey.isDisposed, isFalse);
        expect(ratchetKey.serialize(), hasLength(33)); // Curve25519 public key

        ratchetKey.dispose();
        signalMessage.dispose();
      });

      test('clone creates independent copy', () async {
        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        final plaintext = Uint8List.fromList([1, 2, 3, 4, 5]);
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        final signalMessage = extractSignalMessageFromPreKey(encrypted.bytes);
        final cloned = signalMessage.clone();

        // Properties should be equal
        expect(cloned.counter, equals(signalMessage.counter));
        expect(cloned.messageVersion, equals(signalMessage.messageVersion));
        expect(cloned.body, equals(signalMessage.body));
        expect(cloned.serialize(), equals(signalMessage.serialize()));

        // Dispose original
        signalMessage.dispose();

        // Cloned should still work
        expect(cloned.isDisposed, isFalse);
        expect(() => cloned.counter, returnsNormally);

        cloned.dispose();
      });

      test('clone has same properties', () async {
        final aliceCipher = SessionCipher(
          sessionStore: aliceSessionStore,
          identityKeyStore: aliceIdentityStore,
        );

        final plaintext = Uint8List.fromList([1, 2, 3, 4, 5]);
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        final signalMessage = extractSignalMessageFromPreKey(encrypted.bytes);
        final cloned = signalMessage.clone();

        // Compare all properties
        expect(cloned.counter, equals(signalMessage.counter));
        expect(cloned.messageVersion, equals(signalMessage.messageVersion));
        expect(cloned.body, equals(signalMessage.body));
        // Note: pqRatchet comparison skipped - function not available in current native lib

        final originalRatchetKey = signalMessage.getSenderRatchetKey();
        final clonedRatchetKey = cloned.getSenderRatchetKey();
        expect(
          clonedRatchetKey.serialize(),
          equals(originalRatchetKey.serialize()),
        );

        originalRatchetKey.dispose();
        clonedRatchetKey.dispose();
        signalMessage.dispose();
        cloned.dispose();
      });
    });

    group('dispose', () {
      test('dispose releases resources', () async {
        final aliceIdentity = IdentityKeyPair.generate();
        final aliceSessionStore = InMemorySessionStore();
        final aliceIdentityStore = InMemoryIdentityKeyStore(
          aliceIdentity,
          12345,
        );
        final bobAddress = ProtocolAddress('bob', 1);
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);

        // Create bundle and establish session
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

        final plaintext = Uint8List.fromList([1, 2, 3]);
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        // Extract SignalMessage from PreKeySignalMessage
        final dataPtr = calloc<Uint8>(encrypted.bytes.length);
        dataPtr.asTypedList(encrypted.bytes.length).setAll(0, encrypted.bytes);

        final buffer = calloc<ffi.SignalBorrowedBuffer>();
        buffer.ref.base = dataPtr.cast<UnsignedChar>();
        buffer.ref.length = encrypted.bytes.length;

        final preKeyMsgPtr = calloc<ffi.SignalMutPointerPreKeySignalMessage>();
        ffi.signal_pre_key_signal_message_deserialize(preKeyMsgPtr, buffer.ref);

        final signalMsgPtr = calloc<ffi.SignalMutPointerSignalMessage>();
        final constPreKeyPtr =
            calloc<ffi.SignalConstPointerPreKeySignalMessage>();
        constPreKeyPtr.ref.raw = preKeyMsgPtr.ref.raw;
        ffi.signal_pre_key_signal_message_get_signal_message(
          signalMsgPtr,
          constPreKeyPtr.ref,
        );

        final signalMessage = SignalMessage.fromPointer(signalMsgPtr.ref.raw);

        expect(signalMessage.isDisposed, isFalse);
        signalMessage.dispose();
        expect(signalMessage.isDisposed, isTrue);

        // Cleanup FFI
        ffi.signal_pre_key_signal_message_destroy(preKeyMsgPtr.ref);
        calloc.free(preKeyMsgPtr);
        calloc.free(signalMsgPtr);
        calloc.free(constPreKeyPtr);
        calloc.free(dataPtr);
        calloc.free(buffer);

        // Cleanup other resources
        bobBundle.dispose();
        bobKeys.dispose();
        bobAddress.dispose();
        aliceIdentity.dispose();
        aliceSessionStore.clear();
      });

      test('double dispose is safe', () async {
        final aliceIdentity = IdentityKeyPair.generate();
        final aliceSessionStore = InMemorySessionStore();
        final aliceIdentityStore = InMemoryIdentityKeyStore(
          aliceIdentity,
          12345,
        );
        final bobAddress = ProtocolAddress('bob', 1);
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);

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

        final plaintext = Uint8List.fromList([1, 2, 3]);
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        // Extract SignalMessage using FFI
        final dataPtr = calloc<Uint8>(encrypted.bytes.length);
        dataPtr.asTypedList(encrypted.bytes.length).setAll(0, encrypted.bytes);

        final buffer = calloc<ffi.SignalBorrowedBuffer>();
        buffer.ref.base = dataPtr.cast<UnsignedChar>();
        buffer.ref.length = encrypted.bytes.length;

        final preKeyMsgPtr = calloc<ffi.SignalMutPointerPreKeySignalMessage>();
        ffi.signal_pre_key_signal_message_deserialize(preKeyMsgPtr, buffer.ref);

        final signalMsgPtr = calloc<ffi.SignalMutPointerSignalMessage>();
        final constPreKeyPtr =
            calloc<ffi.SignalConstPointerPreKeySignalMessage>();
        constPreKeyPtr.ref.raw = preKeyMsgPtr.ref.raw;
        ffi.signal_pre_key_signal_message_get_signal_message(
          signalMsgPtr,
          constPreKeyPtr.ref,
        );

        final signalMessage = SignalMessage.fromPointer(signalMsgPtr.ref.raw);

        // Double dispose should not throw
        signalMessage.dispose();
        expect(() => signalMessage.dispose(), returnsNormally);

        // Cleanup FFI
        ffi.signal_pre_key_signal_message_destroy(preKeyMsgPtr.ref);
        calloc.free(preKeyMsgPtr);
        calloc.free(signalMsgPtr);
        calloc.free(constPreKeyPtr);
        calloc.free(dataPtr);
        calloc.free(buffer);

        bobBundle.dispose();
        bobKeys.dispose();
        bobAddress.dispose();
        aliceIdentity.dispose();
        aliceSessionStore.clear();
      });

      test('operations after dispose throw StateError', () async {
        final aliceIdentity = IdentityKeyPair.generate();
        final aliceSessionStore = InMemorySessionStore();
        final aliceIdentityStore = InMemoryIdentityKeyStore(
          aliceIdentity,
          12345,
        );
        final bobAddress = ProtocolAddress('bob', 1);
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);

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

        final plaintext = Uint8List.fromList([1, 2, 3]);
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        // Extract SignalMessage using FFI
        final dataPtr = calloc<Uint8>(encrypted.bytes.length);
        dataPtr.asTypedList(encrypted.bytes.length).setAll(0, encrypted.bytes);

        final buffer = calloc<ffi.SignalBorrowedBuffer>();
        buffer.ref.base = dataPtr.cast<UnsignedChar>();
        buffer.ref.length = encrypted.bytes.length;

        final preKeyMsgPtr = calloc<ffi.SignalMutPointerPreKeySignalMessage>();
        ffi.signal_pre_key_signal_message_deserialize(preKeyMsgPtr, buffer.ref);

        final signalMsgPtr = calloc<ffi.SignalMutPointerSignalMessage>();
        final constPreKeyPtr =
            calloc<ffi.SignalConstPointerPreKeySignalMessage>();
        constPreKeyPtr.ref.raw = preKeyMsgPtr.ref.raw;
        ffi.signal_pre_key_signal_message_get_signal_message(
          signalMsgPtr,
          constPreKeyPtr.ref,
        );

        final signalMessage = SignalMessage.fromPointer(signalMsgPtr.ref.raw);

        signalMessage.dispose();

        // All operations should throw StateError
        expect(() => signalMessage.body, throwsA(isA<LibSignalException>()));
        expect(() => signalMessage.counter, throwsA(isA<LibSignalException>()));
        expect(
          () => signalMessage.messageVersion,
          throwsA(isA<LibSignalException>()),
        );
        // Note: pqRatchet test skipped - function not available in current native lib
        expect(
          () => signalMessage.getSenderRatchetKey(),
          throwsA(isA<LibSignalException>()),
        );
        expect(
          () => signalMessage.serialize(),
          throwsA(isA<LibSignalException>()),
        );
        expect(() => signalMessage.clone(), throwsA(isA<LibSignalException>()));
        expect(() => signalMessage.pointer, throwsA(isA<LibSignalException>()));

        // Cleanup FFI
        ffi.signal_pre_key_signal_message_destroy(preKeyMsgPtr.ref);
        calloc.free(preKeyMsgPtr);
        calloc.free(signalMsgPtr);
        calloc.free(constPreKeyPtr);
        calloc.free(dataPtr);
        calloc.free(buffer);

        bobBundle.dispose();
        bobKeys.dispose();
        bobAddress.dispose();
        aliceIdentity.dispose();
        aliceSessionStore.clear();
      });

      test('isDisposed returns correct state', () async {
        final aliceIdentity = IdentityKeyPair.generate();
        final aliceSessionStore = InMemorySessionStore();
        final aliceIdentityStore = InMemoryIdentityKeyStore(
          aliceIdentity,
          12345,
        );
        final bobAddress = ProtocolAddress('bob', 1);
        final bobKeys = generateRemotePartyKeys(registrationId: 67890);

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

        final plaintext = Uint8List.fromList([1, 2, 3]);
        final encrypted = await aliceCipher.encrypt(bobAddress, plaintext);

        // Extract SignalMessage using FFI
        final dataPtr = calloc<Uint8>(encrypted.bytes.length);
        dataPtr.asTypedList(encrypted.bytes.length).setAll(0, encrypted.bytes);

        final buffer = calloc<ffi.SignalBorrowedBuffer>();
        buffer.ref.base = dataPtr.cast<UnsignedChar>();
        buffer.ref.length = encrypted.bytes.length;

        final preKeyMsgPtr = calloc<ffi.SignalMutPointerPreKeySignalMessage>();
        ffi.signal_pre_key_signal_message_deserialize(preKeyMsgPtr, buffer.ref);

        final signalMsgPtr = calloc<ffi.SignalMutPointerSignalMessage>();
        final constPreKeyPtr =
            calloc<ffi.SignalConstPointerPreKeySignalMessage>();
        constPreKeyPtr.ref.raw = preKeyMsgPtr.ref.raw;
        ffi.signal_pre_key_signal_message_get_signal_message(
          signalMsgPtr,
          constPreKeyPtr.ref,
        );

        final signalMessage = SignalMessage.fromPointer(signalMsgPtr.ref.raw);

        expect(signalMessage.isDisposed, isFalse);
        signalMessage.dispose();
        expect(signalMessage.isDisposed, isTrue);

        // Cleanup FFI
        ffi.signal_pre_key_signal_message_destroy(preKeyMsgPtr.ref);
        calloc.free(preKeyMsgPtr);
        calloc.free(signalMsgPtr);
        calloc.free(constPreKeyPtr);
        calloc.free(dataPtr);
        calloc.free(buffer);

        bobBundle.dispose();
        bobKeys.dispose();
        bobAddress.dispose();
        aliceIdentity.dispose();
        aliceSessionStore.clear();
      });
    });
  });
}
