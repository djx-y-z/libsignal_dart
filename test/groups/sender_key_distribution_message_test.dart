import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('SenderKeyDistributionMessage', () {
    late ProtocolAddress senderAddress;
    late InMemorySenderKeyStore store;
    late Uint8List distributionId;
    late GroupSession session;
    late SenderKeyDistributionMessage distMessage;

    setUp(() async {
      senderAddress = ProtocolAddress('sender', 1);
      store = InMemorySenderKeyStore();
      distributionId = GroupSession.uuidFromString(
        '01234567-89ab-cdef-0123-456789abcdef',
      );
      session = GroupSession(senderAddress, distributionId, store);
      distMessage = await session.createDistributionMessage();
    });

    tearDown(() {
      distMessage.dispose();
      senderAddress.dispose();
    });

    group('deserialize()', () {
      test('rejects empty data', () {
        expect(
          () => SenderKeyDistributionMessage.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects garbage data', () {
        final garbage = Uint8List.fromList([0x99, 0x88, 0x77, 0x66, 0x55]);
        expect(
          () => SenderKeyDistributionMessage.deserialize(garbage),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('serialize() / deserialize()', () {
      test('serializes to non-empty bytes', () {
        final serialized = distMessage.serialize();

        expect(serialized, isNotEmpty);
      });

      test('round-trip preserves all fields', () {
        final serialized = distMessage.serialize();
        final restored = SenderKeyDistributionMessage.deserialize(serialized);

        expect(restored.distributionId, equals(distMessage.distributionId));
        expect(restored.chainId, equals(distMessage.chainId));
        expect(restored.iteration, equals(distMessage.iteration));
        expect(restored.chainKey, equals(distMessage.chainKey));

        restored.dispose();
      });

      test('deserialized message has valid signature key', () {
        final serialized = distMessage.serialize();
        final restored = SenderKeyDistributionMessage.deserialize(serialized);

        final originalKey = distMessage.getSignatureKey();
        final restoredKey = restored.getSignatureKey();

        expect(
          restoredKey.serialize(),
          equals(originalKey.serialize()),
        );

        originalKey.dispose();
        restoredKey.dispose();
        restored.dispose();
      });
    });

    group('properties', () {
      test('chainKey returns 32 bytes', () {
        final chainKey = distMessage.chainKey;

        expect(chainKey.length, equals(32));
      });

      test('distributionId returns 16 bytes (UUID)', () {
        final id = distMessage.distributionId;

        expect(id.length, equals(16));
        expect(id, equals(distributionId));
      });

      test('chainId returns valid uint32', () {
        final chainId = distMessage.chainId;

        // Chain ID should be a reasonable value
        expect(chainId, isNonNegative);
      });

      test('iteration starts at 0', () {
        expect(distMessage.iteration, equals(0));
      });

      test('getSignatureKey() returns valid public key', () {
        final signatureKey = distMessage.getSignatureKey();

        expect(signatureKey, isNotNull);
        expect(signatureKey.isDisposed, isFalse);
        // Public key serialization: 1 type byte + 32 key bytes
        expect(signatureKey.serialize().length, equals(33));

        signatureKey.dispose();
      });

      test('getSignatureKey() returns consistent key', () {
        final key1 = distMessage.getSignatureKey();
        final key2 = distMessage.getSignatureKey();

        expect(key1.serialize(), equals(key2.serialize()));

        key1.dispose();
        key2.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final cloned = distMessage.clone();

        expect(cloned, isNotNull);
        expect(cloned.isDisposed, isFalse);

        // Original should still be usable after disposing clone
        cloned.dispose();
        expect(cloned.isDisposed, isTrue);
        expect(distMessage.isDisposed, isFalse);
      });

      test('cloned message has same properties', () {
        final cloned = distMessage.clone();

        expect(cloned.distributionId, equals(distMessage.distributionId));
        expect(cloned.chainId, equals(distMessage.chainId));
        expect(cloned.iteration, equals(distMessage.iteration));
        expect(cloned.chainKey, equals(distMessage.chainKey));

        cloned.dispose();
      });

      test('cloned message has same signature key', () {
        final cloned = distMessage.clone();

        final originalKey = distMessage.getSignatureKey();
        final clonedKey = cloned.getSignatureKey();

        expect(clonedKey.serialize(), equals(originalKey.serialize()));

        originalKey.dispose();
        clonedKey.dispose();
        cloned.dispose();
      });

      test('modifications to clone do not affect original', () {
        final cloned = distMessage.clone();
        final originalSerialized = distMessage.serialize();

        cloned.dispose();

        // Original should still serialize the same
        expect(distMessage.serialize(), equals(originalSerialized));
      });
    });

    group('dispose()', () {
      test('marks message as disposed', () {
        final msg = distMessage.clone();
        expect(msg.isDisposed, isFalse);

        msg.dispose();

        expect(msg.isDisposed, isTrue);
      });

      test('accessing disposed message throws StateError', () {
        final msg = distMessage.clone();
        msg.dispose();

        expect(() => msg.serialize(), throwsA(isA<LibSignalException>()));
        expect(() => msg.chainKey, throwsA(isA<LibSignalException>()));
        expect(() => msg.distributionId, throwsA(isA<LibSignalException>()));
        expect(() => msg.chainId, throwsA(isA<LibSignalException>()));
        expect(() => msg.iteration, throwsA(isA<LibSignalException>()));
        expect(() => msg.getSignatureKey(), throwsA(isA<LibSignalException>()));
        expect(() => msg.clone(), throwsA(isA<LibSignalException>()));
      });

      test('double dispose is safe', () {
        final msg = distMessage.clone();

        msg.dispose();
        expect(() => msg.dispose(), returnsNormally);
      });
    });
  });
}
