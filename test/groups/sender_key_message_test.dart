import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('SenderKeyMessage', () {
    late ProtocolAddress senderAddress;
    late InMemorySenderKeyStore store;
    late Uint8List distributionId;
    late GroupSession session;
    late SenderKeyDistributionMessage distributionMessage;

    setUp(() async {
      senderAddress = ProtocolAddress('sender', 1);
      store = InMemorySenderKeyStore();
      distributionId = GroupSession.uuidFromString(
        '01234567-89ab-cdef-0123-456789abcdef',
      );
      session = GroupSession(senderAddress, distributionId, store);
      distributionMessage = await session.createDistributionMessage();
    });

    tearDown(() {
      distributionMessage.dispose();
      senderAddress.dispose();
    });

    /// Helper to create a valid SenderKeyMessage by encrypting data
    Future<SenderKeyMessage> createValidMessage([String text = 'Test']) async {
      final plaintext = Uint8List.fromList(utf8.encode(text));
      final ciphertext = await session.encrypt(plaintext);
      return SenderKeyMessage.deserialize(ciphertext);
    }

    group('deserialize()', () {
      test('rejects empty data', () {
        expect(
          () => SenderKeyMessage.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('rejects garbage data', () {
        final garbage = Uint8List.fromList([0x99, 0x88, 0x77, 0x66, 0x55]);
        expect(
          () => SenderKeyMessage.deserialize(garbage),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserializes valid message', () async {
        final message = await createValidMessage();
        expect(message.isDisposed, isFalse);
        message.dispose();
      });
    });

    group('serialize() / deserialize()', () {
      test('round-trip preserves message', () async {
        final original = await createValidMessage('Round-trip test');
        final serialized = original.serialize();
        final restored = SenderKeyMessage.deserialize(serialized);

        expect(restored.distributionId, equals(original.distributionId));
        expect(restored.chainId, equals(original.chainId));
        expect(restored.iteration, equals(original.iteration));
        expect(restored.cipherText, equals(original.cipherText));

        restored.dispose();
        original.dispose();
      });
    });

    group('distributionId', () {
      test('returns 16-byte UUID', () async {
        final message = await createValidMessage();
        expect(message.distributionId.length, equals(16));
        message.dispose();
      });

      test('matches session distributionId', () async {
        final message = await createValidMessage();
        expect(message.distributionId, equals(distributionId));
        message.dispose();
      });
    });

    group('chainId', () {
      test('returns non-negative value', () async {
        final message = await createValidMessage();
        expect(message.chainId, greaterThanOrEqualTo(0));
        message.dispose();
      });
    });

    group('iteration', () {
      test('starts at 0 for first message', () async {
        final message = await createValidMessage();
        expect(message.iteration, equals(0));
        message.dispose();
      });

      test('increments for subsequent messages', () async {
        final msg1 = await createValidMessage('First');
        final msg2 = await createValidMessage('Second');
        final msg3 = await createValidMessage('Third');

        expect(msg1.iteration, equals(0));
        expect(msg2.iteration, equals(1));
        expect(msg3.iteration, equals(2));

        msg1.dispose();
        msg2.dispose();
        msg3.dispose();
      });
    });

    group('cipherText', () {
      test('returns non-empty bytes', () async {
        final message = await createValidMessage('Some content');
        expect(message.cipherText, isNotEmpty);
        message.dispose();
      });

      test('differs for different plaintexts', () async {
        final msg1 = await createValidMessage('First message');
        final msg2 = await createValidMessage('Second message');

        expect(msg1.cipherText, isNot(equals(msg2.cipherText)));

        msg1.dispose();
        msg2.dispose();
      });
    });

    group('verifySignature()', () {
      test('returns true for valid signature with correct key', () async {
        final message = await createValidMessage();
        final signatureKey = distributionMessage.getSignatureKey();

        expect(message.verifySignature(signatureKey), isTrue);

        signatureKey.dispose();
        message.dispose();
      });

      test('returns false for wrong key', () async {
        final message = await createValidMessage();
        final wrongKey = PrivateKey.generate().getPublicKey();

        expect(message.verifySignature(wrongKey), isFalse);

        wrongKey.dispose();
        message.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () async {
        final original = await createValidMessage();
        final cloned = original.clone();

        expect(cloned.distributionId, equals(original.distributionId));
        expect(cloned.chainId, equals(original.chainId));
        expect(cloned.iteration, equals(original.iteration));
        expect(cloned.cipherText, equals(original.cipherText));

        original.dispose();
        expect(cloned.isDisposed, isFalse);
        cloned.dispose();
      });

      test('clone has own lifecycle', () async {
        final original = await createValidMessage();
        final cloned = original.clone();

        cloned.dispose();
        expect(cloned.isDisposed, isTrue);
        expect(original.isDisposed, isFalse);

        original.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () async {
        final message = await createValidMessage();
        expect(message.isDisposed, isFalse);
        message.dispose();
      });

      test('isDisposed is true after dispose', () async {
        final message = await createValidMessage();
        message.dispose();
        expect(message.isDisposed, isTrue);
      });

      test('double dispose is safe', () async {
        final message = await createValidMessage();
        message.dispose();
        expect(() => message.dispose(), returnsNormally);
      });

      test('serialize throws after dispose', () async {
        final message = await createValidMessage();
        message.dispose();
        expect(() => message.serialize(), throwsA(isA<LibSignalException>()));
      });

      test('distributionId throws after dispose', () async {
        final message = await createValidMessage();
        message.dispose();
        expect(
          () => message.distributionId,
          throwsA(isA<LibSignalException>()),
        );
      });

      test('chainId throws after dispose', () async {
        final message = await createValidMessage();
        message.dispose();
        expect(() => message.chainId, throwsA(isA<LibSignalException>()));
      });

      test('iteration throws after dispose', () async {
        final message = await createValidMessage();
        message.dispose();
        expect(() => message.iteration, throwsA(isA<LibSignalException>()));
      });

      test('cipherText throws after dispose', () async {
        final message = await createValidMessage();
        message.dispose();
        expect(() => message.cipherText, throwsA(isA<LibSignalException>()));
      });

      test('verifySignature throws after dispose', () async {
        final message = await createValidMessage();
        final key = PrivateKey.generate().getPublicKey();
        message.dispose();
        expect(
          () => message.verifySignature(key),
          throwsA(isA<LibSignalException>()),
        );
        key.dispose();
      });

      test('clone throws after dispose', () async {
        final message = await createValidMessage();
        message.dispose();
        expect(() => message.clone(), throwsA(isA<LibSignalException>()));
      });

      test('pointer throws after dispose', () async {
        final message = await createValidMessage();
        message.dispose();
        expect(() => message.pointer, throwsA(isA<LibSignalException>()));
      });
    });
  });
}
