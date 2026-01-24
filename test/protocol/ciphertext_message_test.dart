import 'dart:typed_data';

import 'package:libsignal/src/protocol/ciphertext_message.dart';
import 'package:test/test.dart';

void main() {
  group('CiphertextMessageType', () {
    group('enum values', () {
      test('signal has value 2', () {
        expect(CiphertextMessageType.signal.value, equals(2));
      });

      test('preKey has value 3', () {
        expect(CiphertextMessageType.preKey.value, equals(3));
      });

      test('senderKey has value 7', () {
        expect(CiphertextMessageType.senderKey.value, equals(7));
      });

      test('plaintextContent has value 8', () {
        expect(CiphertextMessageType.plaintextContent.value, equals(8));
      });
    });

    group('fromValue', () {
      test('returns signal for value 1 (Rust internal Whisper)', () {
        // Rust code may return 1 for Whisper internally
        expect(
          CiphertextMessageType.fromValue(1),
          equals(CiphertextMessageType.signal),
        );
      });

      test('returns signal for value 2', () {
        expect(
          CiphertextMessageType.fromValue(2),
          equals(CiphertextMessageType.signal),
        );
      });

      test('returns preKey for value 3', () {
        expect(
          CiphertextMessageType.fromValue(3),
          equals(CiphertextMessageType.preKey),
        );
      });

      test('returns senderKey for value 7', () {
        expect(
          CiphertextMessageType.fromValue(7),
          equals(CiphertextMessageType.senderKey),
        );
      });

      test('returns plaintextContent for value 8', () {
        expect(
          CiphertextMessageType.fromValue(8),
          equals(CiphertextMessageType.plaintextContent),
        );
      });

      test('throws ArgumentError for invalid value 0', () {
        expect(
          () => CiphertextMessageType.fromValue(0),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('throws ArgumentError for invalid value 4', () {
        expect(
          () => CiphertextMessageType.fromValue(4),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('throws ArgumentError for invalid value -1', () {
        expect(
          () => CiphertextMessageType.fromValue(-1),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('throws ArgumentError for invalid value 100', () {
        expect(
          () => CiphertextMessageType.fromValue(100),
          throwsA(isA<ArgumentError>()),
        );
      });
    });
  });

  group('CiphertextMessage', () {
    group('constructor', () {
      test('creates message with type and ciphertext', () {
        final ciphertext = Uint8List.fromList([1, 2, 3, 4]);
        final message = CiphertextMessage(
          type: CiphertextMessageType.signal,
          ciphertext: ciphertext,
        );

        expect(message.type, equals(CiphertextMessageType.signal));
        expect(message.ciphertext, equals(ciphertext));
      });

      test('creates message with empty ciphertext', () {
        final message = CiphertextMessage(
          type: CiphertextMessageType.preKey,
          ciphertext: Uint8List(0),
        );

        expect(message.ciphertext, isEmpty);
      });
    });

    group('fromRaw', () {
      test('creates signal message from type value 2', () {
        final ciphertext = Uint8List.fromList([10, 20, 30]);
        final message = CiphertextMessage.fromRaw(
          messageType: 2,
          ciphertext: ciphertext,
        );

        expect(message.type, equals(CiphertextMessageType.signal));
        expect(message.ciphertext, equals(ciphertext));
      });

      test('creates signal message from type value 1 (Rust internal)', () {
        final message = CiphertextMessage.fromRaw(
          messageType: 1,
          ciphertext: Uint8List.fromList([1]),
        );

        expect(message.type, equals(CiphertextMessageType.signal));
      });

      test('creates preKey message from type value 3', () {
        final message = CiphertextMessage.fromRaw(
          messageType: 3,
          ciphertext: Uint8List.fromList([1, 2]),
        );

        expect(message.type, equals(CiphertextMessageType.preKey));
      });

      test('creates senderKey message from type value 7', () {
        final message = CiphertextMessage.fromRaw(
          messageType: 7,
          ciphertext: Uint8List.fromList([1, 2, 3]),
        );

        expect(message.type, equals(CiphertextMessageType.senderKey));
      });

      test('creates plaintextContent message from type value 8', () {
        final message = CiphertextMessage.fromRaw(
          messageType: 8,
          ciphertext: Uint8List.fromList([1, 2, 3, 4]),
        );

        expect(message.type, equals(CiphertextMessageType.plaintextContent));
      });

      test('throws for invalid message type', () {
        expect(
          () => CiphertextMessage.fromRaw(
            messageType: 99,
            ciphertext: Uint8List(0),
          ),
          throwsA(isA<ArgumentError>()),
        );
      });
    });

    group('isPreKeyMessage', () {
      test('returns true for preKey type', () {
        final message = CiphertextMessage(
          type: CiphertextMessageType.preKey,
          ciphertext: Uint8List(0),
        );

        expect(message.isPreKeyMessage, isTrue);
      });

      test('returns false for signal type', () {
        final message = CiphertextMessage(
          type: CiphertextMessageType.signal,
          ciphertext: Uint8List(0),
        );

        expect(message.isPreKeyMessage, isFalse);
      });

      test('returns false for senderKey type', () {
        final message = CiphertextMessage(
          type: CiphertextMessageType.senderKey,
          ciphertext: Uint8List(0),
        );

        expect(message.isPreKeyMessage, isFalse);
      });

      test('returns false for plaintextContent type', () {
        final message = CiphertextMessage(
          type: CiphertextMessageType.plaintextContent,
          ciphertext: Uint8List(0),
        );

        expect(message.isPreKeyMessage, isFalse);
      });
    });

    group('isSignalMessage', () {
      test('returns true for signal type', () {
        final message = CiphertextMessage(
          type: CiphertextMessageType.signal,
          ciphertext: Uint8List(0),
        );

        expect(message.isSignalMessage, isTrue);
      });

      test('returns false for preKey type', () {
        final message = CiphertextMessage(
          type: CiphertextMessageType.preKey,
          ciphertext: Uint8List(0),
        );

        expect(message.isSignalMessage, isFalse);
      });

      test('returns false for senderKey type', () {
        final message = CiphertextMessage(
          type: CiphertextMessageType.senderKey,
          ciphertext: Uint8List(0),
        );

        expect(message.isSignalMessage, isFalse);
      });

      test('returns false for plaintextContent type', () {
        final message = CiphertextMessage(
          type: CiphertextMessageType.plaintextContent,
          ciphertext: Uint8List(0),
        );

        expect(message.isSignalMessage, isFalse);
      });
    });
  });
}
