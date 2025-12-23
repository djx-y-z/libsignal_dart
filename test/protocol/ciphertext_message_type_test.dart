import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  group('CiphertextMessageType', () {
    group('enum values', () {
      test('whisper has value 2', () {
        expect(CiphertextMessageType.whisper.value, equals(2));
      });

      test('preKey has value 3', () {
        expect(CiphertextMessageType.preKey.value, equals(3));
      });

      test('senderKey has value 7', () {
        expect(CiphertextMessageType.senderKey.value, equals(7));
      });

      test('plaintext has value 8', () {
        expect(CiphertextMessageType.plaintext.value, equals(8));
      });

      test('all values are unique', () {
        final values = CiphertextMessageType.values.map((t) => t.value).toSet();
        expect(values.length, equals(CiphertextMessageType.values.length));
      });
    });

    group('fromValue()', () {
      test('returns whisper for value 2', () {
        expect(
          CiphertextMessageType.fromValue(2),
          equals(CiphertextMessageType.whisper),
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

      test('returns plaintext for value 8', () {
        expect(
          CiphertextMessageType.fromValue(8),
          equals(CiphertextMessageType.plaintext),
        );
      });

      test('throws ArgumentError for unknown value 0', () {
        expect(
          () => CiphertextMessageType.fromValue(0),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('throws ArgumentError for unknown value 1', () {
        expect(
          () => CiphertextMessageType.fromValue(1),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('throws ArgumentError for unknown value 4', () {
        expect(
          () => CiphertextMessageType.fromValue(4),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('throws ArgumentError for unknown value 5', () {
        expect(
          () => CiphertextMessageType.fromValue(5),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('throws ArgumentError for unknown value 6', () {
        expect(
          () => CiphertextMessageType.fromValue(6),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('throws ArgumentError for unknown value 9', () {
        expect(
          () => CiphertextMessageType.fromValue(9),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('throws ArgumentError for negative value', () {
        expect(
          () => CiphertextMessageType.fromValue(-1),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('throws ArgumentError for large value', () {
        expect(
          () => CiphertextMessageType.fromValue(999),
          throwsA(isA<ArgumentError>()),
        );
      });
    });

    group('round-trip', () {
      test('fromValue(type.value) returns same type', () {
        for (final type in CiphertextMessageType.values) {
          expect(CiphertextMessageType.fromValue(type.value), equals(type));
        }
      });
    });
  });
}
