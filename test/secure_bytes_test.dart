import 'dart:typed_data';

import 'package:libsignal/src/secure_bytes.dart';
import 'package:test/test.dart';

void main() {
  group('SecureBytes', () {
    group('constructor', () {
      test('creates with given data', () {
        final data = Uint8List.fromList([1, 2, 3, 4, 5]);
        final secure = SecureBytes(data);

        expect(secure.length, equals(5));
        expect(secure.bytes, equals(data));
        expect(secure.isDisposed, isFalse);

        secure.dispose();
      });

      test('takes ownership of data (no copy)', () {
        final data = Uint8List.fromList([1, 2, 3, 4, 5]);
        final secure = SecureBytes(data);

        // Modifying original should affect SecureBytes (same reference)
        data[0] = 99;
        expect(secure.bytes[0], equals(99));

        secure.dispose();

        // Original data should also be zeroed
        expect(data[0], equals(0));
      });

      test('handles empty data', () {
        final data = Uint8List(0);
        final secure = SecureBytes(data);

        expect(secure.length, equals(0));
        expect(secure.bytes, isEmpty);

        secure.dispose();
      });
    });

    group('copy factory', () {
      test('creates copy of data', () {
        final data = Uint8List.fromList([1, 2, 3, 4, 5]);
        final secure = SecureBytes.copy(data);

        expect(secure.bytes, equals(data));

        // Modifying original should NOT affect SecureBytes
        data[0] = 99;
        expect(secure.bytes[0], equals(1));

        secure.dispose();

        // Original data should be unchanged
        expect(data[0], equals(99));
      });
    });

    group('bytes getter', () {
      test('returns underlying data', () {
        final data = Uint8List.fromList([10, 20, 30]);
        final secure = SecureBytes(data);

        expect(secure.bytes, same(data));

        secure.dispose();
      });

      test('throws after dispose', () {
        final secure = SecureBytes(Uint8List.fromList([1, 2, 3]));
        secure.dispose();

        expect(() => secure.bytes, throwsStateError);
      });
    });

    group('length getter', () {
      test('returns correct length', () {
        final secure = SecureBytes(Uint8List(32));
        expect(secure.length, equals(32));
        secure.dispose();
      });

      test('returns 0 for empty data', () {
        final secure = SecureBytes(Uint8List(0));
        expect(secure.length, equals(0));
        secure.dispose();
      });

      test('works after dispose (returns original length)', () {
        final secure = SecureBytes(Uint8List(32));
        secure.dispose();
        // length still works as it reads from the underlying array
        expect(secure.length, equals(32));
      });
    });

    group('isDisposed', () {
      test('is false initially', () {
        final secure = SecureBytes(Uint8List(10));
        expect(secure.isDisposed, isFalse);
        secure.dispose();
      });

      test('is true after dispose', () {
        final secure = SecureBytes(Uint8List(10));
        secure.dispose();
        expect(secure.isDisposed, isTrue);
      });
    });

    group('dispose', () {
      test('zeros the data', () {
        final data = Uint8List.fromList([1, 2, 3, 4, 5]);
        final secure = SecureBytes(data);

        secure.dispose();

        // Underlying data should be zeroed
        for (var i = 0; i < data.length; i++) {
          expect(data[i], equals(0), reason: 'Byte at index $i should be 0');
        }
      });

      test('double dispose is safe', () {
        final secure = SecureBytes(Uint8List.fromList([1, 2, 3]));

        secure.dispose();
        expect(() => secure.dispose(), returnsNormally);
      });

      test('zeros large data', () {
        final data = Uint8List.fromList(List.generate(1000, (i) => i % 256));
        final secure = SecureBytes(data);

        secure.dispose();

        for (var i = 0; i < data.length; i++) {
          expect(data[i], equals(0));
        }
      });
    });

    group('toString', () {
      test('shows length when not disposed', () {
        final secure = SecureBytes(Uint8List(32));
        expect(secure.toString(), equals('SecureBytes(32 bytes)'));
        secure.dispose();
      });

      test('shows disposed when disposed', () {
        final secure = SecureBytes(Uint8List(32));
        secure.dispose();
        expect(secure.toString(), equals('SecureBytes(disposed)'));
      });
    });

    group('security scenarios', () {
      test('private key zeroing simulation', () {
        // Simulate a 32-byte private key
        final privateKeyData = Uint8List.fromList(List.generate(32, (i) => i));
        final secureKey = SecureBytes(privateKeyData);

        // Use the key
        expect(secureKey.bytes.length, equals(32));
        expect(secureKey.bytes[0], equals(0));

        // Dispose - should zero memory
        secureKey.dispose();

        // Verify all bytes are zeroed
        for (var i = 0; i < 32; i++) {
          expect(
            privateKeyData[i],
            equals(0),
            reason: 'Private key byte $i should be zeroed',
          );
        }
      });

      test('try-finally pattern works correctly', () {
        final data = Uint8List.fromList([1, 2, 3, 4, 5]);
        var processed = false;

        final secureBytes = SecureBytes(data);
        try {
          // Simulate processing
          processed = secureBytes.bytes.isNotEmpty;
        } finally {
          secureBytes.dispose();
        }

        expect(processed, isTrue);
        expect(secureBytes.isDisposed, isTrue);
        expect(data[0], equals(0)); // Data zeroed
      });
    });
  });
}
