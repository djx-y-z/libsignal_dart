import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:libsignal/libsignal.dart';
import 'package:libsignal/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('LibSignalUtils', () {
    group('constantTimeEquals', () {
      test('returns true for equal arrays', () {
        final a = Uint8List.fromList([1, 2, 3, 4, 5]);
        final b = Uint8List.fromList([1, 2, 3, 4, 5]);

        expect(LibSignalUtils.constantTimeEquals(a, b), isTrue);
      });

      test('returns true for empty arrays', () {
        final a = Uint8List(0);
        final b = Uint8List(0);

        expect(LibSignalUtils.constantTimeEquals(a, b), isTrue);
      });

      test('returns false for different arrays same length', () {
        final a = Uint8List.fromList([1, 2, 3, 4, 5]);
        final b = Uint8List.fromList([1, 2, 3, 4, 6]);

        expect(LibSignalUtils.constantTimeEquals(a, b), isFalse);
      });

      test('returns false for different arrays at first position', () {
        final a = Uint8List.fromList([0, 2, 3, 4, 5]);
        final b = Uint8List.fromList([1, 2, 3, 4, 5]);

        expect(LibSignalUtils.constantTimeEquals(a, b), isFalse);
      });

      test('returns false for different lengths', () {
        final a = Uint8List.fromList([1, 2, 3, 4, 5]);
        final b = Uint8List.fromList([1, 2, 3]);

        expect(LibSignalUtils.constantTimeEquals(a, b), isFalse);
      });

      test('returns false when one is empty', () {
        final a = Uint8List.fromList([1, 2, 3]);
        final b = Uint8List(0);

        expect(LibSignalUtils.constantTimeEquals(a, b), isFalse);
        expect(LibSignalUtils.constantTimeEquals(b, a), isFalse);
      });

      test('handles all-zero arrays', () {
        final a = Uint8List(32);
        final b = Uint8List(32);

        expect(LibSignalUtils.constantTimeEquals(a, b), isTrue);
      });

      test('handles all-ones arrays', () {
        final a = Uint8List.fromList(List.filled(32, 0xFF));
        final b = Uint8List.fromList(List.filled(32, 0xFF));

        expect(LibSignalUtils.constantTimeEquals(a, b), isTrue);
      });

      test('detects single bit difference', () {
        final a = Uint8List.fromList([0x00, 0x00, 0x00, 0x00]);
        final b = Uint8List.fromList([0x00, 0x00, 0x01, 0x00]); // bit 0 set

        expect(LibSignalUtils.constantTimeEquals(a, b), isFalse);
      });

      test('works with typical key sizes (32 bytes)', () {
        final a = Uint8List.fromList(List.generate(32, (i) => i));
        final b = Uint8List.fromList(List.generate(32, (i) => i));

        expect(LibSignalUtils.constantTimeEquals(a, b), isTrue);

        // Change one byte
        final c = Uint8List.fromList(b);
        c[15] = c[15] ^ 0x01;
        expect(LibSignalUtils.constantTimeEquals(a, c), isFalse);
      });

      test('works with typical MAC sizes (64 bytes)', () {
        final a = Uint8List.fromList(List.generate(64, (i) => i % 256));
        final b = Uint8List.fromList(List.generate(64, (i) => i % 256));

        expect(LibSignalUtils.constantTimeEquals(a, b), isTrue);
      });
    });

    group('uint8ListToPointer / pointerToUint8List', () {
      test('round-trip preserves data', () {
        final original = Uint8List.fromList([1, 2, 3, 4, 5]);
        final ptr = LibSignalUtils.uint8ListToPointer(original);

        expect(ptr.address, isNot(0));

        final restored = LibSignalUtils.pointerToUint8List(
          ptr,
          original.length,
        );
        expect(restored, equals(original));

        LibSignalUtils.freePointer(ptr);
      });

      test('handles empty list', () {
        final empty = Uint8List(0);
        final ptr = LibSignalUtils.uint8ListToPointer(empty);

        expect(ptr.address, equals(0)); // null pointer
      });

      test('throws for data exceeding max allocation size', () {
        // Create a list that would exceed maxAllocationSize
        // We can't actually allocate 10MB+ in a test, so we test the threshold
        final largeData = Uint8List(LibSignalUtils.maxAllocationSize + 1);
        expect(
          () => LibSignalUtils.uint8ListToPointer(largeData),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('pointerToUint8List throws for null pointer', () {
        expect(
          () => LibSignalUtils.pointerToUint8List(nullptr, 10),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('pointerToUint8List throws for negative length', () {
        final ptr = calloc<Uint8>(10);
        try {
          expect(
            () => LibSignalUtils.pointerToUint8List(ptr, -1),
            throwsA(isA<LibSignalException>()),
          );
        } finally {
          calloc.free(ptr);
        }
      });

      test('pointerToUint8List returns empty list for zero length', () {
        final ptr = calloc<Uint8>(10);
        try {
          final result = LibSignalUtils.pointerToUint8List(ptr, 0);
          expect(result, isEmpty);
        } finally {
          calloc.free(ptr);
        }
      });

      test('pointerToUint8List throws for length exceeding max', () {
        final ptr = calloc<Uint8>(10);
        try {
          expect(
            () => LibSignalUtils.pointerToUint8List(
              ptr,
              LibSignalUtils.maxAllocationSize + 1,
            ),
            throwsA(isA<LibSignalException>()),
          );
        } finally {
          calloc.free(ptr);
        }
      });
    });

    group('allocateBytes', () {
      test('allocates requested size', () {
        final ptr = LibSignalUtils.allocateBytes(100);
        expect(ptr.address, isNot(0));
        LibSignalUtils.freePointer(ptr);
      });

      test('throws for zero size', () {
        expect(
          () => LibSignalUtils.allocateBytes(0),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws for negative size', () {
        expect(
          () => LibSignalUtils.allocateBytes(-1),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws for size exceeding max allocation', () {
        expect(
          () => LibSignalUtils.allocateBytes(
            LibSignalUtils.maxAllocationSize + 1,
          ),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('freePointer', () {
      test('frees valid pointer', () {
        final ptr = calloc<Uint8>(10);
        expect(() => LibSignalUtils.freePointer(ptr), returnsNormally);
      });

      test('handles null dart pointer', () {
        expect(() => LibSignalUtils.freePointer(null), returnsNormally);
      });

      test('handles nullptr', () {
        expect(() => LibSignalUtils.freePointer(nullptr), returnsNormally);
      });
    });

    group('secureFreePointer', () {
      test('zeros and frees memory', () {
        final ptr = calloc<Uint8>(10);
        // Fill with data
        for (var i = 0; i < 10; i++) {
          ptr[i] = i + 1;
        }
        // This should zero the memory and free it
        expect(
          () => LibSignalUtils.secureFreePointer(ptr, 10),
          returnsNormally,
        );
      });

      test('handles null dart pointer', () {
        expect(
          () => LibSignalUtils.secureFreePointer(null, 10),
          returnsNormally,
        );
      });

      test('handles nullptr', () {
        expect(
          () => LibSignalUtils.secureFreePointer(nullptr, 10),
          returnsNormally,
        );
      });

      test('handles zero length', () {
        final ptr = calloc<Uint8>(10);
        // Should not zero but should not crash either
        expect(
          () => LibSignalUtils.secureFreePointer(ptr, 0),
          returnsNormally,
        );
        // Ptr was not freed (length was 0), so we need to free it
        calloc.free(ptr);
      });

      test('handles negative length', () {
        final ptr = calloc<Uint8>(10);
        expect(
          () => LibSignalUtils.secureFreePointer(ptr, -1),
          returnsNormally,
        );
        // Ptr was not freed (length was negative), so we need to free it
        calloc.free(ptr);
      });
    });

    group('zeroBytes', () {
      test('zeros all bytes', () {
        final data = Uint8List.fromList([1, 2, 3, 4, 5]);
        LibSignalUtils.zeroBytes(data);
        expect(data, equals(Uint8List(5)));
      });

      test('handles empty list', () {
        final data = Uint8List(0);
        expect(() => LibSignalUtils.zeroBytes(data), returnsNormally);
      });

      test('handles null', () {
        expect(() => LibSignalUtils.zeroBytes(null), returnsNormally);
      });

      test('zeros large arrays', () {
        final data = Uint8List.fromList(List.generate(1000, (i) => i % 256));
        LibSignalUtils.zeroBytes(data);
        expect(data.every((b) => b == 0), isTrue);
      });
    });

    group('checkNotNull', () {
      test('passes for valid pointer', () {
        final ptr = calloc<Uint8>(10);
        try {
          expect(
            () => LibSignalUtils.checkNotNull(ptr, 'test'),
            returnsNormally,
          );
        } finally {
          calloc.free(ptr);
        }
      });

      test('throws for nullptr', () {
        expect(
          () => LibSignalUtils.checkNotNull(nullptr, 'test_operation'),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('test_operation'),
            ),
          ),
        );
      });
    });

    group('checkNotEmpty', () {
      test('passes for non-empty data', () {
        final data = Uint8List.fromList([1, 2, 3]);
        expect(
          () => LibSignalUtils.checkNotEmpty(data, 'test'),
          returnsNormally,
        );
      });

      test('throws for empty data', () {
        final data = Uint8List(0);
        expect(
          () => LibSignalUtils.checkNotEmpty(data, 'test_param'),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              contains('test_param'),
            ),
          ),
        );
      });
    });

    group('checkLength', () {
      test('passes for correct length', () {
        final data = Uint8List(32);
        expect(
          () => LibSignalUtils.checkLength(data, 32, 'key'),
          returnsNormally,
        );
      });

      test('throws for wrong length', () {
        final data = Uint8List(16);
        expect(
          () => LibSignalUtils.checkLength(data, 32, 'key'),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              allOf(contains('key'), contains('32'), contains('16')),
            ),
          ),
        );
      });
    });

    group('checkMinLength', () {
      test('passes for data at minimum length', () {
        final data = Uint8List(32);
        expect(
          () => LibSignalUtils.checkMinLength(data, 32, 'data'),
          returnsNormally,
        );
      });

      test('passes for data above minimum length', () {
        final data = Uint8List(64);
        expect(
          () => LibSignalUtils.checkMinLength(data, 32, 'data'),
          returnsNormally,
        );
      });

      test('throws for data below minimum length', () {
        final data = Uint8List(16);
        expect(
          () => LibSignalUtils.checkMinLength(data, 32, 'data'),
          throwsA(
            isA<LibSignalException>().having(
              (e) => e.toString(),
              'message',
              allOf(contains('data'), contains('32'), contains('16')),
            ),
          ),
        );
      });
    });

    group('pointerToString / stringToPointer', () {
      test('round-trip preserves ASCII string', () {
        const original = 'Hello, World!';
        final ptr = LibSignalUtils.stringToPointer(original);
        final restored = LibSignalUtils.pointerToString(ptr);

        expect(restored, equals(original));

        calloc.free(ptr);
      });

      test('round-trip preserves Unicode string', () {
        const original = 'Привет мир! 你好世界 🎉';
        final ptr = LibSignalUtils.stringToPointer(original);
        final restored = LibSignalUtils.pointerToString(ptr);

        expect(restored, equals(original));

        calloc.free(ptr);
      });

      test('round-trip preserves empty string', () {
        const original = '';
        final ptr = LibSignalUtils.stringToPointer(original);
        final restored = LibSignalUtils.pointerToString(ptr);

        expect(restored, equals(original));

        calloc.free(ptr);
      });

      test('pointerToString returns null for nullptr', () {
        final result = LibSignalUtils.pointerToString(nullptr);
        expect(result, isNull);
      });
    });

    group('maxAllocationSize', () {
      test('is 10MB', () {
        expect(LibSignalUtils.maxAllocationSize, equals(10 * 1024 * 1024));
      });
    });
  });
}
