import 'dart:typed_data';

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

        final restored = LibSignalUtils.pointerToUint8List(ptr, original.length);
        expect(restored, equals(original));

        LibSignalUtils.freePointer(ptr);
      });

      test('handles empty list', () {
        final empty = Uint8List(0);
        final ptr = LibSignalUtils.uint8ListToPointer(empty);

        expect(ptr.address, equals(0)); // null pointer
      });
    });
  });
}
