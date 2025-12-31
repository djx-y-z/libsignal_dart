import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:libsignal/libsignal.dart';
import 'package:libsignal/src/ffi_helpers.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('FfiHelpers', () {
    group('toBorrowedBuffer()', () {
      test('returns pointer with copied data', () {
        final data = Uint8List.fromList([1, 2, 3, 4, 5]);
        final (_, ptr) = FfiHelpers.toBorrowedBuffer(data);

        // Verify data was copied correctly
        final copied = ptr.asTypedList(5);
        expect(copied, equals(data));

        calloc.free(ptr);
      });

      test('handles empty data', () {
        final data = Uint8List(0);
        final (_, ptr) = FfiHelpers.toBorrowedBuffer(data);

        // Empty data should still allocate (but pointer may be minimal)
        expect(() => calloc.free(ptr), returnsNormally);
      });

      test('creates independent copy of data', () {
        final data = Uint8List.fromList([1, 2, 3]);
        final (_, ptr) = FfiHelpers.toBorrowedBuffer(data);

        // Modify original
        data[0] = 99;

        // Buffer should still have original value
        expect(ptr[0], equals(1));

        calloc.free(ptr);
      });
    });

    group('createBorrowedBuffer()', () {
      test('does not throw', () {
        final ptr = calloc<Uint8>(10);
        for (var i = 0; i < 10; i++) {
          ptr[i] = i;
        }

        expect(
          () => FfiHelpers.createBorrowedBuffer(ptr, 10),
          returnsNormally,
        );

        calloc.free(ptr);
      });
    });

    group('createBorrowedMutableBuffer()', () {
      test('does not throw', () {
        final ptr = calloc<Uint8>(10);
        for (var i = 0; i < 10; i++) {
          ptr[i] = i;
        }

        expect(
          () => FfiHelpers.createBorrowedMutableBuffer(ptr, 10),
          returnsNormally,
        );

        calloc.free(ptr);
      });
    });

    group('checkError()', () {
      test('does nothing for null error', () {
        expect(
          () => FfiHelpers.checkError(null, 'test_operation'),
          returnsNormally,
        );
      });

      test('does nothing for nullptr', () {
        expect(
          () => FfiHelpers.checkError(nullptr, 'test_operation'),
          returnsNormally,
        );
      });

      // Note: Testing actual errors requires creating real FFI errors
      // which is done indirectly in other tests (e.g., deserialize invalid data)
    });

    group('getErrorCode()', () {
      test('returns 0 for nullptr', () {
        expect(FfiHelpers.getErrorCode(nullptr), equals(0));
      });
    });

    group('getErrorMessage()', () {
      test('returns null for nullptr', () {
        expect(FfiHelpers.getErrorMessage(nullptr), isNull);
      });
    });

    group('toNativeString()', () {
      test('converts ASCII string', () {
        const str = 'Hello, World!';
        final ptr = FfiHelpers.toNativeString(str);

        expect(ptr, isNot(nullptr));
        final restored = ptr.cast<Utf8>().toDartString();
        expect(restored, equals(str));

        calloc.free(ptr);
      });

      test('converts Unicode string', () {
        const str = 'Привет мир! 你好世界';
        final ptr = FfiHelpers.toNativeString(str);

        expect(ptr, isNot(nullptr));
        final restored = ptr.cast<Utf8>().toDartString();
        expect(restored, equals(str));

        calloc.free(ptr);
      });

      test('converts empty string', () {
        const str = '';
        final ptr = FfiHelpers.toNativeString(str);

        expect(ptr, isNot(nullptr));
        final restored = ptr.cast<Utf8>().toDartString();
        expect(restored, equals(str));

        calloc.free(ptr);
      });
    });

    group('fromNativeString()', () {
      test('converts native string to Dart', () {
        const original = 'Test string';
        final ptr = original.toNativeUtf8().cast<Char>();

        final result = FfiHelpers.fromNativeString(ptr);

        expect(result, equals(original));

        calloc.free(ptr);
      });

      test('returns null for nullptr', () {
        final result = FfiHelpers.fromNativeString(nullptr);
        expect(result, isNull);
      });
    });

    group('extractNativeString()', () {
      test('returns null for nullptr', () {
        final result = FfiHelpers.extractNativeString(nullptr);
        expect(result, isNull);
      });

      // Note: Testing with real strings requires creating strings
      // via signal_* functions, which is tested indirectly in other tests
    });

    group('pointer wrapper utilities', () {
      // Note: These utilities return struct values by copy, and the wrapper
      // memory is freed immediately. The raw pointer should be valid because
      // it's copied to the struct before the wrapper is freed.
      //
      // However, testing this directly is tricky because the struct is passed
      // by value and the pointer may be copied incorrectly in some edge cases.
      //
      // These utilities are tested indirectly through all the other tests
      // that use keys and perform FFI operations.

      test('toConstPrivateKey does not throw', () {
        final privateKey = PrivateKey.generate();

        expect(
          () => FfiHelpers.toConstPrivateKey(privateKey.pointer),
          returnsNormally,
        );

        privateKey.dispose();
      });

      test('toConstPublicKey does not throw', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        expect(
          () => FfiHelpers.toConstPublicKey(publicKey.pointer),
          returnsNormally,
        );

        publicKey.dispose();
        privateKey.dispose();
      });

      test('toMutPrivateKey does not throw', () {
        final privateKey = PrivateKey.generate();

        expect(
          () => FfiHelpers.toMutPrivateKey(privateKey.pointer),
          returnsNormally,
        );

        privateKey.dispose();
      });

      test('toMutPublicKey does not throw', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        expect(
          () => FfiHelpers.toMutPublicKey(publicKey.pointer),
          returnsNormally,
        );

        publicKey.dispose();
        privateKey.dispose();
      });
    });
  });
}
