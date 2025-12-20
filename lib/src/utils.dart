/// Utility functions for libsignal FFI operations.
///
/// Provides memory management, pointer conversion, and validation utilities.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'exception.dart';

/// Utility class for libsignal FFI operations.
class LibSignalUtils {
  LibSignalUtils._();

  /// Maximum allocation size (10MB - larger than liboqs due to potential
  /// large messages and group data).
  static const int maxAllocationSize = 10 * 1024 * 1024;

  // ============================================
  // Memory conversion utilities
  // ============================================

  /// Converts a [Uint8List] to a native pointer.
  ///
  /// The caller is responsible for freeing the returned pointer using
  /// [freePointer] or [secureFreePointer].
  ///
  /// Throws [LibSignalException] if [data] exceeds [maxAllocationSize].
  static Pointer<Uint8> uint8ListToPointer(Uint8List data) {
    if (data.isEmpty) {
      return nullptr;
    }

    if (data.length > maxAllocationSize) {
      throw LibSignalException.invalidArgument(
        'data',
        'Size ${data.length} exceeds maximum allocation size $maxAllocationSize',
      );
    }

    final pointer = calloc<Uint8>(data.length);
    if (pointer == nullptr) {
      throw LibSignalException('Failed to allocate ${data.length} bytes');
    }

    pointer.asTypedList(data.length).setAll(0, data);
    return pointer;
  }

  /// Converts a native pointer to a [Uint8List].
  ///
  /// Creates a copy of the data, so the original pointer can be freed.
  ///
  /// Throws [LibSignalException] if [ptr] is null or [length] is invalid.
  static Uint8List pointerToUint8List(Pointer<Uint8> ptr, int length) {
    if (ptr == nullptr) {
      throw LibSignalException.nullPointer('pointerToUint8List');
    }

    if (length < 0) {
      throw LibSignalException.invalidArgument(
        'length',
        'Length cannot be negative: $length',
      );
    }

    if (length == 0) {
      return Uint8List(0);
    }

    if (length > maxAllocationSize) {
      throw LibSignalException.invalidArgument(
        'length',
        'Size $length exceeds maximum allocation size $maxAllocationSize',
      );
    }

    return Uint8List.fromList(ptr.asTypedList(length));
  }

  // ============================================
  // Memory allocation utilities
  // ============================================

  /// Allocates [size] bytes of memory.
  ///
  /// The caller is responsible for freeing the returned pointer.
  ///
  /// Throws [LibSignalException] if allocation fails.
  static Pointer<Uint8> allocateBytes(int size) {
    if (size <= 0) {
      throw LibSignalException.invalidArgument(
        'size',
        'Size must be positive: $size',
      );
    }

    if (size > maxAllocationSize) {
      throw LibSignalException.invalidArgument(
        'size',
        'Size $size exceeds maximum allocation size $maxAllocationSize',
      );
    }

    final pointer = calloc<Uint8>(size);
    if (pointer == nullptr) {
      throw LibSignalException('Failed to allocate $size bytes');
    }

    return pointer;
  }

  // ============================================
  // Memory deallocation utilities
  // ============================================

  /// Frees a pointer allocated by [allocateBytes] or [uint8ListToPointer].
  static void freePointer(Pointer? ptr) {
    if (ptr != null && ptr != nullptr) {
      calloc.free(ptr);
    }
  }

  /// Securely frees a pointer by zeroing the memory first.
  ///
  /// This should be used for sensitive data like private keys.
  static void secureFreePointer(Pointer<Uint8>? ptr, int length) {
    if (ptr == null || ptr == nullptr || length <= 0) {
      return;
    }

    // Zero the memory before freeing
    final list = ptr.asTypedList(length);
    for (var i = 0; i < length; i++) {
      list[i] = 0;
    }

    calloc.free(ptr);
  }

  // ============================================
  // Validation utilities
  // ============================================

  /// Validates that [ptr] is not null.
  ///
  /// Throws [LibSignalException] if [ptr] is null.
  static void checkNotNull(Pointer ptr, String operation) {
    if (ptr == nullptr) {
      throw LibSignalException.nullPointer(operation);
    }
  }

  /// Validates that [data] is not empty.
  ///
  /// Throws [LibSignalException] if [data] is empty.
  static void checkNotEmpty(Uint8List data, String name) {
    if (data.isEmpty) {
      throw LibSignalException.invalidArgument(name, 'Cannot be empty');
    }
  }

  /// Validates that [data] has exactly [expectedLength] bytes.
  ///
  /// Throws [LibSignalException] if lengths don't match.
  static void checkLength(Uint8List data, int expectedLength, String name) {
    if (data.length != expectedLength) {
      throw LibSignalException.invalidArgument(
        name,
        'Expected $expectedLength bytes, got ${data.length}',
      );
    }
  }

  /// Validates that [data] has at least [minLength] bytes.
  ///
  /// Throws [LibSignalException] if data is too short.
  static void checkMinLength(Uint8List data, int minLength, String name) {
    if (data.length < minLength) {
      throw LibSignalException.invalidArgument(
        name,
        'Expected at least $minLength bytes, got ${data.length}',
      );
    }
  }

  // ============================================
  // String utilities
  // ============================================

  /// Converts a null-terminated C string to a Dart string.
  ///
  /// Returns null if [ptr] is null.
  static String? pointerToString(Pointer<Char> ptr) {
    if (ptr == nullptr) {
      return null;
    }
    return ptr.cast<Utf8>().toDartString();
  }

  /// Converts a Dart string to a null-terminated C string.
  ///
  /// The caller is responsible for freeing the returned pointer.
  static Pointer<Char> stringToPointer(String str) {
    return str.toNativeUtf8().cast<Char>();
  }
}
