/// FFI helper functions for libsignal operations.
///
/// Provides bridging between Dart types and FFI types,
/// including buffer management and error handling.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings/libsignal_bindings.dart';
import 'exception.dart';

/// Helper class for FFI buffer and error operations.
class FfiHelpers {
  FfiHelpers._();

  // ============================================
  // Buffer conversion utilities
  // ============================================

  /// Creates a [SignalBorrowedBuffer] from a [Uint8List].
  ///
  /// The buffer borrows the data, so the [Pointer] must remain valid
  /// for the duration of the FFI call.
  ///
  /// Returns a record containing the buffer and the pointer that must be freed.
  static (SignalBorrowedBuffer, Pointer<Uint8>) toBorrowedBuffer(
    Uint8List data,
  ) {
    final ptr = calloc<Uint8>(data.length);
    if (data.isNotEmpty) {
      ptr.asTypedList(data.length).setAll(0, data);
    }

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = ptr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    return (buffer.ref, ptr);
  }

  /// Creates a [SignalBorrowedBuffer] on the stack from a [Uint8List].
  ///
  /// Use this when you need to pass a buffer to FFI and will free
  /// the data pointer separately.
  static SignalBorrowedBuffer createBorrowedBuffer(
    Pointer<Uint8> ptr,
    int length,
  ) {
    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = ptr.cast<UnsignedChar>();
    buffer.ref.length = length;
    final result = buffer.ref;
    // Note: We don't free the buffer struct here as ref gives a copy
    return result;
  }

  /// Creates a [SignalBorrowedMutableBuffer] for in-place operations.
  static SignalBorrowedMutableBuffer createBorrowedMutableBuffer(
    Pointer<Uint8> ptr,
    int length,
  ) {
    final buffer = calloc<SignalBorrowedMutableBuffer>();
    buffer.ref.base = ptr.cast<UnsignedChar>();
    buffer.ref.length = length;
    final result = buffer.ref;
    return result;
  }

  /// Extracts data from a [SignalOwnedBuffer] and frees it.
  ///
  /// This copies the data to a new [Uint8List] and frees the native buffer.
  static Uint8List fromOwnedBuffer(SignalOwnedBuffer buffer) {
    if (buffer.base == nullptr || buffer.length == 0) {
      return Uint8List(0);
    }

    final data = Uint8List.fromList(
      buffer.base.cast<Uint8>().asTypedList(buffer.length),
    );

    // Free the native buffer
    signal_free_buffer(buffer.base, buffer.length);

    return data;
  }

  /// Extracts data from a [Pointer<SignalOwnedBuffer>] and frees it.
  static Uint8List extractOwnedBuffer(Pointer<SignalOwnedBuffer> bufferPtr) {
    final buffer = bufferPtr.ref;
    final data = fromOwnedBuffer(buffer);
    calloc.free(bufferPtr);
    return data;
  }

  // ============================================
  // Error handling utilities
  // ============================================

  /// Checks if the FFI error pointer indicates an error and throws if so.
  ///
  /// Frees the error pointer after extracting the message.
  static void checkError(Pointer<SignalFfiError>? error, String operation) {
    if (error == null || error == nullptr) {
      return;
    }

    final errorType = signal_error_get_type(error);
    final message = getErrorMessage(error);

    // Free the error
    signal_error_free(error);

    throw LibSignalException(
      message ?? 'Unknown error in $operation',
      errorCode: errorType,
      context: operation,
    );
  }

  /// Gets the error message from a [SignalFfiError].
  ///
  /// Does not free the error pointer.
  static String? getErrorMessage(Pointer<SignalFfiError> error) {
    if (error == nullptr) {
      return null;
    }

    final messagePtr = calloc<Pointer<Char>>();
    try {
      final getMessageError = signal_error_get_message(error, messagePtr);
      if (getMessageError != nullptr) {
        signal_error_free(getMessageError);
        return null;
      }

      if (messagePtr.value == nullptr) {
        return null;
      }

      final message = messagePtr.value.cast<Utf8>().toDartString();
      signal_free_string(messagePtr.value);
      return message;
    } finally {
      calloc.free(messagePtr);
    }
  }

  /// Gets the error code (type) from a [SignalFfiError].
  static int getErrorCode(Pointer<SignalFfiError> error) {
    if (error == nullptr) {
      return 0;
    }
    return signal_error_get_type(error);
  }

  // ============================================
  // String utilities
  // ============================================

  /// Converts a Dart string to a null-terminated native string.
  ///
  /// The caller is responsible for freeing the returned pointer.
  static Pointer<Char> toNativeString(String str) {
    return str.toNativeUtf8().cast<Char>();
  }

  /// Converts a null-terminated native string to a Dart string.
  ///
  /// Does not free the pointer.
  static String? fromNativeString(Pointer<Char> ptr) {
    if (ptr == nullptr) {
      return null;
    }
    return ptr.cast<Utf8>().toDartString();
  }

  /// Converts a native string to Dart string and frees it.
  static String? extractNativeString(Pointer<Char> ptr) {
    if (ptr == nullptr) {
      return null;
    }
    final str = ptr.cast<Utf8>().toDartString();
    signal_free_string(ptr);
    return str;
  }

  // ============================================
  // Pointer wrapper utilities
  // ============================================

  /// Creates a SignalConstPointerPrivateKey from a raw pointer.
  static SignalConstPointerPrivateKey toConstPrivateKey(
    Pointer<SignalPrivateKey> ptr,
  ) {
    final wrapper = calloc<SignalConstPointerPrivateKey>();
    wrapper.ref.raw = ptr;
    final result = wrapper.ref;
    calloc.free(wrapper);
    return result;
  }

  /// Creates a SignalConstPointerPublicKey from a raw pointer.
  static SignalConstPointerPublicKey toConstPublicKey(
    Pointer<SignalPublicKey> ptr,
  ) {
    final wrapper = calloc<SignalConstPointerPublicKey>();
    wrapper.ref.raw = ptr;
    final result = wrapper.ref;
    calloc.free(wrapper);
    return result;
  }

  /// Creates a SignalMutPointerPrivateKey from a raw pointer.
  static SignalMutPointerPrivateKey toMutPrivateKey(
    Pointer<SignalPrivateKey> ptr,
  ) {
    final wrapper = calloc<SignalMutPointerPrivateKey>();
    wrapper.ref.raw = ptr;
    final result = wrapper.ref;
    calloc.free(wrapper);
    return result;
  }

  /// Creates a SignalMutPointerPublicKey from a raw pointer.
  static SignalMutPointerPublicKey toMutPublicKey(
    Pointer<SignalPublicKey> ptr,
  ) {
    final wrapper = calloc<SignalMutPointerPublicKey>();
    wrapper.ref.raw = ptr;
    final result = wrapper.ref;
    calloc.free(wrapper);
    return result;
  }
}
