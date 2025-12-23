/// HKDF key derivation for Signal Protocol.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../ffi_helpers.dart';
import '../libsignal.dart';

/// HKDF (HMAC-based Key Derivation Function) utility.
///
/// HKDF is used throughout the Signal Protocol for key derivation.
/// This provides a simple interface to the libsignal HKDF implementation.
///
/// Example:
/// ```dart
/// // Derive a 32-byte key from input material
/// final derivedKey = Hkdf.deriveSecrets(
///   inputKeyMaterial: sharedSecret,
///   info: utf8.encode('my-context-info'),
///   salt: salt,
///   outputLength: 32,
/// );
/// ```
abstract final class Hkdf {
  /// Derives key material using HKDF.
  ///
  /// Parameters:
  /// - [inputKeyMaterial]: The input keying material (IKM)
  /// - [info]: Context and application specific information (label)
  /// - [salt]: Optional salt value (a non-secret random value)
  /// - [outputLength]: The desired length of the output key material
  ///
  /// Returns the derived key material.
  static Uint8List deriveSecrets({
    required Uint8List inputKeyMaterial,
    required Uint8List info,
    Uint8List? salt,
    required int outputLength,
  }) {
    LibSignal.ensureInitialized();

    if (outputLength <= 0) {
      throw ArgumentError.value(
        outputLength,
        'outputLength',
        'Must be positive',
      );
    }

    // Allocate output buffer
    final outputPtr = calloc<Uint8>(outputLength);
    final outputBuffer = calloc<SignalBorrowedMutableBuffer>();
    outputBuffer.ref.base = outputPtr.cast<UnsignedChar>();
    outputBuffer.ref.length = outputLength;

    // IKM buffer
    final ikmPtr = calloc<Uint8>(inputKeyMaterial.length);
    ikmPtr.asTypedList(inputKeyMaterial.length).setAll(0, inputKeyMaterial);
    final ikmBuffer = calloc<SignalBorrowedBuffer>();
    ikmBuffer.ref.base = ikmPtr.cast<UnsignedChar>();
    ikmBuffer.ref.length = inputKeyMaterial.length;

    // Info (label) buffer
    final infoPtr = calloc<Uint8>(info.length);
    infoPtr.asTypedList(info.length).setAll(0, info);
    final infoBuffer = calloc<SignalBorrowedBuffer>();
    infoBuffer.ref.base = infoPtr.cast<UnsignedChar>();
    infoBuffer.ref.length = info.length;

    // Salt buffer
    final saltData = salt ?? Uint8List(0);
    final saltPtr = calloc<Uint8>(saltData.length);
    if (saltData.isNotEmpty) {
      saltPtr.asTypedList(saltData.length).setAll(0, saltData);
    }
    final saltBuffer = calloc<SignalBorrowedBuffer>();
    saltBuffer.ref.base = saltPtr.cast<UnsignedChar>();
    saltBuffer.ref.length = saltData.length;

    try {
      final error = signal_hkdf_derive(
        outputBuffer.ref,
        ikmBuffer.ref,
        infoBuffer.ref,
        saltBuffer.ref,
      );
      FfiHelpers.checkError(error, 'signal_hkdf_derive');

      // Copy output to result
      final result = Uint8List(outputLength);
      for (var i = 0; i < outputLength; i++) {
        result[i] = outputPtr[i];
      }
      return result;
    } finally {
      calloc.free(outputPtr);
      calloc.free(outputBuffer);
      calloc.free(ikmPtr);
      calloc.free(ikmBuffer);
      calloc.free(infoPtr);
      calloc.free(infoBuffer);
      calloc.free(saltPtr);
      calloc.free(saltBuffer);
    }
  }
}
