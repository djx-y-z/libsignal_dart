/// Fingerprint verification for Signal Protocol.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../keys/public_key.dart';
import '../libsignal.dart';

/// Finalizer for Fingerprint.
final Finalizer<Pointer<SignalFingerprint>> _fingerprintFinalizer =
    Finalizer((ptr) {
  final mutPtr = calloc<SignalMutPointerFingerprint>();
  mutPtr.ref.raw = ptr;
  signal_fingerprint_destroy(mutPtr.ref);
  calloc.free(mutPtr);
});

/// A fingerprint for verifying identity keys.
///
/// Fingerprints provide a way for users to verify each other's identity
/// keys out-of-band. They can be displayed as a numeric string for
/// verbal verification or as a scannable QR code.
///
/// Example:
/// ```dart
/// // Create a fingerprint
/// final fingerprint = Fingerprint.create(
///   localIdentifier: utf8.encode(localUuid),
///   localKey: localIdentityKey,
///   remoteIdentifier: utf8.encode(remoteUuid),
///   remoteKey: remoteIdentityKey,
/// );
///
/// // Get the display string for verbal verification
/// final displayString = fingerprint.displayString;
/// print('Safety Number: $displayString');
///
/// // Get the scannable encoding for QR code
/// final scannable = fingerprint.scannableEncoding;
/// // Encode as QR code...
///
/// // Compare two fingerprints
/// final matches = Fingerprint.compare(encoding1, encoding2);
///
/// fingerprint.dispose();
/// ```
final class Fingerprint {
  final Pointer<SignalFingerprint> _ptr;
  bool _disposed = false;

  Fingerprint._(this._ptr) {
    _fingerprintFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a Fingerprint from a raw pointer.
  factory Fingerprint.fromPointer(Pointer<SignalFingerprint> ptr) {
    return Fingerprint._(ptr);
  }

  /// Creates a new fingerprint for identity verification.
  ///
  /// Parameters:
  /// - [localIdentifier]: The local user's identifier (e.g., UUID bytes)
  /// - [localKey]: The local user's identity public key
  /// - [remoteIdentifier]: The remote user's identifier (e.g., UUID bytes)
  /// - [remoteKey]: The remote user's identity public key
  /// - [iterations]: Number of hash iterations (default 5200 for v2)
  /// - [version]: Fingerprint version (default 2)
  static Fingerprint create({
    required Uint8List localIdentifier,
    required PublicKey localKey,
    required Uint8List remoteIdentifier,
    required PublicKey remoteKey,
    int iterations = 5200,
    int version = 2,
  }) {
    LibSignal.ensureInitialized();
    localKey.checkNotDisposed();
    remoteKey.checkNotDisposed();

    final outPtr = calloc<SignalMutPointerFingerprint>();

    final localIdPtr = calloc<Uint8>(localIdentifier.length);
    localIdPtr.asTypedList(localIdentifier.length).setAll(0, localIdentifier);
    final localIdBuffer = calloc<SignalBorrowedBuffer>();
    localIdBuffer.ref.base = localIdPtr.cast<UnsignedChar>();
    localIdBuffer.ref.length = localIdentifier.length;

    final localKeyPtr = calloc<SignalConstPointerPublicKey>();
    localKeyPtr.ref.raw = localKey.pointer;

    final remoteIdPtr = calloc<Uint8>(remoteIdentifier.length);
    remoteIdPtr.asTypedList(remoteIdentifier.length).setAll(0, remoteIdentifier);
    final remoteIdBuffer = calloc<SignalBorrowedBuffer>();
    remoteIdBuffer.ref.base = remoteIdPtr.cast<UnsignedChar>();
    remoteIdBuffer.ref.length = remoteIdentifier.length;

    final remoteKeyPtr = calloc<SignalConstPointerPublicKey>();
    remoteKeyPtr.ref.raw = remoteKey.pointer;

    try {
      final error = signal_fingerprint_new(
        outPtr,
        iterations,
        version,
        localIdBuffer.ref,
        localKeyPtr.ref,
        remoteIdBuffer.ref,
        remoteKeyPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_fingerprint_new');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_fingerprint_new');
      }

      return Fingerprint._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(localIdPtr);
      calloc.free(localIdBuffer);
      calloc.free(localKeyPtr);
      calloc.free(remoteIdPtr);
      calloc.free(remoteIdBuffer);
      calloc.free(remoteKeyPtr);
    }
  }

  /// Gets the display string for this fingerprint.
  ///
  /// This is a numeric string suitable for verbal verification.
  /// It consists of 60 digits arranged in 12 groups of 5.
  String get displayString {
    _checkDisposed();

    final outPtr = calloc<Pointer<Char>>();
    final constPtr = calloc<SignalConstPointerFingerprint>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_fingerprint_display_string(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_fingerprint_display_string');

      if (outPtr.value == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_fingerprint_display_string',
        );
      }

      final result = outPtr.value.cast<Utf8>().toDartString();
      signal_free_string(outPtr.value);
      return result;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the scannable encoding for this fingerprint.
  ///
  /// This encoding can be used to generate a QR code for scanning.
  Uint8List get scannableEncoding {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerFingerprint>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_fingerprint_scannable_encoding(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_fingerprint_scannable_encoding');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Compares two scannable fingerprint encodings.
  ///
  /// Returns `true` if the fingerprints match, `false` otherwise.
  static bool compare(Uint8List fingerprint1, Uint8List fingerprint2) {
    LibSignal.ensureInitialized();

    final outPtr = calloc<Bool>();

    final fp1Ptr = calloc<Uint8>(fingerprint1.length);
    fp1Ptr.asTypedList(fingerprint1.length).setAll(0, fingerprint1);
    final fp1Buffer = calloc<SignalBorrowedBuffer>();
    fp1Buffer.ref.base = fp1Ptr.cast<UnsignedChar>();
    fp1Buffer.ref.length = fingerprint1.length;

    final fp2Ptr = calloc<Uint8>(fingerprint2.length);
    fp2Ptr.asTypedList(fingerprint2.length).setAll(0, fingerprint2);
    final fp2Buffer = calloc<SignalBorrowedBuffer>();
    fp2Buffer.ref.base = fp2Ptr.cast<UnsignedChar>();
    fp2Buffer.ref.length = fingerprint2.length;

    try {
      final error = signal_fingerprint_compare(
        outPtr,
        fp1Buffer.ref,
        fp2Buffer.ref,
      );
      FfiHelpers.checkError(error, 'signal_fingerprint_compare');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(fp1Ptr);
      calloc.free(fp1Buffer);
      calloc.free(fp2Ptr);
      calloc.free(fp2Buffer);
    }
  }

  /// Creates a copy of this fingerprint.
  Fingerprint clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerFingerprint>();
    final constPtr = calloc<SignalConstPointerFingerprint>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_fingerprint_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_fingerprint_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_fingerprint_clone');
      }

      return Fingerprint._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('Fingerprint');
    }
  }

  /// Releases the native resources.
  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _fingerprintFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerFingerprint>();
      mutPtr.ref.raw = _ptr;
      signal_fingerprint_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  /// Whether this fingerprint has been disposed.
  bool get isDisposed => _disposed;
}
