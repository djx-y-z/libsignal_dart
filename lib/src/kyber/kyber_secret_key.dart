/// Kyber secret key for post-quantum cryptography.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../libsignal.dart';
import '../secure_bytes.dart';
import '../serialization_validator.dart';
import '../utils.dart';

/// Finalizer for KyberSecretKey.
final Finalizer<Pointer<SignalKyberSecretKey>> _kyberSecretKeyFinalizer =
    Finalizer((ptr) {
  final mutPtr = calloc<SignalMutPointerKyberSecretKey>();
  mutPtr.ref.raw = ptr;
  signal_kyber_secret_key_destroy(mutPtr.ref);
  calloc.free(mutPtr);
});

/// A Kyber secret key for post-quantum key encapsulation.
///
/// Kyber is a post-quantum key encapsulation mechanism (KEM) that
/// provides security against quantum computer attacks.
///
/// **Security note**: This key contains sensitive cryptographic material.
/// Ensure proper handling and secure disposal when no longer needed.
final class KyberSecretKey {
  final Pointer<SignalKyberSecretKey> _ptr;
  bool _disposed = false;

  KyberSecretKey._(this._ptr) {
    _kyberSecretKeyFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a KyberSecretKey from a raw pointer.
  factory KyberSecretKey.fromPointer(Pointer<SignalKyberSecretKey> ptr) {
    return KyberSecretKey._(ptr);
  }

  /// Deserializes a Kyber secret key from bytes.
  ///
  /// **Security note**: The input bytes should be securely cleared
  /// after calling this method.
  static KyberSecretKey deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Pre-validate to prevent native crashes on invalid data
    SerializationValidator.validateKyberSecretKey(data);

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerKyberSecretKey>();

    try {
      final error = signal_kyber_secret_key_deserialize(outPtr, buffer.ref);
      FfiHelpers.checkError(error, 'signal_kyber_secret_key_deserialize');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_kyber_secret_key_deserialize',
        );
      }

      return KyberSecretKey._(outPtr.ref.raw);
    } finally {
      // Secure clear the key data
      LibSignalUtils.secureFreePointer(dataPtr, data.length);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes the Kyber secret key to bytes.
  ///
  /// Returns a [SecureBytes] wrapper. The caller MUST call
  /// [SecureBytes.dispose] when done to securely zero the memory.
  ///
  /// Example:
  /// ```dart
  /// final keyBytes = kyberSecretKey.serialize();
  /// try {
  ///   saveToSecureStorage(keyBytes.bytes);
  /// } finally {
  ///   keyBytes.dispose(); // Securely zeros the memory
  /// }
  /// ```
  SecureBytes serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerKyberSecretKey>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_secret_key_serialize(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_kyber_secret_key_serialize');

      return SecureBytes(FfiHelpers.fromOwnedBuffer(outPtr.ref));
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Creates a copy of this Kyber secret key.
  KyberSecretKey clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerKyberSecretKey>();
    final constPtr = calloc<SignalConstPointerKyberSecretKey>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_secret_key_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_kyber_secret_key_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_kyber_secret_key_clone');
      }

      return KyberSecretKey._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalKyberSecretKey> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw StateError('KyberSecretKey has been disposed');
    }
  }

  /// For internal use - allows other classes to check disposed state.
  void checkNotDisposed() {
    _checkDisposed();
  }

  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _kyberSecretKeyFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerKyberSecretKey>();
      mutPtr.ref.raw = _ptr;
      signal_kyber_secret_key_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  bool get isDisposed => _disposed;
}
