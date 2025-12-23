/// Kyber public key for post-quantum cryptography.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../libsignal.dart';
import '../serialization_validator.dart';

/// Finalizer for KyberPublicKey.
final Finalizer<Pointer<SignalKyberPublicKey>> _kyberPublicKeyFinalizer =
    Finalizer((ptr) {
  final mutPtr = calloc<SignalMutPointerKyberPublicKey>();
  mutPtr.ref.raw = ptr;
  signal_kyber_public_key_destroy(mutPtr.ref);
  calloc.free(mutPtr);
});

/// A Kyber public key for post-quantum key encapsulation.
///
/// Kyber is a post-quantum key encapsulation mechanism (KEM) that
/// provides security against quantum computer attacks.
///
/// This key is used for hybrid key agreement in Signal Protocol,
/// combining X25519 with Kyber1024 for quantum resistance.
final class KyberPublicKey {
  final Pointer<SignalKyberPublicKey> _ptr;
  bool _disposed = false;

  KyberPublicKey._(this._ptr) {
    _kyberPublicKeyFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a KyberPublicKey from a raw pointer.
  factory KyberPublicKey.fromPointer(Pointer<SignalKyberPublicKey> ptr) {
    return KyberPublicKey._(ptr);
  }

  /// Deserializes a Kyber public key from bytes.
  static KyberPublicKey deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Pre-validate to prevent native crashes on invalid data
    SerializationValidator.validateKyberPublicKey(data);

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerKyberPublicKey>();

    try {
      final error = signal_kyber_public_key_deserialize(outPtr, buffer.ref);
      FfiHelpers.checkError(error, 'signal_kyber_public_key_deserialize');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_kyber_public_key_deserialize',
        );
      }

      return KyberPublicKey._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes the Kyber public key to bytes.
  Uint8List serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerKyberPublicKey>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_public_key_serialize(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_kyber_public_key_serialize');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Checks if this Kyber public key equals another.
  bool equals(KyberPublicKey other) {
    _checkDisposed();
    other._checkDisposed();

    final outPtr = calloc<Bool>();
    final lhsPtr = calloc<SignalConstPointerKyberPublicKey>();
    lhsPtr.ref.raw = _ptr;

    final rhsPtr = calloc<SignalConstPointerKyberPublicKey>();
    rhsPtr.ref.raw = other._ptr;

    try {
      final error = signal_kyber_public_key_equals(
        outPtr,
        lhsPtr.ref,
        rhsPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_kyber_public_key_equals');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(lhsPtr);
      calloc.free(rhsPtr);
    }
  }

  /// Creates a copy of this Kyber public key.
  KyberPublicKey clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerKyberPublicKey>();
    final constPtr = calloc<SignalConstPointerKyberPublicKey>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_public_key_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_kyber_public_key_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_kyber_public_key_clone');
      }

      return KyberPublicKey._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalKyberPublicKey> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('KyberPublicKey');
    }
  }

  /// For internal use - allows other classes to check disposed state.
  void checkNotDisposed() {
    _checkDisposed();
  }

  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _kyberPublicKeyFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerKyberPublicKey>();
      mutPtr.ref.raw = _ptr;
      signal_kyber_public_key_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  bool get isDisposed => _disposed;

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! KyberPublicKey) return false;
    if (_disposed || other._disposed) return false;
    return equals(other);
  }

  @override
  int get hashCode {
    if (_disposed) return 0;
    final bytes = serialize();
    if (bytes.length < 4) return 0;
    return bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
  }
}
