/// Kyber key pair for post-quantum cryptography.
library;

import 'dart:ffi';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../libsignal.dart';
import 'kyber_public_key.dart';
import 'kyber_secret_key.dart';

/// Finalizer for KyberKeyPair.
final Finalizer<Pointer<SignalKyberKeyPair>> _kyberKeyPairFinalizer = Finalizer(
  (ptr) {
    final mutPtr = calloc<SignalMutPointerKyberKeyPair>();
    mutPtr.ref.raw = ptr;
    signal_kyber_key_pair_destroy(mutPtr.ref);
    calloc.free(mutPtr);
  },
);

/// A Kyber key pair for post-quantum key encapsulation.
///
/// Kyber is a post-quantum key encapsulation mechanism (KEM) that
/// provides security against quantum computer attacks. Signal uses
/// Kyber1024 in combination with X25519 for hybrid key agreement.
///
/// Example:
/// ```dart
/// final keyPair = KyberKeyPair.generate();
/// final publicKey = keyPair.getPublicKey();
/// final secretKey = keyPair.getSecretKey();
/// keyPair.dispose();
/// ```
final class KyberKeyPair {
  final Pointer<SignalKyberKeyPair> _ptr;
  bool _disposed = false;

  KyberKeyPair._(this._ptr) {
    _kyberKeyPairFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a KyberKeyPair from a raw pointer.
  factory KyberKeyPair.fromPointer(Pointer<SignalKyberKeyPair> ptr) {
    return KyberKeyPair._(ptr);
  }

  /// Generates a new random Kyber key pair.
  ///
  /// Uses cryptographically secure random number generation.
  static KyberKeyPair generate() {
    LibSignal.ensureInitialized();

    final outPtr = calloc<SignalMutPointerKyberKeyPair>();

    try {
      final error = signal_kyber_key_pair_generate(outPtr);
      FfiHelpers.checkError(error, 'signal_kyber_key_pair_generate');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_kyber_key_pair_generate');
      }

      return KyberKeyPair._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
    }
  }

  /// Gets the public key from this key pair.
  ///
  /// Returns a new [KyberPublicKey] instance. The caller is responsible
  /// for disposing the returned key.
  KyberPublicKey getPublicKey() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerKyberPublicKey>();
    final constPtr = calloc<SignalConstPointerKyberKeyPair>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_key_pair_get_public_key(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_kyber_key_pair_get_public_key');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_kyber_key_pair_get_public_key',
        );
      }

      return KyberPublicKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the secret key from this key pair.
  ///
  /// Returns a new [KyberSecretKey] instance. The caller is responsible
  /// for disposing the returned key.
  KyberSecretKey getSecretKey() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerKyberSecretKey>();
    final constPtr = calloc<SignalConstPointerKyberKeyPair>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_key_pair_get_secret_key(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_kyber_key_pair_get_secret_key');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_kyber_key_pair_get_secret_key',
        );
      }

      return KyberSecretKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Creates a copy of this Kyber key pair.
  KyberKeyPair clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerKyberKeyPair>();
    final constPtr = calloc<SignalConstPointerKyberKeyPair>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_key_pair_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_kyber_key_pair_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_kyber_key_pair_clone');
      }

      return KyberKeyPair._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalKyberKeyPair> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('KyberKeyPair');
    }
  }

  /// Checks that this key pair has not been disposed.
  ///
  /// Throws [LibSignalException] if the key pair has been disposed.
  void checkNotDisposed() => _checkDisposed();

  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _kyberKeyPairFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerKyberKeyPair>();
      mutPtr.ref.raw = _ptr;
      signal_kyber_key_pair_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  bool get isDisposed => _disposed;
}
