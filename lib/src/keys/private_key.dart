/// Private key for Signal Protocol cryptographic operations.
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
import 'public_key.dart';

/// Weak reference tracking for finalizer.
final Finalizer<Pointer<SignalPrivateKey>> _privateKeyFinalizer = Finalizer(
  (ptr) {
    final mutPtr = calloc<SignalMutPointerPrivateKey>();
    mutPtr.ref.raw = ptr;
    signal_privatekey_destroy(mutPtr.ref);
    calloc.free(mutPtr);
  },
);

/// A private key for Signal Protocol operations.
///
/// Used for signing messages, key agreement (ECDH), and as part of
/// identity key pairs and pre-key pairs.
///
/// Private keys use the X25519/Ed25519 curve.
///
/// Example:
/// ```dart
/// final privateKey = PrivateKey.generate();
/// final signature = privateKey.sign(message);
/// final sharedSecret = privateKey.agree(otherPublicKey);
/// privateKey.dispose();
/// ```
final class PrivateKey {
  final Pointer<SignalPrivateKey> _ptr;
  bool _disposed = false;

  PrivateKey._(this._ptr) {
    _privateKeyFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a PrivateKey from a raw pointer.
  ///
  /// This is intended for internal use by other libsignal classes.
  factory PrivateKey.fromPointer(Pointer<SignalPrivateKey> ptr) {
    return PrivateKey._(ptr);
  }

  /// Generates a new random private key.
  ///
  /// Uses cryptographically secure random number generation.
  static PrivateKey generate() {
    LibSignal.ensureInitialized();

    final outPtr = calloc<SignalMutPointerPrivateKey>();
    try {
      final error = signal_privatekey_generate(outPtr);
      FfiHelpers.checkError(error, 'signal_privatekey_generate');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_privatekey_generate');
      }

      return PrivateKey._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
    }
  }

  /// Deserializes a private key from bytes.
  ///
  /// The [data] should be a 32-byte serialized private key.
  ///
  /// Throws [LibSignalException] if the data is invalid.
  static PrivateKey deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Pre-validate to prevent native crashes on invalid data
    SerializationValidator.validatePrivateKey(data);

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerPrivateKey>();

    try {
      final error = signal_privatekey_deserialize(outPtr, buffer.ref);
      FfiHelpers.checkError(error, 'signal_privatekey_deserialize');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_privatekey_deserialize');
      }

      return PrivateKey._(outPtr.ref.raw);
    } finally {
      // Secure clear the key data
      LibSignalUtils.zeroBytes(dataPtr.asTypedList(data.length));
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes the private key to bytes.
  ///
  /// Returns a [SecureBytes] containing a 32-byte representation of the
  /// private key. The caller MUST call [SecureBytes.dispose] when done
  /// to securely zero the memory.
  ///
  /// Example:
  /// ```dart
  /// final keyBytes = privateKey.serialize();
  /// try {
  ///   saveToSecureStorage(keyBytes.bytes);
  /// } finally {
  ///   keyBytes.dispose(); // Securely zeros the memory
  /// }
  /// ```
  SecureBytes serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerPrivateKey>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_privatekey_serialize(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_privatekey_serialize');

      return SecureBytes(FfiHelpers.fromOwnedBuffer(outPtr.ref));
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the corresponding public key.
  ///
  /// Returns a new [PublicKey] instance. The caller is responsible
  /// for disposing the returned key.
  PublicKey getPublicKey() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPublicKey>();
    final constPtr = calloc<SignalConstPointerPrivateKey>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_privatekey_get_public_key(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_privatekey_get_public_key');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_privatekey_get_public_key');
      }

      return PublicKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Signs a message using this private key.
  ///
  /// Returns the Ed25519 signature of the message.
  Uint8List sign(Uint8List message) {
    _checkDisposed();

    final messagePtr = calloc<Uint8>(message.length);
    if (message.isNotEmpty) {
      messagePtr.asTypedList(message.length).setAll(0, message);
    }

    final messageBuffer = calloc<SignalBorrowedBuffer>();
    messageBuffer.ref.base = messagePtr.cast<UnsignedChar>();
    messageBuffer.ref.length = message.length;

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerPrivateKey>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_privatekey_sign(
        outPtr,
        constPtr.ref,
        messageBuffer.ref,
      );
      FfiHelpers.checkError(error, 'signal_privatekey_sign');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(messagePtr);
      calloc.free(messageBuffer);
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Performs ECDH key agreement with a public key.
  ///
  /// Returns the shared secret derived from this private key
  /// and the given [publicKey].
  Uint8List agree(PublicKey publicKey) {
    _checkDisposed();
    publicKey.checkNotDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final privateConstPtr = calloc<SignalConstPointerPrivateKey>();
    privateConstPtr.ref.raw = _ptr;

    final publicConstPtr = calloc<SignalConstPointerPublicKey>();
    publicConstPtr.ref.raw = publicKey.pointer;

    try {
      final error = signal_privatekey_agree(
        outPtr,
        privateConstPtr.ref,
        publicConstPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_privatekey_agree');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(privateConstPtr);
      calloc.free(publicConstPtr);
    }
  }

  /// Creates a copy of this private key.
  ///
  /// The returned key is independent and must be disposed separately.
  PrivateKey clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPrivateKey>();
    final constPtr = calloc<SignalConstPointerPrivateKey>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_privatekey_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_privatekey_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_privatekey_clone');
      }

      return PrivateKey._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer to the native private key.
  ///
  /// This is intended for internal use by other libsignal classes.
  Pointer<SignalPrivateKey> get pointer {
    _checkDisposed();
    return _ptr;
  }

  /// Checks if this key has been disposed.
  void _checkDisposed() {
    if (_disposed) {
      throw StateError('PrivateKey has been disposed');
    }
  }

  /// Checks if this key has been disposed (public version for internal use).
  ///
  /// Throws [StateError] if the key has been disposed.
  void checkNotDisposed() => _checkDisposed();

  /// Releases the native resources associated with this key.
  ///
  /// After calling dispose, this key can no longer be used.
  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _privateKeyFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerPrivateKey>();
      mutPtr.ref.raw = _ptr;
      signal_privatekey_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  /// Whether this key has been disposed.
  bool get isDisposed => _disposed;
}
