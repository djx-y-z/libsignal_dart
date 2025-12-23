/// Public key for Signal Protocol cryptographic operations.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../libsignal.dart';
import '../serialization_validator.dart';
import '../utils.dart';

/// Weak reference tracking for finalizer.
final Finalizer<Pointer<SignalPublicKey>> _publicKeyFinalizer = Finalizer(
  (ptr) {
    final mutPtr = calloc<SignalMutPointerPublicKey>();
    mutPtr.ref.raw = ptr;
    signal_publickey_destroy(mutPtr.ref);
    calloc.free(mutPtr);
  },
);

/// A public key for Signal Protocol operations.
///
/// Used for verifying signatures, key agreement (ECDH), and as part of
/// identity keys, pre-keys, and other protocol components.
///
/// Public keys use the X25519/Ed25519 curve.
///
/// Example:
/// ```dart
/// final publicKey = PublicKey.deserialize(bytes);
/// final isValid = publicKey.verify(message, signature);
/// publicKey.dispose();
/// ```
final class PublicKey {
  final Pointer<SignalPublicKey> _ptr;
  bool _disposed = false;

  PublicKey._(this._ptr) {
    _publicKeyFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a PublicKey from a raw pointer.
  ///
  /// This is intended for internal use by other libsignal classes.
  factory PublicKey.fromPointer(Pointer<SignalPublicKey> ptr) {
    return PublicKey._(ptr);
  }

  /// Deserializes a public key from bytes.
  ///
  /// The [data] should be a 33-byte serialized public key
  /// (1 byte type prefix + 32 bytes key).
  ///
  /// Throws [LibSignalException] if the data is invalid.
  static PublicKey deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Pre-validate to prevent native crashes on invalid data
    SerializationValidator.validatePublicKey(data);

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerPublicKey>();

    try {
      final error = signal_publickey_deserialize(outPtr, buffer.ref);
      FfiHelpers.checkError(error, 'signal_publickey_deserialize');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_publickey_deserialize');
      }

      return PublicKey._(outPtr.ref.raw);
    } finally {
      // Securely zero key data before freeing (public keys are less sensitive,
      // but consistent handling helps prevent copy-paste errors)
      LibSignalUtils.zeroBytes(dataPtr.asTypedList(data.length));
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes the public key to bytes.
  ///
  /// Returns a 33-byte representation (1 byte type prefix + 32 bytes key).
  Uint8List serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerPublicKey>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_publickey_serialize(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_publickey_serialize');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the raw public key bytes without the type prefix.
  ///
  /// Returns the 32-byte raw key material.
  Uint8List getPublicKeyBytes() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerPublicKey>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_publickey_get_public_key_bytes(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_publickey_get_public_key_bytes');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Verifies a signature against a message.
  ///
  /// Returns true if the [signature] is valid for the given [message].
  bool verify(Uint8List message, Uint8List signature) {
    _checkDisposed();

    final messagePtr = calloc<Uint8>(message.length);
    if (message.isNotEmpty) {
      messagePtr.asTypedList(message.length).setAll(0, message);
    }

    final signaturePtr = calloc<Uint8>(signature.length);
    if (signature.isNotEmpty) {
      signaturePtr.asTypedList(signature.length).setAll(0, signature);
    }

    final messageBuffer = calloc<SignalBorrowedBuffer>();
    messageBuffer.ref.base = messagePtr.cast<UnsignedChar>();
    messageBuffer.ref.length = message.length;

    final signatureBuffer = calloc<SignalBorrowedBuffer>();
    signatureBuffer.ref.base = signaturePtr.cast<UnsignedChar>();
    signatureBuffer.ref.length = signature.length;

    final outPtr = calloc<Bool>();
    final constPtr = calloc<SignalConstPointerPublicKey>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_publickey_verify(
        outPtr,
        constPtr.ref,
        messageBuffer.ref,
        signatureBuffer.ref,
      );
      FfiHelpers.checkError(error, 'signal_publickey_verify');

      return outPtr.value;
    } finally {
      // Securely zero buffers before freeing
      LibSignalUtils.zeroBytes(messagePtr.asTypedList(message.length));
      LibSignalUtils.zeroBytes(signaturePtr.asTypedList(signature.length));
      calloc.free(messagePtr);
      calloc.free(signaturePtr);
      calloc.free(messageBuffer);
      calloc.free(signatureBuffer);
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Checks if this public key equals another.
  bool equals(PublicKey other) {
    _checkDisposed();
    other._checkDisposed();

    final outPtr = calloc<Bool>();
    final lhsPtr = calloc<SignalConstPointerPublicKey>();
    lhsPtr.ref.raw = _ptr;

    final rhsPtr = calloc<SignalConstPointerPublicKey>();
    rhsPtr.ref.raw = other._ptr;

    try {
      final error = signal_publickey_equals(outPtr, lhsPtr.ref, rhsPtr.ref);
      FfiHelpers.checkError(error, 'signal_publickey_equals');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(lhsPtr);
      calloc.free(rhsPtr);
    }
  }

  /// Compares this public key with another for ordering.
  ///
  /// Returns:
  /// - negative if this < other
  /// - zero if this == other
  /// - positive if this > other
  int compare(PublicKey other) {
    _checkDisposed();
    other._checkDisposed();

    final outPtr = calloc<Int32>();
    final key1Ptr = calloc<SignalConstPointerPublicKey>();
    key1Ptr.ref.raw = _ptr;

    final key2Ptr = calloc<SignalConstPointerPublicKey>();
    key2Ptr.ref.raw = other._ptr;

    try {
      final error = signal_publickey_compare(outPtr, key1Ptr.ref, key2Ptr.ref);
      FfiHelpers.checkError(error, 'signal_publickey_compare');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(key1Ptr);
      calloc.free(key2Ptr);
    }
  }

  /// Creates a copy of this public key.
  ///
  /// The returned key is independent and must be disposed separately.
  PublicKey clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPublicKey>();
    final constPtr = calloc<SignalConstPointerPublicKey>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_publickey_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_publickey_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_publickey_clone');
      }

      return PublicKey._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer to the native public key.
  ///
  /// This is intended for internal use by other libsignal classes.
  Pointer<SignalPublicKey> get pointer {
    _checkDisposed();
    return _ptr;
  }

  /// Checks if this key has been disposed.
  void _checkDisposed() {
    if (_disposed) {
      throw StateError('PublicKey has been disposed');
    }
  }

  /// For internal use - allows other classes to check disposed state.
  void checkNotDisposed() {
    _checkDisposed();
  }

  /// Releases the native resources associated with this key.
  ///
  /// After calling dispose, this key can no longer be used.
  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _publicKeyFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerPublicKey>();
      mutPtr.ref.raw = _ptr;
      signal_publickey_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  /// Whether this key has been disposed.
  bool get isDisposed => _disposed;

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! PublicKey) return false;
    if (_disposed || other._disposed) return false;
    return equals(other);
  }

  @override
  int get hashCode {
    if (_disposed) return 0;
    // Use first few bytes of serialized key for hash
    final bytes = serialize();
    if (bytes.length < 4) return 0;
    return bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
  }
}
