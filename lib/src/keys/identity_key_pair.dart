/// Identity key pair for Signal Protocol.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../libsignal.dart';
import 'private_key.dart';
import 'public_key.dart';

/// An identity key pair for Signal Protocol.
///
/// The identity key pair is the long-term key pair that identifies
/// a Signal Protocol participant. It consists of a private key for
/// signing and a public key for identity verification.
///
/// Example:
/// ```dart
/// final identity = IdentityKeyPair.generate();
/// final publicKey = identity.publicKey;
/// final serialized = identity.serialize();
/// identity.dispose();
/// ```
final class IdentityKeyPair {
  final PrivateKey _privateKey;
  final PublicKey _publicKey;
  bool _disposed = false;

  IdentityKeyPair._(this._privateKey, this._publicKey);

  /// Generates a new random identity key pair.
  ///
  /// Uses cryptographically secure random number generation.
  factory IdentityKeyPair.generate() {
    LibSignal.ensureInitialized();

    final privateKey = PrivateKey.generate();
    final publicKey = privateKey.getPublicKey();

    return IdentityKeyPair._(privateKey, publicKey);
  }

  /// Creates an identity key pair from existing keys.
  ///
  /// Takes ownership of the provided keys. Do not use or dispose
  /// the keys after passing them to this constructor.
  factory IdentityKeyPair.fromKeys(PrivateKey privateKey, PublicKey publicKey) {
    return IdentityKeyPair._(privateKey, publicKey);
  }

  /// Deserializes an identity key pair from bytes.
  ///
  /// The [data] should be a 64-byte serialized identity key pair
  /// (32 bytes public key + 32 bytes private key, or as encoded by serialize).
  ///
  /// Throws [LibSignalException] if the data is invalid.
  static IdentityKeyPair deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    if (data.isEmpty) {
      throw LibSignalException.invalidArgument('data', 'Cannot be empty');
    }

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr =
        calloc<SignalPairOfMutPointerPublicKeyMutPointerPrivateKey>();

    try {
      final error = signal_identitykeypair_deserialize(
        outPtr,
        buffer.ref,
      );
      FfiHelpers.checkError(error, 'signal_identitykeypair_deserialize');

      if (outPtr.ref.second.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_identitykeypair_deserialize (private key)',
        );
      }

      if (outPtr.ref.first.raw == nullptr) {
        // Clean up private key if public key failed
        final mutPtr = calloc<SignalMutPointerPrivateKey>();
        mutPtr.ref.raw = outPtr.ref.second.raw;
        signal_privatekey_destroy(mutPtr.ref);
        calloc.free(mutPtr);

        throw LibSignalException.nullPointer(
          'signal_identitykeypair_deserialize (public key)',
        );
      }

      // Create wrapper objects that take ownership
      // Note: first = PublicKey, second = PrivateKey
      final privateKey = PrivateKey.fromPointer(outPtr.ref.second.raw);
      final publicKey = PublicKey.fromPointer(outPtr.ref.first.raw);

      return IdentityKeyPair._(privateKey, publicKey);
    } finally {
      // Secure clear the key data
      for (var i = 0; i < data.length; i++) {
        dataPtr[i] = 0;
      }
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes the identity key pair to bytes.
  ///
  /// Returns a serialized representation that can be restored
  /// with [deserialize].
  ///
  /// **Security note**: The returned bytes contain sensitive key material.
  /// Ensure they are securely handled and cleared when no longer needed.
  Uint8List serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final publicConstPtr = calloc<SignalConstPointerPublicKey>();
    publicConstPtr.ref.raw = _publicKey.pointer;

    final privateConstPtr = calloc<SignalConstPointerPrivateKey>();
    privateConstPtr.ref.raw = _privateKey.pointer;

    try {
      final error = signal_identitykeypair_serialize(
        outPtr,
        publicConstPtr.ref,
        privateConstPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_identitykeypair_serialize');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(publicConstPtr);
      calloc.free(privateConstPtr);
    }
  }

  /// Signs an alternate identity key.
  ///
  /// This is used in the multi-device protocol to link devices.
  Uint8List signAlternateIdentity(PublicKey other) {
    _checkDisposed();
    other.checkNotDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final publicConstPtr = calloc<SignalConstPointerPublicKey>();
    publicConstPtr.ref.raw = _publicKey.pointer;

    final privateConstPtr = calloc<SignalConstPointerPrivateKey>();
    privateConstPtr.ref.raw = _privateKey.pointer;

    final otherConstPtr = calloc<SignalConstPointerPublicKey>();
    otherConstPtr.ref.raw = other.pointer;

    try {
      final error = signal_identitykeypair_sign_alternate_identity(
        outPtr,
        publicConstPtr.ref,
        privateConstPtr.ref,
        otherConstPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_identitykeypair_sign_alternate_identity',
      );

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(publicConstPtr);
      calloc.free(privateConstPtr);
      calloc.free(otherConstPtr);
    }
  }

  /// The private key of this identity.
  PrivateKey get privateKey {
    _checkDisposed();
    return _privateKey;
  }

  /// The public key of this identity.
  PublicKey get publicKey {
    _checkDisposed();
    return _publicKey;
  }

  /// Checks if this key pair has been disposed.
  void _checkDisposed() {
    if (_disposed) {
      throw StateError('IdentityKeyPair has been disposed');
    }
  }

  /// Releases the native resources associated with this key pair.
  ///
  /// This also disposes both the private and public keys.
  /// After calling dispose, this key pair can no longer be used.
  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _privateKey.dispose();
      _publicKey.dispose();
    }
  }

  /// Whether this key pair has been disposed.
  bool get isDisposed => _disposed;
}
