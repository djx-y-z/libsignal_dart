/// Identity key pair for Signal Protocol.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../libsignal.dart';
import '../secure_bytes.dart';
import '../utils.dart';
import 'private_key.dart';
import 'public_key.dart';

/// Protobuf wire types and field tags for IdentityKeyPair serialization.
///
/// Format:
/// - Field 1 (tag 0x0a): PublicKey (length-delimited, 33 bytes)
/// - Field 2 (tag 0x12): PrivateKey (length-delimited, 32 bytes)
const int _kPublicKeyFieldTag = 0x0a; // field 1, wire type 2
const int _kPrivateKeyFieldTag = 0x12; // field 2, wire type 2
const int _kPublicKeyLength = 33;
const int _kPrivateKeyLength = 32;

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
  /// The [data] should be a 69-byte serialized identity key pair in protobuf
  /// format (as encoded by [serialize]).
  ///
  /// Throws [LibSignalException] if the data is invalid.
  ///
  /// **Security Note:** The [data] parameter contains sensitive private key
  /// material. The caller is responsible for securely zeroing [data] after
  /// this method returns. Use [LibSignalUtils.zeroBytes] for secure cleanup:
  ///
  /// ```dart
  /// final serializedKeyPair = loadFromSecureStorage();
  /// try {
  ///   final keyPair = IdentityKeyPair.deserialize(serializedKeyPair);
  ///   // Use keyPair...
  /// } finally {
  ///   LibSignalUtils.zeroBytes(serializedKeyPair);
  /// }
  /// ```
  static IdentityKeyPair deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Validate minimum structure
    // Expected: 1 + 1 + 33 + 1 + 1 + 32 = 69 bytes
    const expectedLength =
        1 + 1 + _kPublicKeyLength + 1 + 1 + _kPrivateKeyLength;

    if (data.isEmpty) {
      throw LibSignalException.invalidArgument(
        'identityKeyPair',
        'Cannot be empty',
      );
    }

    if (data.length != expectedLength) {
      throw LibSignalException.invalidArgument(
        'identityKeyPair',
        'Invalid length: expected $expectedLength bytes, got ${data.length}',
      );
    }

    // Parse protobuf structure manually.
    //
    // TODO(libsignal): Remove this workaround when signal_identitykeypair_deserialize
    // is fixed in a future libsignal version. Currently (v0.86.9) it causes SEGFAULT
    // even on valid data. See docs/NATIVE_CRASH_ISOLATION.md for details.
    //
    // We parse the protobuf format and deserialize the keys separately using
    // signal_publickey_deserialize and signal_privatekey_deserialize which work correctly.
    //
    // Format:
    //   0x0a 0x21 <33 bytes public key>   (field 1, length 33)
    //   0x12 0x20 <32 bytes private key>  (field 2, length 32)

    var offset = 0;

    // Field 1: Public Key
    if (data[offset] != _kPublicKeyFieldTag) {
      throw LibSignalException.invalidArgument(
        'identityKeyPair',
        'Invalid format: expected public key field tag 0x0a, '
            'got 0x${data[offset].toRadixString(16)}',
      );
    }
    offset++;

    if (data[offset] != _kPublicKeyLength) {
      throw LibSignalException.invalidArgument(
        'identityKeyPair',
        'Invalid format: expected public key length $_kPublicKeyLength, '
            'got ${data[offset]}',
      );
    }
    offset++;

    // Bounds check before sublistView
    if (offset + _kPublicKeyLength > data.length) {
      throw LibSignalException.invalidArgument(
        'identityKeyPair',
        'Buffer overrun: public key extends beyond data',
      );
    }
    final publicKeyBytes = Uint8List.sublistView(
      data,
      offset,
      offset + _kPublicKeyLength,
    );
    offset += _kPublicKeyLength;

    // Field 2: Private Key
    if (data[offset] != _kPrivateKeyFieldTag) {
      throw LibSignalException.invalidArgument(
        'identityKeyPair',
        'Invalid format: expected private key field tag 0x12, '
            'got 0x${data[offset].toRadixString(16)}',
      );
    }
    offset++;

    if (data[offset] != _kPrivateKeyLength) {
      throw LibSignalException.invalidArgument(
        'identityKeyPair',
        'Invalid format: expected private key length $_kPrivateKeyLength, '
            'got ${data[offset]}',
      );
    }
    offset++;

    // Bounds check before sublistView
    if (offset + _kPrivateKeyLength > data.length) {
      throw LibSignalException.invalidArgument(
        'identityKeyPair',
        'Buffer overrun: private key extends beyond data',
      );
    }
    final privateKeyBytes = Uint8List.sublistView(
      data,
      offset,
      offset + _kPrivateKeyLength,
    );

    // Deserialize keys using their individual deserialize methods
    // (which work correctly, unlike signal_identitykeypair_deserialize)
    final publicKey = PublicKey.deserialize(publicKeyBytes);

    PrivateKey privateKey;
    try {
      privateKey = PrivateKey.deserialize(privateKeyBytes);
    } catch (e) {
      // Clean up public key if private key deserialization fails
      publicKey.dispose();
      rethrow;
    }

    return IdentityKeyPair._(privateKey, publicKey);
  }

  /// Serializes the identity key pair to bytes.
  ///
  /// Returns a [SecureBytes] containing a serialized representation that
  /// can be restored with [deserialize]. The caller MUST call
  /// [SecureBytes.dispose] when done to securely zero the memory.
  ///
  /// Example:
  /// ```dart
  /// final keyPairBytes = identityKeyPair.serialize();
  /// try {
  ///   saveToSecureStorage(keyPairBytes.bytes);
  /// } finally {
  ///   keyPairBytes.dispose(); // Securely zeros the memory
  /// }
  /// ```
  SecureBytes serialize() {
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

      return SecureBytes(FfiHelpers.fromOwnedBuffer(outPtr.ref));
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
      throw LibSignalException.disposed('IdentityKeyPair');
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
