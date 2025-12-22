/// Signed pre-key record for Signal Protocol.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../keys/private_key.dart';
import '../keys/public_key.dart';
import '../libsignal.dart';
import '../serialization_validator.dart';

/// Finalizer for SignedPreKeyRecord.
final Finalizer<Pointer<SignalSignedPreKeyRecord>>
    _signedPreKeyRecordFinalizer = Finalizer((ptr) {
  final mutPtr = calloc<SignalMutPointerSignedPreKeyRecord>();
  mutPtr.ref.raw = ptr;
  signal_signed_pre_key_record_destroy(mutPtr.ref);
  calloc.free(mutPtr);
});

/// A signed pre-key record for Signal Protocol.
///
/// Signed pre-keys are medium-term keys signed by the identity key.
/// They are rotated periodically (e.g., weekly) and allow verification
/// of the pre-key bundle's authenticity.
///
/// Example:
/// ```dart
/// final privateKey = PrivateKey.generate();
/// final publicKey = privateKey.getPublicKey();
/// final signature = identityKey.sign(publicKey.serialize());
/// final signedPreKey = SignedPreKeyRecord.create(
///   id: 1,
///   timestamp: DateTime.now().millisecondsSinceEpoch,
///   publicKey: publicKey,
///   privateKey: privateKey,
///   signature: signature,
/// );
/// signedPreKey.dispose();
/// ```
final class SignedPreKeyRecord {
  final Pointer<SignalSignedPreKeyRecord> _ptr;
  bool _disposed = false;

  SignedPreKeyRecord._(this._ptr) {
    _signedPreKeyRecordFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a SignedPreKeyRecord from a raw pointer.
  factory SignedPreKeyRecord.fromPointer(Pointer<SignalSignedPreKeyRecord> ptr) {
    return SignedPreKeyRecord._(ptr);
  }

  /// Creates a new signed pre-key record.
  ///
  /// The [id] is a unique identifier for this signed pre-key.
  /// The [timestamp] is the creation time (milliseconds since epoch).
  /// The [publicKey] and [privateKey] form the key pair.
  /// The [signature] is the identity key's signature over the public key.
  static SignedPreKeyRecord create({
    required int id,
    required int timestamp,
    required PublicKey publicKey,
    required PrivateKey privateKey,
    required Uint8List signature,
  }) {
    LibSignal.ensureInitialized();

    final outPtr = calloc<SignalMutPointerSignedPreKeyRecord>();
    final pubKeyPtr = calloc<SignalConstPointerPublicKey>();
    pubKeyPtr.ref.raw = publicKey.pointer;

    final privKeyPtr = calloc<SignalConstPointerPrivateKey>();
    privKeyPtr.ref.raw = privateKey.pointer;

    final sigPtr = calloc<Uint8>(signature.length);
    if (signature.isNotEmpty) {
      sigPtr.asTypedList(signature.length).setAll(0, signature);
    }

    final sigBuffer = calloc<SignalBorrowedBuffer>();
    sigBuffer.ref.base = sigPtr.cast<UnsignedChar>();
    sigBuffer.ref.length = signature.length;

    try {
      final error = signal_signed_pre_key_record_new(
        outPtr,
        id,
        timestamp,
        pubKeyPtr.ref,
        privKeyPtr.ref,
        sigBuffer.ref,
      );
      FfiHelpers.checkError(error, 'signal_signed_pre_key_record_new');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_signed_pre_key_record_new');
      }

      return SignedPreKeyRecord._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(pubKeyPtr);
      calloc.free(privKeyPtr);
      calloc.free(sigPtr);
      calloc.free(sigBuffer);
    }
  }

  /// Deserializes a signed pre-key record from bytes.
  static SignedPreKeyRecord deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Pre-validate to prevent native crashes on invalid data
    SerializationValidator.validateSignedPreKeyRecord(data);

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerSignedPreKeyRecord>();

    try {
      final error = signal_signed_pre_key_record_deserialize(
        outPtr,
        buffer.ref,
      );
      FfiHelpers.checkError(error, 'signal_signed_pre_key_record_deserialize');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_signed_pre_key_record_deserialize',
        );
      }

      return SignedPreKeyRecord._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes the signed pre-key record to bytes.
  Uint8List serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerSignedPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_signed_pre_key_record_serialize(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_signed_pre_key_record_serialize');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the unique identifier of this signed pre-key.
  int get id {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerSignedPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_signed_pre_key_record_get_id(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_signed_pre_key_record_get_id');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the timestamp (milliseconds since epoch) of this signed pre-key.
  int get timestamp {
    _checkDisposed();

    final outPtr = calloc<Uint64>();
    final constPtr = calloc<SignalConstPointerSignedPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_signed_pre_key_record_get_timestamp(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_signed_pre_key_record_get_timestamp');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the signature of this signed pre-key.
  Uint8List get signature {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerSignedPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_signed_pre_key_record_get_signature(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_signed_pre_key_record_get_signature');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the public key of this signed pre-key.
  PublicKey getPublicKey() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPublicKey>();
    final constPtr = calloc<SignalConstPointerSignedPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_signed_pre_key_record_get_public_key(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_signed_pre_key_record_get_public_key',
      );

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_signed_pre_key_record_get_public_key',
        );
      }

      return PublicKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the private key of this signed pre-key.
  PrivateKey getPrivateKey() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPrivateKey>();
    final constPtr = calloc<SignalConstPointerSignedPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_signed_pre_key_record_get_private_key(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_signed_pre_key_record_get_private_key',
      );

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_signed_pre_key_record_get_private_key',
        );
      }

      return PrivateKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Creates a copy of this signed pre-key record.
  SignedPreKeyRecord clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerSignedPreKeyRecord>();
    final constPtr = calloc<SignalConstPointerSignedPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_signed_pre_key_record_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_signed_pre_key_record_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_signed_pre_key_record_clone',
        );
      }

      return SignedPreKeyRecord._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalSignedPreKeyRecord> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw StateError('SignedPreKeyRecord has been disposed');
    }
  }

  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _signedPreKeyRecordFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerSignedPreKeyRecord>();
      mutPtr.ref.raw = _ptr;
      signal_signed_pre_key_record_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  bool get isDisposed => _disposed;
}
