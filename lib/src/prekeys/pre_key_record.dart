/// Pre-key record for Signal Protocol.
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
import '../utils.dart';

/// Finalizer for PreKeyRecord.
final Finalizer<Pointer<SignalPreKeyRecord>> _preKeyRecordFinalizer = Finalizer(
  (ptr) {
    final mutPtr = calloc<SignalMutPointerPreKeyRecord>();
    mutPtr.ref.raw = ptr;
    signal_pre_key_record_destroy(mutPtr.ref);
    calloc.free(mutPtr);
  },
);

/// A pre-key record for Signal Protocol session establishment.
///
/// Pre-keys are one-time use keys that allow establishing a session
/// without requiring both parties to be online simultaneously.
///
/// Example:
/// ```dart
/// final privateKey = PrivateKey.generate();
/// final publicKey = privateKey.getPublicKey();
/// final preKey = PreKeyRecord.create(id: 1, publicKey: publicKey, privateKey: privateKey);
/// preKey.dispose();
/// ```
final class PreKeyRecord {
  final Pointer<SignalPreKeyRecord> _ptr;
  bool _disposed = false;

  PreKeyRecord._(this._ptr) {
    _preKeyRecordFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a PreKeyRecord from a raw pointer.
  factory PreKeyRecord.fromPointer(Pointer<SignalPreKeyRecord> ptr) {
    return PreKeyRecord._(ptr);
  }

  /// Creates a new pre-key record.
  ///
  /// The [id] is a unique identifier for this pre-key.
  /// The [publicKey] and [privateKey] form the key pair.
  static PreKeyRecord create({
    required int id,
    required PublicKey publicKey,
    required PrivateKey privateKey,
  }) {
    LibSignal.ensureInitialized();
    publicKey.checkNotDisposed();
    privateKey.checkNotDisposed();

    final outPtr = calloc<SignalMutPointerPreKeyRecord>();
    final pubKeyPtr = calloc<SignalConstPointerPublicKey>();
    pubKeyPtr.ref.raw = publicKey.pointer;

    final privKeyPtr = calloc<SignalConstPointerPrivateKey>();
    privKeyPtr.ref.raw = privateKey.pointer;

    try {
      final error = signal_pre_key_record_new(
        outPtr,
        id,
        pubKeyPtr.ref,
        privKeyPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_pre_key_record_new');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_pre_key_record_new');
      }

      return PreKeyRecord._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(pubKeyPtr);
      calloc.free(privKeyPtr);
    }
  }

  /// Deserializes a pre-key record from bytes.
  static PreKeyRecord deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Pre-validate to prevent native crashes on invalid data
    SerializationValidator.validatePreKeyRecord(data);

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerPreKeyRecord>();

    try {
      final error = signal_pre_key_record_deserialize(outPtr, buffer.ref);
      FfiHelpers.checkError(error, 'signal_pre_key_record_deserialize');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_pre_key_record_deserialize',
        );
      }

      return PreKeyRecord._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes the pre-key record to bytes.
  ///
  /// **Security Note:** The returned data contains sensitive private key
  /// material. The caller is responsible for securely zeroing the data after
  /// use. Use [LibSignalUtils.zeroBytes] for secure cleanup:
  ///
  /// ```dart
  /// final serialized = record.serialize();
  /// try {
  ///   // Store or transmit serialized
  /// } finally {
  ///   LibSignalUtils.zeroBytes(serialized);
  /// }
  /// ```
  Uint8List serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_record_serialize(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_pre_key_record_serialize');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the unique identifier of this pre-key.
  int get id {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_record_get_id(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_pre_key_record_get_id');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the public key of this pre-key.
  PublicKey getPublicKey() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPublicKey>();
    final constPtr = calloc<SignalConstPointerPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_record_get_public_key(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_pre_key_record_get_public_key');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_pre_key_record_get_public_key',
        );
      }

      return PublicKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the private key of this pre-key.
  PrivateKey getPrivateKey() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPrivateKey>();
    final constPtr = calloc<SignalConstPointerPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_record_get_private_key(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_pre_key_record_get_private_key');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_pre_key_record_get_private_key',
        );
      }

      return PrivateKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Creates a copy of this pre-key record.
  PreKeyRecord clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPreKeyRecord>();
    final constPtr = calloc<SignalConstPointerPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_record_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_pre_key_record_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_pre_key_record_clone');
      }

      return PreKeyRecord._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalPreKeyRecord> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('PreKeyRecord');
    }
  }

  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _preKeyRecordFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerPreKeyRecord>();
      mutPtr.ref.raw = _ptr;
      signal_pre_key_record_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  bool get isDisposed => _disposed;
}
