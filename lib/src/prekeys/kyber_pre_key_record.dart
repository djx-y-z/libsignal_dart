/// Kyber pre-key record for post-quantum Signal Protocol.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../kyber/kyber_key_pair.dart';
import '../kyber/kyber_public_key.dart';
import '../kyber/kyber_secret_key.dart';
import '../libsignal.dart';
import '../serialization_validator.dart';

/// Finalizer for KyberPreKeyRecord.
final Finalizer<Pointer<SignalKyberPreKeyRecord>> _kyberPreKeyRecordFinalizer =
    Finalizer((ptr) {
  final mutPtr = calloc<SignalMutPointerKyberPreKeyRecord>();
  mutPtr.ref.raw = ptr;
  signal_kyber_pre_key_record_destroy(mutPtr.ref);
  calloc.free(mutPtr);
});

/// A Kyber pre-key record for post-quantum Signal Protocol.
///
/// Kyber pre-keys provide post-quantum security for session establishment.
/// They are used in hybrid mode together with X25519 pre-keys.
final class KyberPreKeyRecord {
  final Pointer<SignalKyberPreKeyRecord> _ptr;
  bool _disposed = false;

  KyberPreKeyRecord._(this._ptr) {
    _kyberPreKeyRecordFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a KyberPreKeyRecord from a raw pointer.
  factory KyberPreKeyRecord.fromPointer(Pointer<SignalKyberPreKeyRecord> ptr) {
    return KyberPreKeyRecord._(ptr);
  }

  /// Creates a new Kyber pre-key record.
  ///
  /// The [id] is a unique identifier for this Kyber pre-key.
  /// The [timestamp] is the creation time (milliseconds since epoch).
  /// The [keyPair] is the Kyber key pair.
  /// The [signature] is the identity key's signature over the public key.
  static KyberPreKeyRecord create({
    required int id,
    required int timestamp,
    required KyberKeyPair keyPair,
    required Uint8List signature,
  }) {
    LibSignal.ensureInitialized();
    keyPair.checkNotDisposed();

    final outPtr = calloc<SignalMutPointerKyberPreKeyRecord>();
    final keyPairPtr = calloc<SignalConstPointerKyberKeyPair>();
    keyPairPtr.ref.raw = keyPair.pointer;

    final sigPtr = calloc<Uint8>(signature.length);
    if (signature.isNotEmpty) {
      sigPtr.asTypedList(signature.length).setAll(0, signature);
    }

    final sigBuffer = calloc<SignalBorrowedBuffer>();
    sigBuffer.ref.base = sigPtr.cast<UnsignedChar>();
    sigBuffer.ref.length = signature.length;

    try {
      final error = signal_kyber_pre_key_record_new(
        outPtr,
        id,
        timestamp,
        keyPairPtr.ref,
        sigBuffer.ref,
      );
      FfiHelpers.checkError(error, 'signal_kyber_pre_key_record_new');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_kyber_pre_key_record_new');
      }

      return KyberPreKeyRecord._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(keyPairPtr);
      calloc.free(sigPtr);
      calloc.free(sigBuffer);
    }
  }

  /// Deserializes a Kyber pre-key record from bytes.
  static KyberPreKeyRecord deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Pre-validate to prevent native crashes on invalid data
    SerializationValidator.validateKyberPreKeyRecord(data);

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerKyberPreKeyRecord>();

    try {
      final error = signal_kyber_pre_key_record_deserialize(outPtr, buffer.ref);
      FfiHelpers.checkError(error, 'signal_kyber_pre_key_record_deserialize');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_kyber_pre_key_record_deserialize',
        );
      }

      return KyberPreKeyRecord._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes the Kyber pre-key record to bytes.
  Uint8List serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerKyberPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_pre_key_record_serialize(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_kyber_pre_key_record_serialize');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the unique identifier of this Kyber pre-key.
  int get id {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerKyberPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_pre_key_record_get_id(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_kyber_pre_key_record_get_id');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the timestamp (milliseconds since epoch) of this Kyber pre-key.
  int get timestamp {
    _checkDisposed();

    final outPtr = calloc<Uint64>();
    final constPtr = calloc<SignalConstPointerKyberPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_pre_key_record_get_timestamp(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_kyber_pre_key_record_get_timestamp');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the signature of this Kyber pre-key.
  Uint8List get signature {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerKyberPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_pre_key_record_get_signature(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_kyber_pre_key_record_get_signature');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the public key of this Kyber pre-key.
  KyberPublicKey getPublicKey() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerKyberPublicKey>();
    final constPtr = calloc<SignalConstPointerKyberPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_pre_key_record_get_public_key(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_kyber_pre_key_record_get_public_key');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_kyber_pre_key_record_get_public_key',
        );
      }

      return KyberPublicKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the secret key of this Kyber pre-key.
  KyberSecretKey getSecretKey() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerKyberSecretKey>();
    final constPtr = calloc<SignalConstPointerKyberPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_pre_key_record_get_secret_key(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_kyber_pre_key_record_get_secret_key');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_kyber_pre_key_record_get_secret_key',
        );
      }

      return KyberSecretKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the key pair of this Kyber pre-key.
  KyberKeyPair getKeyPair() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerKyberKeyPair>();
    final constPtr = calloc<SignalConstPointerKyberPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_pre_key_record_get_key_pair(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_kyber_pre_key_record_get_key_pair');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_kyber_pre_key_record_get_key_pair',
        );
      }

      return KyberKeyPair.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Creates a copy of this Kyber pre-key record.
  KyberPreKeyRecord clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerKyberPreKeyRecord>();
    final constPtr = calloc<SignalConstPointerKyberPreKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_kyber_pre_key_record_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_kyber_pre_key_record_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_kyber_pre_key_record_clone',
        );
      }

      return KyberPreKeyRecord._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalKyberPreKeyRecord> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('KyberPreKeyRecord');
    }
  }

  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _kyberPreKeyRecordFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerKyberPreKeyRecord>();
      mutPtr.ref.raw = _ptr;
      signal_kyber_pre_key_record_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  bool get isDisposed => _disposed;
}
