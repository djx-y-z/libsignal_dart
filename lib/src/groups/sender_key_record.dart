/// Sender key record for Signal Protocol group messaging.
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

/// Finalizer for SenderKeyRecord.
final Finalizer<Pointer<SignalSenderKeyRecord>> _senderKeyRecordFinalizer =
    Finalizer((ptr) {
      final mutPtr = calloc<SignalMutPointerSenderKeyRecord>();
      mutPtr.ref.raw = ptr;
      signal_sender_key_record_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    });

/// A sender key record for group messaging.
///
/// Sender key records contain the cryptographic state needed for
/// sending and receiving group messages. Each group member maintains
/// sender key records for other group members.
final class SenderKeyRecord {
  final Pointer<SignalSenderKeyRecord> _ptr;
  bool _disposed = false;

  SenderKeyRecord._(this._ptr) {
    _senderKeyRecordFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a SenderKeyRecord from a raw pointer.
  factory SenderKeyRecord.fromPointer(Pointer<SignalSenderKeyRecord> ptr) {
    return SenderKeyRecord._(ptr);
  }

  /// Deserializes a sender key record from bytes.
  static SenderKeyRecord deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Pre-validate to prevent native crashes on invalid data
    SerializationValidator.validateSenderKeyRecord(data);

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerSenderKeyRecord>();

    try {
      final error = signal_sender_key_record_deserialize(outPtr, buffer.ref);
      FfiHelpers.checkError(error, 'signal_sender_key_record_deserialize');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_sender_key_record_deserialize',
        );
      }

      return SenderKeyRecord._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes the sender key record to bytes.
  ///
  /// **Security Note:** The returned data contains sensitive key material.
  /// The caller is responsible for securely zeroing the data after use.
  /// Use [LibSignalUtils.zeroBytes] for secure cleanup:
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
    final constPtr = calloc<SignalConstPointerSenderKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_key_record_serialize(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_sender_key_record_serialize');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Creates a copy of this sender key record.
  SenderKeyRecord clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerSenderKeyRecord>();
    final constPtr = calloc<SignalConstPointerSenderKeyRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_key_record_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_sender_key_record_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_sender_key_record_clone');
      }

      return SenderKeyRecord._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalSenderKeyRecord> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('SenderKeyRecord');
    }
  }

  /// Releases the native resources.
  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _senderKeyRecordFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerSenderKeyRecord>();
      mutPtr.ref.raw = _ptr;
      signal_sender_key_record_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  /// Whether this record has been disposed.
  bool get isDisposed => _disposed;
}
