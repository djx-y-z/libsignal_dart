/// Session record for Signal Protocol.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../keys/public_key.dart';
import '../libsignal.dart';
import '../serialization_validator.dart';

/// Finalizer for SessionRecord.
final Finalizer<Pointer<SignalSessionRecord>> _sessionRecordFinalizer =
    Finalizer((ptr) {
  final mutPtr = calloc<SignalMutPointerSessionRecord>();
  mutPtr.ref.raw = ptr;
  signal_session_record_destroy(mutPtr.ref);
  calloc.free(mutPtr);
});

/// A session record containing the state of a Signal Protocol session.
///
/// Session records store the cryptographic state needed for encrypting
/// and decrypting messages. They include the ratchet keys, chain keys,
/// and message keys used by the Double Ratchet algorithm.
///
/// Session records are stored by the [SessionStore] implementation.
final class SessionRecord {
  final Pointer<SignalSessionRecord> _ptr;
  bool _disposed = false;

  SessionRecord._(this._ptr) {
    _sessionRecordFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a SessionRecord from a raw pointer.
  factory SessionRecord.fromPointer(Pointer<SignalSessionRecord> ptr) {
    return SessionRecord._(ptr);
  }

  /// Deserializes a session record from bytes.
  static SessionRecord deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Pre-validate to prevent native crashes on invalid data
    SerializationValidator.validateSessionRecord(data);

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerSessionRecord>();

    try {
      final error = signal_session_record_deserialize(outPtr, buffer.ref);
      FfiHelpers.checkError(error, 'signal_session_record_deserialize');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_session_record_deserialize',
        );
      }

      return SessionRecord._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes the session record to bytes.
  Uint8List serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerSessionRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_session_record_serialize(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_session_record_serialize');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Archives the current session state.
  ///
  /// This moves the current session state to the list of previous states,
  /// allowing a new session to be established while preserving the ability
  /// to decrypt late-arriving messages from the old session.
  void archiveCurrentState() {
    _checkDisposed();

    final mutPtr = calloc<SignalMutPointerSessionRecord>();
    mutPtr.ref.raw = _ptr;

    try {
      final error = signal_session_record_archive_current_state(mutPtr.ref);
      FfiHelpers.checkError(error, 'signal_session_record_archive_current_state');
    } finally {
      calloc.free(mutPtr);
    }
  }

  /// Checks if the session has a usable sender chain.
  ///
  /// The [now] parameter is the current timestamp in seconds since epoch.
  /// A sender chain is usable if it hasn't expired.
  bool hasUsableSenderChain(int now) {
    _checkDisposed();

    final outPtr = calloc<Bool>();
    final constPtr = calloc<SignalConstPointerSessionRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_session_record_has_usable_sender_chain(
        outPtr,
        constPtr.ref,
        now,
      );
      FfiHelpers.checkError(
        error,
        'signal_session_record_has_usable_sender_chain',
      );

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Checks if the current ratchet key matches the given public key.
  bool currentRatchetKeyMatches(PublicKey key) {
    _checkDisposed();
    key.checkNotDisposed();

    final outPtr = calloc<Bool>();
    final sessionPtr = calloc<SignalConstPointerSessionRecord>();
    sessionPtr.ref.raw = _ptr;

    final keyPtr = calloc<SignalConstPointerPublicKey>();
    keyPtr.ref.raw = key.pointer;

    try {
      final error = signal_session_record_current_ratchet_key_matches(
        outPtr,
        sessionPtr.ref,
        keyPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_session_record_current_ratchet_key_matches',
      );

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(sessionPtr);
      calloc.free(keyPtr);
    }
  }

  /// Gets the local registration ID for this session.
  int get localRegistrationId {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerSessionRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_session_record_get_local_registration_id(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_session_record_get_local_registration_id',
      );

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the remote registration ID for this session.
  int get remoteRegistrationId {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerSessionRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_session_record_get_remote_registration_id(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_session_record_get_remote_registration_id',
      );

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Creates a copy of this session record.
  SessionRecord clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerSessionRecord>();
    final constPtr = calloc<SignalConstPointerSessionRecord>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_session_record_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_session_record_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_session_record_clone');
      }

      return SessionRecord._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalSessionRecord> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('SessionRecord');
    }
  }

  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _sessionRecordFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerSessionRecord>();
      mutPtr.ref.raw = _ptr;
      signal_session_record_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  bool get isDisposed => _disposed;
}
