/// Signal Protocol encrypted message (whisper message).
///
/// Represents an encrypted message in the Signal Protocol Double Ratchet.
/// Contains ciphertext body, ratchet key, counter, and optionally PQ ratchet state.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart' as ffi;
import '../exception.dart';
import '../ffi_helpers.dart';
import '../keys/public_key.dart';
import '../libsignal.dart';
import '../serialization_validator.dart';

/// Finalizer for SignalMessage native resources.
final Finalizer<Pointer<ffi.SignalMessage>> _signalMessageFinalizer = Finalizer(
  (ptr) {
    final mutPtr = calloc<ffi.SignalMutPointerSignalMessage>();
    mutPtr.ref.raw = ptr;
    ffi.signal_message_destroy(mutPtr.ref);
    calloc.free(mutPtr);
  },
);

/// An encrypted Signal Protocol message (whisper message).
///
/// This represents a message encrypted using the Double Ratchet algorithm.
/// It contains:
/// - The encrypted message body (ciphertext)
/// - The sender's current ratchet public key
/// - A message counter for replay protection and ordering
/// - The protocol version
/// - Optional PQ (Post-Quantum) ratchet state for PQXDH sessions
///
/// SignalMessage is used for ongoing communication after a session has been
/// established. For the initial message that establishes a session, see
/// PreKeySignalMessage (handled internally by SessionCipher).
///
/// Example:
/// ```dart
/// // Deserialize a received message
/// final message = SignalMessage.deserialize(receivedBytes);
///
/// // Inspect message properties
/// print('Version: ${message.messageVersion}');
/// print('Counter: ${message.counter}');
/// print('Has PQ ratchet: ${message.pqRatchet != null}');
///
/// // Get the sender's ratchet key
/// final ratchetKey = message.getSenderRatchetKey();
///
/// // Clean up
/// ratchetKey.dispose();
/// message.dispose();
/// ```
final class SignalMessage {
  final Pointer<ffi.SignalMessage> _ptr;
  bool _disposed = false;

  SignalMessage._(this._ptr) {
    _signalMessageFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a SignalMessage from a raw pointer.
  ///
  /// For internal use by other libsignal classes.
  factory SignalMessage.fromPointer(Pointer<ffi.SignalMessage> ptr) {
    return SignalMessage._(ptr);
  }

  /// Deserializes a SignalMessage from bytes.
  ///
  /// Throws [LibSignalException] if the data is invalid.
  static SignalMessage deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Pre-validate to prevent native crashes on invalid data
    SerializationValidator.validateSignalMessage(data);

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<ffi.SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<ffi.SignalMutPointerSignalMessage>();

    try {
      final error = ffi.signal_message_deserialize(outPtr, buffer.ref);
      FfiHelpers.checkError(error, 'signal_message_deserialize');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_message_deserialize');
      }

      return SignalMessage._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes the message to bytes.
  Uint8List serialize() {
    _checkDisposed();

    final outPtr = calloc<ffi.SignalOwnedBuffer>();
    final constPtr = calloc<ffi.SignalConstPointerSignalMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = ffi.signal_message_get_serialized(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_message_get_serialized');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// The encrypted message body (ciphertext).
  Uint8List get body {
    _checkDisposed();

    final outPtr = calloc<ffi.SignalOwnedBuffer>();
    final constPtr = calloc<ffi.SignalConstPointerSignalMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = ffi.signal_message_get_body(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_message_get_body');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// The message counter.
  ///
  /// Used for replay protection and message ordering within a ratchet chain.
  int get counter {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<ffi.SignalConstPointerSignalMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = ffi.signal_message_get_counter(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_message_get_counter');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// The Signal Protocol message version.
  ///
  /// Current version is 3 for standard sessions, may include
  /// additional version info for PQXDH sessions.
  int get messageVersion {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<ffi.SignalConstPointerSignalMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = ffi.signal_message_get_message_version(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_message_get_message_version');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the sender's current ratchet public key.
  ///
  /// The caller is responsible for disposing the returned [PublicKey].
  PublicKey getSenderRatchetKey() {
    _checkDisposed();

    final outPtr = calloc<ffi.SignalMutPointerPublicKey>();
    final constPtr = calloc<ffi.SignalConstPointerSignalMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = ffi.signal_message_get_sender_ratchet_key(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_message_get_sender_ratchet_key');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_message_get_sender_ratchet_key',
        );
      }

      return PublicKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// The Post-Quantum ratchet state, if present.
  ///
  /// Returns `null` if this message is not part of a PQXDH session
  /// or if the PQ ratchet is not active for this message.
  ///
  /// For PQXDH (Post-Quantum Extended Diffie-Hellman) sessions,
  /// this contains the Kyber-derived ratchet state.
  Uint8List? get pqRatchet {
    _checkDisposed();

    final outPtr = calloc<ffi.SignalOwnedBuffer>();
    final constPtr = calloc<ffi.SignalConstPointerSignalMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = ffi.signal_message_get_pq_ratchet(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_message_get_pq_ratchet');

      final buffer = outPtr.ref;
      if (buffer.base == nullptr || buffer.length == 0) {
        return null;
      }

      return FfiHelpers.fromOwnedBuffer(buffer);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Verifies the MAC on this message.
  ///
  /// Returns `true` if the MAC is valid for the given identity keys and MAC key.
  bool verifyMac(
    PublicKey senderIdentityKey,
    PublicKey receiverIdentityKey,
    Uint8List macKey,
  ) {
    _checkDisposed();
    senderIdentityKey.checkNotDisposed();
    receiverIdentityKey.checkNotDisposed();

    final outPtr = calloc<Bool>();
    final msgPtr = calloc<ffi.SignalConstPointerSignalMessage>();
    msgPtr.ref.raw = _ptr;

    final senderKeyPtr = calloc<ffi.SignalConstPointerPublicKey>();
    senderKeyPtr.ref.raw = senderIdentityKey.pointer;

    final receiverKeyPtr = calloc<ffi.SignalConstPointerPublicKey>();
    receiverKeyPtr.ref.raw = receiverIdentityKey.pointer;

    final macKeyPtr = calloc<Uint8>(macKey.length);
    if (macKey.isNotEmpty) {
      macKeyPtr.asTypedList(macKey.length).setAll(0, macKey);
    }

    final macKeyBuffer = calloc<ffi.SignalBorrowedBuffer>();
    macKeyBuffer.ref.base = macKeyPtr.cast<UnsignedChar>();
    macKeyBuffer.ref.length = macKey.length;

    try {
      final error = ffi.signal_message_verify_mac(
        outPtr,
        msgPtr.ref,
        senderKeyPtr.ref,
        receiverKeyPtr.ref,
        macKeyBuffer.ref,
      );
      FfiHelpers.checkError(error, 'signal_message_verify_mac');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(msgPtr);
      calloc.free(senderKeyPtr);
      calloc.free(receiverKeyPtr);
      calloc.free(macKeyPtr);
      calloc.free(macKeyBuffer);
    }
  }

  /// Creates a copy of this message.
  ///
  /// The caller is responsible for disposing the returned message.
  SignalMessage clone() {
    _checkDisposed();

    final outPtr = calloc<ffi.SignalMutPointerSignalMessage>();
    final constPtr = calloc<ffi.SignalConstPointerSignalMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = ffi.signal_message_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_message_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_message_clone');
      }

      return SignalMessage._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<ffi.SignalMessage> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('SignalMessage');
    }
  }

  /// Releases the native resources.
  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _signalMessageFinalizer.detach(this);

      final mutPtr = calloc<ffi.SignalMutPointerSignalMessage>();
      mutPtr.ref.raw = _ptr;
      ffi.signal_message_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  /// Whether this message has been disposed.
  bool get isDisposed => _disposed;
}
