/// Sender key message for Signal Protocol group messaging.
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

/// Finalizer for SenderKeyMessage.
///
/// Safety net for undisposed objects. GC-dependent, cannot be tested.
// coverage:ignore-start
final Finalizer<Pointer<SignalSenderKeyMessage>> _senderKeyMessageFinalizer =
    Finalizer((ptr) {
      final mutPtr = calloc<SignalMutPointerSenderKeyMessage>();
      mutPtr.ref.raw = ptr;
      signal_sender_key_message_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    });
// coverage:ignore-end

/// A sender key message for group messaging.
///
/// These messages are encrypted using the sender's chain key and can
/// be decrypted by any group member who has received the corresponding
/// sender key distribution message.
final class SenderKeyMessage {
  final Pointer<SignalSenderKeyMessage> _ptr;
  bool _disposed = false;

  SenderKeyMessage._(this._ptr) {
    _senderKeyMessageFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a SenderKeyMessage from a raw pointer.
  factory SenderKeyMessage.fromPointer(Pointer<SignalSenderKeyMessage> ptr) {
    return SenderKeyMessage._(ptr); // coverage:ignore-line
  }

  /// Deserializes a sender key message from bytes.
  static SenderKeyMessage deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Pre-validate to prevent native crashes on invalid data
    SerializationValidator.validateSenderKeyMessage(data);

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerSenderKeyMessage>();

    try {
      final error = signal_sender_key_message_deserialize(outPtr, buffer.ref);
      FfiHelpers.checkError(error, 'signal_sender_key_message_deserialize');

      // coverage:ignore-start
      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_sender_key_message_deserialize',
        );
      }
      // coverage:ignore-end

      return SenderKeyMessage._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes the sender key message to bytes.
  Uint8List serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerSenderKeyMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_key_message_serialize(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_sender_key_message_serialize');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the ciphertext portion of this message.
  Uint8List get cipherText {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerSenderKeyMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_key_message_get_cipher_text(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_sender_key_message_get_cipher_text');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the distribution ID (UUID) for this message.
  Uint8List get distributionId {
    _checkDisposed();

    final outPtr = calloc<SignalUuid>();
    final constPtr = calloc<SignalConstPointerSenderKeyMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_key_message_get_distribution_id(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_sender_key_message_get_distribution_id',
      );

      // Copy UUID (16 bytes) from the struct
      final result = Uint8List(16);
      for (var i = 0; i < 16; i++) {
        result[i] = outPtr.ref.bytes[i];
      }
      return result;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the chain ID for this message.
  int get chainId {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerSenderKeyMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_key_message_get_chain_id(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_sender_key_message_get_chain_id');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the iteration (message counter) for this message.
  int get iteration {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerSenderKeyMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_key_message_get_iteration(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_sender_key_message_get_iteration');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Verifies the signature on this message using the given public key.
  ///
  /// Returns `true` if the signature is valid, `false` otherwise.
  bool verifySignature(PublicKey publicKey) {
    _checkDisposed();
    publicKey.checkNotDisposed();

    final outPtr = calloc<Bool>();
    final msgPtr = calloc<SignalConstPointerSenderKeyMessage>();
    msgPtr.ref.raw = _ptr;

    final keyPtr = calloc<SignalConstPointerPublicKey>();
    keyPtr.ref.raw = publicKey.pointer;

    try {
      final error = signal_sender_key_message_verify_signature(
        outPtr,
        msgPtr.ref,
        keyPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_sender_key_message_verify_signature',
      );

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(msgPtr);
      calloc.free(keyPtr);
    }
  }

  /// Creates a copy of this sender key message.
  SenderKeyMessage clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerSenderKeyMessage>();
    final constPtr = calloc<SignalConstPointerSenderKeyMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_key_message_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_sender_key_message_clone');

      // coverage:ignore-start
      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_sender_key_message_clone');
      }
      // coverage:ignore-end

      return SenderKeyMessage._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalSenderKeyMessage> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('SenderKeyMessage');
    }
  }

  /// Releases the native resources.
  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _senderKeyMessageFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerSenderKeyMessage>();
      mutPtr.ref.raw = _ptr;
      signal_sender_key_message_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  /// Whether this message has been disposed.
  bool get isDisposed => _disposed;
}
