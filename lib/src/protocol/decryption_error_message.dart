/// Decryption error message for Signal Protocol.
///
/// Used to notify the sender that a message could not be decrypted,
/// enabling retry mechanisms and session recovery.
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

/// Finalizer for DecryptionErrorMessage.
final Finalizer<Pointer<SignalDecryptionErrorMessage>>
_decryptionErrorMessageFinalizer = Finalizer((ptr) {
  final mutPtr = calloc<SignalMutPointerDecryptionErrorMessage>();
  mutPtr.ref.raw = ptr;
  signal_decryption_error_message_destroy(mutPtr.ref);
  calloc.free(mutPtr);
});

/// A message indicating that decryption failed.
///
/// When a message cannot be decrypted, the recipient can send a
/// [DecryptionErrorMessage] back to the sender. This allows the sender
/// to know that the message was not received and potentially retry
/// or reset the session.
///
/// Example:
/// ```dart
/// // Create an error message for a failed decryption
/// final errorMsg = DecryptionErrorMessage.forOriginalMessage(
///   originalBytes: failedMessageBytes,
///   messageType: CiphertextMessageType.whisper.value,
///   timestamp: DateTime.now().millisecondsSinceEpoch,
///   originalSenderDeviceId: 1,
/// );
///
/// // Serialize and send to the original sender
/// final serialized = errorMsg.serialize();
/// sendToOriginalSender(serialized);
///
/// errorMsg.dispose();
/// ```
final class DecryptionErrorMessage {
  final Pointer<SignalDecryptionErrorMessage> _ptr;
  bool _disposed = false;

  DecryptionErrorMessage._(this._ptr) {
    _decryptionErrorMessageFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a DecryptionErrorMessage from a raw pointer.
  factory DecryptionErrorMessage.fromPointer(
    Pointer<SignalDecryptionErrorMessage> ptr,
  ) {
    return DecryptionErrorMessage._(ptr);
  }

  /// Deserializes a decryption error message from bytes.
  ///
  /// Throws [LibSignalException] if the data is invalid.
  static DecryptionErrorMessage deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Pre-validate to prevent native crashes on invalid data
    SerializationValidator.validateDecryptionErrorMessage(data);

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerDecryptionErrorMessage>();

    try {
      final error = signal_decryption_error_message_deserialize(
        outPtr,
        buffer.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_decryption_error_message_deserialize',
      );

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_decryption_error_message_deserialize',
        );
      }

      return DecryptionErrorMessage._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Creates a decryption error message for a failed original message.
  ///
  /// The [originalBytes] is the serialized form of the message that failed.
  /// The [messageType] is the numeric type of the original message
  /// (2 for whisper, 3 for preKey, 7 for senderKey, 8 for plaintext).
  /// The [timestamp] is the timestamp of the original message in milliseconds.
  /// The [originalSenderDeviceId] is the device ID of the original sender.
  ///
  /// Example:
  /// ```dart
  /// final errorMsg = DecryptionErrorMessage.forOriginalMessage(
  ///   originalBytes: failedMessage.serialize(),
  ///   messageType: 3, // preKey message
  ///   timestamp: messageTimestamp,
  ///   originalSenderDeviceId: senderDeviceId,
  /// );
  /// ```
  static DecryptionErrorMessage forOriginalMessage({
    required Uint8List originalBytes,
    required int messageType,
    required int timestamp,
    required int originalSenderDeviceId,
  }) {
    LibSignal.ensureInitialized();

    if (originalBytes.isEmpty) {
      throw LibSignalException.invalidArgument(
        'originalBytes',
        'Cannot be empty',
      );
    }

    final dataPtr = calloc<Uint8>(originalBytes.length);
    dataPtr.asTypedList(originalBytes.length).setAll(0, originalBytes);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = originalBytes.length;

    final outPtr = calloc<SignalMutPointerDecryptionErrorMessage>();

    try {
      final error = signal_decryption_error_message_for_original_message(
        outPtr,
        buffer.ref,
        messageType,
        timestamp,
        originalSenderDeviceId,
      );
      FfiHelpers.checkError(
        error,
        'signal_decryption_error_message_for_original_message',
      );

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_decryption_error_message_for_original_message',
        );
      }

      return DecryptionErrorMessage._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Extracts a decryption error message from serialized PlaintextContent.
  ///
  /// This is used to extract the error message from the content of a
  /// received message.
  ///
  /// Throws [LibSignalException] if the data does not contain a valid
  /// decryption error message.
  static DecryptionErrorMessage extractFromSerializedContent(Uint8List data) {
    LibSignal.ensureInitialized();

    if (data.isEmpty) {
      throw LibSignalException.invalidArgument('data', 'Cannot be empty');
    }

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerDecryptionErrorMessage>();

    try {
      final error =
          signal_decryption_error_message_extract_from_serialized_content(
            outPtr,
            buffer.ref,
          );
      FfiHelpers.checkError(
        error,
        'signal_decryption_error_message_extract_from_serialized_content',
      );

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_decryption_error_message_extract_from_serialized_content',
        );
      }

      return DecryptionErrorMessage._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes this message to bytes.
  ///
  /// The serialized form can be sent to the original sender to inform them
  /// of the decryption failure.
  Uint8List serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerDecryptionErrorMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_decryption_error_message_serialize(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_decryption_error_message_serialize');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// The timestamp of the original message in milliseconds since epoch.
  int get timestamp {
    _checkDisposed();

    final outPtr = calloc<Uint64>();
    final constPtr = calloc<SignalConstPointerDecryptionErrorMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_decryption_error_message_get_timestamp(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_decryption_error_message_get_timestamp',
      );

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// The device ID of the original sender.
  int get deviceId {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerDecryptionErrorMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_decryption_error_message_get_device_id(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_decryption_error_message_get_device_id',
      );

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// The ratchet key from the failed message, if available.
  ///
  /// Returns `null` if the ratchet key is not available in the error message.
  /// The caller is responsible for disposing the returned [PublicKey].
  PublicKey? getRatchetKey() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPublicKey>();
    final constPtr = calloc<SignalConstPointerDecryptionErrorMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_decryption_error_message_get_ratchet_key(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_decryption_error_message_get_ratchet_key',
      );

      if (outPtr.ref.raw == nullptr) {
        return null;
      }

      return PublicKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Creates a copy of this message.
  ///
  /// The caller is responsible for disposing the returned message.
  DecryptionErrorMessage clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerDecryptionErrorMessage>();
    final constPtr = calloc<SignalConstPointerDecryptionErrorMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_decryption_error_message_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_decryption_error_message_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_decryption_error_message_clone',
        );
      }

      return DecryptionErrorMessage._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalDecryptionErrorMessage> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('DecryptionErrorMessage');
    }
  }

  /// Releases the native resources.
  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _decryptionErrorMessageFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerDecryptionErrorMessage>();
      mutPtr.ref.raw = _ptr;
      signal_decryption_error_message_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  /// Whether this message has been disposed.
  bool get isDisposed => _disposed;
}
