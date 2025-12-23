/// Unidentified sender message content for Signal Protocol sealed sender.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../libsignal.dart';
import 'sender_certificate.dart';

/// Content hint for sealed sender messages.
///
/// These hints help the recipient determine how to handle the message
/// if decryption fails.
abstract class ContentHint {
  /// Default content hint - no special handling.
  static const int none = 0;

  /// Resendable content - can be requested again if decryption fails.
  static const int resendable = 1;

  /// Implicit content - recipient should not ask for resend.
  static const int implicit = 2;
}

/// Finalizer for UnidentifiedSenderMessageContent.
final Finalizer<Pointer<SignalUnidentifiedSenderMessageContent>>
    _usmcFinalizer = Finalizer((ptr) {
  final mutPtr = calloc<SignalMutPointerUnidentifiedSenderMessageContent>();
  mutPtr.ref.raw = ptr;
  signal_unidentified_sender_message_content_destroy(mutPtr.ref);
  calloc.free(mutPtr);
});

/// Unidentified sender message content (USMC).
///
/// This is the inner content of a sealed sender message. It contains:
/// - The encrypted message content
/// - The sender's certificate (proving identity)
/// - Content hint for retry handling
/// - Optional group ID for group messages
///
/// Example:
/// ```dart
/// // Deserialize a received USMC
/// final usmc = UnidentifiedSenderMessageContent.deserialize(usmcBytes);
///
/// // Get the sender's certificate
/// final senderCert = usmc.getSenderCertificate();
/// print('Message from: ${senderCert.senderUuid}');
///
/// // Get the encrypted content
/// final content = usmc.contents;
///
/// usmc.dispose();
/// senderCert.dispose();
/// ```
final class UnidentifiedSenderMessageContent {
  final Pointer<SignalUnidentifiedSenderMessageContent> _ptr;
  bool _disposed = false;

  UnidentifiedSenderMessageContent._(this._ptr) {
    _usmcFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates an UnidentifiedSenderMessageContent from a raw pointer.
  ///
  /// This is primarily for internal use.
  factory UnidentifiedSenderMessageContent.fromPointer(
    Pointer<SignalUnidentifiedSenderMessageContent> ptr,
  ) {
    return UnidentifiedSenderMessageContent._(ptr);
  }

  /// Deserializes an USMC from bytes.
  ///
  /// Throws [LibSignalException] if the data is invalid.
  static UnidentifiedSenderMessageContent deserialize(Uint8List data) {
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
        calloc<SignalMutPointerUnidentifiedSenderMessageContent>();

    try {
      final error = signal_unidentified_sender_message_content_deserialize(
        outPtr,
        buffer.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_unidentified_sender_message_content_deserialize',
      );

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_unidentified_sender_message_content_deserialize',
        );
      }

      return UnidentifiedSenderMessageContent._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes this USMC to bytes.
  Uint8List serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr =
        calloc<SignalConstPointerUnidentifiedSenderMessageContent>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_unidentified_sender_message_content_serialize(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_unidentified_sender_message_content_serialize',
      );

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the encrypted message contents.
  ///
  /// This is the serialized form of the underlying encrypted message.
  Uint8List get contents {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr =
        calloc<SignalConstPointerUnidentifiedSenderMessageContent>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_unidentified_sender_message_content_get_contents(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_unidentified_sender_message_content_get_contents',
      );

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the group ID if this is a group message.
  ///
  /// Returns an empty [Uint8List] if this is not a group message.
  Uint8List get groupId {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr =
        calloc<SignalConstPointerUnidentifiedSenderMessageContent>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_unidentified_sender_message_content_get_group_id_or_empty(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_unidentified_sender_message_content_get_group_id_or_empty',
      );

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the sender's certificate.
  ///
  /// The caller is responsible for disposing the returned certificate.
  SenderCertificate getSenderCertificate() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerSenderCertificate>();
    final constPtr =
        calloc<SignalConstPointerUnidentifiedSenderMessageContent>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_unidentified_sender_message_content_get_sender_cert(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_unidentified_sender_message_content_get_sender_cert',
      );

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_unidentified_sender_message_content_get_sender_cert',
        );
      }

      return SenderCertificate.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the message type.
  ///
  /// Returns the numeric message type value:
  /// - 2: whisper (standard message)
  /// - 3: preKey (session establishment)
  /// - 7: senderKey (group message)
  /// - 8: plaintext
  int get messageType {
    _checkDisposed();

    final outPtr = calloc<Uint8>();
    final constPtr =
        calloc<SignalConstPointerUnidentifiedSenderMessageContent>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_unidentified_sender_message_content_get_msg_type(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_unidentified_sender_message_content_get_msg_type',
      );

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the content hint.
  ///
  /// The content hint indicates how the recipient should handle
  /// this message if decryption fails. See [ContentHint] for values.
  int get contentHint {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr =
        calloc<SignalConstPointerUnidentifiedSenderMessageContent>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_unidentified_sender_message_content_get_content_hint(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_unidentified_sender_message_content_get_content_hint',
      );

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalUnidentifiedSenderMessageContent> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('UnidentifiedSenderMessageContent');
    }
  }

  /// Releases the native resources.
  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _usmcFinalizer.detach(this);

      final mutPtr =
          calloc<SignalMutPointerUnidentifiedSenderMessageContent>();
      mutPtr.ref.raw = _ptr;
      signal_unidentified_sender_message_content_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  /// Whether this USMC has been disposed.
  bool get isDisposed => _disposed;
}
