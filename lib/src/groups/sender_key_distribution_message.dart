/// Sender key distribution message for Signal Protocol group messaging.
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

/// A struct to hold a 16-byte UUID array for FFI calls.
///
/// **FFI Workaround**: This struct is needed because of a limitation in ffigen.
/// The C header declares functions with `uint8_t (*out)[16]` (pointer to array
/// of 16 bytes), but ffigen incorrectly generates `Pointer<Pointer<Uint8>>`.
///
/// The workaround:
/// 1. Use a Struct with `Array<Uint8>[16]` to allocate exactly 16 bytes
/// 2. Cast the struct pointer when calling the FFI function
/// 3. Read bytes from the struct after the call
///
/// This approach is safe because:
/// - The allocated size (16 bytes) exactly matches the C expectation
/// - We copy data before freeing memory
/// - Tests verify the correct UUID values are returned
///
/// This workaround survives `make regen` because it's in wrapper code,
/// not in the auto-generated bindings.
final class _Uuid16 extends Struct {
  @Array.multi([16])
  external Array<Uint8> bytes;
}

/// Finalizer for SenderKeyDistributionMessage.
final Finalizer<Pointer<SignalSenderKeyDistributionMessage>>
    _senderKeyDistributionMessageFinalizer = Finalizer((ptr) {
  final mutPtr = calloc<SignalMutPointerSenderKeyDistributionMessage>();
  mutPtr.ref.raw = ptr;
  signal_sender_key_distribution_message_destroy(mutPtr.ref);
  calloc.free(mutPtr);
});

/// A sender key distribution message for group messaging.
///
/// This message contains the sender's key material that other group
/// members need to decrypt messages from this sender. It should be
/// sent to all group members (typically encrypted with their individual
/// session keys).
///
/// Example:
/// ```dart
/// // Sender creates distribution message for a group
/// final distMessage = await groupSession.createDistributionMessage();
///
/// // Send to all group members (encrypted individually)
/// for (final member in groupMembers) {
///   final encrypted = await session.encrypt(distMessage.serialize());
///   sendTo(member, encrypted);
/// }
/// ```
final class SenderKeyDistributionMessage {
  final Pointer<SignalSenderKeyDistributionMessage> _ptr;
  bool _disposed = false;

  SenderKeyDistributionMessage._(this._ptr) {
    _senderKeyDistributionMessageFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a SenderKeyDistributionMessage from a raw pointer.
  factory SenderKeyDistributionMessage.fromPointer(
    Pointer<SignalSenderKeyDistributionMessage> ptr,
  ) {
    return SenderKeyDistributionMessage._(ptr);
  }

  /// Deserializes a sender key distribution message from bytes.
  static SenderKeyDistributionMessage deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Pre-validate to prevent native crashes on invalid data
    SerializationValidator.validateSenderKeyDistributionMessage(data);

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerSenderKeyDistributionMessage>();

    try {
      final error =
          signal_sender_key_distribution_message_deserialize(outPtr, buffer.ref);
      FfiHelpers.checkError(
        error,
        'signal_sender_key_distribution_message_deserialize',
      );

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_sender_key_distribution_message_deserialize',
        );
      }

      return SenderKeyDistributionMessage._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Serializes the sender key distribution message to bytes.
  Uint8List serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerSenderKeyDistributionMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_key_distribution_message_serialize(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_sender_key_distribution_message_serialize',
      );

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the chain key for this distribution message.
  Uint8List get chainKey {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerSenderKeyDistributionMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_key_distribution_message_get_chain_key(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_sender_key_distribution_message_get_chain_key',
      );

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the distribution ID (UUID) for this message.
  Uint8List get distributionId {
    _checkDisposed();

    // The C function signature is: uint8_t (*out)[16]
    // This means "pointer to array of 16 uint8_t".
    // We use a Struct with Array<Uint8>[16] to properly allocate and access it.
    final outPtr = calloc<_Uuid16>();
    final constPtr = calloc<SignalConstPointerSenderKeyDistributionMessage>();
    constPtr.ref.raw = _ptr;

    try {
      // The binding expects Pointer<Pointer<Uint8>> due to ffigen limitation,
      // but the actual C type is uint8_t (*)[16]. We cast our struct pointer.
      final error = signal_sender_key_distribution_message_get_distribution_id(
        outPtr.cast<Pointer<Uint8>>(),
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_sender_key_distribution_message_get_distribution_id',
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

  /// Gets the chain ID for this distribution message.
  int get chainId {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerSenderKeyDistributionMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_key_distribution_message_get_chain_id(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_sender_key_distribution_message_get_chain_id',
      );

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the iteration (starting message counter) for this distribution.
  int get iteration {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerSenderKeyDistributionMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_key_distribution_message_get_iteration(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_sender_key_distribution_message_get_iteration',
      );

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the signature key (public key) for this distribution.
  PublicKey getSignatureKey() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPublicKey>();
    final constPtr = calloc<SignalConstPointerSenderKeyDistributionMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_key_distribution_message_get_signature_key(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_sender_key_distribution_message_get_signature_key',
      );

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_sender_key_distribution_message_get_signature_key',
        );
      }

      return PublicKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Creates a copy of this distribution message.
  SenderKeyDistributionMessage clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerSenderKeyDistributionMessage>();
    final constPtr = calloc<SignalConstPointerSenderKeyDistributionMessage>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_sender_key_distribution_message_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(
        error,
        'signal_sender_key_distribution_message_clone',
      );

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_sender_key_distribution_message_clone',
        );
      }

      return SenderKeyDistributionMessage._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalSenderKeyDistributionMessage> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw StateError('SenderKeyDistributionMessage has been disposed');
    }
  }

  /// Releases the native resources.
  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _senderKeyDistributionMessageFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerSenderKeyDistributionMessage>();
      mutPtr.ref.raw = _ptr;
      signal_sender_key_distribution_message_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  /// Whether this message has been disposed.
  bool get isDisposed => _disposed;
}
