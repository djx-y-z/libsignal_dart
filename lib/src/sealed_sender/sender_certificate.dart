/// Sender certificate for Signal Protocol sealed sender.
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
import 'server_certificate.dart';

/// Finalizer for SenderCertificate.
final Finalizer<Pointer<SignalSenderCertificate>> _senderCertificateFinalizer =
    Finalizer((ptr) {
  final mutPtr = calloc<SignalMutPointerSenderCertificate>();
  mutPtr.ref.raw = ptr;
  signal_sender_certificate_destroy(mutPtr.ref);
  calloc.free(mutPtr);
});

/// A sender certificate for sealed sender.
///
/// Sender certificates identify a sender for sealed sender messages.
/// They contain the sender's UUID, device ID, and public key, and are
/// signed by a server certificate.
///
/// Example:
/// ```dart
/// // Create a sender certificate
/// final cert = SenderCertificate.create(
///   senderUuid: 'user-uuid',
///   senderE164: '+1234567890',
///   deviceId: 1,
///   senderKey: senderPublicKey,
///   expiration: DateTime.now().add(Duration(days: 30)),
///   signerCertificate: serverCert,
///   signerKey: serverPrivateKey,
/// );
///
/// // Or deserialize from bytes
/// final cert = SenderCertificate.deserialize(certBytes);
/// ```
final class SenderCertificate {
  final Pointer<SignalSenderCertificate> _ptr;
  bool _disposed = false;

  SenderCertificate._(this._ptr) {
    _senderCertificateFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a SenderCertificate from a raw pointer.
  factory SenderCertificate.fromPointer(Pointer<SignalSenderCertificate> ptr) {
    return SenderCertificate._(ptr);
  }

  /// Deserializes a sender certificate from bytes.
  static SenderCertificate deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    if (data.isEmpty) {
      throw LibSignalException.invalidArgument('data', 'Cannot be empty');
    }

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerSenderCertificate>();

    try {
      final error = signal_sender_certificate_deserialize(outPtr, buffer.ref);
      FfiHelpers.checkError(error, 'signal_sender_certificate_deserialize');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_sender_certificate_deserialize',
        );
      }

      return SenderCertificate._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Creates a new sender certificate.
  ///
  /// The [senderUuid] is the sender's UUID.
  /// The [senderE164] is the sender's phone number (optional, can be null).
  /// The [deviceId] is the sender's device ID.
  /// The [senderKey] is the sender's public key.
  /// The [expiration] is when this certificate expires.
  /// The [signerCertificate] is the server certificate that signs this.
  /// The [signerKey] is the private key for signing.
  static SenderCertificate create({
    required String senderUuid,
    String? senderE164,
    required int deviceId,
    required PublicKey senderKey,
    required DateTime expiration,
    required ServerCertificate signerCertificate,
    required PrivateKey signerKey,
  }) {
    LibSignal.ensureInitialized();
    senderKey.checkNotDisposed();
    signerKey.checkNotDisposed();

    final outPtr = calloc<SignalMutPointerSenderCertificate>();
    final uuidPtr = senderUuid.toNativeUtf8().cast<Char>();
    final e164Ptr =
        senderE164 != null ? senderE164.toNativeUtf8().cast<Char>() : nullptr;

    final senderKeyPtr = calloc<SignalConstPointerPublicKey>();
    senderKeyPtr.ref.raw = senderKey.pointer;

    final signerCertPtr = calloc<SignalConstPointerServerCertificate>();
    signerCertPtr.ref.raw = signerCertificate.pointer;

    final signerKeyPtr = calloc<SignalConstPointerPrivateKey>();
    signerKeyPtr.ref.raw = signerKey.pointer;

    // Expiration is in milliseconds since epoch
    final expirationMs = expiration.millisecondsSinceEpoch;

    try {
      final error = signal_sender_certificate_new(
        outPtr,
        uuidPtr,
        e164Ptr,
        deviceId,
        senderKeyPtr.ref,
        expirationMs,
        signerCertPtr.ref,
        signerKeyPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_sender_certificate_new');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_sender_certificate_new');
      }

      return SenderCertificate._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(uuidPtr);
      if (e164Ptr != nullptr) calloc.free(e164Ptr);
      calloc.free(senderKeyPtr);
      calloc.free(signerCertPtr);
      calloc.free(signerKeyPtr);
    }
  }

  /// Gets the serialized form of this certificate.
  Uint8List serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerSenderCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_sender_certificate_get_serialized(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_sender_certificate_get_serialized');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the certificate data (the signed portion).
  Uint8List get certificate {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerSenderCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_sender_certificate_get_certificate(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_sender_certificate_get_certificate');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the signature on this certificate.
  Uint8List get signature {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerSenderCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_sender_certificate_get_signature(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_sender_certificate_get_signature');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the sender's UUID.
  String get senderUuid {
    _checkDisposed();

    final outPtr = calloc<Pointer<Char>>();
    final constPtr = calloc<SignalConstPointerSenderCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_sender_certificate_get_sender_uuid(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_sender_certificate_get_sender_uuid');

      if (outPtr.value == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_sender_certificate_get_sender_uuid',
        );
      }

      final uuid = outPtr.value.cast<Utf8>().toDartString();
      signal_free_string(outPtr.value);
      return uuid;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the sender's E164 phone number (may be null).
  String? get senderE164 {
    _checkDisposed();

    final outPtr = calloc<Pointer<Char>>();
    final constPtr = calloc<SignalConstPointerSenderCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_sender_certificate_get_sender_e164(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_sender_certificate_get_sender_e164');

      if (outPtr.value == nullptr) {
        return null;
      }

      final e164 = outPtr.value.cast<Utf8>().toDartString();
      signal_free_string(outPtr.value);
      return e164;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the expiration time.
  DateTime get expiration {
    _checkDisposed();

    final outPtr = calloc<Uint64>();
    final constPtr = calloc<SignalConstPointerSenderCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_sender_certificate_get_expiration(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_sender_certificate_get_expiration');

      return DateTime.fromMillisecondsSinceEpoch(outPtr.value);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the device ID.
  int get deviceId {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerSenderCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_sender_certificate_get_device_id(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_sender_certificate_get_device_id');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the sender's public key.
  PublicKey getKey() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPublicKey>();
    final constPtr = calloc<SignalConstPointerSenderCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_certificate_get_key(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_sender_certificate_get_key');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_sender_certificate_get_key');
      }

      return PublicKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the server certificate that signed this certificate.
  ServerCertificate getServerCertificate() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerServerCertificate>();
    final constPtr = calloc<SignalConstPointerSenderCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_sender_certificate_get_server_certificate(outPtr, constPtr.ref);
      FfiHelpers.checkError(
        error,
        'signal_sender_certificate_get_server_certificate',
      );

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_sender_certificate_get_server_certificate',
        );
      }

      return ServerCertificate.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Validates this certificate against a trust root.
  ///
  /// The [trustRoot] is the public key of the trust root.
  /// The [now] is the current time to check expiration against.
  ///
  /// Returns `true` if the certificate is valid, `false` otherwise.
  bool validate(PublicKey trustRoot, {DateTime? now}) {
    _checkDisposed();
    trustRoot.checkNotDisposed();

    final outPtr = calloc<Bool>();
    final certPtr = calloc<SignalConstPointerSenderCertificate>();
    certPtr.ref.raw = _ptr;

    // Create a slice of one trust root key
    final keyPtr = calloc<SignalConstPointerPublicKey>();
    keyPtr.ref.raw = trustRoot.pointer;

    final trustRootsSlice = calloc<SignalBorrowedSliceOfConstPointerPublicKey>();
    trustRootsSlice.ref.base = keyPtr;
    trustRootsSlice.ref.length = 1;

    final time = (now ?? DateTime.now()).millisecondsSinceEpoch;

    try {
      final error = signal_sender_certificate_validate(
        outPtr,
        certPtr.ref,
        trustRootsSlice.ref,
        time,
      );
      FfiHelpers.checkError(error, 'signal_sender_certificate_validate');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(certPtr);
      calloc.free(keyPtr);
      calloc.free(trustRootsSlice);
    }
  }

  /// Creates a copy of this certificate.
  SenderCertificate clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerSenderCertificate>();
    final constPtr = calloc<SignalConstPointerSenderCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_sender_certificate_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_sender_certificate_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_sender_certificate_clone');
      }

      return SenderCertificate._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalSenderCertificate> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw StateError('SenderCertificate has been disposed');
    }
  }

  /// Releases the native resources.
  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _senderCertificateFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerSenderCertificate>();
      mutPtr.ref.raw = _ptr;
      signal_sender_certificate_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  /// Whether this certificate has been disposed.
  bool get isDisposed => _disposed;
}
