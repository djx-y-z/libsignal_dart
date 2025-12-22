/// Server certificate for Signal Protocol sealed sender.
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

/// Finalizer for ServerCertificate.
final Finalizer<Pointer<SignalServerCertificate>> _serverCertificateFinalizer =
    Finalizer((ptr) {
  final mutPtr = calloc<SignalMutPointerServerCertificate>();
  mutPtr.ref.raw = ptr;
  signal_server_certificate_destroy(mutPtr.ref);
  calloc.free(mutPtr);
});

/// A server certificate for sealed sender.
///
/// Server certificates are issued by Signal's servers and are used
/// to validate sender certificates. They contain a server public key
/// signed by a trust root.
///
/// Example:
/// ```dart
/// // Create a new server certificate
/// final cert = ServerCertificate.create(
///   keyId: 1,
///   serverKey: serverPublicKey,
///   trustRoot: trustRootPrivateKey,
/// );
///
/// // Or deserialize from bytes
/// final cert = ServerCertificate.deserialize(certBytes);
/// ```
final class ServerCertificate {
  final Pointer<SignalServerCertificate> _ptr;
  bool _disposed = false;

  ServerCertificate._(this._ptr) {
    _serverCertificateFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a ServerCertificate from a raw pointer.
  factory ServerCertificate.fromPointer(Pointer<SignalServerCertificate> ptr) {
    return ServerCertificate._(ptr);
  }

  /// Deserializes a server certificate from bytes.
  static ServerCertificate deserialize(Uint8List data) {
    LibSignal.ensureInitialized();

    // Pre-validate to prevent native crashes on invalid data
    SerializationValidator.validateServerCertificate(data);

    final dataPtr = calloc<Uint8>(data.length);
    dataPtr.asTypedList(data.length).setAll(0, data);

    final buffer = calloc<SignalBorrowedBuffer>();
    buffer.ref.base = dataPtr.cast<UnsignedChar>();
    buffer.ref.length = data.length;

    final outPtr = calloc<SignalMutPointerServerCertificate>();

    try {
      final error = signal_server_certificate_deserialize(outPtr, buffer.ref);
      FfiHelpers.checkError(error, 'signal_server_certificate_deserialize');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_server_certificate_deserialize',
        );
      }

      return ServerCertificate._(outPtr.ref.raw);
    } finally {
      calloc.free(dataPtr);
      calloc.free(buffer);
      calloc.free(outPtr);
    }
  }

  /// Creates a new server certificate.
  ///
  /// The [keyId] is a unique identifier for this key.
  /// The [serverKey] is the server's public key.
  /// The [trustRoot] is the private key used to sign this certificate.
  static ServerCertificate create({
    required int keyId,
    required PublicKey serverKey,
    required PrivateKey trustRoot,
  }) {
    LibSignal.ensureInitialized();
    serverKey.checkNotDisposed();
    trustRoot.checkNotDisposed();

    final outPtr = calloc<SignalMutPointerServerCertificate>();
    final serverKeyPtr = calloc<SignalConstPointerPublicKey>();
    serverKeyPtr.ref.raw = serverKey.pointer;

    final trustRootPtr = calloc<SignalConstPointerPrivateKey>();
    trustRootPtr.ref.raw = trustRoot.pointer;

    try {
      final error = signal_server_certificate_new(
        outPtr,
        keyId,
        serverKeyPtr.ref,
        trustRootPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_server_certificate_new');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_server_certificate_new');
      }

      return ServerCertificate._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(serverKeyPtr);
      calloc.free(trustRootPtr);
    }
  }

  /// Gets the serialized form of this certificate.
  Uint8List serialize() {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerServerCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_server_certificate_get_serialized(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_server_certificate_get_serialized');

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
    final constPtr = calloc<SignalConstPointerServerCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_server_certificate_get_certificate(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_server_certificate_get_certificate');

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
    final constPtr = calloc<SignalConstPointerServerCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_server_certificate_get_signature(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_server_certificate_get_signature');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the key ID for this certificate.
  int get keyId {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerServerCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error =
          signal_server_certificate_get_key_id(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_server_certificate_get_key_id');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the public key from this certificate.
  PublicKey getKey() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPublicKey>();
    final constPtr = calloc<SignalConstPointerServerCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_server_certificate_get_key(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_server_certificate_get_key');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_server_certificate_get_key');
      }

      return PublicKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Creates a copy of this certificate.
  ServerCertificate clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerServerCertificate>();
    final constPtr = calloc<SignalConstPointerServerCertificate>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_server_certificate_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_server_certificate_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_server_certificate_clone');
      }

      return ServerCertificate._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalServerCertificate> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw StateError('ServerCertificate has been disposed');
    }
  }

  /// Checks that this certificate has not been disposed.
  ///
  /// Throws [StateError] if the certificate has been disposed.
  void checkNotDisposed() => _checkDisposed();

  /// Releases the native resources.
  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _serverCertificateFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerServerCertificate>();
      mutPtr.ref.raw = _ptr;
      signal_server_certificate_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  /// Whether this certificate has been disposed.
  bool get isDisposed => _disposed;
}
