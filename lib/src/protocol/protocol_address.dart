/// Protocol address for Signal Protocol.
library;

import 'dart:ffi';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../libsignal.dart';

/// Finalizer for ProtocolAddress.
final Finalizer<Pointer<SignalProtocolAddress>> _protocolAddressFinalizer =
    Finalizer((ptr) {
      final mutPtr = calloc<SignalMutPointerProtocolAddress>();
      mutPtr.ref.raw = ptr;
      signal_address_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    });

/// A Signal Protocol address identifying a user and device.
///
/// Combines a user identifier (name/UUID) with a device ID to uniquely
/// identify a specific device belonging to a user.
///
/// Example:
/// ```dart
/// final address = ProtocolAddress('alice-uuid', 1);
/// print('${address.name}:${address.deviceId}');
/// address.dispose();
/// ```
final class ProtocolAddress {
  final Pointer<SignalProtocolAddress> _ptr;
  bool _disposed = false;

  ProtocolAddress._(this._ptr) {
    _protocolAddressFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a ProtocolAddress from a raw pointer.
  factory ProtocolAddress.fromPointer(Pointer<SignalProtocolAddress> ptr) {
    return ProtocolAddress._(ptr);
  }

  /// Creates a new protocol address.
  ///
  /// The [name] is typically a UUID string identifying the user.
  /// The [deviceId] identifies a specific device of that user (must be non-negative).
  ///
  /// Throws [LibSignalException] if [deviceId] is negative.
  factory ProtocolAddress(String name, int deviceId) {
    if (deviceId < 0) {
      throw LibSignalException.invalidArgument(
        'deviceId',
        'Device ID must be non-negative, got $deviceId',
      );
    }

    LibSignal.ensureInitialized();

    final outPtr = calloc<SignalMutPointerProtocolAddress>();
    final namePtr = name.toNativeUtf8().cast<Char>();

    try {
      final error = signal_address_new(outPtr, namePtr, deviceId);
      FfiHelpers.checkError(error, 'signal_address_new');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_address_new');
      }

      return ProtocolAddress._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(namePtr);
    }
  }

  /// Gets the name (user identifier) of this address.
  String get name {
    _checkDisposed();

    final outPtr = calloc<Pointer<Char>>();
    final constPtr = calloc<SignalConstPointerProtocolAddress>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_address_get_name(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_address_get_name');

      if (outPtr.value == nullptr) {
        throw LibSignalException.nullPointer('signal_address_get_name');
      }

      final name = outPtr.value.cast<Utf8>().toDartString();
      signal_free_string(outPtr.value);
      return name;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the device ID of this address.
  int get deviceId {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerProtocolAddress>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_address_get_device_id(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_address_get_device_id');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Creates a copy of this address.
  ProtocolAddress clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerProtocolAddress>();
    final constPtr = calloc<SignalConstPointerProtocolAddress>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_address_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_address_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_address_clone');
      }

      return ProtocolAddress._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalProtocolAddress> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('ProtocolAddress');
    }
  }

  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _protocolAddressFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerProtocolAddress>();
      mutPtr.ref.raw = _ptr;
      signal_address_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  bool get isDisposed => _disposed;

  @override
  String toString() {
    if (_disposed) return 'ProtocolAddress(disposed)';
    // Redact name to prevent sensitive data leaking to logs.
    // Show only first 4 chars + length hint for debugging.
    final n = name;
    final redacted = n.length > 4 ? '${n.substring(0, 4)}...[${n.length}]' : n;
    return 'ProtocolAddress($redacted:$deviceId)';
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! ProtocolAddress) return false;
    if (_disposed || other._disposed) return false;
    return name == other.name && deviceId == other.deviceId;
  }

  @override
  int get hashCode {
    if (_disposed) return 0;
    return Object.hash(name, deviceId);
  }
}
