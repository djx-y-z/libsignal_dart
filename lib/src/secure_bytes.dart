/// Secure byte container with automatic zeroing on disposal.
///
/// Use this for sensitive data like private keys to ensure
/// memory is securely cleared when no longer needed.
library;

import 'dart:typed_data';

import 'exception.dart';
import 'utils.dart';

/// Weak reference tracking for finalizer (safety net for forgotten dispose calls).
final Finalizer<Uint8List> _secureBytesProtector = Finalizer(
  LibSignalUtils.zeroBytes,
);

/// A wrapper for sensitive byte data that provides secure disposal.
///
/// When [dispose] is called, the underlying bytes are securely zeroed
/// to prevent sensitive data from remaining in memory.
///
/// Example:
/// ```dart
/// final secureKey = privateKey.serialize();
/// try {
///   // Use secureKey.bytes...
///   saveToSecureStorage(secureKey.bytes);
/// } finally {
///   secureKey.dispose(); // Zeros the memory
/// }
/// ```
///
/// **Security note**: Always call [dispose] when done with sensitive data.
/// Consider using try/finally to ensure disposal even on exceptions.
final class SecureBytes {
  final Uint8List _data;
  bool _disposed = false;

  /// Creates a SecureBytes wrapper around the given data.
  ///
  /// The data is NOT copied - the wrapper takes ownership of the bytes.
  /// After disposal, the original bytes will be zeroed.
  SecureBytes(this._data) {
    // Attach finalizer as safety net in case dispose() is not called
    _secureBytesProtector.attach(this, _data, detach: this);
  }

  /// Creates a SecureBytes wrapper with a copy of the data.
  ///
  /// Use this when you need to preserve the original data.
  factory SecureBytes.copy(Uint8List data) {
    return SecureBytes(Uint8List.fromList(data));
  }

  /// Access to the underlying bytes.
  ///
  /// Throws [StateError] if disposed.
  ///
  /// **Security note**: Do not store references to these bytes beyond
  /// the lifetime of this SecureBytes instance.
  Uint8List get bytes {
    _checkDisposed();
    return _data;
  }

  /// The length of the data in bytes.
  int get length => _data.length;

  /// Whether this SecureBytes has been disposed.
  bool get isDisposed => _disposed;

  /// Securely disposes the bytes by zeroing the memory.
  ///
  /// After calling dispose:
  /// - The underlying bytes are zeroed
  /// - Accessing [bytes] will throw [StateError]
  /// - Calling dispose again is safe (no-op)
  void dispose() {
    if (!_disposed) {
      _disposed = true;
      // Detach from finalizer since we're disposing manually
      _secureBytesProtector.detach(this);
      // Securely zero the memory
      LibSignalUtils.zeroBytes(_data);
    }
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('SecureBytes');
    }
  }

  @override
  String toString() {
    if (_disposed) {
      return 'SecureBytes(disposed)';
    }
    return 'SecureBytes(${_data.length} bytes)';
  }
}
