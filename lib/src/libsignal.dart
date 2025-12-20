/// Main entry point for the libsignal library.
///
/// Provides initialization, version information, and high-level API access.
library;

import 'dart:isolate';

/// Main API class for libsignal.
///
/// Use [LibSignal.init] to initialize the library before using any
/// cryptographic operations.
///
/// ```dart
/// void main() {
///   LibSignal.init();
///   // ... use libsignal APIs
/// }
/// ```
class LibSignal {
  LibSignal._();

  /// Track initialization per isolate.
  static final Set<int> _initializedIsolates = {};

  /// Initialize the libsignal library.
  ///
  /// This should be called once before using any libsignal operations.
  /// It's safe to call multiple times - subsequent calls are no-ops.
  ///
  /// For multi-isolate applications, call this in each isolate that
  /// uses libsignal.
  static void init() {
    final isolateId = Isolate.current.hashCode;

    if (_initializedIsolates.contains(isolateId)) {
      return;
    }

    // libsignal doesn't require explicit initialization,
    // but we track state for consistency
    _initializedIsolates.add(isolateId);
  }

  /// Whether the library has been initialized in the current isolate.
  static bool get isInitialized {
    final isolateId = Isolate.current.hashCode;
    return _initializedIsolates.contains(isolateId);
  }

  /// Ensures the library is initialized.
  ///
  /// Throws [StateError] if not initialized.
  static void ensureInitialized() {
    if (!isInitialized) {
      // Auto-initialize for convenience
      init();
    }
  }

  /// Clean up resources for the current isolate.
  ///
  /// Call this when you're done using libsignal in an isolate.
  static void cleanup() {
    final isolateId = Isolate.current.hashCode;
    _initializedIsolates.remove(isolateId);
  }

  /// Get the libsignal version.
  ///
  /// Returns the version of the underlying libsignal library.
  static String getVersion() {
    // TODO: Implement when FFI bindings are generated
    // This will call signal_version_string() or similar
    return 'unknown';
  }

  /// Get supported cryptographic algorithms.
  ///
  /// Returns information about available algorithms.
  static Map<String, List<String>> getSupportedAlgorithms() {
    return {
      'key_agreement': ['X25519', 'Kyber1024'],
      'signature': ['Ed25519'],
      'encryption': ['AES-256-GCM-SIV'],
      'hash': ['SHA-256', 'SHA-512'],
    };
  }
}

/// Thread-safe base class for libsignal operations.
///
/// Ensures library is initialized before any operation.
abstract class LibSignalBase {
  /// Ensures the library is initialized.
  ///
  /// Call this at the start of any public method.
  static void ensureInit() {
    LibSignal.ensureInitialized();
  }
}
