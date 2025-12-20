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
  /// Auto-initializes if not already initialized.
  static void ensureInitialized() {
    if (!isInitialized) {
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
}

/// Base mixin for libsignal operations.
///
/// Ensures library is initialized before any operation.
mixin LibSignalBase {
  /// Ensures the library is initialized.
  ///
  /// Call this at the start of any public method.
  static void ensureInit() {
    LibSignal.ensureInitialized();
  }
}
