/// Exception thrown by libsignal operations.
///
/// This exception is thrown when a libsignal operation fails.
/// The [message] contains a description of what went wrong.
/// Optional [errorCode] and [context] provide additional details.
class LibSignalException implements Exception {
  /// A human-readable description of the error.
  final String message;

  /// Optional error code from the native library.
  final int? errorCode;

  /// Optional context information (e.g., function name, algorithm).
  final String? context;

  /// Optional stack trace captured when the exception was created.
  final StackTrace? stackTrace;

  /// Creates a new [LibSignalException].
  LibSignalException(
    this.message, {
    this.errorCode,
    this.context,
    this.stackTrace,
  });

  /// Creates an exception for an invalid argument.
  factory LibSignalException.invalidArgument(String argument, String reason) {
    return LibSignalException(
      'Invalid argument "$argument": $reason',
      context: 'argument_validation',
    );
  }

  /// Creates an exception for a null pointer from the native library.
  factory LibSignalException.nullPointer(String operation) {
    return LibSignalException(
      'Null pointer returned from native library',
      context: operation,
    );
  }

  /// Creates an exception for an unsupported operation.
  factory LibSignalException.unsupported(String operation, {String? reason}) {
    return LibSignalException(
      'Unsupported operation: $operation${reason != null ? ' ($reason)' : ''}',
      context: operation,
    );
  }

  /// Creates an exception for a serialization error.
  factory LibSignalException.serialization(String type, {String? reason}) {
    return LibSignalException(
      'Failed to serialize/deserialize $type${reason != null ? ': $reason' : ''}',
      context: 'serialization',
    );
  }

  /// Creates an exception for a cryptographic operation failure.
  factory LibSignalException.cryptoError(String operation, {int? errorCode}) {
    return LibSignalException(
      'Cryptographic operation failed: $operation',
      errorCode: errorCode,
      context: 'crypto',
    );
  }

  /// Creates an exception for accessing a disposed object.
  ///
  /// This is thrown when trying to use an object after [dispose] has been called.
  factory LibSignalException.disposed(String objectType) {
    return LibSignalException(
      '$objectType has been disposed',
      context: 'disposed',
    );
  }

  @override
  String toString() {
    final buffer = StringBuffer('LibSignalException: $message');

    if (errorCode != null) {
      buffer.write(' (error code: $errorCode)');
    }

    if (context != null) {
      buffer.write(' [context: $context]');
    }

    return buffer.toString();
  }
}
