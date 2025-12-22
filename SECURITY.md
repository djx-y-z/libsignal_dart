# Security

This document describes the security audit performed on the library and provides guidelines for secure development.

## Security Audit Summary

A comprehensive security audit was conducted covering the following categories:

### Category A: FFI Memory Management

**Problem:** Incorrect memory deallocation can lead to memory leaks or double-free vulnerabilities.

**Fixes:**
- Ensured all FFI pointers are freed using appropriate functions (`signal_*_destroy`, `calloc.free`)
- Implemented `dispose()` pattern with `_disposed` flag to prevent double-free
- Added null-pointer checks before freeing memory

**Files affected:**
- All files in `lib/src/` using FFI bindings

### Category B: Buffer Overflow Prevention

**Problem:** Passing incorrect sizes to FFI functions can cause buffer overflows.

**Fixes:**
- Added `SerializationValidator` class for validating serialized data sizes
- Implemented minimum and maximum size checks for all serialized types
- Added bounds checking before `sublistView()` operations

**Key validation constants:**
```dart
static const int publicKeyLength = 33;      // Exact
static const int privateKeyLength = 32;     // Exact
static const int sessionRecordMin = 50;     // Minimum
static const int sessionRecordMax = 100000; // Maximum
static const int senderKeyRecordMin = 20;   // Minimum
```

**Files affected:**
- `lib/src/serialization_validator.dart`
- `lib/src/keys/identity_key_pair.dart`

### Category C: Timing Attack Prevention

**Problem:** Variable-time comparison operations can leak secret information through timing analysis.

**Fixes:**
- Implemented `LibSignalUtils.constantTimeEquals()` for cryptographic data comparison
- Uses XOR accumulator pattern that processes all bytes regardless of match status

**Implementation:**
```dart
static bool constantTimeEquals(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var result = 0;
  for (var i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result == 0;
}
```

**Files affected:**
- `lib/src/utils.dart`

### Category D: Disposed State Validation

**Problem:** Using disposed objects can lead to use-after-free vulnerabilities or undefined behavior.

**Fixes:**
- Added `checkNotDisposed()` method to key classes
- Added validation in `create()` factory methods for all input objects
- Consistent `StateError` thrown when accessing disposed objects

**Protected classes:**
- `KyberKeyPair`
- `ServerCertificate`
- `PreKeyRecord`
- `SignedPreKeyRecord`
- `KyberPreKeyRecord`
- `SenderCertificate`

**Files affected:**
- `lib/src/kyber/kyber_key_pair.dart`
- `lib/src/sealed_sender/server_certificate.dart`
- `lib/src/prekeys/pre_key_record.dart`
- `lib/src/prekeys/signed_pre_key_record.dart`
- `lib/src/prekeys/kyber_pre_key_record.dart`
- `lib/src/sealed_sender/sender_certificate.dart`

### Category E: Input Validation

**Problem:** Processing malformed input can cause crashes or security vulnerabilities.

**Fixes:**
- Added bounds checking before buffer operations in `IdentityKeyPair.deserialize()`
- Validates that buffer contains enough bytes before extracting data

**Example:**
```dart
if (offset + _kPublicKeyLength > data.length) {
  throw LibSignalException.invalidArgument(
    'identityKeyPair',
    'Buffer overrun: public key extends beyond data',
  );
}
```

**Files affected:**
- `lib/src/keys/identity_key_pair.dart`

### Category F: Information Disclosure Prevention

**Problem:** Logging or displaying sensitive data can lead to information leakage.

**Fixes:**
- Modified `ProtocolAddress.toString()` to redact sensitive identifiers
- Shows only first 4 characters + length instead of full name
- Example: `"alice"` becomes `"alic...[5]"`

**Files affected:**
- `lib/src/protocol/protocol_address.dart`

### Category G: Security Test Coverage

**Problem:** Security-critical code must have comprehensive test coverage.

**New test files:**
- `test/utils_test.dart` - Tests for `constantTimeEquals()`
- `test/secure_bytes_test.dart` - Tests for `SecureBytes` class
- Updated `test/prekeys/pre_key_record_test.dart` - Tests for disposed key handling

## Secure Development Guidelines

### Memory Management

1. **Always implement `dispose()` pattern:**
   ```dart
   bool _disposed = false;

   void _checkDisposed() {
     if (_disposed) {
       throw StateError('Object has been disposed');
     }
   }

   void dispose() {
     if (_disposed) return;
     _disposed = true;
     // Free resources
   }
   ```

2. **Use `try-finally` for FFI operations:**
   ```dart
   final ptr = calloc<SomeStruct>();
   try {
     // Use ptr
   } finally {
     calloc.free(ptr);
   }
   ```

3. **Use `SecureBytes` for sensitive data:**
   ```dart
   final secureKey = SecureBytes(keyData);
   try {
     // Use secureKey.bytes
   } finally {
     secureKey.dispose(); // Zeroes memory
   }
   ```

### Input Validation

1. **Validate sizes before deserialization:**
   ```dart
   SerializationValidator.validatePublicKey(data);
   ```

2. **Check bounds before buffer operations:**
   ```dart
   if (offset + length > data.length) {
     throw LibSignalException.invalidArgument(...);
   }
   ```

3. **Validate object state before use:**
   ```dart
   inputObject.checkNotDisposed();
   ```

### Cryptographic Operations

1. **Use constant-time comparison for secrets:**
   ```dart
   if (LibSignalUtils.constantTimeEquals(expected, actual)) {
     // Match
   }
   ```

2. **Never log or display cryptographic material:**
   ```dart
   // Wrong
   print('Key: $privateKey');

   // Correct
   print('Key: [REDACTED]');
   ```

3. **Zero sensitive data after use:**
   ```dart
   secureBytes.dispose(); // Automatically zeros
   ```

## Code Review Security Checklist

When reviewing code changes, verify:

- [ ] All FFI pointers are freed in `finally` blocks
- [ ] `dispose()` methods check `_disposed` flag
- [ ] `checkNotDisposed()` called on input objects in factory methods
- [ ] Buffer bounds checked before `sublistView()` operations
- [ ] Serialized data validated with `SerializationValidator`
- [ ] Constant-time comparison used for cryptographic data
- [ ] `toString()` methods don't expose sensitive data
- [ ] New security-critical code has test coverage

## Known Limitations

1. **Dart VM memory:** Memory zeroing in `SecureBytes` may not be effective if Dart GC has already copied the data. This is a platform limitation.

2. **FFI struct by value (ARM64):** Some functions using 16-byte structs passed by value have ABI issues on ARM64. See `CLAUDE.md` for workarounds.

3. **Timing side channels:** While `constantTimeEquals` provides constant-time comparison, other operations may still have timing variations due to Dart runtime behavior.

## Reporting Security Issues

If you discover a security vulnerability, please report it privately rather than opening a public issue. Contact the maintainers directly.
