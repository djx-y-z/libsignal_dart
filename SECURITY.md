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

### Category H: DateTime UTC Consistency

**Problem:** Using local time (`DateTime.now()`) for cryptographic timestamps causes:
- Certificate validation results varying by timezone
- Message timestamps inconsistent across devices
- Potential replay attack vulnerabilities

**Fixes:**
- All timestamp operations use UTC via `DateTime.now().toUtc()`
- `DateTime.fromMillisecondsSinceEpoch()` uses `isUtc: true`
- Library API accepts any DateTime and converts internally to UTC

**Files affected:**
- `lib/src/sealed_sender/sender_certificate.dart` - expiration, validate(), create()
- `lib/src/protocol/session_cipher.dart` - encryption timestamp
- `lib/src/sealed_sender/sealed_session_cipher.dart` - sealed sender timestamp
- `lib/src/protocol/session_builder.dart` - pre-key bundle timestamp
- All test files updated to use `.toUtc()`

### Category I: Secure Memory Zeroing

**Problem:** Sensitive data (plaintext, ciphertext, session records) persists in memory after `calloc.free()`.

**Fixes:**
- Added centralized `LibSignalUtils.zeroBytes()` function
- All sensitive buffers zeroed before `calloc.free()`
- Consistent pattern across all FFI operations

**Implementation:**
```dart
// In lib/src/utils.dart
static void zeroBytes(Uint8List? data) {
  if (data == null || data.isEmpty) return;
  for (var i = 0; i < data.length; i++) {
    data[i] = 0;
  }
}

// Usage in FFI operations
finally {
  LibSignalUtils.zeroBytes(plaintextPtr.asTypedList(plaintext.length));
  calloc.free(plaintextPtr);
}
```

**Files affected:**
- `lib/src/utils.dart` - centralized function
- `lib/src/protocol/session_cipher.dart` - encrypt/decrypt
- `lib/src/sealed_sender/sealed_session_cipher.dart` - encrypt/decrypt
- `lib/src/groups/group_session.dart` - encrypt/decrypt
- `lib/src/keys/public_key.dart` - deserialize, verify
- `lib/src/keys/private_key.dart` - deserialize

### Category J: Context Data Cleanup

**Problem:** Encryption/decryption context classes store sensitive session data without cleanup.

**Fixes:**
- Added `clear()` method to `_EncryptionContext` and `_DecryptionContext`
- Context data zeroed in `finally` blocks after use
- Prevents session state leakage

**Implementation:**
```dart
class _EncryptionContext {
  Uint8List? sessionRecordBytes;
  Uint8List? remoteIdentityBytes;
  // ...

  void clear() {
    LibSignalUtils.zeroBytes(sessionRecordBytes);
    LibSignalUtils.zeroBytes(remoteIdentityBytes);
    // Clear all sensitive fields
  }
}
```

**Files affected:**
- `lib/src/protocol/session_cipher.dart`
- `lib/src/sealed_sender/sealed_session_cipher.dart`

### Category K: SecureBytes Finalizer

**Problem:** If user forgets to call `dispose()`, sensitive data may leak to garbage collector.

**Fixes:**
- Added `Finalizer<Uint8List>` as safety net
- Automatically zeros data if object is garbage collected
- Explicit `dispose()` still recommended for deterministic cleanup

**Implementation:**
```dart
final Finalizer<Uint8List> _secureBytesProtector = Finalizer(
  LibSignalUtils.zeroBytes,
);

class SecureBytes {
  SecureBytes(this._data) {
    _secureBytesProtector.attach(this, _data, detach: this);
  }

  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _secureBytesProtector.detach(this);
      LibSignalUtils.zeroBytes(_data);
    }
  }
}
```

**Files affected:**
- `lib/src/secure_bytes.dart`

### Category L: Operation Counter Overflow Protection

**Problem:** Group session operation counter could overflow after ~2^63 operations.

**Fixes:**
- Added overflow check with reset to 1
- Prevents potential undefined behavior

**Implementation:**
```dart
int _nextOperationId() {
  _operationCounter++;
  if (_operationCounter > 0x7FFFFFFFFFFFFFF) {
    _operationCounter = 1;
  }
  return _operationCounter;
}
```

**Files affected:**
- `lib/src/groups/group_session.dart`

### Category M: PublicKey hashCode Secure Caching

**Problem:** `PublicKey.hashCode()` called `serialize()` on every invocation without zeroing the resulting bytes, causing key material to accumulate in memory.

**Fixes:**
- Added lazy caching of hash code on first access
- Bytes are securely zeroed after computing hash
- Cache is checked before serialization on subsequent calls

**Implementation:**
```dart
int? _cachedHashCode;

@override
int get hashCode {
  if (_disposed) return 0;
  if (_cachedHashCode != null) return _cachedHashCode!;

  final bytes = serialize();
  try {
    _cachedHashCode = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
    return _cachedHashCode!;
  } finally {
    LibSignalUtils.zeroBytes(bytes);
  }
}
```

**Files affected:**
- `lib/src/keys/public_key.dart`

### Category N: Unified Exception Types

**Problem:** Disposed object checks threw `StateError` instead of `LibSignalException`, making error handling inconsistent.

**Fixes:**
- Added `LibSignalException.disposed()` factory method
- All disposed checks now throw `LibSignalException` with context 'disposed'
- Consistent exception type across entire library

**Files affected:**
- `lib/src/exception.dart` - new factory method
- All files with disposed object checks (23 files)

### Category O: Protocol Address Validation

**Problem:** `ProtocolAddress` deviceId parameter was not validated, allowing negative values.

**Fixes:**
- Added validation: `deviceId >= 0`
- Throws `LibSignalException.invalidArgument` for negative values

**Files affected:**
- `lib/src/protocol/protocol_address.dart`

### Category P: Callback Pointer Zeroing

**Problem:** FFI callback handlers freed pointers without zeroing them first.

**Fixes:**
- Added defensive zeroing of pointers before `calloc.free()`
- Defense in depth against use-after-free

**Files affected:**
- `lib/src/protocol/session_cipher.dart`
- `lib/src/sealed_sender/sealed_session_cipher.dart`

### Category Q: Thread Safety Documentation

**Problem:** Global mutable state in GroupSession was not documented as non-thread-safe.

**Fixes:**
- Added warning documentation about thread safety limitations
- Clear guidance for multi-isolate scenarios

**Files affected:**
- `lib/src/groups/group_session.dart`

### Category R: Sensitive Data Documentation

**Problem:** `serialize()` methods returning sensitive data lacked security documentation.

**Fixes:**
- Added Security Note to `PreKeyRecord.serialize()`
- Added Security Note to `SenderKeyRecord.serialize()`
- Added Security Note to `IdentityKeyPair.deserialize()`
- Clear guidance on zeroing returned/input data

**Files affected:**
- `lib/src/prekeys/pre_key_record.dart`
- `lib/src/groups/sender_key_record.dart`
- `lib/src/keys/identity_key_pair.dart`

## Secure Development Guidelines

### Memory Management

1. **Always implement `dispose()` pattern:**
   ```dart
   bool _disposed = false;

   void _checkDisposed() {
     if (_disposed) {
       throw LibSignalException.disposed('ObjectType');
     }
   }

   void dispose() {
     if (_disposed) return;
     _disposed = true;
     // Free resources
   }
   ```

2. **Use `try-finally` for FFI operations with memory zeroing:**
   ```dart
   final ptr = calloc<Uint8>(dataLength);
   try {
     // Use ptr
   } finally {
     LibSignalUtils.zeroBytes(ptr.asTypedList(dataLength));
     calloc.free(ptr);
   }
   ```

3. **Use centralized `zeroBytes()` for sensitive data:**
   ```dart
   // Don't write inline loops - use the centralized function
   LibSignalUtils.zeroBytes(sensitiveData);
   ```

4. **Use `SecureBytes` for sensitive data:
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

### DateTime Handling

1. **Always use UTC for cryptographic timestamps:**
   ```dart
   // Wrong - local time varies by timezone
   final now = DateTime.now();

   // Correct - UTC is timezone-independent
   final now = DateTime.now().toUtc();
   ```

2. **Convert timestamps to UTC internally:**
   ```dart
   // Accept any DateTime but convert to UTC
   final utcTime = inputTime.toUtc();
   final timestampMs = utcTime.millisecondsSinceEpoch;
   ```

3. **Parse timestamps as UTC:**
   ```dart
   // Wrong - returns local time
   DateTime.fromMillisecondsSinceEpoch(value);

   // Correct - returns UTC time
   DateTime.fromMillisecondsSinceEpoch(value, isUtc: true);
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
   LibSignalUtils.zeroBytes(sensitiveBuffer);
   secureBytes.dispose(); // Automatically zeros
   ```

4. **Clean up context objects:**
   ```dart
   final context = _EncryptionContext();
   try {
     // Use context
   } finally {
     context.clear(); // Zero all sensitive fields
   }
   ```

## Code Review Security Checklist

When reviewing code changes, verify:

- [ ] All FFI pointers are freed in `finally` blocks
- [ ] Sensitive FFI buffers zeroed with `LibSignalUtils.zeroBytes()` before `calloc.free()`
- [ ] `dispose()` methods check `_disposed` flag
- [ ] `checkNotDisposed()` called on input objects in factory methods
- [ ] Buffer bounds checked before `sublistView()` operations
- [ ] Serialized data validated with `SerializationValidator`
- [ ] Constant-time comparison used for cryptographic data
- [ ] `toString()` methods don't expose sensitive data
- [ ] `DateTime.now().toUtc()` used instead of `DateTime.now()`
- [ ] `DateTime.fromMillisecondsSinceEpoch()` uses `isUtc: true`
- [ ] Context classes have `clear()` method for sensitive data
- [ ] New security-critical code has test coverage

## Known Limitations

1. **Dart VM memory:** Memory zeroing in `SecureBytes` may not be effective if Dart GC has already copied the data. This is a platform limitation. The `Finalizer` added to `SecureBytes` provides a safety net but is not a guarantee.

2. **FFI struct by value (ARM64):** Some functions using 16-byte structs passed by value have ABI issues on ARM64. See `CLAUDE.md` for workarounds.

3. **Timing side channels:** While `constantTimeEquals` provides constant-time comparison, other operations may still have timing variations due to Dart runtime behavior.

4. **Finalizer timing:** The `SecureBytes` finalizer runs at GC's discretion, not immediately when the object becomes unreachable. Always prefer explicit `dispose()` calls for deterministic cleanup.

## Reporting Security Issues

If you discover a security vulnerability, please report it privately rather than opening a public issue. Contact the maintainers directly.
