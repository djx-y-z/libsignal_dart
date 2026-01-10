---
name: security-review
description: Review libsignal Dart FFI code for security issues. Use when reviewing code changes, checking for memory leaks, verifying secure memory handling, or auditing cryptographic code.
allowed-tools:
  - Read
  - Grep
  - Glob
---

# Security Review for libsignal_dart

Review code for security issues specific to this Signal Protocol FFI library.

## Security Categories (A-R)

This project has established 18 security categories. See `SECURITY.md` for full details.

## Quick Checklist

### A: FFI Memory Management

- [ ] All FFI pointers freed using `signal_*_destroy()` or `calloc.free()`
- [ ] `dispose()` pattern with `_disposed` flag to prevent double-free
- [ ] Null-pointer checks before freeing

### B: Buffer Overflow Prevention

- [ ] Use `SerializationValidator` for validating serialized data
- [ ] Bounds checking before `sublistView()` operations

```dart
SerializationValidator.validatePublicKey(data);
SerializationValidator.validateSessionRecord(data);
```

### C: Timing Attack Prevention

- [ ] Use `LibSignalUtils.constantTimeEquals()` for cryptographic data
- [ ] NEVER use `==` or loop comparison for secrets

```dart
// CORRECT
if (LibSignalUtils.constantTimeEquals(expected, actual)) { ... }

// WRONG - vulnerable to timing attacks!
if (expected == actual) { ... }
```

### D: Disposed State Validation

- [ ] `_checkDisposed()` called at start of public methods
- [ ] Factory methods validate input objects: `inputObject.checkNotDisposed()`

```dart
void _checkDisposed() {
  if (_disposed) {
    throw LibSignalException.disposed('ClassName');
  }
}
```

### E: Input Validation

- [ ] Bounds checking before buffer operations

```dart
if (offset + length > data.length) {
  throw LibSignalException.invalidArgument(
    'paramName',
    'Buffer overrun: data extends beyond buffer',
  );
}
```

### F: Information Disclosure

- [ ] `toString()` methods redact sensitive data
- [ ] No logging of keys, secrets, or plaintext

### G: Test Coverage

- [ ] Security-critical code has test coverage
- [ ] Tests verify disposed state behavior

### H: DateTime UTC Consistency

- [ ] Use `DateTime.now().toUtc()` (not `DateTime.now()`)
- [ ] Use `DateTime.fromMillisecondsSinceEpoch(value, isUtc: true)`

### I: Secure Memory Zeroing

- [ ] Sensitive buffers zeroed with `LibSignalUtils.zeroBytes()` before `calloc.free()`

```dart
finally {
  LibSignalUtils.zeroBytes(plaintextPtr.asTypedList(plaintext.length));
  calloc.free(plaintextPtr);
}
```

### J: Context Data Cleanup

- [ ] Encryption/decryption context classes have `clear()` method
- [ ] Context cleared in `finally` blocks

### K: SecureBytes Usage

- [ ] Sensitive data wrapped in `SecureBytes`
- [ ] `dispose()` called explicitly (don't rely only on finalizer)

```dart
final secureKey = SecureBytes(keyData);
try {
  // Use secureKey.bytes
} finally {
  secureKey.dispose();
}
```

### L: Counter Overflow

- [ ] Operation counters have overflow protection

### M: hashCode Secure Caching

- [ ] `hashCode` implementations zero temporary buffers

### N: Unified Exceptions

- [ ] All disposed checks throw `LibSignalException.disposed()`
- [ ] NOT `StateError`

### O: Parameter Validation

- [ ] Validate numeric parameters (e.g., `deviceId >= 0`)

### P: Callback Pointer Zeroing

- [ ] FFI callback handlers zero pointers before `calloc.free()`

### Q: Thread Safety Documentation

- [ ] Global mutable state documented as non-thread-safe

### R: Sensitive Data Documentation

- [ ] Methods returning sensitive data have `/// **Security Note:**` docs

## Red Flags

- `calloc.free()` without prior `zeroBytes()` for sensitive data
- Missing `_checkDisposed()` in public methods
- `==` used for key/secret comparison
- `DateTime.now()` without `.toUtc()`
- `StateError` instead of `LibSignalException.disposed()`
- Logging or printing cryptographic material

## Example Review Output

```
## Security Review: lib/src/new_feature.dart

### Issues Found

1. **Line 45**: Missing `zeroBytes()` before `calloc.free()`
   - Category: I
   - Severity: HIGH
   - Fix: Add `LibSignalUtils.zeroBytes(ptr.asTypedList(length))` before free

2. **Line 78**: Using `==` for signature comparison
   - Category: C
   - Severity: HIGH
   - Fix: Use `LibSignalUtils.constantTimeEquals(a, b)`

3. **Line 102**: `DateTime.now()` without `.toUtc()`
   - Category: H
   - Severity: MEDIUM
   - Fix: Change to `DateTime.now().toUtc()`

### Recommendations

- Add `clear()` method to context class on line 30
- Add security warning to `exportKey()` docstring
```
