---
name: security-review
description: Review libsignal Dart code for security issues. Use when reviewing code changes, checking for proper API usage, verifying secure patterns, or auditing cryptographic code.
allowed-tools:
  - Read
  - Grep
  - Glob
---

# Security Review for libsignal_dart

Review code for security issues specific to this Signal Protocol library.

## Architecture Context

This library uses Flutter Rust Bridge (FRB) with libsignal-protocol (pure Rust):
- **Memory safety** is handled by Rust (no manual FFI memory management)
- **Cryptographic operations** are implemented in libsignal-protocol
- **Store callbacks** use DartFn to bridge Dart stores to Rust

## Security Categories

### A: API Usage Correctness

- [ ] Correct constructor patterns used (`PrivateKey.generate()` not manual FFI)
- [ ] Proper async/await for store operations
- [ ] Store callbacks return correct data types

### B: Store Security

- [ ] Production stores use secure storage (not in-memory)
- [ ] Session records persisted correctly (Double Ratchet state)
- [ ] Identity keys stored in secure storage (e.g., flutter_secure_storage)

```dart
// ❌ WRONG - in-memory stores lose state on restart
final sessionStore = InMemorySessionStore();

// ✅ CORRECT - production stores persist securely
final sessionStore = SecureSqliteSessionStore();
```

### C: Timing Attack Prevention

All cryptographic operations are handled by Rust's libsignal-protocol with constant-time implementations.

- [ ] Let library handle cryptographic comparisons
- [ ] Avoid comparing serialized cryptographic data directly in Dart

```dart
// ✅ CORRECT - let Rust handle cryptographic verification
final isValid = publicKey.verifySignature(message: data, signature: sig);

// ✅ CORRECT - compare public keys using library methods
final keysMatch = key1.compare(other: key2) == 0;

// ❌ AVOID - comparing serialized cryptographic data in Dart
if (key1.serialize() == key2.serialize()) { ... }  // Not constant-time
```

### D: DateTime UTC Consistency

- [ ] Use `DateTime.now().toUtc()` (not `DateTime.now()`)
- [ ] Use `DateTime.fromMillisecondsSinceEpoch(value, isUtc: true)`
- [ ] Certificate validation uses UTC timestamps

```dart
// ✅ CORRECT
final now = DateTime.now().toUtc();
final expiration = DateTime.fromMillisecondsSinceEpoch(ms, isUtc: true);

// ❌ WRONG - local time can cause certificate validation issues
final now = DateTime.now();
```

### E: Key Material Handling

- [ ] Private keys not logged or printed
- [ ] Serialized keys not stored in plain text
- [ ] Keys not included in error messages

```dart
// ❌ WRONG - exposes key material
print('Generated key: ${privateKey.serialize()}');
throw Exception('Failed with key: $keyBytes');

// ✅ CORRECT - no key material in logs
print('Generated new private key');
throw Exception('Key operation failed');
```

### F: Certificate Validation

- [ ] Trust roots properly configured
- [ ] Certificate expiration checked
- [ ] Server certificates validated before use

```dart
// ✅ CORRECT - validate before use
final isValid = senderCert.validate(
  trustRoot: serverTrustRoot,
  timestamp: DateTime.now().toUtc(),
);
if (!isValid) {
  throw SecurityException('Invalid sender certificate');
}
```

### G: Error Handling

- [ ] Cryptographic failures don't leak information
- [ ] Proper exception types used
- [ ] Errors logged without sensitive data

```dart
// ✅ CORRECT
try {
  final plaintext = await cipher.decrypt(ciphertext);
} catch (e) {
  // Log operation failure, not the ciphertext
  log.warning('Decryption failed for message from ${sender.name}');
  rethrow;
}
```

### H: Concurrency Safety

- [ ] Store operations properly synchronized
- [ ] No race conditions in session updates

```dart
// ✅ CORRECT - synchronized store access
class MySessionStore implements SessionStore {
  final _lock = Lock();

  @override
  Future<void> storeSession(ProtocolAddress addr, SessionRecord record) async {
    await _lock.synchronized(() async {
      await _db.insert('sessions', record.serialize());
    });
  }
}
```

### I: Input Validation

- [ ] Device IDs validated (1-127 range)
- [ ] UUIDs properly formatted
- [ ] Serialized data length checked

```dart
// ✅ FRB validates in Rust - but Dart code should also check
if (deviceId < 1 || deviceId > 127) {
  throw ArgumentError('Device ID must be 1-127');
}
```

### J: Initialization

- [ ] `LibSignal.init()` called before use
- [ ] Proper cleanup on app termination (optional)

```dart
void main() async {
  await LibSignal.init();  // Initialize FRB
  runApp(MyApp());
}
```

## Quick Checklist

```
[ ] No in-memory stores in production code
[ ] No key material in logs/errors
[ ] UTC timestamps for certificates
[ ] Cryptographic comparisons via library methods (not raw bytes)
[ ] Proper async/await for store operations
[ ] LibSignal.init() called at startup
[ ] Store operations synchronized
```

## Red Flags

- `InMemorySessionStore` in production code
- `print()` or logging with key bytes
- `DateTime.now()` without `.toUtc()`
- Comparing serialized cryptographic data with `==` in Dart
- Missing `await` on store operations
- Certificate validation without timestamp check

## Example Review Output

```
## Security Review: lib/src/my_feature.dart

### Issues Found

1. **Line 45**: Using in-memory store in production
   - Category: B
   - Severity: HIGH
   - Fix: Implement persistent secure storage

2. **Line 78**: DateTime.now() without UTC
   - Category: D
   - Severity: MEDIUM
   - Fix: Change to `DateTime.now().toUtc()`

3. **Line 102**: Key bytes logged
   - Category: E
   - Severity: HIGH
   - Fix: Remove key material from log statement

### Recommendations

- Add lock synchronization to store operations
- Validate device IDs before creating addresses
```

## Files to Review

| Area | Files |
|------|-------|
| Store implementations | `lib/src/stores/**/*.dart` |
| Session operations | `lib/src/protocol/*.dart` |
| Certificate handling | `lib/src/sealed_sender/*.dart` |
| Group messaging | `lib/src/groups/*.dart` |

## Reference

- See `SECURITY.md` for full security guidelines
- See `.claude/skills/stores-implementation/SKILL.md` for production store patterns
