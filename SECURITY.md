# Security

## Architecture Overview

This library uses **Flutter Rust Bridge (FRB)** with the **libsignal-protocol** Rust crate.

**Key security properties:**

- **Memory safety** is handled by Rust's ownership system
- **Cryptographic operations** are implemented in libsignal-protocol (Signal's official Rust implementation)
- **No manual memory management** in Dart - FRB handles all cleanup automatically
- **No `dispose()` calls needed** - Rust drops resources when they go out of scope

## Security Considerations

### A: Memory Safety (Rust-handled)

With FRB, memory management is handled automatically:

```dart
// FRB Architecture - no cleanup needed
final privateKey = PrivateKey.generate();
final signature = privateKey.sign(message: data);
// privateKey is automatically cleaned up when no longer referenced
```

Rust's ownership system ensures:
- No use-after-free
- No double-free
- No memory leaks
- Deterministic cleanup

### B: Timing Attack Prevention

All cryptographic operations and comparisons are handled by Rust's libsignal-protocol, which uses constant-time implementations internally.

**Best practice:** Avoid comparing cryptographic data in Dart code. Let the library handle it:

```dart
// CORRECT - let Rust handle cryptographic verification
final isValid = publicKey.verifySignature(message: data, signature: sig);

// CORRECT - compare public keys using library methods
final keysMatch = key1.compare(other: key2) == 0;

// AVOID - comparing serialized cryptographic data in Dart
if (key1.serialize() == key2.serialize()) { ... }  // Not constant-time
```

If you must compare bytes in Dart (e.g., for non-cryptographic purposes), use a constant-time implementation from a crypto package like `package:crypto`.

### C: DateTime UTC Consistency

Always use UTC for cryptographic timestamps:

```dart
// Correct - UTC is timezone-independent
final now = DateTime.now().toUtc();
final expiration = DateTime.fromMillisecondsSinceEpoch(ms, isUtc: true);

// WRONG - local time varies by timezone, can cause certificate validation issues
final now = DateTime.now();
```

This affects:
- Certificate validation (SenderCertificate, ServerCertificate)
- Session timestamps
- Key expiration checks

### D: Store Security

Stores persist sensitive cryptographic state. For production:

```dart
// WRONG - testing only, data lost on restart
final sessionStore = InMemorySessionStore();

// CORRECT - production stores persist securely
final sessionStore = SecureSqliteSessionStore();  // Implement yourself
```

**Store security requirements:**

1. **SessionStore** - Persist session records (Double Ratchet state)
2. **IdentityKeyStore** - Store identity keys in secure storage (e.g., flutter_secure_storage)
3. **PreKeyStore** - One-time keys, consumed after use
4. **SignedPreKeyStore** - Rotate periodically (e.g., weekly)
5. **KyberPreKeyStore** - Post-quantum keys
6. **SenderKeyStore** - Group session keys

### E: Key Material Handling

Never expose key material in logs or errors:

```dart
// WRONG - exposes key material
print('Generated key: ${privateKey.serialize()}');
throw Exception('Failed with key: $keyBytes');

// CORRECT - no key material in logs
print('Generated new private key');
throw Exception('Key operation failed');
```

### F: Certificate Validation

Always validate certificates before use:

```dart
final isValid = senderCert.validate(
  trustRoot: serverTrustRoot,
  timestamp: DateTime.now().toUtc(),
);
if (!isValid) {
  throw SecurityException('Invalid sender certificate');
}
```

### G: Input Validation

Device IDs and other inputs are validated in Rust, but Dart code should also validate:

```dart
// FRB validates in Rust, but Dart code can also check
if (deviceId < 1 || deviceId > 127) {
  throw ArgumentError('Device ID must be 1-127');
}
```

### H: Concurrency Safety

Store operations should be properly synchronized:

```dart
import 'package:synchronized/synchronized.dart';

class MySessionStore implements SessionStore {
  final _lock = Lock();
  final Database _db;

  @override
  Future<void> storeSession(ProtocolAddress address, SessionRecord record) async {
    await _lock.synchronized(() async {
      await _db.insert('sessions', {
        'address': '${address.name()}:${address.deviceId()}',
        'record': record.serialize(),
      });
    });
  }
}
```

### I: Initialization

Always initialize the library before use:

```dart
void main() async {
  await LibSignal.init();  // Initialize FRB runtime
  runApp(MyApp());
}
```

## Code Review Security Checklist

When reviewing code changes, verify:

- [ ] No in-memory stores in production code
- [ ] No key material in logs or error messages
- [ ] `DateTime.now().toUtc()` used for timestamps
- [ ] `DateTime.fromMillisecondsSinceEpoch()` uses `isUtc: true`
- [ ] Cryptographic comparisons done via library methods (not raw byte comparison)
- [ ] Certificates validated before use
- [ ] Store operations properly synchronized
- [ ] `LibSignal.init()` called before any operations

## What's Handled by Rust/FRB

These concerns from the old C FFI architecture are now handled automatically:

| Old Concern | Now Handled By |
|-------------|----------------|
| FFI pointer management | Rust ownership |
| `dispose()` pattern | Rust drop semantics |
| Double-free prevention | Rust borrow checker |
| Buffer overflow prevention | Rust bounds checking |
| Use-after-free | Rust ownership |
| Memory zeroing | Rust (zeroize crate in libsignal) |

## Known Limitations

1. **Dart VM memory:** Dart's garbage collector may copy data before Rust can zero it. This is a platform limitation, but libsignal's Rust code uses the `zeroize` crate for sensitive data.

2. **Timing side channels:** All cryptographic operations use constant-time implementations in libsignal-protocol (Rust). Avoid comparing cryptographic data directly in Dart.

3. **Store persistence:** In-memory stores lose all state on app restart. Production apps must implement persistent stores.

### Plaintext Handling After Decryption

After decryption, plaintext is intentionally NOT zeroized because:

1. **Plaintext is application data** - per NIST guidelines, zeroization applies to cryptographic keys and secret data, not application plaintext
2. **Responsibility transfer** - once decrypted, data belongs to the application layer
3. **Keys ARE zeroized** - identity key pairs and session keys are properly zeroized after use

If your application requires plaintext zeroization, implement it at the Dart layer after processing.

## Reporting Security Issues

If you discover a security vulnerability, please report it privately rather than opening a public issue. Contact the maintainers directly.
