# Security

## Architecture Overview

This library uses **Flutter Rust Bridge (FRB)** with the **libsignal-protocol** Rust crate.

**Key security properties:**

- **Memory safety** is handled by Rust's ownership system
- **Cryptographic operations** are implemented in libsignal-protocol (Signal's official Rust implementation)
- **No manual memory management** in Dart - FRB handles all cleanup automatically
- **No `dispose()` calls needed for correctness** - Rust drops resources when the
  owning Dart object is garbage-collected. Cleanup timing is *not* deterministic,
  so security-critical code holding secrets should still dispose explicitly
  (see [A: Memory Safety](#a-memory-safety-rust-handled))

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

#### Cleanup timing and secret material

An opaque handle (`PrivateKey`, `KyberSecretKey`, `SessionRecord`, …) keeps its
Rust value — including any secret key material — alive in **native memory** until
the underlying `Arc` is dropped, which only happens when Dart's garbage collector
eventually reclaims the Dart object via its `NativeFinalizer`. **GC timing is
non-deterministic**: the secret can linger in native memory from milliseconds to
minutes after your last use.

For ordinary use this is fine — the statement "no `dispose()` calls needed" is
correct for *correctness* and leak-freedom. But when you are building a secure
messenger on top of this library, minimise the window in which secrets are
resident:

```dart
final privateKey = PrivateKey.generate();
try {
  final signature = privateKey.sign(message: data);
  // ...
} finally {
  privateKey.dispose(); // frees the native allocation now, not at GC time
}
```

`dispose()` (from FRB's `RustOpaqueInterface`) is available on every opaque type
and forces the drop deterministically instead of waiting for the GC. After
`dispose()` the handle must not be used again (`isDisposed` becomes `true`).

Note what `dispose()` does and does not guarantee. It **bounds how long the
secret is resident and reachable** by returning the native allocation to the
allocator immediately rather than at an unpredictable GC point — a real
reduction in exposure. It does **not** actively wipe those bytes: libsignal's
extractable key types are not zeroized on drop (`PrivateKey` is `Copy`, so it
cannot have a `Drop` impl at all; the Kyber `SecretKey` holds a plain boxed
buffer with no `ZeroizeOnDrop`), so the freed memory is reclaimed unwiped and
lingers until the allocator reuses it. Prompt `dispose()` therefore shrinks the
window but is not erasure. This matters most for the secret-bearing types
(`PrivateKey`, `KyberSecretKey`, key pairs, and the record types that embed
them) and for any copies made via `cloneKey()` — each copy holds its own native
secret. The strongest protection is to not extract secrets into Dart in the
first place (keep them behind opaque handles).

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

### J: Zeroing Sensitive Data

The library provides utilities for zeroing sensitive data in Dart.

#### SecureBytes wrapper (automatic zeroing)

```dart
// Wrap takes ownership - no extra copy
final secureData = SecureBytes.wrap(sensitiveBytes);
try {
  // ... use secureData.bytes ...
} finally {
  secureData.dispose(); // Immediate zeroing (recommended)
}

// Copy constructor - original NOT zeroed (caller responsible)
final secureCopy = SecureBytes(sensitiveBytes);
sensitiveBytes.zeroize(); // Zero the original yourself
```

#### Manual zeroing extension

```dart
final sensitiveList = Uint8List.fromList([...]);
try {
  // ... use sensitiveList ...
} finally {
  sensitiveList.zeroize(); // Zero all bytes
}
```

**Limitations:**
- Dart's garbage collector may copy data before zeroing
- These utilities provide defence-in-depth, not absolute security guarantees
- For critical secrets, prefer keeping them in Rust (opaque types)

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
- [ ] Sensitive data in Dart uses `SecureBytes` or `zeroize()` extension

## What's Handled by Rust/FRB

These concerns from the old C FFI architecture are now handled automatically:

| Old Concern | Now Handled By |
|-------------|----------------|
| FFI pointer management | Rust ownership |
| `dispose()` pattern | Rust drop semantics |
| Double-free prevention | Rust borrow checker |
| Buffer overflow prevention | Rust bounds checking |
| Use-after-free | Rust ownership |
| Memory zeroing (Rust-side only) | Rust (zeroize crate in libsignal) |

> **Memory zeroing covers Rust memory only.** libsignal's `zeroize` guarantees
> apply to secrets *while they live inside Rust*. As soon as a value crosses the
> FFI boundary into Dart — every `serialize()` / `private_key()` call returns a
> `Vec<u8>` that becomes a Dart `Uint8List` — those bytes live on the Dart GC
> heap, which is **never zeroed on collection** (freed blocks go back on the VM
> free-list unsanitized, and the copying scavenger duplicates live objects
> without wiping the from-space copy). On the Dart side, `SecureBytes` /
> `zeroize()` are **best-effort defence-in-depth, not a guarantee** (see
> [J: Zeroing Sensitive Data](#j-zeroing-sensitive-data)). For strong guarantees,
> keep secrets in Rust (opaque types) and avoid serializing them into Dart at all.

## Supply Chain Security

Native libraries are built from source in GitHub Actions and downloaded by the
build hook (`hook/build.dart`) from GitHub Releases at consumer build time.

- **Integrity (implemented):** every downloaded archive is verified against a
  SHA256 checksum published in the same release. Verification is **fail-closed** —
  if the checksums file cannot be fetched or lacks an entry for the archive, the
  build **aborts** rather than loading an unverified binary. The escape hatch
  `LIBSIGNAL_ALLOW_UNVERIFIED_DOWNLOAD=1` exists only for building against older
  releases with no checksums file and should not be used in production.
- **Authenticity (not yet implemented):** the checksums file is served from the
  same release as the archive, so SHA256 alone does not defend against a release
  or maintainer-token compromise (an attacker who replaces the archive can also
  replace its checksum). A detached signature (e.g. minisign/cosign) with a
  public key pinned in `hook/build.dart`, plus SLSA build provenance
  (`actions/attest-build-provenance`), is the recommended next step and is
  tracked as future work.

### Release & build-trigger protection

The native binaries above are published by `build-libsignal.yml`, triggered by a
`libsignal_frb-*` tag push or by manual dispatch. Two controls restrict who can
cause a publish, mirroring the `pub.dev` environment that gates the pub.dev
publish:

- **Tag protection** — a repository ruleset restricts creating, moving, and
  deleting **all tags** to Admins/Maintainers (and requires them signed), so a
  plain `write` collaborator cannot mint a release tag (`libsignal_frb-*` / `v*`)
  or any other tag.
- **Approval gate** — the publishing job runs in the `native-build` environment,
  whose required reviewers must approve before any binary is released. Unlike the
  tag ruleset, this also covers the `workflow_dispatch` path.

Rationale, exact `gh` commands to apply/verify/roll back, the current ruleset
inventory, and residual risks are in
[`.github/rulesets/README.md`](.github/rulesets/README.md).

### Dependency Auditing

Two complementary checks run in CI (on pushes to `main` and on pull requests
that touch the sources) and can be run locally:

```bash
make rust-audit   # cargo audit — fails on known RustSec vulnerabilities
make rust-deny    # cargo deny — advisories + license + source allow-list policy
```

`rust/deny.toml` restricts dependency sources to crates.io and the official
Signal git repositories, and constrains licenses to an AGPL-compatible set.

## Static Analysis

Both language surfaces are linted in CI (and can be run locally):

```bash
make analyze ARGS="--fatal-infos"   # dart analyze — Dart/Flutter lints (fatal infos)
make rust-clippy                    # cargo clippy --all-targets -- -D warnings
```

`make rust-clippy` treats every Clippy warning as an error, so the hand-written
Rust wrapper stays lint-clean. The handful of Clippy lints that are inherent to
the FRB boundary — the many-argument store-callback signatures and the tuple
return types the async wrappers hand back — carry a justified site-local
`#[allow]` rather than a blanket suppression. The FRB-generated bridge is out of
scope. The separate, nightly-only fuzz crate can additionally be linted with
`cd rust/fuzz && cargo +nightly clippy` — a manual command, not part of the CI
clippy gate.

## Fuzzing

Byte-parsing entry points (the network/storage boundary) are covered by
`cargo-fuzz` targets under `rust/fuzz/`:

| Target | Covers |
|--------|--------|
| `keys` | `PublicKey` / `PrivateKey` / `IdentityKeyPair` deserialization |
| `messages` | `SignalMessage` / `DecryptionErrorMessage` parsing |
| `records` | pre-key / signed-pre-key / session / Kyber record deserialization |
| `certificates` | sealed-sender certificate parsing and validation |
| `crypto_primitives` | HKDF, AES-256-GCM-SIV, fingerprint comparison |
| `session_decrypt` | pre-key message decryption (network-controlled ciphertext) |

```bash
make setup-fuzz                          # one-time: nightly toolchain + cargo-fuzz
make fuzz-seed                           # generate a valid seed corpus
make fuzz ARGS="keys -- -max_total_time=60"
```

A dedicated `Fuzz` workflow runs a short smoke pass on every PR that touches
`rust/**` and a longer weekly pass, uploading any crash reproducer as an artifact.

## Identity Trust (MITM / safety-number-change detection)

Identity-trust is **enforced on every session operation**, matching upstream
libsignal's `is_trusted_identity` semantics: session establishment
(`processPreKeyBundle`), encryption (`SessionCipher.encrypt` and
`SealedSenderCipher.encrypt` — upstream's `Direction::Sending` check), and
decryption of both pre-key and regular (Whisper) messages, including Sealed
Sender (`Direction::Receiving`). The library pre-seeds the previously-trusted
remote identity (read from your `IdentityKeyStore.getIdentity`) into libsignal,
so a **remote identity key that differs from the stored one is rejected with an
`UntrustedIdentity` error** rather than being silently accepted — whether it
arrives in a new bundle / pre-key message or disagrees with the identity bound
to an existing session. First contact (no stored identity) is
trusted-on-first-use.

Applications **must handle the `UntrustedIdentity` error** (its message contains
`untrusted identity`): treat it as a safety-number change — surface it to the
user, and only after explicit verification save the new identity (or remove the
old one) in your store. Note that after re-trusting a new identity, messages
from sessions still bound to the old key are rejected too — archive or delete
the old session for that address so a fresh one is established. Continue to
offer fingerprint / safety-number verification via `Fingerprint`.

This depends on your `IdentityKeyStore` implementing `getIdentity` correctly (the
provided in-memory store does). A store that always returns `null` from
`getIdentity` effectively disables the check.

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
