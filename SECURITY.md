# Security

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### How to Report

Use [GitHub Security Advisories](https://github.com/djx-y-z/libsignal_dart/security/advisories/new) to report vulnerabilities privately, so the risk can be assessed and a fix prepared before public disclosure.

Please include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- A suggested fix (if any)

### Response Timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix timeline**: depends on severity, typically 30–90 days

### Coordinated Disclosure

We follow coordinated disclosure. Once a fix is available we will (1) release a patched version, (2) publish a security advisory, and (3) credit the reporter unless anonymity is requested.

## Security Scope

### In Scope

This package provides Dart bindings to [libsignal](https://github.com/signalapp/libsignal) via Flutter Rust Bridge. The security scope covers:

- **Memory safety** of the FRB wrapper and the hand-written Rust in `rust/src/api/`
- **Correct API usage** of the underlying libsignal primitives (session handling, identity-trust enforcement, key management)
- **Secret handling** across the FFI boundary (deterministic `dispose()`, `zeroize()`, keeping secrets in Rust where possible)
- **Supply-chain integrity** of the prebuilt native binaries (build pipeline, fail-closed download verification, release/tag protections)

### Out of Scope

The cryptography itself is implemented and maintained by the upstream **libsignal** project (Signal Foundation):

- The Signal Protocol / Double Ratchet / X3DH / PQXDH algorithm implementations
- Constant-time / side-channel resistance of the cryptographic code
- Cryptographic protocol design and proofs

Report vulnerabilities in the underlying protocol or cryptography to the [libsignal project](https://github.com/signalapp/libsignal/security).

### Threat Model Limitations

This library inherits libsignal's threat model. Out of scope:

- **Physical side-channels** (power analysis, electromagnetic emissions)
- **Fault injection** (Rowhammer, voltage/clock glitching)
- **Hardware vulnerabilities**
- **Compromised host** — an OS/runtime/memory an attacker controls; secrets that cross into Dart's GC heap cannot be reliably erased (see [A: Memory Safety](#a-memory-safety-rust-handled))

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

Confidentiality of the stored data is only half of it: because message keys are
derived deterministically, a write that is lost or rolled back causes key reuse.
[Store Durability, Write Ordering and Rollback](#store-durability-write-ordering-and-rollback)
states the contract your implementations must satisfy — read it before writing a
production store.

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

Synchronize at the **call site**, not inside the store. A lock inside
`storeSession` serializes writes but leaves the dangerous window wide open: the
`load → ratchet → store` cycle spans the whole cipher call, so two concurrent
`encrypt` calls for one address both load the same session and derive the same
message key.

```dart
import 'package:synchronized/synchronized.dart';

// WRONG (necessary, not sufficient) - the lock is inside the store
class MySessionStore implements SessionStore {
  final _lock = Lock();

  @override
  Future<void> storeSession(ProtocolAddress address, SessionRecord record) =>
      _lock.synchronized(() => _db.upsertSession(address, record));
}

// CORRECT - the lock spans the whole operation, keyed per address
final _sessionLocks = <String, Lock>{};

Future<CiphertextMessage> sendTo(ProtocolAddress to, Uint8List body) {
  final key = '${to.name()}:${to.deviceId()}';
  return _sessionLocks
      .putIfAbsent(key, Lock.new)
      .synchronized(() => cipher.encrypt(to, body));
}
```

Thread-safety inside the store is still worth having (it protects the store's own
invariants), but it is the call-site lock that prevents key reuse. See
[Store Durability, Write Ordering and Rollback](#store-durability-write-ordering-and-rollback)
for the scope rules (`SessionCipher`, `SealedSenderCipher` and `SessionBuilder`
share one lock per address; group messaging locks per sender key).

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
- [ ] Store writes durable before the ciphertext is sent / the plaintext is acted on
- [ ] Cipher operations serialized per address (call-site lock, not a store-internal one)
- [ ] Deletes and pre-key consumption as durable as writes; no state rolled back on failure
- [ ] Store bound to a non-backed-up marker, restored copies reset instead of resumed
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
- **Authenticity (build provenance attestation):** the checksums file is served
  from the same release as the archive, so SHA256 alone does not defend against
  a release or maintainer-token compromise (an attacker who replaces the archive
  can also replace its checksum). To break that self-trust, every release
  archive is attested with [GitHub Artifact
  Attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
  (Sigstore, SLSA Build L2): CI signs a provenance statement proving each
  archive was built by this repository's tag-triggered `build-libsignal.yml`
  workflow from a specific commit. Verify any downloaded archive with the
  GitHub CLI:

  ```bash
  gh attestation verify libsignal_frb-<version>-<platform>.tar.gz \
    --repo djx-y-z/libsignal_dart
  ```

  For fully offline verification, each release also attaches the Sigstore
  bundle as `libsignal_frb-<version>.sigstore.jsonl`:

  ```bash
  gh attestation trusted-root > trusted_root.jsonl   # once, from a trusted machine
  gh attestation verify libsignal_frb-<version>-<platform>.tar.gz \
    --repo djx-y-z/libsignal_dart \
    --bundle libsignal_frb-<version>.sigstore.jsonl \
    --custom-trusted-root trusted_root.jsonl
  ```

  **Known limitation:** verification is manual — the build hook itself does not
  verify attestations automatically. There is currently no Sigstore/DSSE
  implementation for Dart, so an in-hook verifier would mean hand-rolling
  X.509 path validation and transparency-log checks (weeks of security-critical
  code); no package ecosystem verifies Sigstore attestations client-side by
  default today. Automatic (opt-in) verification via an installed `gh` CLI is
  tracked as a possible future hardening step.

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

CI workflows run with a least-privilege `GITHUB_TOKEN` (`contents: read` by
default; only the release-publishing jobs get the specific writes they need),
third-party actions are pinned to commit SHAs, and pub.dev publishing uses
OIDC — no long-lived publishing tokens exist.

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

## Store Durability, Write Ordering and Rollback

Storage is **delegated to the application**: this library holds no database, and
every piece of protocol state it advances is handed to your store
implementations. Those writes are part of the protocol's correctness, not cache
updates.

The reason is specific to the Signal Protocol. Message keys are derived
deterministically from stored state — a session record's chain key plus a
counter, or a sender key's chain key plus its iteration — and, unlike MLS, the
Double Ratchet has **no per-message random nonce guard**. Feed libsignal the
same session record twice and it produces the same message key and the same IV.
So a store write that is **lost** (crash, power loss, an unflushed buffer) or a
store that is **rolled back** (restored backup, cloned image, reverted snapshot)
makes the next operation reuse a message key and IV that were already used.

Concretely — libsignal encrypts messages with AES-256-CBC plus HMAC-SHA256
(`signal_crypto::aes_256_cbc_encrypt` over the derived `cipher_key`/`iv`), so a
reused slot means:

- **Encryption becomes deterministic there.** Two different messages sent in the
  same slot leak their relationship: identical plaintexts — or identical leading
  blocks — produce visibly identical ciphertext blocks. (This is CBC, so it is
  not the total plaintext recovery that reusing a stream cipher's keystream would
  give; it is a real confidentiality leak, not a cosmetic one.)
- **Forward secrecy stops working for those messages.** The ratchet's guarantee
  rests on used message keys being deleted; a rewound state can derive them
  again, so a later device compromise recovers messages that should have been
  unrecoverable.
- **Replay protection is rewound with it.** Receive-chain keys are consumed on
  use; restoring them makes the session accept a message it already accepted.

Those are precisely the guarantees the Double Ratchet exists to provide, and
losing them is deterministic here rather than a probabilistic near-miss: unlike
MLS, the Double Ratchet has **no per-message random nonce guard**, so the
collision is certain, not a ~2⁻³² event. Everything below follows from that.

### The rule: durable before release

> State that a cryptographic operation advanced must be **durably persisted
> before that operation's output is released** — before a ciphertext leaves the
> device, and before a plaintext is displayed, acted on or acknowledged.

**What this library already guarantees.** Every store-write callback is awaited
before the operation returns its result, on all entry points:

| Entry point | Awaited writes, in order, before the result is returned |
|---|---|
| `SessionBuilder.processPreKeyBundle` | `storeSession`, `saveIdentity` |
| `SessionCipher.encrypt` | `storeSession` |
| `SessionCipher.decrypt` (Whisper) | `storeSession`, `saveIdentity` |
| `SessionCipher.decrypt` (pre-key) | `storeSession`, `saveIdentity`, `removePreKey`, `markKyberPreKeyUsed` |
| `SealedSenderCipher.encrypt` | `storeSession` |
| `SealedSenderCipher.decrypt` | `storeSession`, `saveIdentity`, `removePreKey` |
| `GroupCipher.createDistributionMessage` / `processDistributionMessage` / `encrypt` / `decrypt` | `storeSenderKey` |

There is no fire-and-forget write anywhere in the bridge, so the *ordering* half
of the rule holds by construction. What the library cannot do for you is decide
when your write became durable, or stop you from running two operations on one
session at the same time.

> **Known gap on the sealed-sender path.** The row above is exhaustive:
> `markKyberPreKeyUsed` is **not** called when a pre-key message arrives through
> `SealedSenderCipher.decrypt`, even though the one-time EC pre-key on that same
> path *is* removed. A one-time Kyber pre-key consumed via sealed sender is
> therefore never marked, so a store that retires marked keys (as
> `KyberPreKeyStore.markKyberPreKeyUsed` tells it to) will keep serving that
> one. Until this is fixed, do not treat the mark as the only thing that retires
> a one-time Kyber pre-key — retire it from the application side when you
> publish a new bundle. Tracked as a limitation below.

**Two conforming implementations.** Pick one:

1. **Durable inside the callback** — the write is on stable storage before the
   future completes.

   ```dart
   @override
   Future<void> storeSession(ProtocolAddress address, SessionRecord record) async {
     await _lock.synchronized(() async {
       await _appendRecord(address, record);
       await _file.flush(); // fsync — see platform limits below
     });
   }
   ```

   Simple, and correct even if the caller forgets everything else. Costs one
   `fsync` per message.

2. **A transaction around the call, committed before release** — cheaper, and it
   also makes the multiple writes of one operation atomic (the table above shows
   that a single `decrypt` can issue four separate callbacks; a crash between
   them otherwise leaves session and identity inconsistent).

   ```dart
   final ciphertext = await db.transaction((txn) {
     // The stores must write through *this* transaction — see the note below.
     return cipherWithStoresOn(txn).encrypt(bob, body);
   });
   // commit has returned durably here — only now may the ciphertext be sent
   await transport.send(ciphertext);
   ```

   The invariant is **commit, then release**. If the commit fails, do not
   release the output: rolling back is safe precisely because nothing was
   released. The converse is not — once a ciphertext has been sent, that
   transaction must never be rolled back.

   > **Route the store's writes through the ambient transaction.** A store that
   > holds its own database handle writes *outside* the transaction, which
   > silently defeats both the atomicity and the commit barrier — and with
   > `sqflite` it does worse: using the `db` object inside `db.transaction(...)`
   > [deadlocks](https://github.com/tekartik/sqflite/blob/master/sqflite/doc/troubleshooting.md),
   > so the whole operation hangs. Pass the transaction object into the stores
   > for the duration of the call (`drift` does this for you: its transactions
   > are zone-scoped, so inner queries are routed automatically).

**Non-conforming**, however convenient: returning from a store callback once the
record is in a `Map`, an unflushed file, a write-behind cache or a background
queue; `unawaited(...)` inside a store method; SQLite with
`synchronous = OFF`/`NORMAL` while relying on option 1.

### Deletes and consumption are writes too

- A non-durable `deleteSession` / `deleteAllSessions` resurrects the deleted
  session after a crash. Resuming a session whose keys were already used is the
  same failure as a rollback.
- `removePreKey` and `markKyberPreKeyUsed` consume a one-time key. If that write
  is lost, the key is offered again as unused: forward secrecy for the initial
  message is weakened (it still exists on the device for a later attacker), and a
  replayed pre-key message can re-establish a session whose message keys have
  already been used. Note that `markKyberPreKeyUsed` only protects anything if
  your `loadKyberPreKey` then **refuses to serve a marked one-time key** —
  last-resort Kyber keys are meant to be reused and the record does not say which
  kind it is, so the store must remember that from the moment it generated the
  key. A durable mark that nothing consults buys nothing.
- On failure, **never roll state backwards**. If an operation throws after some
  writes already landed, the safe recovery is to keep the persisted state and
  drop the message — losing a message is recoverable, rewinding a ratchet is
  not. Make store writes idempotent so retries are harmless.

### Serialize operations per address

The `load → ratchet → store` cycle is a critical section, and **a lock inside
the store does not protect it**. Two concurrent `SessionCipher.encrypt` calls for
the same address both load the same session record, both derive the same message
key, and the second `storeSession` overwrites the first — deterministic key
reuse, with no crash involved. This is the failure mode most likely to be hit in
practice: one stray `unawaited(cipher.encrypt(...))`, or two sends triggered from
a UI, is enough.

Hold the lock around the **whole** cipher call:

```dart
import 'package:synchronized/synchronized.dart';

// One map per store instance. What needs serializing is access to the store, so
// do not scope this to a single (possibly short-lived) SessionCipher object.
final _sessionLocks = <String, Lock>{};

Future<CiphertextMessage> sendTo(ProtocolAddress to, Uint8List body) {
  final key = '${to.name()}:${to.deviceId()}';
  return _sessionLocks
      .putIfAbsent(key, Lock.new)
      .synchronized(() => cipher.encrypt(to, body));
}
```

Scope notes:

- One address is one critical section. `SessionCipher`, `SealedSenderCipher` and
  `SessionBuilder` all advance the *same* session, so they must share the lock
  for that address.
- Group messaging serializes per `(sender address, distribution ID)` — the
  identity of a sender key.
- If your store is shared across isolates or processes, the lock must be too
  (a database transaction with row locking, or a single owning isolate).

### Rollback protection is a deployment property

At-rest encryption — Keychain, Keystore, SQLCipher, a sealed key — provides
**confidentiality, not rollback protection**. An attacker (or a well-meaning
restore) that replaces the whole encrypted store with an earlier copy of itself
does not need to decrypt anything to rewind your ratchets.

Realistic rollback vectors, in rough order of likelihood: restoring a device or
app backup, migrating to a new device, reverting a VM/container image or a
filesystem snapshot, and — for anything server-side or desktop — restoring from
an ordinary backup.

Neither iOS nor ordinary Android app storage exposes a monotonic counter or
rollback-resistant data facility an app can use to *detect* this, so treat
anti-rollback as a deployment obligation, and implement the achievable form:

- **Bind the store to a non-backed-up marker.** Store a random installation ID
  in storage that does not travel with backups — an iOS Keychain item with a
  `…ThisDeviceOnly` accessibility class, Android's `no_backup` directory or
  `android:allowBackup="false"` — and record it inside the store as well. If the
  two disagree (or the marker is gone), the store you are holding is a restored
  copy: treat it as a **session reset**. Discard/archive the sessions and sender
  keys and let fresh ones be established, instead of resuming ratchet state whose
  keys may already have been used.
- **Treat an unclean shutdown the same way** when you cannot prove your writes
  were durable (see the web note below): clear a "clean shutdown" flag on start,
  set it on graceful exit, and on a start that finds it missing, reset sessions
  rather than resuming them. A session reset is visible to the user and costs a
  re-handshake; a reused message key is not visible at all.
- Identity keys are the exception: they are *meant* to survive, and rotating them
  triggers safety-number changes for every contact. Persist those durably, and
  scope the reset above to session / sender-key state.

Residual risk to state plainly in your own threat model: an attacker with
repeated write access to the device's storage can roll back a store between
sends, and no application-level measure fully prevents that.

### Platform limits worth knowing

- **Apple platforms.** `dart:io`'s `RandomAccessFile.flush()` / `File.flush()`
  calls `fsync(2)`, which on macOS and iOS hands the data to the drive but does
  **not** force its write cache to stable media; Apple's full barrier
  (`F_FULLFSYNC`) is not exposed through `dart:io`. Process and OS crashes are
  covered; sudden power loss is not. SQLite can request the barrier —
  `PRAGMA fullfsync = ON` (with `synchronous = FULL`) — which is the main reason
  to prefer SQLite over hand-rolled files on Apple platforms.
- **Newly created files.** `fsync` on a file does not make its *directory entry*
  durable, and `dart:io` cannot `fsync` a directory. A file created and then
  flushed can still vanish on power loss. Prefer appending to / overwriting a
  file created once (as the reference store does), or let a database handle it.
- **Web.** IndexedDB provides no power-loss durability guarantee: browsers
  default to relaxed durability, flushing lazily, and a strict mode is only
  available in newer APIs and not on every engine. The strongest available
  signal is to resolve the store callback on the transaction's `complete` event
  (not on request success), and to ask for strict durability where the engine
  supports it. Because that still is not a barrier, web deployments should use
  the clean-shutdown/session-reset mitigation above, and their threat model
  should state that ratchet durability is best-effort on this platform. This is
  a property of the platform, not of the callback design — a Rust-owned store
  compiled to WASM would face exactly the same IndexedDB semantics.
- **A working reference** lives in the repository (it is not part of the
  published archive):
  [`example_cli/lib/stores/durable_file_stores.dart`](https://github.com/djx-y-z/libsignal_dart/blob/main/example_cli/lib/stores/durable_file_stores.dart)
  is an append-only journal that flushes before returning from every write,
  serializes writes internally, replays on open and tolerates a torn tail, with
  all six stores on top of it.
  [`example_cli/lib/demos/durable_store_demo.dart`](https://github.com/djx-y-z/libsignal_dart/blob/main/example_cli/lib/demos/durable_store_demo.dart)
  proves the round trip by reopening the stores from disk and continuing an
  established conversation.

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

4. **Durability and rollback are delegated:** the library cannot verify that your store writes reached stable storage, cannot serialize your calls for you, and cannot detect that the store it was handed is a restored copy. `fsync` is not a full barrier on Apple platforms and IndexedDB gives no power-loss guarantee on the web. See [Store Durability, Write Ordering and Rollback](#store-durability-write-ordering-and-rollback) for the contract and the achievable mitigations.

5. **Kyber pre-keys are not marked used on the sealed-sender path:** `SealedSenderCipher.decrypt` removes the one-time EC pre-key a pre-key message consumed, but never calls `markKyberPreKeyUsed` for the Kyber pre-key it consumed (`SessionCipher.decrypt` does both). A store that retires marked one-time Kyber pre-keys will therefore keep serving one that sealed sender already consumed. Retire one-time Kyber pre-keys from the application side when you publish a new bundle; closing the gap requires a new store callback and so a native-crate release.

### Plaintext Handling After Decryption

After decryption, plaintext is intentionally NOT zeroized because:

1. **Plaintext is application data** - per NIST guidelines, zeroization applies to cryptographic keys and secret data, not application plaintext
2. **Responsibility transfer** - once decrypted, data belongs to the application layer
3. **Keys ARE zeroized** - identity key pairs and session keys are properly zeroized after use

If your application requires plaintext zeroization, implement it at the Dart layer after processing.
