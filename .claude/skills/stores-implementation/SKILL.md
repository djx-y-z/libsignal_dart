---
name: stores-implementation
description: Implement Signal Protocol stores for libsignal_dart. Use when implementing SessionStore, IdentityKeyStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore, or SenderKeyStore for production use.
---

# Stores Implementation Guide

Guide for implementing Signal Protocol stores for production use.

## Why Stores Are Required

Signal Protocol uses the Double Ratchet algorithm:
- Each message changes session state (ratchet advances)
- State must be persisted for correct encryption/decryption
- Without stores, repeated operations will fail or produce incorrect results

## Architecture

Stores are Dart interfaces that provide persistence for the Signal Protocol. The FRB layer uses DartFn callbacks to access stores during cryptographic operations.

```
┌─────────────────────────────────────────────┐
│            Your Application                  │
├─────────────────────────────────────────────┤
│  Store Interfaces (SessionStore, etc.)       │  ← You implement these
├─────────────────────────────────────────────┤
│  FRB Callbacks (DartFn)                      │  ← Bridges Dart to Rust
├─────────────────────────────────────────────┤
│  libsignal-protocol (Rust)                   │  ← Cryptographic operations
└─────────────────────────────────────────────┘
```

## Store Types

| Store | Purpose | Required For |
|-------|---------|--------------|
| `SessionStore` | Session state (Double Ratchet) | Encrypt/Decrypt messages |
| `IdentityKeyStore` | Identity keys & trust | All operations |
| `PreKeyStore` | One-time pre-keys | New session establishment |
| `SignedPreKeyStore` | Signed pre-keys | New session establishment |
| `KyberPreKeyStore` | Post-quantum keys | New session (with Kyber) |
| `SenderKeyStore` | Group session keys | Group messaging |

## Minimum Required Stores

| Operation | Session | Identity | PreKey | SignedPreKey | KyberPreKey |
|-----------|:-------:|:--------:|:------:|:------------:|:-----------:|
| Encrypt/Decrypt (existing session) | Yes | Yes | - | - | - |
| Process PreKey message (new session) | Yes | Yes | Yes | Yes | Yes |
| Group messaging | - | - | - | - | - |

**Note:** Group messaging uses `SenderKeyStore`.

## Abstract Store Interfaces

### SessionStore

```dart
abstract class SessionStore {
  /// Load session for address, returns null if not found
  Future<SessionRecord?> loadSession(ProtocolAddress address);

  /// Store session for address
  Future<void> storeSession(ProtocolAddress address, SessionRecord record);
}
```

### IdentityKeyStore

```dart
abstract class IdentityKeyStore {
  /// Get local identity key pair
  Future<IdentityKeyPair> getIdentityKeyPair();

  /// Get local registration ID
  Future<int> getLocalRegistrationId();

  /// Get identity key for address, returns null if not found
  Future<PublicKey?> getIdentity(ProtocolAddress address);

  /// Save identity key for address
  /// Returns true if identity changed (key mismatch)
  Future<bool> saveIdentity(ProtocolAddress address, PublicKey identityKey);

  /// Check if identity is trusted
  Future<bool> isTrustedIdentity(
    ProtocolAddress address,
    PublicKey identityKey,
    Direction direction,
  );
}

enum Direction { sending, receiving }
```

### PreKeyStore

```dart
abstract class PreKeyStore {
  /// Load pre-key by ID, returns null if not found
  Future<PreKeyRecord?> loadPreKey(int preKeyId);

  /// Store pre-key
  Future<void> storePreKey(int preKeyId, PreKeyRecord record);

  /// Remove pre-key (consumed after use)
  Future<void> removePreKey(int preKeyId);
}
```

### SignedPreKeyStore

```dart
abstract class SignedPreKeyStore {
  /// Load signed pre-key by ID
  Future<SignedPreKeyRecord?> loadSignedPreKey(int signedPreKeyId);

  /// Store signed pre-key
  Future<void> storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record);
}
```

### KyberPreKeyStore

```dart
abstract class KyberPreKeyStore {
  /// Load Kyber pre-key by ID
  Future<KyberPreKeyRecord?> loadKyberPreKey(int kyberPreKeyId);

  /// Store Kyber pre-key
  Future<void> storeKyberPreKey(int kyberPreKeyId, KyberPreKeyRecord record);

  /// Mark Kyber pre-key as used.
  ///
  /// Retire a one-time key here (loadKyberPreKey must then refuse to serve
  /// it). A last-resort key stays in service, so record the
  /// (kyberPreKeyId, signedPreKeyId, baseKey) triple instead and treat a
  /// repeat as a replayed pre-key message. Must not throw — the callback is
  /// not failable.
  Future<void> markKyberPreKeyUsed(
    int kyberPreKeyId,
    int signedPreKeyId,
    PublicKey baseKey,
  );
}
```

### SenderKeyStore

```dart
abstract class SenderKeyStore {
  /// Load sender key for group session
  Future<SenderKeyRecord?> loadSenderKey(
    ProtocolAddress sender,
    String distributionId,
  );

  /// Store sender key for group session
  Future<void> storeSenderKey(
    ProtocolAddress sender,
    String distributionId,
    SenderKeyRecord record,
  );
}
```

## Implementation Checklist

### 1. Choose Storage Backend

| Backend | Pros | Cons |
|---------|------|------|
| SQLite (sqflite/drift) | Fast, reliable, ACID, `synchronous = FULL` gives real durability | More complex setup |
| Hive | Simple, fast | No ACID guarantees — do not use for session/sender-key state |
| flutter_secure_storage | Encrypted at rest | Slower, size limits, no durability guarantee |
| SharedPreferences | Simple | Not for large data, no durability guarantee |

**Recommendation:** SQLite (with `synchronous = FULL`, plus `PRAGMA fullfsync = ON`
on Apple platforms) for session, sender-key and pre-key state;
flutter_secure_storage for identity keys.

A backend without a durability guarantee is not merely slower to persist — see
step 3. Session and sender-key records must be flushed before the operation's
output is released.

### 2. Implement Serialization

All records can be serialized to `Uint8List`:

```dart
// Serialize to store
final bytes = record.serialize();
await storage.put(key, bytes);

// Deserialize when loading
final bytes = await storage.get(key);
if (bytes != null) {
  return SessionRecord.deserialize(bytes: bytes);
}
return null;
```

### 3. Durability and Concurrency (the part that breaks crypto if wrong)

libsignal derives message keys deterministically from stored state and the Double
Ratchet has **no per-message random nonce guard**. A session write that is lost to
a crash, or a session that is rolled back, makes the next send encrypt a
different plaintext under an already-used key and IV. Two rules follow — see
`SECURITY.md` → *Store Durability, Write Ordering and Rollback* for the full
contract.

**Rule 1 — durable before release.** The write must be on stable storage before
the operation's output is released. The library awaits every store callback
before returning a ciphertext/plaintext, so satisfy this either inside the
callback or with a transaction around the cipher call:

```dart
// (a) durable inside the callback
@override
Future<void> storeSession(ProtocolAddress address, SessionRecord record) async {
  await _db.insert('sessions', {          // db opened with synchronous = FULL
    'address': '${address.name()}:${address.deviceId()}',
    'record': record.serialize(),
  }, conflictAlgorithm: ConflictAlgorithm.replace);
}

// (b) one transaction per operation — faster, and atomic across the
//     session + identity + pre-key writes a single decrypt performs
final plaintext = await _db.transaction((txn) {
  // The stores must write through `txn`, not through the outer `_db` handle.
  return cipherWithStoresOn(txn).decrypt(alice, message);
});
await handle(plaintext); // only after the commit returned
```

⚠️ **Route store writes through the ambient transaction.** A store holding its
own handle writes outside the transaction (losing atomicity *and* the commit
barrier), and in `sqflite` using `db` inside `db.transaction(...)`
[deadlocks](https://github.com/tekartik/sqflite/blob/master/sqflite/doc/troubleshooting.md)
— the operation hangs. So with sqflite, pass the `Transaction` into the stores
for the duration of the call; `drift` routes inner queries automatically because
its transactions are zone-scoped.

Deletes (`deleteSession`) and consumption (`removePreKey`,
`markKyberPreKeyUsed`) are writes with the same requirement. On failure, never
roll state backwards — drop the message instead.

**Rule 2 — serialize per address at the call site.** A lock inside the store is
not enough: `load → ratchet → store` spans the whole cipher call, so two
concurrent `encrypt` calls for one address derive the same message key with no
crash involved.

```dart
import 'package:synchronized/synchronized.dart';

// One map per store instance, not per SessionCipher.
final _locks = <String, Lock>{};

Future<CiphertextMessage> sendTo(ProtocolAddress to, Uint8List body) {
  return _locks
      .putIfAbsent('${to.name()}:${to.deviceId()}', Lock.new)
      .synchronized(() => cipher.encrypt(to, body));
}
```

`SessionCipher`, `SealedSenderCipher` and `SessionBuilder` advance the same
session, so they share one lock per address; group messaging locks per
`(sender address, distribution ID)`.

**Reference implementation:** `example_cli/lib/stores/durable_file_stores.dart`
(all six stores on a flush-before-return journal, plus `AddressLocks`) and
`example_cli/lib/demos/durable_store_demo.dart` (a conversation that survives
closing and reopening the stores).

### 4. Secure Key Storage

Identity keys should use secure storage:

```dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureIdentityKeyStore implements IdentityKeyStore {
  final FlutterSecureStorage _secureStorage;
  IdentityKeyPair? _cachedKeyPair;

  @override
  Future<IdentityKeyPair> getIdentityKeyPair() async {
    if (_cachedKeyPair != null) return _cachedKeyPair!;

    final bytes = await _secureStorage.read(key: 'identity_key_pair');
    if (bytes == null) {
      // Generate new key pair
      final keyPair = IdentityKeyPair.generate();
      await _secureStorage.write(
        key: 'identity_key_pair',
        value: base64Encode(keyPair.serialize()),
      );
      _cachedKeyPair = keyPair;
      return keyPair;
    }
    _cachedKeyPair = IdentityKeyPair.deserialize(bytes: base64Decode(bytes));
    return _cachedKeyPair!;
  }
}
```

### 5. Key Rotation

Pre-keys should be rotated after use:

```dart
@override
Future<void> removePreKey(int preKeyId) async {
  // Pre-keys are one-time use
  await _db.delete('pre_keys', where: 'id = ?', whereArgs: [preKeyId]);
}
```

Signed pre-keys should be rotated periodically (e.g., weekly).

## Example: SQLite SessionStore

```dart
import 'package:sqflite/sqflite.dart';
import 'package:libsignal/libsignal.dart';

class SqliteSessionStore implements SessionStore {
  final Database _db;

  SqliteSessionStore(this._db);

  static Future<void> createTable(Database db) async {
    await db.execute('''
      CREATE TABLE IF NOT EXISTS sessions (
        address TEXT PRIMARY KEY,
        record BLOB NOT NULL,
        updated_at INTEGER NOT NULL
      )
    ''');
  }

  String _addressKey(ProtocolAddress address) {
    return '${address.name()}:${address.deviceId()}';
  }

  @override
  Future<SessionRecord?> loadSession(ProtocolAddress address) async {
    final key = _addressKey(address);
    final rows = await _db.query(
      'sessions',
      where: 'address = ?',
      whereArgs: [key],
    );

    if (rows.isEmpty) return null;

    final bytes = rows.first['record'] as Uint8List;
    return SessionRecord.deserialize(bytes: bytes);
  }

  @override
  Future<void> storeSession(ProtocolAddress address, SessionRecord record) async {
    final key = _addressKey(address);
    final bytes = record.serialize();

    await _db.insert(
      'sessions',
      {
        'address': key,
        'record': bytes,
        'updated_at': DateTime.now().millisecondsSinceEpoch,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }
}
```

## Usage with SessionBuilder/SessionCipher

```dart
// Create stores
final sessionStore = SqliteSessionStore(db);
final identityStore = SecureIdentityKeyStore(secureStorage, registrationId);
final preKeyStore = SqlitePreKeyStore(db);
final signedPreKeyStore = SqliteSignedPreKeyStore(db);
final kyberPreKeyStore = SqliteKyberPreKeyStore(db);

// Build session from pre-key bundle
final builder = SessionBuilder(
  sessionStore: sessionStore,
  identityKeyStore: identityStore,
);
await builder.processPreKeyBundle(recipientAddress, preKeyBundle);

// Encrypt/decrypt messages
final cipher = SessionCipher(
  localAddress: myAddress,
  sessionStore: sessionStore,
  identityKeyStore: identityStore,
  preKeyStore: preKeyStore,
  signedPreKeyStore: signedPreKeyStore,
  kyberPreKeyStore: kyberPreKeyStore,
);
final ciphertext = await cipher.encrypt(recipientAddress, plaintext);
```

## Testing Your Implementation

```dart
void main() {
  group('SessionStore', () {
    late MySessionStore store;

    setUp(() async {
      store = await MySessionStore.create(':memory:');
    });

    test('stores and loads session', () async {
      final address = ProtocolAddress(name: 'alice', deviceId: 1);
      final session = SessionRecord.newFresh();

      await store.storeSession(address, session);
      final loaded = await store.loadSession(address);

      expect(loaded, isNotNull);
      expect(loaded!.serialize(), equals(session.serialize()));
    });

    test('returns null for unknown address', () async {
      final address = ProtocolAddress(name: 'unknown', deviceId: 1);
      final loaded = await store.loadSession(address);

      expect(loaded, isNull);
    });

    // The test that actually catches a broken store: state must survive being
    // closed and reopened, with no in-memory carry-over.
    test('session survives a restart', () async {
      final address = ProtocolAddress(name: 'bob', deviceId: 1);
      final path = '${Directory.systemTemp.path}/store_test.db';

      var store = await MySessionStore.create(path);
      await store.storeSession(address, session);
      await store.close();

      store = await MySessionStore.create(path);
      expect(await store.containsSession(address), isTrue);
      // Best done end-to-end: reopen and decrypt a message encrypted with the
      // reopened session, as durable_store_demo.dart does.
    });
  });
}
```

## In-Memory Stores (Testing Only)

For testing, use the provided in-memory implementations:

```dart
import 'package:libsignal/libsignal.dart';

final sessionStore = InMemorySessionStore();
final identityStore = InMemoryIdentityKeyStore(
  identityKeyPair: IdentityKeyPair.generate(),
  registrationId: 12345,
);
final preKeyStore = InMemoryPreKeyStore();
final signedPreKeyStore = InMemorySignedPreKeyStore();
final kyberPreKeyStore = InMemoryKyberPreKeyStore();
final senderKeyStore = InMemorySenderKeyStore();
```

**WARNING:** In-memory stores are NOT for production use - data is lost on app restart!

## Reference Files

| Store | Interface | In-Memory Example |
|-------|-----------|-------------------|
| Session | `lib/src/stores/session_store.dart` | `in_memory/in_memory_session_store.dart` |
| Identity | `lib/src/stores/identity_key_store.dart` | `in_memory/in_memory_identity_key_store.dart` |
| PreKey | `lib/src/stores/pre_key_store.dart` | `in_memory/in_memory_pre_key_store.dart` |
| SignedPreKey | `lib/src/stores/signed_pre_key_store.dart` | `in_memory/in_memory_signed_pre_key_store.dart` |
| KyberPreKey | `lib/src/stores/kyber_pre_key_store.dart` | `in_memory/in_memory_kyber_pre_key_store.dart` |
| SenderKey | `lib/src/stores/sender_key_store.dart` | `in_memory/in_memory_sender_key_store.dart` |

Durable reference (all six stores, flush-before-return, plus per-address locks):

| File | Contents |
|------|----------|
| `example_cli/lib/stores/durable_file_stores.dart` | Append-only journal + the six stores + `AddressLocks` |
| `example_cli/lib/demos/durable_store_demo.dart` | Conversation continued after closing and reopening the stores |
| `SECURITY.md` → *Store Durability, Write Ordering and Rollback* | The contract, rollback mitigation, platform limits |
