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

**Note:** Group messaging uses `SenderKeyStore` with built-in FFI callbacks.

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

  /// Mark Kyber pre-key as used (may delete depending on policy)
  Future<void> markKyberPreKeyUsed(int kyberPreKeyId);
}
```

### SenderKeyStore

```dart
abstract class SenderKeyStore {
  /// Load sender key for group session
  Future<SenderKeyRecord?> loadSenderKey(
    ProtocolAddress sender,
    Uint8List distributionId,
  );

  /// Store sender key for group session
  Future<void> storeSenderKey(
    ProtocolAddress sender,
    Uint8List distributionId,
    SenderKeyRecord record,
  );
}
```

## Implementation Checklist

### 1. Choose Storage Backend

| Backend | Pros | Cons |
|---------|------|------|
| SQLite (sqflite) | Fast, reliable, ACID | More complex setup |
| Hive | Simple, fast | No ACID guarantees |
| flutter_secure_storage | Encrypted at rest | Slower, size limits |
| SharedPreferences | Simple | Not for large data |

**Recommendation:** SQLite for production, flutter_secure_storage for keys only.

### 2. Implement Serialization

All records can be serialized:

```dart
// Serialize to store
final bytes = record.serialize();
await storage.put(key, bytes);

// Deserialize when loading
final bytes = await storage.get(key);
if (bytes != null) {
  return SessionRecord.deserialize(bytes);
}
return null;
```

### 3. Handle Concurrency

```dart
class MySessionStore implements SessionStore {
  final _lock = Lock(); // from synchronized package

  @override
  Future<void> storeSession(ProtocolAddress address, SessionRecord record) async {
    await _lock.synchronized(() async {
      // Store session atomically
    });
  }
}
```

### 4. Secure Key Storage

Identity keys should use secure storage:

```dart
class SecureIdentityKeyStore implements IdentityKeyStore {
  final FlutterSecureStorage _secureStorage;

  @override
  Future<IdentityKeyPair> getIdentityKeyPair() async {
    final bytes = await _secureStorage.read(key: 'identity_key_pair');
    if (bytes == null) {
      // Generate new key pair
      final keyPair = IdentityKeyPair.generate();
      await _secureStorage.write(
        key: 'identity_key_pair',
        value: base64Encode(keyPair.serialize()),
      );
      return keyPair;
    }
    return IdentityKeyPair.deserialize(base64Decode(bytes));
  }
}
```

### 5. Key Rotation

Pre-keys should be rotated after use:

```dart
@override
Future<void> removePreKey(int preKeyId) async {
  // Pre-keys are one-time use
  await _database.delete('pre_keys', where: 'id = ?', whereArgs: [preKeyId]);
}
```

Signed pre-keys should be rotated periodically (e.g., weekly).

## Example: SQLite SessionStore

```dart
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
    return '${address.name}:${address.deviceId}';
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
    return SessionRecord.deserialize(bytes);
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

## Testing Your Implementation

```dart
void main() {
  group('SessionStore', () {
    late MySessionStore store;

    setUp(() async {
      store = await MySessionStore.create(':memory:');
    });

    test('stores and loads session', () async {
      final address = ProtocolAddress('alice', 1);
      final session = SessionRecord.freshSession();

      await store.storeSession(address, session);
      final loaded = await store.loadSession(address);

      expect(loaded, isNotNull);
      expect(loaded!.serialize(), equals(session.serialize()));
    });

    test('returns null for unknown address', () async {
      final address = ProtocolAddress('unknown', 1);
      final loaded = await store.loadSession(address);

      expect(loaded, isNull);
    });
  });
}
```

## In-Memory Stores (Testing Only)

For testing, use the provided in-memory implementations:

```dart
import 'package:libsignal/src/stores/in_memory/in_memory_stores.dart';

final sessionStore = InMemorySessionStore();
final identityStore = InMemoryIdentityKeyStore(
  identityKeyPair: IdentityKeyPair.generate(),
  registrationId: 12345,
);
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
