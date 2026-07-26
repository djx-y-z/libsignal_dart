/// Session store interface for Signal Protocol.
library;

import '../rust/api/address.dart';
import '../rust/api/session.dart';

/// Abstract interface for storing and retrieving session records.
///
/// Implementations must provide persistent storage for Signal Protocol
/// sessions. Each session is identified by a [ProtocolAddress] (user + device).
///
/// Example implementation:
/// ```dart
/// class MySessionStore implements SessionStore {
///   final _sessions = <String, Uint8List>{};
///
///   @override
///   Future<SessionRecord?> loadSession(ProtocolAddress address) async {
///     final key = '${address.name}:${address.deviceId}';
///     final data = _sessions[key];
///     return data != null ? SessionRecord.deserialize(data) : null;
///   }
///   // ... other methods
/// }
/// ```
///
/// ## Durability, ordering and rollback (critical)
///
/// A session record *is* the Double Ratchet state, and the message keys for
/// the next messages are derived from it deterministically (chain key +
/// counter). The Signal Protocol has no per-message random nonce guard, so if
/// a stored session is **lost or rolled back to an earlier version**, the next
/// send re-derives a message key and IV that were already used. Since messages
/// are encrypted with AES-256-CBC + HMAC, that slot then encrypts
/// deterministically — two different messages leak their relationship, and
/// identical leading blocks become identical ciphertext — the deletion of used
/// message keys that provides forward secrecy stops happening, and the rewound
/// state accepts a message it already accepted. Those are the guarantees the
/// ratchet exists to provide, so treat every session write as a correctness
/// requirement, not a caching detail.
///
/// 1. **Durable before release.** The updated session must be durably
///    persisted before the output of the operation that produced it leaves the
///    device (a ciphertext being sent) or is acted upon (a plaintext being
///    displayed or acknowledged). The library always awaits [storeSession]
///    before returning that output, so you satisfy this in one of two ways:
///    - make the write durable inside [storeSession] (`fsync` on the file,
///      SQLite `synchronous = FULL`, …), or
///    - open a transaction around the whole `SessionCipher.encrypt` /
///      `SessionCipher.decrypt` call and commit it durably before you send the
///      ciphertext or act on the plaintext. This is usually faster and has the
///      added benefit of making the session write atomic with the
///      accompanying `IdentityKeyStore.saveIdentity` and pre-key writes, which
///      the library performs as separate callbacks.
///
///    What is *not* sufficient: returning from [storeSession] once the record
///    is in a memory buffer, an unflushed file, or a write queue.
/// 2. **Deletes are writes too.** A [deleteSession] or [deleteAllSessions]
///    that is not durable can resurrect the deleted session after a crash,
///    which is exactly the rollback case above.
/// 3. **Serialize operations per address.** The load → ratchet → store cycle
///    is a critical section that this store cannot protect on its own: two
///    concurrent `encrypt` calls for the same address both load the same
///    record, both derive the same message key, and the second
///    [storeSession] overwrites the first. A lock *inside* the store does not
///    prevent this — the lock must be held around the entire
///    `SessionCipher`/`SealedSenderCipher` call. See `SECURITY.md`.
/// 4. **Rollback protection is a deployment property.** At-rest encryption
///    (Keychain, Keystore, SQLCipher) provides confidentiality, not rollback
///    protection: restoring a device backup, cloning a VM or container image,
///    or reverting an app snapshot rolls the store back to a state whose
///    message keys have already been used. Neither iOS nor ordinary Android
///    app storage exposes a monotonic counter an app can use to detect this,
///    so bind the store to a marker held in **non-backed-up** storage (an iOS
///    Keychain item with a `ThisDeviceOnly` accessibility class, Android's
///    `no_backup` directory) and treat a store whose marker is missing as a
///    session reset — establish fresh sessions instead of resuming the
///    restored ratchet state.
///
/// `SECURITY.md` documents the full contract, including the platform-specific
/// limits of `fsync` and of durability on the web, and
/// [durable_file_stores.dart](https://github.com/djx-y-z/libsignal_dart/blob/main/example_cli/lib/stores/durable_file_stores.dart)
/// in the repository is a reference implementation of all six stores that
/// persists durably before returning.
abstract interface class SessionStore {
  /// Loads a session record for the given address.
  ///
  /// Returns `null` if no session exists for this address.
  Future<SessionRecord?> loadSession(ProtocolAddress address);

  /// Stores a session record for the given address.
  ///
  /// This will overwrite any existing session for this address.
  ///
  /// **Do not complete the returned future until the record is durably
  /// persisted** (or until it is part of a transaction you commit durably
  /// before the ciphertext is sent / the plaintext is acted upon). Losing this
  /// write to a crash or power loss rewinds the ratchet and causes message-key
  /// reuse — see the class documentation.
  Future<void> storeSession(ProtocolAddress address, SessionRecord record);

  /// Checks if a session exists for the given address.
  Future<bool> containsSession(ProtocolAddress address);

  /// Deletes the session for the given address.
  ///
  /// Does nothing if no session exists.
  ///
  /// This delete must be as durable as [storeSession]: a lost delete
  /// resurrects the old session, and resuming a session whose keys were
  /// already used is the same failure as a rollback.
  Future<void> deleteSession(ProtocolAddress address);

  /// Deletes all sessions for the given name (user).
  ///
  /// This removes sessions for all devices of that user.
  ///
  /// Must be durable for the same reason as [deleteSession].
  Future<void> deleteAllSessions(String name);

  /// Gets all device IDs with sessions for the given name (user).
  Future<List<int>> getSubDeviceSessions(String name);
}
