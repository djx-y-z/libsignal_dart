/// Kyber pre-key store interface for Signal Protocol.
library;

import '../rust/api/keys.dart';
import '../rust/api/kyber.dart';

/// Abstract interface for storing Kyber (post-quantum) pre-keys.
///
/// Kyber pre-keys provide post-quantum security for session establishment.
/// They work similarly to regular pre-keys but use Kyber KEM for
/// key encapsulation.
///
/// They come in two kinds, and the record does not say which: **one-time**
/// keys, each used for a single session and then retired, and a
/// **last-resort** key, reused once the one-time keys have run out. Both kinds
/// are signed with the identity key. Your store has to remember the kind
/// itself — see [markKyberPreKeyUsed] for what each one needs.
///
/// Example implementation:
/// ```dart
/// class MyKyberPreKeyStore implements KyberPreKeyStore {
///   final _kyberPreKeys = <int, Uint8List>{};
///   final _usedKyberPreKeys = <int>{};
///
///   @override
///   Future<KyberPreKeyRecord?> loadKyberPreKey(int kyberPreKeyId) async {
///     final data = _kyberPreKeys[kyberPreKeyId];
///     return data != null ? KyberPreKeyRecord.deserialize(bytes: data) : null;
///   }
///   // ... other methods
/// }
/// ```
///
/// ## Durability (critical)
///
/// Writes to this store must be **durably persisted before the returned future
/// completes**, or be part of a transaction committed durably before the
/// decrypted plaintext is acted upon. [markKyberPreKeyUsed] is such a write:
/// it is how a one-time Kyber pre-key is consumed, and how a replayed
/// agreement is recognized. See [PreKeyStore] for the consequences of losing a
/// consumption write and [SessionStore] for the full contract.
abstract interface class KyberPreKeyStore {
  /// Loads a Kyber pre-key by its ID.
  ///
  /// Returns `null` if no Kyber pre-key exists with this ID.
  Future<KyberPreKeyRecord?> loadKyberPreKey(int kyberPreKeyId);

  /// Stores a Kyber pre-key.
  Future<void> storeKyberPreKey(int kyberPreKeyId, KyberPreKeyRecord record);

  /// Checks if a Kyber pre-key exists with the given ID.
  Future<bool> containsKyberPreKey(int kyberPreKeyId);

  /// Marks the Kyber pre-key [kyberPreKeyId] as used in one PQXDH agreement,
  /// and answers whether that agreement is new.
  ///
  /// Called whenever a pre-key message establishes a new session — from both
  /// `SessionCipher.decrypt` and `SealedSenderCipher.decrypt` — and only then.
  /// A redelivered pre-key message that matches a session you already have
  /// consumes nothing and does not call this.
  ///
  /// The arguments are the ones libsignal's own `KyberPreKeyStore` receives:
  /// [signedPreKeyId] is the signed EC pre-key this Kyber key was used with,
  /// and [baseKey] is the sender's ephemeral base key for this agreement.
  /// Together they identify one PQXDH agreement.
  ///
  /// **Return `false` for a `(kyberPreKeyId, signedPreKeyId, baseKey)` triple
  /// you have recorded before**, and otherwise record it and return `true`.
  /// The same triple twice means the same pre-key message was processed
  /// twice: a replay. `false` fails the decryption with
  /// `LibSignalErrorCode.invalidMessage` before anything is written — this
  /// call comes before `saveIdentity`, `removePreKey` and `storeSession` — as
  /// libsignal fails it when its own store refuses the agreement.
  ///
  /// **What else to do depends on which kind of key it is** — and the record
  /// does not say, so your store must remember that from the moment it
  /// generated the key (see [storeKyberPreKey]):
  ///
  /// - **One-time key:** retire it as well. The mark only protects anything if
  ///   [loadKyberPreKey] then refuses to serve it; persisting the mark and
  ///   still serving the key protects nothing.
  /// - **Last-resort key:** keep serving it — it is designed to be reused. The
  ///   recorded triples are its whole defence: a message that used no one-time
  ///   EC pre-key builds its session again once that session has left the
  ///   record, which since libsignal v0.106.0 takes three newer archived
  ///   sessions. A store that always returns `true` leaves it open to replay.
  ///
  /// **The record must be durable before you return `true`.** The library
  /// awaits this call before any other write and before returning the
  /// plaintext. Refuse with `false`, never by throwing: a store callback that
  /// throws panics the Rust worker thread rather than returning a clean
  /// error.
  Future<bool> markKyberPreKeyUsed(
    int kyberPreKeyId,
    int signedPreKeyId,
    PublicKey baseKey,
  );

  /// Removes a Kyber pre-key by its ID.
  Future<void> removeKyberPreKey(int kyberPreKeyId);

  /// Gets all stored Kyber pre-key IDs.
  Future<List<int>> getAllKyberPreKeyIds();
}
