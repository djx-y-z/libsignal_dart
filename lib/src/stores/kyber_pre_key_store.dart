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
/// Like regular pre-keys, Kyber pre-keys are one-time use (for "last resort"
/// keys) or can be reused (for signed Kyber pre-keys).
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
///     return data != null ? KyberPreKeyRecord.deserialize(data) : null;
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
/// it is how a one-time Kyber pre-key is consumed. See [PreKeyStore] for the
/// consequences of losing a consumption write and [SessionStore] for the full
/// contract.
abstract interface class KyberPreKeyStore {
  /// Loads a Kyber pre-key by its ID.
  ///
  /// Returns `null` if no Kyber pre-key exists with this ID.
  Future<KyberPreKeyRecord?> loadKyberPreKey(int kyberPreKeyId);

  /// Stores a Kyber pre-key.
  Future<void> storeKyberPreKey(int kyberPreKeyId, KyberPreKeyRecord record);

  /// Checks if a Kyber pre-key exists with the given ID.
  Future<bool> containsKyberPreKey(int kyberPreKeyId);

  /// Marks the Kyber pre-key [kyberPreKeyId] as used.
  ///
  /// Called whenever a pre-key message establishes a new session — from both
  /// `SessionCipher.decrypt` and `SealedSenderCipher.decrypt` — and only then.
  /// A redelivered pre-key message that matches a session you already have
  /// consumes nothing and does not call this.
  ///
  /// The arguments are the ones libsignal's own `KyberPreKeyStore` receives:
  /// [signedPreKeyId] is the signed EC pre-key this Kyber key was used with,
  /// and [baseKey] is the sender's ephemeral base key for this agreement.
  /// Together they identify one PQXDH agreement, which is what makes the
  /// last-resort check below possible.
  ///
  /// **What to do depends on which kind of key it is** — and the record does
  /// not say, so your store must remember that from the moment it generated
  /// the key (see [storeKyberPreKey]):
  ///
  /// - **One-time key:** retire it. The mark only protects anything if
  ///   [loadKyberPreKey] then refuses to serve it; persisting the mark and
  ///   still serving the key protects nothing.
  /// - **Last-resort key:** keep serving it — it is designed to be reused —
  ///   but record the `(kyberPreKeyId, signedPreKeyId, baseKey)` triple. Seeing
  ///   the same triple twice means the same pre-key message was processed
  ///   twice, which is the replay this argument list exists to let you detect.
  ///
  /// **The write must be durable before the decrypted plaintext is acted
  /// upon** — the library awaits this call before returning that plaintext.
  ///
  /// **Detection here is after the fact, and must not throw.** Upstream
  /// libsignal fails the decryption when its store rejects a repeated triple.
  /// This library cannot: the callback runs after libsignal has already
  /// produced the plaintext. It is also not a failable callback — throwing from
  /// it panics the Rust worker thread rather than returning a clean error.
  /// Record the repeat and report it to your application instead, and let it
  /// drop the message; do not treat this callback as a decryption barrier.
  Future<void> markKyberPreKeyUsed(
    int kyberPreKeyId,
    int signedPreKeyId,
    PublicKey baseKey,
  );

  /// Removes a Kyber pre-key by its ID.
  Future<void> removeKyberPreKey(int kyberPreKeyId);

  /// Gets all stored Kyber pre-key IDs.
  Future<List<int>> getAllKyberPreKeyIds();
}
