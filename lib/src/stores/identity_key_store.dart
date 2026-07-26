/// Identity key store interface for Signal Protocol.
library;

import '../rust/api/address.dart';
import '../rust/api/keys.dart';

/// The trust decision for an identity key.
enum IdentityTrustDecision {
  /// This is the first time seeing this identity key.
  untrusted,

  /// The identity key matches what we have stored (trusted).
  trusted,

  /// The identity key has changed from what we had stored.
  changed,
}

/// Direction of communication for identity verification.
enum Direction {
  /// We are sending a message to this identity.
  sending,

  /// We are receiving a message from this identity.
  receiving,
}

/// Abstract interface for storing identity keys.
///
/// This store manages:
/// - Our own identity key pair
/// - Our local registration ID
/// - Remote identities (public keys of other users)
/// - Trust decisions for remote identities
///
/// Example implementation:
/// ```dart
/// class MyIdentityKeyStore implements IdentityKeyStore {
///   final IdentityKeyPair _identityKeyPair;
///   final int _registrationId;
///   final _identities = <String, PublicKey>{};
///
///   MyIdentityKeyStore(this._identityKeyPair, this._registrationId);
///
///   @override
///   Future<IdentityKeyPair> getIdentityKeyPair() async => _identityKeyPair;
///   // ... other methods
/// }
/// ```
///
/// ## Durability (critical)
///
/// Writes to this store must be **durably persisted before the returned future
/// completes**, or be part of a transaction committed durably before the
/// ciphertext is sent / the plaintext is acted upon. The failure mode differs
/// from [SessionStore]: losing a [saveIdentity] write does not rewind the
/// ratchet, it silently downgrades MITM detection, because an address with no
/// stored identity is trusted on first use. A remote key substituted while the
/// write was missing is then accepted instead of raising `UntrustedIdentity`.
///
/// Note that the library stores the session and the remote identity through two
/// separate callbacks, so a crash between them leaves the pair inconsistent.
/// Wrapping the whole `SessionCipher`/`SessionBuilder` call in one transaction
/// avoids that; see [SessionStore] and `SECURITY.md` for the full contract.
abstract interface class IdentityKeyStore {
  /// Gets our own identity key pair.
  Future<IdentityKeyPair> getIdentityKeyPair();

  /// Gets our local registration ID.
  ///
  /// The registration ID is a random number generated at install time
  /// that helps prevent replay attacks.
  Future<int> getLocalRegistrationId();

  /// Saves the identity key for a remote user.
  ///
  /// Returns `true` if this is a new identity or the identity changed,
  /// `false` if the identity was already known and unchanged.
  ///
  /// **Do not complete the returned future until the identity is durably
  /// persisted.** A lost write leaves the address in the trust-on-first-use
  /// state, which disables safety-number-change detection for it.
  Future<bool> saveIdentity(ProtocolAddress address, PublicKey identityKey);

  /// Gets the stored identity key for a remote user.
  ///
  /// Returns `null` if no identity is stored for this address.
  Future<PublicKey?> getIdentity(ProtocolAddress address);

  /// Checks if the given identity key is trusted for the given address.
  ///
  /// The [direction] parameter indicates the context of the trust check:
  /// - [Direction.sending]: Validating identity before encrypting a message
  ///   TO this recipient. You may want stricter validation here (e.g.,
  ///   require explicit user approval for changed keys).
  /// - [Direction.receiving]: Validating identity when decrypting a message
  ///   FROM this sender. You may want more lenient validation here (e.g.,
  ///   trust-on-first-use for new contacts).
  ///
  /// Returns `true` if the identity should be trusted, `false` otherwise.
  /// An identity is typically trusted if:
  /// - It's the first time seeing this identity (TOFU policy)
  /// - It matches what we have stored
  /// - The user has explicitly verified/trusted this identity
  ///
  /// **Security Note**: Different applications may have different trust
  /// policies. Some may always trust on first use, others may require
  /// explicit verification for all new identities.
  Future<bool> isTrustedIdentity(
    ProtocolAddress address,
    PublicKey identityKey,
    Direction direction,
  );
}
