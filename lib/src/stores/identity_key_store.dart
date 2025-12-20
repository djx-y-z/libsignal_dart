/// Identity key store interface for Signal Protocol.
library;

import '../keys/identity_key_pair.dart';
import '../keys/public_key.dart';
import '../protocol/protocol_address.dart';

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
  Future<bool> saveIdentity(ProtocolAddress address, PublicKey identityKey);

  /// Gets the stored identity key for a remote user.
  ///
  /// Returns `null` if no identity is stored for this address.
  Future<PublicKey?> getIdentity(ProtocolAddress address);

  /// Checks if the given identity key is trusted for the given address.
  ///
  /// The [direction] parameter indicates whether we're sending to or
  /// receiving from this identity.
  ///
  /// Returns `true` if the identity should be trusted, `false` otherwise.
  /// An identity is typically trusted if:
  /// - It's the first time seeing this identity (for receiving)
  /// - It matches what we have stored
  /// - The user has explicitly verified/trusted this identity
  Future<bool> isTrustedIdentity(
    ProtocolAddress address,
    PublicKey identityKey,
    Direction direction,
  );
}
