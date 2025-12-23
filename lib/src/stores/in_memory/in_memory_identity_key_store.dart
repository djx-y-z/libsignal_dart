/// In-memory identity key store implementation.
library;

import '../../keys/identity_key_pair.dart';
import '../../keys/public_key.dart';
import '../../protocol/protocol_address.dart';
import '../identity_key_store.dart';

/// In-memory implementation of [IdentityKeyStore].
///
/// This implementation stores identity keys in memory and is suitable for
/// testing and prototyping. For production use, implement a persistent
/// store backed by secure storage.
///
/// Note: This implementation does NOT persist data across app restarts.
class InMemoryIdentityKeyStore implements IdentityKeyStore {
  final IdentityKeyPair _identityKeyPair;
  final int _localRegistrationId;
  final Map<String, PublicKey> _identities = {};

  /// Creates an in-memory identity key store.
  ///
  /// The [identityKeyPair] is our own identity key pair.
  /// The [localRegistrationId] is our registration ID.
  InMemoryIdentityKeyStore(this._identityKeyPair, this._localRegistrationId);

  String _key(ProtocolAddress address) => address.name;

  @override
  Future<IdentityKeyPair> getIdentityKeyPair() async => _identityKeyPair;

  @override
  Future<int> getLocalRegistrationId() async => _localRegistrationId;

  @override
  Future<bool> saveIdentity(
    ProtocolAddress address,
    PublicKey identityKey,
  ) async {
    final key = _key(address);
    final existing = _identities[key];

    if (existing == null) {
      _identities[key] = identityKey;
      return true; // New identity
    }

    if (existing != identityKey) {
      _identities[key] = identityKey;
      return true; // Changed identity
    }

    return false; // Same identity
  }

  @override
  Future<PublicKey?> getIdentity(ProtocolAddress address) async {
    return _identities[_key(address)];
  }

  @override
  Future<bool> isTrustedIdentity(
    ProtocolAddress address,
    PublicKey identityKey,
    Direction direction,
  ) async {
    final key = _key(address);
    final existing = _identities[key];

    // Trust on first use (TOFU) policy:
    // - If we don't have a stored identity, trust this one
    // - If we have a stored identity, only trust if it matches
    if (existing == null) {
      return true;
    }

    return existing == identityKey;
  }

  /// Clears all stored identities.
  void clear() => _identities.clear();

  /// Gets the number of stored identities.
  int get length => _identities.length;
}
