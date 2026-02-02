/// Session builder for establishing Signal Protocol sessions.
library;

import 'dart:typed_data';

import '../rust/api/address.dart';
import '../rust/api/bundle.dart';
import '../rust/api/keys.dart';
import '../rust/api/session.dart';
import '../rust/api/session_builder.dart' as rust;
import '../stores/identity_key_store.dart';
import '../stores/session_store.dart';

/// Builds sessions with remote users using their pre-key bundles.
///
/// The SessionBuilder handles the X3DH key agreement protocol to establish
/// a shared session with a remote user. Once a session is established,
/// use [SessionCipher] to encrypt and decrypt messages.
///
/// Example usage:
/// ```dart
/// final builder = SessionBuilder(
///   sessionStore: mySessionStore,
///   identityKeyStore: myIdentityKeyStore,
/// );
///
/// // Process a pre-key bundle from Bob
/// await builder.processPreKeyBundle(
///   bobAddress,
///   bobPreKeyBundle,
/// );
///
/// // Now we can encrypt messages to Bob using SessionCipher
/// ```
class SessionBuilder {
  /// Creates a new SessionBuilder with the given stores.
  ///
  /// The stores are used to persist session state and identity information.
  SessionBuilder({
    required SessionStore sessionStore,
    required IdentityKeyStore identityKeyStore,
  }) : _sessionStore = sessionStore,
       _identityKeyStore = identityKeyStore;

  /// The session store for persisting session state.
  final SessionStore _sessionStore;

  /// The identity key store for our identity and remote identities.
  final IdentityKeyStore _identityKeyStore;

  /// Processes a pre-key bundle to establish a session with a remote user.
  ///
  /// This performs the X3DH/PQXDH key agreement protocol using the remote
  /// user's pre-key bundle. After successful completion, a session will be
  /// stored for the remote address.
  ///
  /// The [remoteAddress] identifies the remote user and device.
  /// The [preKeyBundle] contains the remote user's public keys for session
  /// establishment.
  ///
  /// Throws an exception if:
  /// - The pre-key bundle signature is invalid
  /// - The remote identity is not trusted
  /// - Any cryptographic operation fails
  Future<void> processPreKeyBundle(
    ProtocolAddress remoteAddress,
    PreKeyBundle preKeyBundle,
  ) async {
    await rust.processPrekeyBundleWithCallbacks(
      remoteName: remoteAddress.name(),
      remoteDeviceId: remoteAddress.deviceId(),
      bundle: preKeyBundle,
      loadSession: (name, deviceId) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final record = await _sessionStore.loadSession(addr);
        return record?.serialize();
      },
      storeSession: (name, deviceId, recordBytes) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final record = SessionRecord.deserialize(bytes: recordBytes);
        await _sessionStore.storeSession(addr, record);
      },
      getIdentityKeyPair: () async {
        final keyPair = await _identityKeyStore.getIdentityKeyPair();
        return Uint8List.fromList(keyPair.serialize());
      },
      getLocalRegistrationId: () async {
        return _identityKeyStore.getLocalRegistrationId();
      },
      saveIdentity: (name, deviceId, identityKeyBytes) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final identityKey = PublicKey.deserialize(
          bytes: identityKeyBytes.toList(),
        );
        await _identityKeyStore.saveIdentity(addr, identityKey);
      },
    );
  }
}
