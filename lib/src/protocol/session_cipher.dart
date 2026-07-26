/// Session cipher for encrypting and decrypting Signal Protocol messages.
library;

import 'dart:typed_data';

import '../rust/api/address.dart';
import '../rust/api/keys.dart';
import '../rust/api/session.dart';
import '../rust/api/session_cipher.dart' as rust;
import '../stores/identity_key_store.dart';
import '../stores/kyber_pre_key_store.dart';
import '../stores/pre_key_store.dart';
import '../stores/session_store.dart';
import '../stores/signed_pre_key_store.dart';
import 'ciphertext_message.dart';

/// Encrypts and decrypts messages using an established Signal Protocol session.
///
/// The SessionCipher handles the Double Ratchet algorithm for message
/// encryption and decryption. Before using SessionCipher, a session must
/// be established using [SessionBuilder].
///
/// Example usage:
/// ```dart
/// final cipher = SessionCipher(
///   localAddress: myAddress,
///   sessionStore: mySessionStore,
///   identityKeyStore: myIdentityKeyStore,
///   preKeyStore: myPreKeyStore,
///   signedPreKeyStore: mySignedPreKeyStore,
///   kyberPreKeyStore: myKyberPreKeyStore,
/// );
///
/// // Encrypt a message to Bob
/// final ciphertext = await cipher.encrypt(bobAddress, utf8.encode('Hello!'));
///
/// // Decrypt a message from Alice
/// final plaintext = await cipher.decrypt(aliceAddress, ciphertext);
/// ```
///
/// ## Ratchet state: what the library guarantees, and what you must do
///
/// Every operation here advances the Double Ratchet, and the library persists
/// the advanced state through your stores **before** it hands back the
/// ciphertext or plaintext: `storeSession` — plus `saveIdentity`,
/// `removePreKey` and `markKyberPreKeyUsed` where they apply — are awaited
/// first. The ordering "persist, then release the output" therefore holds by
/// construction, on this and every other entry point in this package.
///
/// Two things are still yours to get right, and both are silent failures:
///
/// - **Durability.** Your store callbacks must not complete their futures
///   until the write is durable, or you must commit a transaction opened
///   around this call before you send the ciphertext / act on the plaintext.
///   Otherwise a crash after the callback returned but before the bytes reached
///   stable storage rewinds the ratchet, and the next send re-derives a message
///   key and IV that were already used.
/// - **Serialization.** Never run two operations for the same remote address
///   concurrently. [encrypt] loads the session, advances it and stores it back;
///   two overlapping calls both start from the same record and derive the same
///   message key, with no crash needed. A lock inside the store does not help,
///   because the whole load → ratchet → store cycle is the critical section:
///
///   ```dart
///   // One map per store instance — it is the store that needs serializing,
///   // so do not scope it to a single (possibly short-lived) SessionCipher.
///   final locks = <String, Lock>{}; // package:synchronized
///
///   Future<CiphertextMessage> send(ProtocolAddress to, Uint8List body) {
///     final key = '${to.name()}:${to.deviceId()}';
///     return locks
///         .putIfAbsent(key, Lock.new)
///         .synchronized(() => cipher.encrypt(to, body));
///   }
///   ```
///
/// See [SessionStore] and `SECURITY.md` for the full contract.
class SessionCipher {
  /// Creates a new SessionCipher with the given stores.
  ///
  /// All stores are required for full functionality:
  /// - [localAddress] our protocol address (UUID + device ID)
  /// - [sessionStore] for session state
  /// - [identityKeyStore] for identity keys
  /// - [preKeyStore] for one-time pre-keys (needed for decrypting pre-key messages)
  /// - [signedPreKeyStore] for signed pre-keys (needed for decrypting pre-key messages)
  /// - [kyberPreKeyStore] for Kyber pre-keys (needed for decrypting pre-key messages)
  SessionCipher({
    required ProtocolAddress localAddress,
    required SessionStore sessionStore,
    required IdentityKeyStore identityKeyStore,
    required PreKeyStore preKeyStore,
    required SignedPreKeyStore signedPreKeyStore,
    required KyberPreKeyStore kyberPreKeyStore,
  }) : _localAddress = localAddress,
       _sessionStore = sessionStore,
       _identityKeyStore = identityKeyStore,
       _preKeyStore = preKeyStore,
       _signedPreKeyStore = signedPreKeyStore,
       _kyberPreKeyStore = kyberPreKeyStore;

  /// Our local protocol address.
  final ProtocolAddress _localAddress;

  /// The session store for persisting session state.
  final SessionStore _sessionStore;

  /// The identity key store for our identity and remote identities.
  final IdentityKeyStore _identityKeyStore;

  /// The pre-key store for one-time pre-keys.
  final PreKeyStore _preKeyStore;

  /// The signed pre-key store for medium-term pre-keys.
  final SignedPreKeyStore _signedPreKeyStore;

  /// The Kyber pre-key store for post-quantum pre-keys.
  final KyberPreKeyStore _kyberPreKeyStore;

  /// Encrypts a message for the remote user.
  ///
  /// The [remoteAddress] identifies the recipient.
  /// The [plaintext] is the message to encrypt.
  ///
  /// Returns a [CiphertextMessage] containing the encrypted message.
  /// The message type indicates whether this is a pre-key message
  /// (for session establishment) or a regular Signal message.
  ///
  /// Throws an exception if no session exists for the remote address.
  Future<CiphertextMessage> encrypt(
    ProtocolAddress remoteAddress,
    Uint8List plaintext,
  ) async {
    final result = await rust.messageEncryptWithCallbacks(
      remoteName: remoteAddress.name(),
      remoteDeviceId: remoteAddress.deviceId(),
      localName: _localAddress.name(),
      localDeviceId: _localAddress.deviceId(),
      plaintext: plaintext.toList(),
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
      // Enforces identity-trust when sending: the Rust layer pre-seeds this
      // known identity so libsignal rejects encryption to a session whose
      // remote key differs from the stored one with UntrustedIdentity.
      getIdentity: (name, deviceId) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final identity = await _identityKeyStore.getIdentity(addr);
        return identity?.serialize();
      },
    );

    return CiphertextMessage.fromRaw(
      messageType: result.messageType,
      ciphertext: result.ciphertext,
    );
  }

  /// Decrypts a message from the remote user.
  ///
  /// The [remoteAddress] identifies the sender.
  /// The [ciphertext] is the encrypted message.
  ///
  /// This method automatically detects the message type and handles both
  /// regular Signal messages and pre-key messages (for session establishment).
  ///
  /// For pre-key messages, this will look up the required pre-keys from
  /// the stores and remove one-time pre-keys after use.
  ///
  /// Returns the decrypted plaintext.
  ///
  /// Throws an exception if decryption fails (invalid MAC, missing keys, etc.).
  Future<Uint8List> decrypt(
    ProtocolAddress remoteAddress,
    CiphertextMessage ciphertext,
  ) async {
    if (ciphertext.isPreKeyMessage) {
      return _decryptPreKeyMessage(remoteAddress, ciphertext.ciphertext);
    } else {
      return _decryptSignalMessage(remoteAddress, ciphertext.ciphertext);
    }
  }

  /// Decrypts a Signal message (regular message, not pre-key).
  ///
  /// Use this when you know the message type is a regular Signal message.
  Future<Uint8List> decryptSignalMessage(
    ProtocolAddress remoteAddress,
    Uint8List ciphertext,
  ) async {
    return _decryptSignalMessage(remoteAddress, ciphertext);
  }

  /// Decrypts a pre-key Signal message (for session establishment).
  ///
  /// Use this when you know the message type is a pre-key message.
  Future<Uint8List> decryptPreKeyMessage(
    ProtocolAddress remoteAddress,
    Uint8List ciphertext,
  ) async {
    return _decryptPreKeyMessage(remoteAddress, ciphertext);
  }

  Future<Uint8List> _decryptSignalMessage(
    ProtocolAddress remoteAddress,
    Uint8List ciphertext,
  ) async {
    final plaintext = await rust.messageDecryptSignalWithCallbacks(
      remoteName: remoteAddress.name(),
      remoteDeviceId: remoteAddress.deviceId(),
      localName: _localAddress.name(),
      localDeviceId: _localAddress.deviceId(),
      ciphertext: ciphertext.toList(),
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
      // Enforces identity-trust when receiving: the Rust layer pre-seeds this
      // known identity so libsignal rejects a message from a session whose
      // remote key differs from the stored one with UntrustedIdentity.
      getIdentity: (name, deviceId) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final identity = await _identityKeyStore.getIdentity(addr);
        return identity?.serialize();
      },
    );

    return plaintext;
  }

  Future<Uint8List> _decryptPreKeyMessage(
    ProtocolAddress remoteAddress,
    Uint8List ciphertext,
  ) async {
    final plaintext = await rust.messageDecryptPrekeyWithCallbacks(
      remoteName: remoteAddress.name(),
      remoteDeviceId: remoteAddress.deviceId(),
      localName: _localAddress.name(),
      localDeviceId: _localAddress.deviceId(),
      ciphertext: ciphertext.toList(),
      loadSession: (name, deviceId) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final record = await _sessionStore.loadSession(addr);
        return record?.serialize(); // coverage:ignore-line
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
      loadSignedPreKey: (id) async {
        final record = await _signedPreKeyStore.loadSignedPreKey(id);
        return record != null ? Uint8List.fromList(record.serialize()) : null;
      },
      loadPreKey: (id) async {
        final record = await _preKeyStore.loadPreKey(id);
        return record != null ? Uint8List.fromList(record.serialize()) : null;
      },
      removePreKey: (id) async {
        await _preKeyStore.removePreKey(id);
      },
      loadKyberPreKey: (id) async {
        final record = await _kyberPreKeyStore.loadKyberPreKey(id);
        return record != null ? Uint8List.fromList(record.serialize()) : null;
      },
      markKyberPreKeyUsed: (id, signedPreKeyId, baseKey) async {
        await _kyberPreKeyStore.markKyberPreKeyUsed(
          id,
          signedPreKeyId,
          PublicKey.deserialize(bytes: baseKey),
        );
      },
      // Enforces identity-trust for the new session: the Rust layer pre-seeds
      // this known identity so libsignal rejects a changed sender key with
      // UntrustedIdentity instead of silently accepting it.
      getIdentity: (name, deviceId) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final identity = await _identityKeyStore.getIdentity(addr);
        return identity?.serialize();
      },
    );

    return plaintext;
  }
}
