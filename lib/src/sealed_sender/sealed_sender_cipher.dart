/// Sealed Sender cipher for anonymous message encryption/decryption.
library;

import 'dart:typed_data';

import '../rust/api/address.dart';
import '../rust/api/keys.dart';
import '../rust/api/sealed_sender.dart' as rust;
import '../rust/api/session.dart';
import '../stores/identity_key_store.dart';
import '../stores/kyber_pre_key_store.dart';
import '../stores/pre_key_store.dart';
import '../stores/session_store.dart';
import '../stores/signed_pre_key_store.dart';

/// Result of sealed sender decryption containing plaintext and sender info.
class SealedSenderDecryptionResult {
  /// Creates a decryption result.
  SealedSenderDecryptionResult({
    required this.plaintext,
    required this.senderAddress,
    required this.senderIdentityKey,
  });

  /// The decrypted plaintext message.
  final Uint8List plaintext;

  /// The sender's protocol address (name and device ID).
  final ProtocolAddress senderAddress;

  /// The identity key the sender certificate names, validated against the
  /// trust root.
  ///
  /// Not necessarily the key stored for the sender:
  /// [IdentityKeyStore.saveIdentity] receives the key the inner message's
  /// session is bound to, which a genuine sender's certificate repeats.
  final PublicKey senderIdentityKey;
}

/// Encrypts and decrypts messages using Sealed Sender protocol.
///
/// Sealed Sender allows sending messages without revealing the sender's
/// identity to the server. Only the recipient can decrypt and learn who
/// sent the message.
///
/// Example usage:
/// ```dart
/// final cipher = SealedSenderCipher(
///   localAddress: myAddress,
///   sessionStore: mySessionStore,
///   identityKeyStore: myIdentityKeyStore,
///   preKeyStore: myPreKeyStore,
///   signedPreKeyStore: mySignedPreKeyStore,
///   kyberPreKeyStore: myKyberPreKeyStore,
/// );
///
/// // Encrypt a message to Bob using sealed sender
/// final ciphertext = await cipher.encrypt(
///   recipientAddress: bobAddress,
///   plaintext: utf8.encode('Hello!'),
///   senderCertificate: mySenderCert,
/// );
///
/// // Decrypt a sealed sender message
/// final result = await cipher.decrypt(
///   ciphertext: ciphertext,
///   trustRoot: serverTrustRoot,
///   timestamp: DateTime.now().millisecondsSinceEpoch,
/// );
/// ```
///
/// ## Ratchet state
///
/// Sealed sender wraps the same Double Ratchet session as `SessionCipher`, so
/// it carries the same requirements: the library persists the advanced session
/// (and the peer's identity: the recipient's on encrypt, the sender's on
/// decrypt) through your stores before returning the ciphertext or plaintext,
/// but the store writes must be **durable** and operations for one address must
/// be **serialized** — including against plain `SessionCipher` calls on the
/// same address, since both advance the same session. See [SessionStore] and
/// `SECURITY.md`.
class SealedSenderCipher {
  /// Creates a new SealedSenderCipher with the given stores.
  ///
  /// All stores are required for full functionality:
  /// - [localAddress] our protocol address (UUID + device ID)
  /// - [sessionStore] for session state
  /// - [identityKeyStore] for identity keys
  /// - [preKeyStore] for one-time pre-keys (needed for decrypting pre-key messages)
  /// - [signedPreKeyStore] for signed pre-keys (needed for decrypting pre-key messages)
  /// - [kyberPreKeyStore] for Kyber pre-keys (needed for decrypting pre-key messages)
  SealedSenderCipher({
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

  /// Encrypts a message using Sealed Sender (anonymous delivery).
  ///
  /// The [recipientAddress] identifies the recipient.
  /// The [plaintext] is the message to encrypt.
  /// The [senderCertificate] is our sender certificate (serialized bytes).
  ///
  /// Returns the sealed sender ciphertext.
  ///
  /// Stores the recipient's identity key through
  /// [IdentityKeyStore.saveIdentity] on every message, as libsignal does: the
  /// key the session is bound to, just checked against the stored one. While
  /// that identity is stored this changes nothing; for an address whose stored
  /// identity was deleted, it stores the key again.
  ///
  /// Throws an exception if no session exists for the recipient.
  Future<Uint8List> encrypt({
    required ProtocolAddress recipientAddress,
    required Uint8List plaintext,
    required Uint8List senderCertificate,
  }) async {
    final result = await rust.sealedSenderEncryptWithCallbacks(
      recipientName: recipientAddress.name(),
      recipientDeviceId: recipientAddress.deviceId(),
      plaintext: plaintext,
      senderCertificate: senderCertificate,
      loadSession: (name, deviceId) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final session = await _sessionStore.loadSession(addr);
        return session?.serialize();
      },
      storeSession: (name, deviceId, bytes) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final record = SessionRecord.deserialize(bytes: bytes);
        await _sessionStore.storeSession(addr, record);
      },
      getIdentityKeyPair: () async {
        final pair = await _identityKeyStore.getIdentityKeyPair();
        return pair.serialize();
      },
      getLocalRegistrationId: () async {
        return _identityKeyStore.getLocalRegistrationId();
      },
      // sealed_sender_encrypt goes through libsignal's message_encrypt, which
      // saves the identity it has just checked, on every message: a no-op
      // while it is stored, and the key again for an address whose stored
      // identity was deleted.
      saveIdentity: (name, deviceId, identityBytes) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final identityKey = PublicKey.deserialize(bytes: identityBytes);
        await _identityKeyStore.saveIdentity(addr, identityKey);
      },
      // Enforces identity-trust when sending: sealed_sender_encrypt goes
      // through libsignal's message_encrypt, so a stored recipient identity
      // that differs from the session's is rejected with UntrustedIdentity.
      getIdentity: (name, deviceId) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final identity = await _identityKeyStore.getIdentity(addr);
        return identity?.serialize();
      },
    );

    return result.ciphertext;
  }

  /// Decrypts a Sealed Sender message.
  ///
  /// The [ciphertext] is the sealed sender ciphertext to decrypt.
  /// The [trustRoot] is the server's trust root public key (serialized bytes).
  /// The [timestamp] is the current time in milliseconds since epoch,
  /// used for certificate validation.
  ///
  /// Returns a [SealedSenderDecryptionResult] containing the plaintext
  /// and sender information.
  ///
  /// Throws an exception if:
  /// - The sender certificate is invalid or expired
  /// - The message cannot be decrypted
  /// - Required pre-keys are not found
  /// - The message is a pre-key message whose agreement your
  ///   [KyberPreKeyStore.markKyberPreKeyUsed] answers `false` for — one it has
  ///   recorded before, so a replay: a `LibSignalException` with
  ///   `LibSignalErrorCode.invalidMessage`, and nothing is written
  Future<SealedSenderDecryptionResult> decrypt({
    required Uint8List ciphertext,
    required Uint8List trustRoot,
    required int timestamp,
  }) async {
    final result = await rust.sealedSenderDecryptWithCallbacks(
      ciphertext: ciphertext,
      trustRoot: trustRoot,
      timestamp: BigInt.from(timestamp),
      localName: _localAddress.name(),
      localDeviceId: _localAddress.deviceId(),
      loadSession: (name, deviceId) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final session = await _sessionStore.loadSession(addr);
        return session?.serialize(); // coverage:ignore-line
      },
      storeSession: (name, deviceId, bytes) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final record = SessionRecord.deserialize(bytes: bytes);
        await _sessionStore.storeSession(addr, record);
      },
      getIdentityKeyPair: () async {
        final pair = await _identityKeyStore.getIdentityKeyPair();
        return pair.serialize();
      },
      getLocalRegistrationId: () async {
        return _identityKeyStore.getLocalRegistrationId();
      },
      saveIdentity: (name, deviceId, identityBytes) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final identityKey = PublicKey.deserialize(bytes: identityBytes);
        await _identityKeyStore.saveIdentity(addr, identityKey);
      },
      loadSignedPreKey: (id) async {
        final preKey = await _signedPreKeyStore.loadSignedPreKey(id);
        return preKey?.serialize();
      },
      loadPreKey: (id) async {
        final preKey = await _preKeyStore.loadPreKey(id);
        return preKey?.serialize();
      },
      removePreKey: (id) async {
        await _preKeyStore.removePreKey(id);
      },
      loadKyberPreKey: (id) async {
        final preKey = await _kyberPreKeyStore.loadKyberPreKey(id);
        return preKey?.serialize();
      },
      // The store's answer is libsignal's replay check: `false` fails the
      // decryption before anything is written.
      markKyberPreKeyUsed: (id, signedPreKeyId, baseKey) =>
          _kyberPreKeyStore.markKyberPreKeyUsed(
            id,
            signedPreKeyId,
            PublicKey.deserialize(bytes: baseKey),
          ),
      // Enforces identity-trust for the sender: the Rust layer pre-seeds this
      // known identity so a changed sender key is rejected with UntrustedIdentity
      // (relevant for the pre-key branch of sealed-sender decryption).
      getIdentity: (name, deviceId) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        final identity = await _identityKeyStore.getIdentity(addr);
        return identity?.serialize();
      },
    );

    final senderAddress = ProtocolAddress(
      name: result.senderName,
      deviceId: result.senderDeviceId,
    );

    final senderIdentityKey = PublicKey.deserialize(
      bytes: result.senderIdentityKey,
    );

    return SealedSenderDecryptionResult(
      plaintext: result.plaintext,
      senderAddress: senderAddress,
      senderIdentityKey: senderIdentityKey,
    );
  }
}
