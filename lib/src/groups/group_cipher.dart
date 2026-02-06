/// Group cipher for Signal Protocol group messaging.
library;

import 'dart:typed_data';

import '../rust/api/address.dart';
import '../rust/api/group_session.dart' as rust;
import '../stores/identity_key_store.dart';
import '../stores/sender_key_store.dart';

/// Encrypts and decrypts messages for a group using Signal Protocol.
///
/// Group messaging in Signal Protocol uses sender keys, where each participant
/// distributes their own encryption key to other members. This allows efficient
/// fan-out encryption - a message is only encrypted once regardless of group size.
///
/// ## Usage
///
/// ```dart
/// // Create stores
/// final senderKeyStore = InMemorySenderKeyStore();
/// final identityKeyStore = InMemoryIdentityKeyStore(identityKeyPair, registrationId);
///
/// // Create cipher
/// final cipher = GroupCipher(
///   senderKeyStore: senderKeyStore,
///   identityKeyStore: identityKeyStore,
/// );
///
/// // Create distribution message for a new group
/// final myAddress = ProtocolAddress(name: 'alice', deviceId: 1);
/// final distributionId = Uuid().v4(); // Unique group identifier
/// final distMessage = await cipher.createDistributionMessage(myAddress, distributionId);
///
/// // Share distMessage with other group members...
///
/// // Process distribution message from another member
/// await cipher.processDistributionMessage(senderAddress, distributionId, receivedMessage);
///
/// // Encrypt a message to the group
/// final encrypted = await cipher.encrypt(myAddress, distributionId, utf8.encode('Hello group!'));
///
/// // Decrypt a message from a group member
/// final plaintext = await cipher.decrypt(senderAddress, distributionId, encrypted);
/// ```
class GroupCipher {
  /// Creates a new group cipher with the given stores.
  ///
  /// - [senderKeyStore] stores sender keys for group members
  /// - [identityKeyStore] provides our identity key for signing
  GroupCipher({
    required SenderKeyStore senderKeyStore,
    required IdentityKeyStore identityKeyStore,
  }) : _senderKeyStore = senderKeyStore,
       _identityKeyStore = identityKeyStore;

  /// The sender key store for group key storage.
  final SenderKeyStore _senderKeyStore;

  /// The identity key store for signing distribution messages.
  final IdentityKeyStore _identityKeyStore;

  /// Creates a sender key distribution message for a group.
  ///
  /// This creates or updates our sender key for the group and returns a
  /// distribution message that should be sent to all other group members.
  /// Each member needs this message to decrypt our future messages.
  ///
  /// - [senderAddress] is our own address (name + device ID)
  /// - [distributionId] is the unique group identifier (UUID string)
  ///
  /// Returns the distribution message bytes to send to other members.
  Future<Uint8List> createDistributionMessage(
    ProtocolAddress senderAddress,
    String distributionId,
  ) async {
    final result = await rust.createSenderKeyDistributionMessageWithCallbacks(
      senderName: senderAddress.name(),
      senderDeviceId: senderAddress.deviceId(),
      distributionId: distributionId,
      loadSenderKey: (name, deviceId, distId) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        return _senderKeyStore.loadSenderKey(SenderKeyName(addr, distId));
      },
      storeSenderKey: (name, deviceId, distId, record) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        await _senderKeyStore.storeSenderKey(
          SenderKeyName(addr, distId),
          record,
        );
      },
      getIdentityKeyPair: () async {
        final keyPair = await _identityKeyStore.getIdentityKeyPair();
        return keyPair.serialize();
      },
    );
    return result.distributionMessage;
  }

  /// Processes a sender key distribution message from another group member.
  ///
  /// This stores the sender's key so we can decrypt their future messages.
  /// Call this when receiving a distribution message from another member.
  ///
  /// - [senderAddress] is the address of the member who sent the distribution message
  /// - [distributionId] is the unique group identifier (UUID string)
  /// - [distributionMessage] is the distribution message bytes received
  Future<void> processDistributionMessage(
    ProtocolAddress senderAddress,
    String distributionId,
    Uint8List distributionMessage,
  ) async {
    await rust.processSenderKeyDistributionMessageWithCallbacks(
      senderName: senderAddress.name(),
      senderDeviceId: senderAddress.deviceId(),
      distributionId: distributionId,
      distributionMessage: distributionMessage.toList(),
      loadSenderKey: (name, deviceId, distId) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        return _senderKeyStore.loadSenderKey(SenderKeyName(addr, distId));
      },
      storeSenderKey: (name, deviceId, distId, record) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        await _senderKeyStore.storeSenderKey(
          SenderKeyName(addr, distId),
          record,
        );
      },
    );
  }

  /// Encrypts a message to the group.
  ///
  /// The message is encrypted using our sender key. All group members who
  /// have processed our distribution message can decrypt this.
  ///
  /// - [senderAddress] is our own address
  /// - [distributionId] is the unique group identifier
  /// - [plaintext] is the message to encrypt
  ///
  /// Returns the encrypted ciphertext bytes.
  ///
  /// Throws if we haven't created a distribution message for this group yet.
  Future<Uint8List> encrypt(
    ProtocolAddress senderAddress,
    String distributionId,
    List<int> plaintext,
  ) async {
    final result = await rust.groupEncryptWithCallbacks(
      senderName: senderAddress.name(),
      senderDeviceId: senderAddress.deviceId(),
      distributionId: distributionId,
      plaintext: plaintext,
      loadSenderKey: (name, deviceId, distId) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        return _senderKeyStore.loadSenderKey(SenderKeyName(addr, distId));
      },
      storeSenderKey: (name, deviceId, distId, record) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        await _senderKeyStore.storeSenderKey(
          SenderKeyName(addr, distId),
          record,
        );
      },
      getIdentityKeyPair: () async {
        final keyPair = await _identityKeyStore.getIdentityKeyPair();
        return keyPair.serialize();
      },
    );
    return result.ciphertext;
  }

  /// Decrypts a message from a group member.
  ///
  /// - [senderAddress] is the address of the member who sent the message
  /// - [distributionId] is the unique group identifier
  /// - [ciphertext] is the encrypted message bytes
  ///
  /// Returns the decrypted plaintext bytes.
  ///
  /// Throws if we haven't processed a distribution message from this sender.
  Future<Uint8List> decrypt(
    ProtocolAddress senderAddress,
    String distributionId,
    List<int> ciphertext,
  ) async {
    final result = await rust.groupDecryptWithCallbacks(
      senderName: senderAddress.name(),
      senderDeviceId: senderAddress.deviceId(),
      distributionId: distributionId,
      ciphertext: ciphertext,
      loadSenderKey: (name, deviceId, distId) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        return _senderKeyStore.loadSenderKey(SenderKeyName(addr, distId));
      },
      storeSenderKey: (name, deviceId, distId, record) async {
        final addr = ProtocolAddress(name: name, deviceId: deviceId);
        await _senderKeyStore.storeSenderKey(
          SenderKeyName(addr, distId),
          record,
        );
      },
    );
    return result.plaintext;
  }
}
