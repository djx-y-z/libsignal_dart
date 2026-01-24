import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

import '../utils.dart';

/// Demonstrates group messaging using SenderKey protocol.
Future<void> runGroupsDemo() async {
  printHeader('Groups Demo');

  // 1. Create protocol addresses
  final aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
  final bobAddress = ProtocolAddress(name: 'bob', deviceId: 1);
  printStep(1, 'Protocol addresses created', [
    'Alice: ${aliceAddress.name()}:${aliceAddress.deviceId()}',
    'Bob: ${bobAddress.name()}:${bobAddress.deviceId()}',
  ]);
  print('');

  // 2. Distribution ID (UUID string)
  const distributionId = '01234567-89ab-cdef-0123-456789abcdef';
  printStep(2, 'Distribution ID (UUID)', ['UUID: $distributionId']);
  print('');

  // 3. Create stores
  final aliceStore = InMemorySenderKeyStore();
  final bobStore = InMemorySenderKeyStore();
  final aliceIdentity = IdentityKeyPair.generate();
  printStep(3, 'Stores created', [
    'Alice store: InMemorySenderKeyStore',
    'Bob store: InMemorySenderKeyStore',
  ]);
  print('');

  // 4. Alice creates distribution message using callback API
  final createResult = await createSenderKeyDistributionMessageWithCallbacks(
    senderName: aliceAddress.name(),
    senderDeviceId: aliceAddress.deviceId(),
    distributionId: distributionId,
    loadSenderKey: (name, deviceId, distId) async {
      final addr = ProtocolAddress(name: name, deviceId: deviceId);
      final keyName = SenderKeyName(addr, distId);
      return aliceStore.loadSenderKey(keyName);
    },
    storeSenderKey: (name, deviceId, distId, recordBytes) async {
      final addr = ProtocolAddress(name: name, deviceId: deviceId);
      final keyName = SenderKeyName(addr, distId);
      await aliceStore.storeSenderKey(keyName, recordBytes);
    },
    getIdentityKeyPair: () async => aliceIdentity.serialize(),
  );
  printStep(4, 'Alice created distribution message', [
    'Message size: ${createResult.distributionMessage.length} bytes',
  ]);
  print('');

  // 5. Bob processes distribution message
  await processSenderKeyDistributionMessageWithCallbacks(
    senderName: aliceAddress.name(),
    senderDeviceId: aliceAddress.deviceId(),
    distributionId: distributionId,
    distributionMessage: createResult.distributionMessage,
    loadSenderKey: (name, deviceId, distId) async {
      final addr = ProtocolAddress(name: name, deviceId: deviceId);
      final keyName = SenderKeyName(addr, distId);
      return bobStore.loadSenderKey(keyName);
    },
    storeSenderKey: (name, deviceId, distId, recordBytes) async {
      final addr = ProtocolAddress(name: name, deviceId: deviceId);
      final keyName = SenderKeyName(addr, distId);
      await bobStore.storeSenderKey(keyName, recordBytes);
    },
  );
  printStep(5, 'Bob processed distribution message', [
    'Bob store entries: ${bobStore.length}',
  ]);
  print('');

  // 6. Alice encrypts message
  const messageText = 'Hello, group!';
  final plaintext = Uint8List.fromList(utf8.encode(messageText));
  final encryptResult = await groupEncryptWithCallbacks(
    senderName: aliceAddress.name(),
    senderDeviceId: aliceAddress.deviceId(),
    distributionId: distributionId,
    plaintext: plaintext,
    loadSenderKey: (name, deviceId, distId) async {
      final addr = ProtocolAddress(name: name, deviceId: deviceId);
      final keyName = SenderKeyName(addr, distId);
      return aliceStore.loadSenderKey(keyName);
    },
    storeSenderKey: (name, deviceId, distId, recordBytes) async {
      final addr = ProtocolAddress(name: name, deviceId: deviceId);
      final keyName = SenderKeyName(addr, distId);
      await aliceStore.storeSenderKey(keyName, recordBytes);
    },
    getIdentityKeyPair: () async => aliceIdentity.serialize(),
  );
  printStep(6, 'Alice encrypted message', [
    'Message: "$messageText"',
    'Ciphertext size: ${encryptResult.ciphertext.length} bytes',
  ]);
  print('');

  // 7. Bob decrypts message
  final decryptResult = await groupDecryptWithCallbacks(
    senderName: aliceAddress.name(),
    senderDeviceId: aliceAddress.deviceId(),
    distributionId: distributionId,
    ciphertext: encryptResult.ciphertext,
    loadSenderKey: (name, deviceId, distId) async {
      final addr = ProtocolAddress(name: name, deviceId: deviceId);
      final keyName = SenderKeyName(addr, distId);
      return bobStore.loadSenderKey(keyName);
    },
    storeSenderKey: (name, deviceId, distId, recordBytes) async {
      final addr = ProtocolAddress(name: name, deviceId: deviceId);
      final keyName = SenderKeyName(addr, distId);
      await bobStore.storeSenderKey(keyName, recordBytes);
    },
  );
  final decryptedText = utf8.decode(decryptResult.plaintext);
  printStep(7, 'Bob decrypted message', [
    'Decrypted: "$decryptedText"',
    'Match: ${decryptedText == messageText}',
  ]);

  // No dispose() needed - FRB handles memory automatically
}
