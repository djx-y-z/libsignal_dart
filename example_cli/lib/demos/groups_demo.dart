import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

import '../utils.dart';

/// Demonstrates group messaging using SenderKey protocol.
Future<void> runGroupsDemo() async {
  printHeader('Groups Demo');

  ProtocolAddress? aliceAddress;
  ProtocolAddress? bobAddress;
  SenderKeyDistributionMessage? distMessage;

  try {
    // 1. Create protocol addresses
    aliceAddress = ProtocolAddress('alice', 1);
    bobAddress = ProtocolAddress('bob', 1);
    printStep(1, 'Protocol addresses created', [
      'Alice: ${aliceAddress.name}:${aliceAddress.deviceId}',
      'Bob: ${bobAddress.name}:${bobAddress.deviceId}',
    ]);
    print('');

    // 2. Generate distribution ID (UUID)
    final distributionId = GroupSession.uuidFromString(
      '01234567-89ab-cdef-0123-456789abcdef',
    );
    final uuidString = GroupSession.uuidToString(distributionId);
    printStep(2, 'Distribution ID (UUID)', [
      'UUID: $uuidString',
      'Size: ${distributionId.length} bytes',
    ]);
    print('');

    // 3. Create stores and sessions
    final aliceStore = InMemorySenderKeyStore();
    final bobStore = InMemorySenderKeyStore();
    final aliceSession = GroupSession(aliceAddress, distributionId, aliceStore);
    final bobSession = GroupSession(bobAddress, distributionId, bobStore);
    printStep(3, 'Group sessions created', [
      'Alice store: InMemorySenderKeyStore',
      'Bob store: InMemorySenderKeyStore',
    ]);
    print('');

    // 4. Alice creates distribution message
    distMessage = await aliceSession.createDistributionMessage();
    printStep(4, 'Alice created distribution message', [
      'Distribution ID: ${GroupSession.uuidToString(distMessage.distributionId)}',
      'Chain key size: ${distMessage.chainKey.length} bytes',
      'Iteration: ${distMessage.iteration}',
    ]);
    print('');

    // 5. Bob processes distribution message
    await bobSession.processDistributionMessage(aliceAddress, distMessage);
    printStep(5, 'Bob processed distribution message', [
      'Bob store entries: ${bobStore.length}',
    ]);
    print('');

    // 6. Alice encrypts message
    const messageText = 'Hello, group!';
    final plaintext = Uint8List.fromList(utf8.encode(messageText));
    final ciphertext = await aliceSession.encrypt(plaintext);
    printStep(6, 'Alice encrypted message', [
      'Message: "$messageText"',
      'Ciphertext size: ${ciphertext.length} bytes',
    ]);
    print('');

    // 7. Bob decrypts message
    final decrypted = await bobSession.decrypt(aliceAddress, ciphertext);
    final decryptedText = utf8.decode(decrypted);
    printStep(7, 'Bob decrypted message', [
      'Decrypted: "$decryptedText"',
      'Match: ${decryptedText == messageText}',
    ]);
  } finally {
    aliceAddress?.dispose();
    bobAddress?.dispose();
    distMessage?.dispose();
  }
}
