import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

import '../utils.dart';

/// Demonstrates key generation and digital signatures.
Future<void> runKeysDemo() async {
  printHeader('Keys Demo');

  PrivateKey? privateKey;
  PublicKey? publicKey;
  IdentityKeyPair? identityKeyPair;

  try {
    // 1. Generate PrivateKey
    privateKey = PrivateKey.generate();
    final privateBytes = privateKey.serialize();
    printStep(1, 'PrivateKey generated', [
      'Size: ${privateBytes.bytes.length} bytes',
      'Hex: ${bytesToHex(privateBytes.bytes, maxLength: 32)}',
    ]);
    print('');

    // 2. Get PublicKey from PrivateKey
    publicKey = privateKey.getPublicKey();
    final publicBytes = publicKey.serialize();
    printStep(2, 'PublicKey derived', [
      'Size: ${publicBytes.length} bytes (1 type + 32 key)',
      'Hex: ${bytesToHex(publicBytes, maxLength: 32)}',
    ]);
    print('');

    // 3. Sign a message
    const messageText = 'Hello, Signal Protocol!';
    final message = Uint8List.fromList(utf8.encode(messageText));
    final signature = privateKey.sign(message);
    printStep(3, 'Message signed (Ed25519)', [
      'Message: "$messageText"',
      'Signature size: ${signature.length} bytes',
      'Signature: ${bytesToHex(signature, maxLength: 32)}',
    ]);
    print('');

    // 4. Verify signature
    final isValid = publicKey.verify(message, signature);
    printStep(4, 'Signature verification', [
      'Valid: $isValid',
    ]);
    print('');

    // 5. Verify with wrong message fails
    final wrongMessage = Uint8List.fromList(utf8.encode('Wrong message'));
    final isInvalid = publicKey.verify(wrongMessage, signature);
    printStep(5, 'Wrong message verification', [
      'Valid: $isInvalid (expected: false)',
    ]);
    print('');

    // 6. Generate IdentityKeyPair
    identityKeyPair = IdentityKeyPair.generate();
    final identitySerialized = identityKeyPair.serialize();
    printStep(6, 'IdentityKeyPair generated', [
      'Serialized size: ${identitySerialized.bytes.length} bytes',
      'Public key: ${bytesToHex(identityKeyPair.publicKey.serialize(), maxLength: 32)}',
    ]);
  } finally {
    privateKey?.dispose();
    publicKey?.dispose();
    identityKeyPair?.dispose();
  }
}
