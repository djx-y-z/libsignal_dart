import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

import '../utils.dart';

/// Demonstrates key generation and digital signatures.
Future<void> runKeysDemo() async {
  printHeader('Keys Demo');

  // 1. Generate PrivateKey
  final privateKey = PrivateKey.generate();
  final privateBytes = privateKey.serialize();
  printStep(1, 'PrivateKey generated', [
    'Size: ${privateBytes.length} bytes',
    'Hex: ${bytesToHex(privateBytes, maxLength: 32)}',
  ]);
  print('');

  // 2. Get PublicKey from PrivateKey
  final publicKey = privateKey.getPublicKey();
  final publicBytes = publicKey.serialize();
  printStep(2, 'PublicKey derived', [
    'Size: ${publicBytes.length} bytes (1 type + 32 key)',
    'Hex: ${bytesToHex(publicBytes, maxLength: 32)}',
  ]);
  print('');

  // 3. Sign a message
  const messageText = 'Hello, Signal Protocol!';
  final message = Uint8List.fromList(utf8.encode(messageText));
  final signature = privateKey.sign(message: message);
  printStep(3, 'Message signed (Ed25519)', [
    'Message: "$messageText"',
    'Signature size: ${signature.length} bytes',
    'Signature: ${bytesToHex(signature, maxLength: 32)}',
  ]);
  print('');

  // 4. Verify signature
  final isValid = publicKey.verify(message: message, signature: signature);
  printStep(4, 'Signature verification', ['Valid: $isValid']);
  print('');

  // 5. Verify with wrong message fails
  final wrongMessage = Uint8List.fromList(utf8.encode('Wrong message'));
  final isInvalid = publicKey.verify(
    message: wrongMessage,
    signature: signature,
  );
  printStep(5, 'Wrong message verification', [
    'Valid: $isInvalid (expected: false)',
  ]);
  print('');

  // 6. Generate IdentityKeyPair
  final identityKeyPair = IdentityKeyPair.generate();
  final identitySerialized = identityKeyPair.serialize();
  printStep(6, 'IdentityKeyPair generated', [
    'Serialized size: ${identitySerialized.length} bytes',
    'Public key: ${bytesToHex(identityKeyPair.publicKey, maxLength: 32)}',
  ]);

  // No dispose() needed - FRB handles memory automatically
}
