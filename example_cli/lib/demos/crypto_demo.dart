import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

import '../utils.dart';

/// Demonstrates AES-256-GCM-SIV symmetric encryption.
Future<void> runCryptoDemo() async {
  printHeader('Crypto Demo');

  Aes256GcmSiv? cipher;

  try {
    // 1. Generate key and nonce
    final key = randomBytes(32);
    final nonce = randomBytes(12);
    printStep(1, 'Key and nonce generated', [
      'Key size: ${key.length} bytes (256 bits)',
      'Key: ${bytesToHex(key, maxLength: 32)}',
      'Nonce size: ${nonce.length} bytes (96 bits)',
      'Nonce: ${bytesToHex(nonce)}',
    ]);
    print('');

    // 2. Create cipher
    cipher = Aes256GcmSiv(key);
    printStep(2, 'AES-256-GCM-SIV cipher created');
    print('');

    // 3. Encrypt message
    const messageText = 'Secret message for encryption';
    final plaintext = Uint8List.fromList(utf8.encode(messageText));
    final ciphertext = cipher.encrypt(plaintext: plaintext, nonce: nonce);
    printStep(3, 'Message encrypted', [
      'Plaintext: "$messageText"',
      'Plaintext size: ${plaintext.length} bytes',
      'Ciphertext size: ${ciphertext.length} bytes',
      'Size diff: +${ciphertext.length - plaintext.length} bytes (auth tag)',
      'Ciphertext: ${bytesToHex(ciphertext, maxLength: 40)}',
    ]);
    print('');

    // 4. Decrypt message
    final decrypted = cipher.decrypt(ciphertext: ciphertext, nonce: nonce);
    final decryptedText = utf8.decode(decrypted);
    printStep(4, 'Message decrypted', [
      'Decrypted: "$decryptedText"',
      'Match: ${decryptedText == messageText}',
    ]);
    print('');

    // 5. Demonstrate determinism
    final ciphertext2 = cipher.encrypt(plaintext: plaintext, nonce: nonce);
    final isSame = bytesToHex(ciphertext) == bytesToHex(ciphertext2);
    printStep(5, 'Determinism test (same key + nonce)', [
      'Same ciphertext: $isSame',
    ]);
    print('');

    // 6. Different nonce = different ciphertext
    final nonce2 = randomBytes(12);
    final ciphertext3 = cipher.encrypt(plaintext: plaintext, nonce: nonce2);
    final isDifferent = bytesToHex(ciphertext) != bytesToHex(ciphertext3);
    printStep(6, 'Different nonce test', [
      'Different ciphertext: $isDifferent',
    ]);
  } finally {
    cipher?.dispose();
  }
}
