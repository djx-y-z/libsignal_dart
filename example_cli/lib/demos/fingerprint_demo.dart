import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

import '../utils.dart';

/// Demonstrates Safety Number (fingerprint) generation for identity verification.
Future<void> runFingerprintDemo() async {
  printHeader('Fingerprint Demo');

  IdentityKeyPair? aliceIdentity;
  IdentityKeyPair? bobIdentity;
  Fingerprint? aliceFingerprint;
  Fingerprint? bobFingerprint;

  try {
    // 1. Generate identity keys
    aliceIdentity = IdentityKeyPair.generate();
    bobIdentity = IdentityKeyPair.generate();
    printStep(1, 'Identity keys generated', [
      'Alice public key: ${bytesToHex(aliceIdentity.publicKey.serialize(), maxLength: 24)}',
      'Bob public key: ${bytesToHex(bobIdentity.publicKey.serialize(), maxLength: 24)}',
    ]);
    print('');

    // 2. Create identifiers
    final aliceId = Uint8List.fromList(utf8.encode('alice-uuid-12345'));
    final bobId = Uint8List.fromList(utf8.encode('bob-uuid-67890'));
    printStep(2, 'User identifiers', [
      'Alice: ${utf8.decode(aliceId)}',
      'Bob: ${utf8.decode(bobId)}',
    ]);
    print('');

    // 3. Create Alice's fingerprint (her view)
    aliceFingerprint = Fingerprint.create(
      localIdentifier: aliceId,
      localKey: aliceIdentity.publicKey,
      remoteIdentifier: bobId,
      remoteKey: bobIdentity.publicKey,
    );
    final aliceDisplay = aliceFingerprint.displayString;
    printStep(3, "Alice's Safety Number", [
      formatFingerprint(aliceDisplay),
      'Length: ${aliceDisplay.length} digits',
    ]);
    print('');

    // 4. Create Bob's fingerprint (his view - swapped)
    bobFingerprint = Fingerprint.create(
      localIdentifier: bobId,
      localKey: bobIdentity.publicKey,
      remoteIdentifier: aliceId,
      remoteKey: aliceIdentity.publicKey,
    );
    final bobDisplay = bobFingerprint.displayString;
    printStep(4, "Bob's Safety Number", [formatFingerprint(bobDisplay)]);
    print('');

    // 5. Verify symmetry
    final isSymmetric = aliceDisplay == bobDisplay;
    printStep(5, 'Symmetry verification', [
      'Alice and Bob see same number: $isSymmetric',
    ]);
    print('');

    // 6. Scannable encoding
    final scannable = aliceFingerprint.scannableEncoding;
    printStep(6, 'Scannable encoding (for QR codes)', [
      'Size: ${scannable.length} bytes',
      'Hex: ${bytesToHex(scannable, maxLength: 32)}',
    ]);
  } finally {
    aliceIdentity?.dispose();
    bobIdentity?.dispose();
    aliceFingerprint?.dispose();
    bobFingerprint?.dispose();
  }
}
