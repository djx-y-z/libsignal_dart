import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

import '../utils.dart';

/// Demonstrates Safety Number (fingerprint) generation for identity verification.
Future<void> runFingerprintDemo() async {
  printHeader('Fingerprint Demo');

  // 1. Generate identity keys
  final aliceIdentity = IdentityKeyPair.generate();
  final bobIdentity = IdentityKeyPair.generate();
  printStep(1, 'Identity keys generated', [
    'Alice public key: ${bytesToHex(aliceIdentity.publicKey, maxLength: 24)}',
    'Bob public key: ${bytesToHex(bobIdentity.publicKey, maxLength: 24)}',
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
  final aliceFingerprint = Fingerprint(
    iterations: 5200,
    version: 2,
    localIdentifier: aliceId,
    localPublicKey: aliceIdentity.publicKey,
    remoteIdentifier: bobId,
    remotePublicKey: bobIdentity.publicKey,
  );
  final aliceDisplay = aliceFingerprint.displayString();
  printStep(3, "Alice's Safety Number", [
    formatFingerprint(aliceDisplay),
    'Length: ${aliceDisplay.length} digits',
  ]);
  print('');

  // 4. Create Bob's fingerprint (his view - swapped)
  final bobFingerprint = Fingerprint(
    iterations: 5200,
    version: 2,
    localIdentifier: bobId,
    localPublicKey: bobIdentity.publicKey,
    remoteIdentifier: aliceId,
    remotePublicKey: aliceIdentity.publicKey,
  );
  final bobDisplay = bobFingerprint.displayString();
  printStep(4, "Bob's Safety Number", [formatFingerprint(bobDisplay)]);
  print('');

  // 5. Verify symmetry
  final isSymmetric = aliceDisplay == bobDisplay;
  printStep(5, 'Symmetry verification', [
    'Alice and Bob see same number: $isSymmetric',
  ]);
  print('');

  // 6. Scannable encoding
  final scannable = aliceFingerprint.scannableEncoding();
  printStep(6, 'Scannable encoding (for QR codes)', [
    'Size: ${scannable.length} bytes',
    'Hex: ${bytesToHex(scannable, maxLength: 32)}',
  ]);

  // No dispose() needed - FRB handles memory automatically
}
