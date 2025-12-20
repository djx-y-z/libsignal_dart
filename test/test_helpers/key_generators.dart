import 'dart:math';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

/// Generates a random PrivateKey for testing.
PrivateKey generatePrivateKey() {
  return PrivateKey.generate();
}

/// Generates a random IdentityKeyPair for testing.
IdentityKeyPair generateIdentityKeyPair() {
  return IdentityKeyPair.generate();
}

/// Generates random bytes for testing.
Uint8List randomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(
    List.generate(length, (_) => random.nextInt(256)),
  );
}

/// Creates a test message with the given content.
Uint8List testMessage(String content) {
  return Uint8List.fromList(content.codeUnits);
}
