import 'dart:math';
import 'dart:typed_data';

/// Generate random bytes of the specified length.
Uint8List randomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(
    List.generate(length, (_) => random.nextInt(256)),
  );
}

/// Convert bytes to hex string, optionally truncating with "...".
String bytesToHex(Uint8List bytes, {int? maxLength}) {
  final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  if (maxLength != null && hex.length > maxLength) {
    return '${hex.substring(0, maxLength)}...';
  }
  return hex;
}

/// Format fingerprint (60 digits -> groups of 5).
String formatFingerprint(String fingerprint) {
  final buffer = StringBuffer();
  for (var i = 0; i < fingerprint.length; i += 5) {
    if (i > 0) buffer.write(' ');
    final end = (i + 5 < fingerprint.length) ? i + 5 : fingerprint.length;
    buffer.write(fingerprint.substring(i, end));
  }
  return buffer.toString();
}

/// Print a section header.
void printHeader(String title) {
  print('');
  print('${'═' * 3} $title ${'═' * 3}');
  print('');
}

/// Print a numbered step with optional indented details.
void printStep(int number, String description, [List<String>? details]) {
  print('$number. $description');
  if (details != null) {
    for (final detail in details) {
      print('   $detail');
    }
  }
}
