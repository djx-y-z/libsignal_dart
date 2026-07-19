import 'dart:io';

/// Prints the Android minSdk from `.copier-answers.yml` (source of truth,
/// key `android_min_sdk`). Used by `make build-android` for cargo-ndk's
/// `--platform` flag.
///
/// Usage: dart scripts/get_android_min_sdk.dart
void main() {
  final file = File('.copier-answers.yml');
  if (!file.existsSync()) {
    stderr.writeln('Error: .copier-answers.yml not found');
    exit(1);
  }

  final content = file.readAsStringSync();
  final match = RegExp(
    r"^android_min_sdk:\s*'?(\d+)'?",
    multiLine: true,
  ).firstMatch(content);

  if (match == null) {
    stderr.writeln('Error: android_min_sdk not found in .copier-answers.yml');
    exit(1);
  }

  print(match.group(1));
}
