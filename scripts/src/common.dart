/// Common utilities for development scripts
///
/// This file provides utilities for version management, logging,
/// and process execution used by check_updates and check_release scripts.

import 'dart:io';

// ============================================
// ANSI Colors for terminal output
// ============================================

class Colors {
  static const reset = '\x1B[0m';
  static const red = '\x1B[31m';
  static const green = '\x1B[32m';
  static const yellow = '\x1B[33m';
  static const blue = '\x1B[34m';
  static const cyan = '\x1B[36m';

  static bool get supportsAnsi {
    return stdout.supportsAnsiEscapes;
  }

  static String colorize(String text, String color) {
    if (!supportsAnsi) return text;
    return '$color$text$reset';
  }
}

// ============================================
// Logging utilities
// ============================================

void logInfo(String message) {
  print(Colors.colorize('[INFO]', Colors.green) + ' $message');
}

void logWarn(String message) {
  print(Colors.colorize('[WARN]', Colors.yellow) + ' $message');
}

/// Alias for logWarn
void logWarning(String message) => logWarn(message);

void logError(String message) {
  print(Colors.colorize('[ERROR]', Colors.red) + ' $message');
}

void logStep(String message) {
  print(Colors.colorize('[STEP]', Colors.blue) + ' $message');
}

void logPlatform(String platform, String message) {
  print(Colors.colorize('[$platform]', Colors.cyan) + ' $message');
}

/// Print a build header for a platform
void printBuildHeader(String platform) {
  print('');
  print('========================================');
  print('  libsignal Build: $platform');
  print('========================================');
  print('');
}

// ============================================
// Path utilities
// ============================================

/// Get the package root directory (where pubspec.yaml is located)
Directory getPackageDir() {
  // scripts/src/common.dart -> scripts/src -> scripts -> package root
  var dir = File(Platform.script.toFilePath()).parent.parent.parent;

  // Verify we found the right directory
  if (!File('${dir.path}/pubspec.yaml').existsSync()) {
    // Try resolving from current directory
    dir = Directory.current;
    while (!File('${dir.path}/pubspec.yaml').existsSync()) {
      final parent = dir.parent;
      if (parent.path == dir.path) {
        throw Exception('Could not find package root (pubspec.yaml)');
      }
      dir = parent;
    }
  }

  return dir;
}

/// Get the libsignal-protocol version from rust/Cargo.toml
///
/// Parses the tag from: libsignal-protocol = { git = "...", tag = "v0.86.13" }
String getLibsignalVersion() {
  final packageDir = getPackageDir();
  final cargoFile = File('${packageDir.path}/rust/Cargo.toml');

  if (!cargoFile.existsSync()) {
    throw Exception('rust/Cargo.toml not found');
  }

  final content = cargoFile.readAsStringSync();

  // Extract the tag from libsignal-protocol dependency
  // Matches: libsignal-protocol = { git = "...", tag = "v0.86.13" }
  final versionMatch = RegExp(
    r'libsignal-protocol\s*=\s*\{[^}]*tag\s*=\s*"([^"]+)"',
  ).firstMatch(content);

  if (versionMatch == null) {
    throw Exception(
      'libsignal-protocol tag not found in rust/Cargo.toml. '
      'Expected format: libsignal-protocol = { git = "...", tag = "vX.Y.Z" }',
    );
  }

  return versionMatch.group(1)!.trim();
}

/// Get the FRB crate version from rust/Cargo.toml [package] section.
///
/// This is the version of the libsignal_frb crate, used for native library releases.
String getFrbVersion() {
  final packageDir = getPackageDir();
  final cargoFile = File('${packageDir.path}/rust/Cargo.toml');

  if (!cargoFile.existsSync()) {
    throw Exception('rust/Cargo.toml not found');
  }

  final content = cargoFile.readAsStringSync();

  // Extract version from [package] section
  // Matches: version = "0.1.0"
  final versionMatch = RegExp(
    r'^version\s*=\s*"([^"]+)"',
    multiLine: true,
  ).firstMatch(content);

  if (versionMatch == null) {
    throw Exception(
      'version not found in rust/Cargo.toml [package] section. '
      'Expected format: version = "X.Y.Z"',
    );
  }

  return versionMatch.group(1)!.trim();
}

// ============================================
// Process execution utilities
// ============================================

/// Run a command and return the result
Future<ProcessResult> runCommand(
  String executable,
  List<String> arguments, {
  String? workingDirectory,
  Map<String, String>? environment,
  bool printOutput = true,
}) async {
  if (printOutput) {
    logInfo('Running: $executable ${arguments.join(' ')}');
  }

  final result = await Process.run(
    executable,
    arguments,
    workingDirectory: workingDirectory,
    environment: environment,
    runInShell: Platform.isWindows,
  );

  if (printOutput && result.stdout.toString().isNotEmpty) {
    stdout.write(result.stdout);
  }

  if (result.stderr.toString().isNotEmpty) {
    stderr.write(result.stderr);
  }

  return result;
}

/// Run a command and throw if it fails
Future<void> runCommandOrFail(
  String executable,
  List<String> arguments, {
  String? workingDirectory,
  Map<String, String>? environment,
  bool printOutput = true,
}) async {
  final result = await runCommand(
    executable,
    arguments,
    workingDirectory: workingDirectory,
    environment: environment,
    printOutput: printOutput,
  );

  if (result.exitCode != 0) {
    throw Exception(
      'Command failed with exit code ${result.exitCode}: '
      '$executable ${arguments.join(' ')}',
    );
  }
}

/// Check if a command exists
Future<bool> commandExists(String command) async {
  try {
    final result = await Process.run(Platform.isWindows ? 'where' : 'which', [
      command,
    ], runInShell: true);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

/// Require a command to exist, or throw
Future<void> requireCommand(String command) async {
  if (!await commandExists(command)) {
    throw Exception('Required command not found: $command');
  }
}
