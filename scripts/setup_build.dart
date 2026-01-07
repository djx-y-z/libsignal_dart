#!/usr/bin/env dart

/// Setup build dependencies for native library compilation
///
/// This script checks and installs:
/// - Rust toolchain (rustup, cargo)
/// - Protocol Buffers compiler (protoc)
///
/// Usage:
///   dart run scripts/setup_build.dart
///   dart run scripts/setup_build.dart --check  # Check only, don't install

import 'dart:io';
import 'src/common.dart';

bool _checkOnly = false;

void main(List<String> args) async {
  _checkOnly = args.contains('--check');

  print('');
  print('========================================');
  print('  libsignal Build Dependencies Setup');
  print('========================================');
  print('');

  if (_checkOnly) {
    logInfo('Running in check-only mode (no installation)');
    print('');
  }

  var allInstalled = true;

  // Check Rust
  final rustInstalled = await _checkRust();
  if (!rustInstalled) allInstalled = false;

  print('');

  // Check protoc
  final protocInstalled = await _checkProtoc();
  if (!protocInstalled) allInstalled = false;

  print('');

  // Summary
  if (allInstalled) {
    logInfo('All build dependencies are installed!');
    logInfo('You can now run: make build ARGS="<platform>"');
    logInfo('               or: make regen');
  } else {
    if (_checkOnly) {
      logError(
        'Some dependencies are missing. Run without --check to install.',
      );
      exit(1);
    } else {
      logError('Some dependencies could not be installed automatically.');
      logError('Please install them manually using the instructions above.');
      exit(1);
    }
  }
}

Future<bool> _checkRust() async {
  logStep('Checking Rust toolchain...');

  final hasRustup = await commandExists('rustup');
  final hasCargo = await commandExists('cargo');

  if (hasRustup && hasCargo) {
    // Get version info
    final rustcResult = await Process.run('rustc', ['--version']);
    final cargoResult = await Process.run('cargo', ['--version']);
    logInfo('rustc: ${rustcResult.stdout.toString().trim()}');
    logInfo('cargo: ${cargoResult.stdout.toString().trim()}');
    return true;
  }

  logWarn('Rust toolchain not found');

  if (_checkOnly) {
    _printRustInstallInstructions();
    return false;
  }

  // Try to install
  return await _installRust();
}

Future<bool> _installRust() async {
  logStep('Installing Rust via rustup...');

  if (Platform.isWindows) {
    logWarn('Automatic Rust installation is not supported on Windows.');
    _printRustInstallInstructions();
    return false;
  }

  // Install via rustup.rs
  try {
    final result = await Process.run('sh', [
      '-c',
      'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y',
    ], runInShell: true);

    if (result.exitCode == 0) {
      logInfo('Rust installed successfully');
      logWarn('Please restart your terminal or run: source \$HOME/.cargo/env');
      return true;
    } else {
      logError('Failed to install Rust: ${result.stderr}');
      _printRustInstallInstructions();
      return false;
    }
  } catch (e) {
    logError('Failed to install Rust: $e');
    _printRustInstallInstructions();
    return false;
  }
}

void _printRustInstallInstructions() {
  print('');
  print('  To install Rust manually:');
  print('');
  if (Platform.isWindows) {
    print('    Windows: Download from https://rustup.rs');
    print('             or run: winget install Rustlang.Rustup');
  } else if (Platform.isMacOS) {
    print(
      '    macOS: curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh',
    );
    print('        or: brew install rustup-init && rustup-init');
  } else {
    print(
      '    Linux: curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh',
    );
  }
  print('');
}

Future<bool> _checkProtoc() async {
  logStep('Checking Protocol Buffers compiler (protoc)...');

  if (await commandExists('protoc')) {
    final result = await Process.run('protoc', ['--version']);
    logInfo('protoc: ${result.stdout.toString().trim()}');
    return true;
  }

  logWarn('protoc not found');

  if (_checkOnly) {
    _printProtocInstallInstructions();
    return false;
  }

  // Try to install
  return await _installProtoc();
}

Future<bool> _installProtoc() async {
  logStep('Installing protoc...');

  if (Platform.isMacOS) {
    return await _installProtocMacOS();
  } else if (Platform.isLinux) {
    return await _installProtocLinux();
  } else if (Platform.isWindows) {
    logWarn('Automatic protoc installation is not supported on Windows.');
    _printProtocInstallInstructions();
    return false;
  }

  _printProtocInstallInstructions();
  return false;
}

Future<bool> _installProtocMacOS() async {
  // Check if Homebrew is available
  if (!await commandExists('brew')) {
    logWarn('Homebrew not found. Please install protoc manually.');
    _printProtocInstallInstructions();
    return false;
  }

  logInfo('Installing via Homebrew...');
  final result = await Process.run('brew', ['install', 'protobuf']);

  if (result.exitCode == 0) {
    logInfo('protoc installed successfully');
    return true;
  } else {
    logError('Failed to install protoc: ${result.stderr}');
    _printProtocInstallInstructions();
    return false;
  }
}

Future<bool> _installProtocLinux() async {
  // Check if apt is available
  if (!await commandExists('apt-get')) {
    logWarn('apt-get not found. Please install protoc manually.');
    _printProtocInstallInstructions();
    return false;
  }

  logInfo('Installing via apt (requires sudo)...');
  print('');
  print(
    '  Running: sudo apt-get update && sudo apt-get install -y protobuf-compiler',
  );
  print('');

  // Update package list
  var result = await Process.run('sudo', [
    'apt-get',
    'update',
  ], runInShell: true);

  if (result.exitCode != 0) {
    logError('Failed to update package list');
    _printProtocInstallInstructions();
    return false;
  }

  // Install protobuf-compiler
  result = await Process.run('sudo', [
    'apt-get',
    'install',
    '-y',
    'protobuf-compiler',
  ], runInShell: true);

  if (result.exitCode == 0) {
    logInfo('protoc installed successfully');
    return true;
  } else {
    logError('Failed to install protoc: ${result.stderr}');
    _printProtocInstallInstructions();
    return false;
  }
}

void _printProtocInstallInstructions() {
  print('');
  print('  To install protoc manually:');
  print('');
  if (Platform.isMacOS) {
    print('    macOS: brew install protobuf');
  } else if (Platform.isLinux) {
    print('    Ubuntu/Debian: sudo apt-get install protobuf-compiler');
    print('    Fedora: sudo dnf install protobuf-compiler');
    print('    Arch: sudo pacman -S protobuf');
  } else if (Platform.isWindows) {
    print(
      '    Windows: Download from https://github.com/protocolbuffers/protobuf/releases',
    );
    print('             Extract and add bin/ to PATH');
    print('         or: choco install protoc');
  }
  print('');
}
