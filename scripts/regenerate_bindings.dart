#!/usr/bin/env dart

/// Regenerate Dart FFI bindings for libsignal
///
/// This script:
/// 1. Clones libsignal at the specified version
/// 2. Installs cbindgen at the required version
/// 3. Runs cbindgen to generate C headers
/// 4. Copies headers to headers/ directory
/// 5. Runs ffigen to generate Dart bindings
///
/// Usage:
///   dart run scripts/regenerate_bindings.dart

import 'dart:io';
import 'src/common.dart';

String? _tempDir;
String? _sourceDir;
String? _headersDir;
Directory? _packageDir;

void main(List<String> args) async {
  print('');
  print('========================================');
  print('  libsignal Dart Bindings Regenerator');
  print('========================================');
  print('');

  try {
    await _checkRequirements();
    await _initialize();
    await _downloadLibsignal();
    await _installCbindgen();
    await _generateHeaders();
    await _copyHeaders();
    await _generateBindings();
    await _cleanup();

    print('');
    logInfo('SUCCESS! Bindings regenerated for libsignal ${getLibsignalVersion()}');
    print('');
  } catch (e) {
    logError(e.toString());
    await _cleanup();
    exit(1);
  }
}

Future<void> _checkRequirements() async {
  logStep('Checking requirements...');

  await requireCommand('git');
  await requireCommand('cargo');
  await requireCommand('rustup');

  logInfo('All requirements satisfied');
}

Future<void> _initialize() async {
  final packageDir = getPackageDir();
  final tempDir = getTempBuildDir();
  _packageDir = packageDir;
  _tempDir = tempDir;
  _sourceDir = '$tempDir/libsignal';
  _headersDir = '${packageDir.path}/headers';

  logInfo('Package directory: ${packageDir.path}');
  logInfo('Temp directory: $tempDir');
}

Future<void> _downloadLibsignal() async {
  final version = getLibsignalVersion();
  logStep('Downloading libsignal $version...');

  await removeDir(_tempDir!);
  await ensureDir(_tempDir!);

  await cloneLibsignal(targetDir: _sourceDir!, version: version);

  logInfo('Downloaded libsignal $version');
}

Future<void> _installCbindgen() async {
  final cbindgenVersion = getCbindgenVersion(_sourceDir!);
  logStep('Installing cbindgen $cbindgenVersion...');

  // Check if correct version is already installed
  final result = await runCommand(
    'cbindgen',
    ['--version'],
    printOutput: false,
  );

  if (result.exitCode == 0) {
    final installedVersion = result.stdout.toString().trim();
    if (installedVersion.contains(cbindgenVersion)) {
      logInfo('cbindgen $cbindgenVersion already installed');
      return;
    }
  }

  // Install specific version
  await runCommandOrFail('cargo', [
    'install',
    'cbindgen',
    '--version',
    cbindgenVersion,
    '--force',
  ]);

  logInfo('Installed cbindgen $cbindgenVersion');
}

Future<void> _generateHeaders() async {
  logStep('Generating C headers with cbindgen...');

  // Find cbindgen config file
  final cbindgenConfig = '${_sourceDir!}/rust/bridge/ffi/cbindgen.toml';
  if (!File(cbindgenConfig).existsSync()) {
    throw Exception('cbindgen.toml not found at $cbindgenConfig');
  }

  // Run cbindgen to generate headers
  await runCommandOrFail('cbindgen', [
    '--config',
    cbindgenConfig,
    '--crate',
    'libsignal-ffi',
    '--output',
    '${_tempDir!}/signal_ffi.h',
  ], workingDirectory: _sourceDir!);

  logInfo('Headers generated');
}

Future<void> _copyHeaders() async {
  logStep('Copying headers to ${_headersDir!}...');

  await removeDir(_headersDir!);
  await ensureDir(_headersDir!);

  await copyFile('${_tempDir!}/signal_ffi.h', '${_headersDir!}/signal_ffi.h');

  logInfo('Copied signal_ffi.h');
}

Future<void> _generateBindings() async {
  logStep('Generating Dart FFI bindings...');

  await runCommandOrFail('fvm', [
    'dart',
    'run',
    'ffigen',
  ], workingDirectory: _packageDir!.path);

  // Verify bindings were generated
  final bindingsFile = File(
    '${_packageDir!.path}/lib/src/bindings/libsignal_bindings.dart',
  );
  if (!bindingsFile.existsSync()) {
    throw Exception('Bindings file was not generated');
  }

  final lineCount = bindingsFile.readAsLinesSync().length;
  logInfo('Generated bindings: $lineCount lines');
}

Future<void> _cleanup() async {
  logStep('Cleaning up...');
  if (_tempDir != null) {
    await removeDir(_tempDir!);
  }
}
