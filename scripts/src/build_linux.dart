/// Linux build script for libsignal
///
/// Builds libsignal-ffi for Linux using Rust/Cargo.
/// Supports x86_64 and arm64 (native builds only).

import 'dart:io';
import 'common.dart';

/// Build libsignal for Linux
Future<void> buildLinux({String? arch}) async {
  if (!Platform.isLinux) {
    throw Exception('Linux build must be run on Linux');
  }

  // Determine architecture
  final targetArch = arch ?? _detectNativeArch();
  final rustTarget = getRustTarget('linux', targetArch);

  printBuildHeader('Linux ($targetArch)');

  // Check dependencies
  logStep('Checking dependencies...');
  await requireCommand('cargo');
  await requireCommand('rustup');

  final version = getLibsignalVersion();
  logInfo('libsignal version: $version');

  final packageDir = getPackageDir();
  final tempDir = getTempBuildDir();
  final sourceDir = '$tempDir/libsignal';
  final outputDir = '${packageDir.path}/bin/linux';

  // Clean and clone
  logStep('Preparing build directory...');
  await removeDir(tempDir);
  await ensureDir(tempDir);

  await cloneLibsignal(targetDir: sourceDir, version: version);

  // Install Rust target
  await ensureRustTarget(rustTarget);

  await ensureDir(outputDir);

  // Build
  final libPath = await buildLibsignalFfi(
    sourceDir: sourceDir,
    rustTarget: rustTarget,
  );

  // Copy output
  await copyFile(libPath, '$outputDir/libsignal_ffi.so');

  // Cleanup
  logStep('Cleaning up...');
  await removeDir(tempDir);

  printBuildSummary('Linux $targetArch', outputDir);
}

/// Detect native architecture
String _detectNativeArch() {
  final result = Process.runSync('uname', ['-m']);
  final machine = result.stdout.toString().trim();

  switch (machine) {
    case 'x86_64':
    case 'amd64':
      return 'x86_64';
    case 'aarch64':
    case 'arm64':
      return 'arm64';
    default:
      throw Exception('Unsupported architecture: $machine');
  }
}
