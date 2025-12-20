/// Windows build script for libsignal
///
/// Builds libsignal-ffi for Windows using Rust/Cargo with MSVC.
/// Supports x86_64 only.

import 'dart:io';
import 'common.dart';

/// Build libsignal for Windows
Future<void> buildWindows() async {
  if (!Platform.isWindows) {
    throw Exception('Windows build must be run on Windows');
  }

  printBuildHeader('Windows (x86_64)');

  // Check dependencies
  logStep('Checking dependencies...');
  await requireCommand('cargo');
  await requireCommand('rustup');

  final version = getLibsignalVersion();
  logInfo('libsignal version: $version');

  final packageDir = getPackageDir();
  final tempDir = getTempBuildDir();
  final sourceDir = '$tempDir\\libsignal';
  final outputDir = '${packageDir.path}\\bin\\windows';

  // Clean and clone
  logStep('Preparing build directory...');
  await removeDir(tempDir);
  await ensureDir(tempDir);

  await cloneLibsignal(targetDir: sourceDir, version: version);

  // Install Rust target
  const rustTarget = 'x86_64-pc-windows-msvc';
  await ensureRustTarget(rustTarget);

  await ensureDir(outputDir);

  // Build
  final libPath = await buildLibsignalFfi(
    sourceDir: sourceDir,
    rustTarget: rustTarget,
  );

  // On Windows, the output is signal_ffi.dll (not libsignal_ffi.dll)
  await copyFile(libPath, '$outputDir\\signal_ffi.dll');

  // Cleanup
  logStep('Cleaning up...');
  await removeDir(tempDir);

  printBuildSummary('Windows x86_64', outputDir);
}
