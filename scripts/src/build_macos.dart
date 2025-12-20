/// macOS build script for libsignal
///
/// Builds libsignal-ffi for macOS using Rust/Cargo.
/// Supports arm64, x86_64, or Universal Binary.

import 'dart:io';
import 'common.dart';

/// Build libsignal for macOS
Future<void> buildMacOS({MacOSArch arch = MacOSArch.universal}) async {
  if (!Platform.isMacOS) {
    throw Exception('macOS build must be run on macOS');
  }

  printBuildHeader('macOS (${arch.name})');

  // Check dependencies
  logStep('Checking dependencies...');
  await requireCommand('cargo');
  await requireCommand('rustup');

  final version = getLibsignalVersion();
  logInfo('libsignal version: $version');

  final packageDir = getPackageDir();
  final tempDir = getTempBuildDir();
  final sourceDir = '$tempDir/libsignal';
  final outputDir = '${packageDir.path}/bin/macos';

  // Clean and clone
  logStep('Preparing build directory...');
  await removeDir(tempDir);
  await ensureDir(tempDir);

  await cloneLibsignal(targetDir: sourceDir, version: version);

  // Install required Rust targets
  if (arch == MacOSArch.universal || arch == MacOSArch.arm64) {
    await ensureRustTarget('aarch64-apple-darwin');
  }
  if (arch == MacOSArch.universal || arch == MacOSArch.x86_64) {
    await ensureRustTarget('x86_64-apple-darwin');
  }

  await ensureDir(outputDir);

  if (arch == MacOSArch.universal) {
    // Build both architectures
    final arm64Lib = await buildLibsignalFfi(
      sourceDir: sourceDir,
      rustTarget: 'aarch64-apple-darwin',
    );
    final x86_64Lib = await buildLibsignalFfi(
      sourceDir: sourceDir,
      rustTarget: 'x86_64-apple-darwin',
    );

    // Create Universal Binary with lipo
    logStep('Creating Universal Binary...');
    await runCommandOrFail('lipo', [
      '-create',
      arm64Lib,
      x86_64Lib,
      '-output',
      '$outputDir/libsignal_ffi.dylib',
    ]);
  } else {
    final target =
        arch == MacOSArch.arm64
            ? 'aarch64-apple-darwin'
            : 'x86_64-apple-darwin';
    final libPath = await buildLibsignalFfi(
      sourceDir: sourceDir,
      rustTarget: target,
    );
    await copyFile(libPath, '$outputDir/libsignal_ffi.dylib');
  }

  // Fix install name
  logStep('Fixing install name...');
  await runCommandOrFail('install_name_tool', [
    '-id',
    '@rpath/libsignal_ffi.dylib',
    '$outputDir/libsignal_ffi.dylib',
  ]);

  // Copy to Flutter plugin directory
  final flutterDir = '${packageDir.path}/macos/Libraries';
  await ensureDir(flutterDir);
  await copyFile(
    '$outputDir/libsignal_ffi.dylib',
    '$flutterDir/libsignal_ffi.dylib',
  );

  // Cleanup
  logStep('Cleaning up...');
  await removeDir(tempDir);

  printBuildSummary('macOS ${arch.name}', outputDir);
}
