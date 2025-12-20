/// iOS build script for libsignal
///
/// Builds libsignal-ffi for iOS using Rust/Cargo.
/// Supports device (arm64) and simulator (arm64, x86_64).

import 'dart:io';
import 'common.dart';

/// Build libsignal for iOS
Future<void> buildIOS({IOSTarget target = IOSTarget.all}) async {
  if (!Platform.isMacOS) {
    throw Exception('iOS build must be run on macOS');
  }

  printBuildHeader('iOS (${target.name})');

  // Check dependencies
  logStep('Checking dependencies...');
  await requireCommand('cargo');
  await requireCommand('rustup');
  await requireCommand('xcrun');

  final version = getLibsignalVersion();
  logInfo('libsignal version: $version');

  final packageDir = getPackageDir();
  final tempDir = getTempBuildDir();
  final sourceDir = '$tempDir/libsignal';
  final outputBaseDir = '${packageDir.path}/ios/Libraries';

  // Clean and clone
  logStep('Preparing build directory...');
  await removeDir(tempDir);
  await ensureDir(tempDir);

  await cloneLibsignal(targetDir: sourceDir, version: version);

  await ensureDir(outputBaseDir);

  // Build based on target
  if (target == IOSTarget.all) {
    await _buildIOSTarget(
      'aarch64-apple-ios',
      'device-arm64',
      sourceDir,
      outputBaseDir,
    );
    await _buildIOSTarget(
      'aarch64-apple-ios-sim',
      'simulator-arm64',
      sourceDir,
      outputBaseDir,
    );
    await _buildIOSTarget(
      'x86_64-apple-ios',
      'simulator-x86_64',
      sourceDir,
      outputBaseDir,
    );
  } else {
    final (rustTarget, outputName) = switch (target) {
      IOSTarget.device => ('aarch64-apple-ios', 'device-arm64'),
      IOSTarget.simulatorArm64 => ('aarch64-apple-ios-sim', 'simulator-arm64'),
      IOSTarget.simulatorX86_64 => ('x86_64-apple-ios', 'simulator-x86_64'),
      IOSTarget.all => throw Exception('Unreachable'),
    };
    await _buildIOSTarget(rustTarget, outputName, sourceDir, outputBaseDir);
  }

  // Cleanup
  logStep('Cleaning up...');
  await removeDir(tempDir);

  printBuildSummary('iOS', outputBaseDir);
}

Future<void> _buildIOSTarget(
  String rustTarget,
  String outputName,
  String sourceDir,
  String outputBaseDir,
) async {
  logPlatform('iOS', 'Building for $rustTarget...');

  // Get iOS SDK path for linking
  final isSimulator = rustTarget.contains('sim');
  final sdkType = isSimulator ? 'iphonesimulator' : 'iphoneos';
  final sdkResult = await runCommand('xcrun', [
    '--sdk',
    sdkType,
    '--show-sdk-path',
  ], printOutput: false);
  final sdkPath = sdkResult.stdout.toString().trim();

  // Determine clang target triple for bindgen
  // Rust uses 'aarch64-apple-ios-sim' but clang needs 'arm64-apple-ios13.0-simulator'
  String clangTarget;
  if (rustTarget == 'aarch64-apple-ios-sim') {
    clangTarget = 'arm64-apple-ios13.0-simulator';
  } else if (rustTarget == 'x86_64-apple-ios') {
    clangTarget = 'x86_64-apple-ios13.0-simulator';
  } else {
    clangTarget = 'arm64-apple-ios13.0';
  }

  final env = <String, String>{
    'SDKROOT': sdkPath,
    'IPHONEOS_DEPLOYMENT_TARGET': '13.0',
    'BINDGEN_EXTRA_CLANG_ARGS': '--target=$clangTarget -isysroot $sdkPath',
  };

  final libPath = await buildLibsignalFfi(
    sourceDir: sourceDir,
    rustTarget: rustTarget,
    environment: env,
  );

  final outputDir = '$outputBaseDir/$outputName';
  await ensureDir(outputDir);
  await copyFile(libPath, '$outputDir/libsignal_ffi.dylib');

  // Fix install name for iOS
  await runCommandOrFail('install_name_tool', [
    '-id',
    '@rpath/libsignal_ffi.dylib',
    '$outputDir/libsignal_ffi.dylib',
  ]);
}
