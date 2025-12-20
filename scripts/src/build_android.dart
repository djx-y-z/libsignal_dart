/// Android build script for libsignal
///
/// Builds libsignal-ffi for Android using Rust/Cargo with NDK.
/// Supports arm64-v8a, armeabi-v7a, and x86_64.

import 'common.dart';

/// Build libsignal for Android
Future<void> buildAndroid({AndroidAbi abi = AndroidAbi.all}) async {
  printBuildHeader('Android (${abi.value})');

  // Check dependencies
  logStep('Checking dependencies...');
  await requireCommand('cargo');
  await requireCommand('rustup');

  // Find Android NDK
  final ndkPath = await findAndroidNdk();
  if (ndkPath == null) {
    throw Exception(
      'Android NDK not found. Set ANDROID_NDK_HOME or ANDROID_NDK_ROOT environment variable.',
    );
  }
  logInfo('Android NDK: $ndkPath');

  final version = getLibsignalVersion();
  logInfo('libsignal version: $version');

  final packageDir = getPackageDir();
  final tempDir = getTempBuildDir();
  final sourceDir = '$tempDir/libsignal';
  final outputBaseDir = '${packageDir.path}/android/src/main/jniLibs';

  // Clean and clone
  logStep('Preparing build directory...');
  await removeDir(tempDir);
  await ensureDir(tempDir);

  await cloneLibsignal(targetDir: sourceDir, version: version);

  // Determine which ABIs to build
  final abis = abi == AndroidAbi.all
      ? [AndroidAbi.arm64V8a, AndroidAbi.armeabiV7a, AndroidAbi.x86_64]
      : [abi];

  for (final targetAbi in abis) {
    await _buildAbi(
      abi: targetAbi,
      ndkPath: ndkPath,
      sourceDir: sourceDir,
      outputBaseDir: outputBaseDir,
    );
  }

  // Cleanup
  logStep('Cleaning up...');
  await removeDir(tempDir);

  printBuildSummary('Android', outputBaseDir);
}

Future<void> _buildAbi({
  required AndroidAbi abi,
  required String ndkPath,
  required String sourceDir,
  required String outputBaseDir,
}) async {
  final abiValue = abi.value;
  final rustTarget = getRustTarget('android', abiValue);

  logPlatform('Android', 'Building for $abiValue ($rustTarget)...');

  // Configure linker for Android
  const apiLevel = 21; // Minimum Android API level
  final hostTag = getNdkHostTag();
  final toolchainBin = '$ndkPath/toolchains/llvm/prebuilt/$hostTag/bin';
  final clangTarget = getNdkClangTarget(abiValue, apiLevel);

  // Convert Rust target to cargo environment variable format
  final envTarget = rustTarget.toUpperCase().replaceAll('-', '_');

  final env = <String, String>{
    'ANDROID_NDK_HOME': ndkPath,
    'CARGO_TARGET_${envTarget}_LINKER': '$toolchainBin/$clangTarget-clang',
    // Set AR for the target
    'AR_$rustTarget': '$toolchainBin/llvm-ar',
    // Set CC for the target
    'CC_$rustTarget': '$toolchainBin/$clangTarget-clang',
  };

  final libPath = await buildLibsignalFfi(
    sourceDir: sourceDir,
    rustTarget: rustTarget,
    environment: env,
  );

  // Copy output to jniLibs directory
  final outputDir = '$outputBaseDir/$abiValue';
  await ensureDir(outputDir);
  await copyFile(libPath, '$outputDir/libsignal_ffi.so');
}
