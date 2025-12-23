/// Common utilities for build scripts
///
/// This file provides cross-platform utilities for building libsignal
/// native libraries on Linux, macOS, iOS, Android, and Windows.
///
/// Key difference from liboqs: uses Rust/Cargo instead of CMake.

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

/// Get the LIBSIGNAL_VERSION from file
String getLibsignalVersion() {
  final packageDir = getPackageDir();
  final versionFile = File('${packageDir.path}/LIBSIGNAL_VERSION');

  if (!versionFile.existsSync()) {
    throw Exception('LIBSIGNAL_VERSION file not found');
  }

  final version = versionFile.readAsStringSync().trim();
  if (version.isEmpty) {
    throw Exception('LIBSIGNAL_VERSION file is empty');
  }

  return version;
}

/// Get the NATIVE_BUILD number from file
String getNativeBuild() {
  final packageDir = getPackageDir();
  final buildFile = File('${packageDir.path}/NATIVE_BUILD');

  if (!buildFile.existsSync()) {
    return '1';
  }

  final build = buildFile.readAsStringSync().trim();
  return build.isEmpty ? '1' : build;
}

/// Get full version string (libsignal version + native build)
/// Returns version without 'v' prefix for archive naming
String getFullVersion() {
  final version = getLibsignalVersion().replaceFirst('v', '');
  return '$version-${getNativeBuild()}';
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

// ============================================
// Git utilities
// ============================================

/// Clone a git repository
Future<void> gitClone({
  required String url,
  required String targetDir,
  String? branch,
  int depth = 1,
}) async {
  final args = ['clone', '--depth', '$depth'];

  if (branch != null) {
    args.addAll(['--branch', branch]);
  }

  args.addAll([url, targetDir]);

  await runCommandOrFail('git', args);
}

// ============================================
// File system utilities
// ============================================

/// Create directory if it doesn't exist
Future<void> ensureDir(String path) async {
  final dir = Directory(path);
  if (!dir.existsSync()) {
    await dir.create(recursive: true);
  }
}

/// Remove directory if it exists
Future<void> removeDir(String path) async {
  final dir = Directory(path);
  if (dir.existsSync()) {
    await dir.delete(recursive: true);
  }
}

/// Copy file to destination
Future<void> copyFile(String source, String destination) async {
  await ensureDir(Directory(destination).parent.path);
  await File(source).copy(destination);
}

/// Get temporary directory for builds
String getTempBuildDir() {
  if (Platform.isWindows) {
    return 'C:\\libsignal-build';
  }
  return '/tmp/libsignal-build';
}

// ============================================
// Platform detection
// ============================================

enum BuildPlatform { linux, macos, ios, android, windows }

/// Get available build platforms for current OS
List<BuildPlatform> getAvailablePlatforms() {
  if (Platform.isMacOS) {
    return [BuildPlatform.macos, BuildPlatform.ios, BuildPlatform.android];
  } else if (Platform.isLinux) {
    return [BuildPlatform.linux, BuildPlatform.android];
  } else if (Platform.isWindows) {
    return [BuildPlatform.windows];
  }
  return [];
}

/// Check if we can build for a specific platform
bool canBuildFor(BuildPlatform platform) {
  return getAvailablePlatforms().contains(platform);
}

// ============================================
// Rust/Cargo utilities (different from liboqs CMake)
// ============================================

/// Get Rust target triple for platform/arch combination
String getRustTarget(String os, String arch) {
  final key = '$os-$arch';
  final targets = {
    'linux-x86_64': 'x86_64-unknown-linux-gnu',
    'linux-arm64': 'aarch64-unknown-linux-gnu',
    'macos-arm64': 'aarch64-apple-darwin',
    'macos-x86_64': 'x86_64-apple-darwin',
    'windows-x86_64': 'x86_64-pc-windows-msvc',
    'ios-device-arm64': 'aarch64-apple-ios',
    'ios-simulator-arm64': 'aarch64-apple-ios-sim',
    'ios-simulator-x86_64': 'x86_64-apple-ios',
    'android-arm64-v8a': 'aarch64-linux-android',
    'android-armeabi-v7a': 'armv7-linux-androideabi',
    'android-x86_64': 'x86_64-linux-android',
  };

  final target = targets[key];
  if (target == null) {
    throw Exception('Unsupported platform/arch combination: $key');
  }
  return target;
}

/// Install Rust target via rustup
Future<void> installRustTarget(String target) async {
  logStep('Installing Rust target: $target');
  await runCommandOrFail('rustup', ['target', 'add', target]);
}

/// Check if Rust target is installed
Future<bool> isRustTargetInstalled(String target) async {
  final result = await runCommand('rustup', [
    'target',
    'list',
    '--installed',
  ], printOutput: false);
  return result.stdout.toString().contains(target);
}

/// Ensure Rust target is installed
Future<void> ensureRustTarget(String target) async {
  if (!await isRustTargetInstalled(target)) {
    await installRustTarget(target);
  }
}

/// Clone libsignal repository
Future<void> cloneLibsignal({
  required String targetDir,
  required String version,
}) async {
  logStep('Cloning libsignal $version...');
  await gitClone(
    url: 'https://github.com/signalapp/libsignal.git',
    targetDir: targetDir,
    branch: version,
    depth: 1,
  );

  // Patch Cargo.toml to include cdylib (needed for Dart FFI)
  // Recent versions of libsignal only build staticlib by default
  await _patchCargoTomlForCdylib(targetDir);
}

/// Patch libsignal-ffi Cargo.toml to include cdylib crate-type
Future<void> _patchCargoTomlForCdylib(String sourceDir) async {
  final cargoPath = '$sourceDir/rust/bridge/ffi/Cargo.toml';
  final cargoFile = File(cargoPath);

  if (!cargoFile.existsSync()) {
    logWarn('Could not find Cargo.toml at $cargoPath');
    return;
  }

  logStep('Patching Cargo.toml to include cdylib...');

  var content = await cargoFile.readAsString();

  // Replace staticlib with cdylib (we only need dynamic library for Dart FFI)
  if (content.contains('crate-type = ["staticlib"]')) {
    content = content.replaceAll(
      'crate-type = ["staticlib"]',
      'crate-type = ["cdylib"]',
    );
    await cargoFile.writeAsString(content);
    logInfo('Patched Cargo.toml: staticlib -> cdylib');
  } else if (content.contains('crate-type = ["cdylib"')) {
    logInfo('Cargo.toml already uses cdylib');
  } else {
    logWarn('Could not find crate-type in Cargo.toml, build may fail');
  }
}

/// Get cbindgen version from libsignal's .cbindgen-version file
String getCbindgenVersion(String sourceDir) {
  final versionFile = File('$sourceDir/.cbindgen-version');
  if (versionFile.existsSync()) {
    return versionFile.readAsStringSync().trim();
  }
  return '0.26.0'; // Fallback default
}

/// Build libsignal-ffi for a specific Rust target
Future<String> buildLibsignalFfi({
  required String sourceDir,
  required String rustTarget,
  Map<String, String>? environment,
}) async {
  logStep('Building libsignal-ffi for $rustTarget...');

  // libsignal uses nightly Rust (via rust-toolchain.toml in their repo).
  // We need to install targets for that specific toolchain.
  // Running rustup from sourceDir will use the correct toolchain.
  logStep(
    'Ensuring Rust target $rustTarget is installed for libsignal toolchain...',
  );
  await runCommandOrFail('rustup', [
    'target',
    'add',
    rustTarget,
  ], workingDirectory: sourceDir);

  final env = {
    ...Platform.environment,
    if (environment != null) ...environment,
  };

  await runCommandOrFail(
    'cargo',
    ['build', '--release', '--target', rustTarget, '-p', 'libsignal-ffi'],
    workingDirectory: sourceDir,
    environment: env,
  );

  // Determine library extension
  String libName;
  if (rustTarget.contains('darwin') || rustTarget.contains('ios')) {
    libName = 'libsignal_ffi.dylib';
  } else if (rustTarget.contains('windows')) {
    libName = 'signal_ffi.dll';
  } else {
    libName = 'libsignal_ffi.so';
  }

  return '$sourceDir/target/$rustTarget/release/$libName';
}

// ============================================
// Android NDK utilities
// ============================================

/// Find Android NDK path
Future<String?> findAndroidNdk() async {
  // Check environment variables
  final ndkHome = Platform.environment['ANDROID_NDK_HOME'];
  if (ndkHome != null && Directory(ndkHome).existsSync()) {
    return ndkHome;
  }

  final ndkRoot = Platform.environment['ANDROID_NDK_ROOT'];
  if (ndkRoot != null && Directory(ndkRoot).existsSync()) {
    return ndkRoot;
  }

  // Check common Android SDK locations
  final androidHome =
      Platform.environment['ANDROID_HOME'] ??
      Platform.environment['ANDROID_SDK_ROOT'];
  if (androidHome != null) {
    final ndkDir = Directory('$androidHome/ndk');
    if (ndkDir.existsSync()) {
      // Find the latest NDK version
      final versions = ndkDir.listSync().whereType<Directory>().toList();
      if (versions.isNotEmpty) {
        versions.sort((a, b) => b.path.compareTo(a.path));
        return versions.first.path;
      }
    }
  }

  return null;
}

/// Get NDK host tag (e.g., "darwin-x86_64", "linux-x86_64")
String getNdkHostTag() {
  if (Platform.isMacOS) {
    return 'darwin-x86_64';
  } else if (Platform.isLinux) {
    return 'linux-x86_64';
  } else if (Platform.isWindows) {
    return 'windows-x86_64';
  }
  throw Exception('Unsupported platform for Android NDK');
}

/// Get NDK clang target for Android ABI
String getNdkClangTarget(String abi, int apiLevel) {
  switch (abi) {
    case 'arm64-v8a':
      return 'aarch64-linux-android$apiLevel';
    case 'armeabi-v7a':
      return 'armv7a-linux-androideabi$apiLevel';
    case 'x86_64':
      return 'x86_64-linux-android$apiLevel';
    default:
      throw Exception('Unsupported Android ABI: $abi');
  }
}

// ============================================
// Build option parsing
// ============================================

enum MacOSArch { arm64, x86_64, universal }

MacOSArch parseArch(String? arch) {
  switch (arch?.toLowerCase()) {
    case 'arm64':
      return MacOSArch.arm64;
    case 'x86_64':
      return MacOSArch.x86_64;
    case 'universal':
    case null:
      return MacOSArch.universal;
    default:
      throw Exception('Invalid architecture: $arch');
  }
}

enum IOSTarget { device, simulatorArm64, simulatorX86_64, all }

IOSTarget parseTarget(String? target) {
  switch (target?.toLowerCase()) {
    case 'device':
      return IOSTarget.device;
    case 'simulator-arm64':
      return IOSTarget.simulatorArm64;
    case 'simulator-x86_64':
      return IOSTarget.simulatorX86_64;
    case 'all':
    case null:
      return IOSTarget.all;
    default:
      throw Exception('Invalid iOS target: $target');
  }
}

enum AndroidAbi { arm64V8a, armeabiV7a, x86_64, all }

AndroidAbi parseAbi(String? abi) {
  switch (abi?.toLowerCase()) {
    case 'arm64-v8a':
      return AndroidAbi.arm64V8a;
    case 'armeabi-v7a':
      return AndroidAbi.armeabiV7a;
    case 'x86_64':
      return AndroidAbi.x86_64;
    case 'all':
    case null:
      return AndroidAbi.all;
    default:
      throw Exception('Invalid Android ABI: $abi');
  }
}

extension AndroidAbiValue on AndroidAbi {
  String get value {
    switch (this) {
      case AndroidAbi.arm64V8a:
        return 'arm64-v8a';
      case AndroidAbi.armeabiV7a:
        return 'armeabi-v7a';
      case AndroidAbi.x86_64:
        return 'x86_64';
      case AndroidAbi.all:
        return 'all';
    }
  }
}

// ============================================
// Build summary
// ============================================

void printBuildSummary(String platform, String outputDir) {
  print('');
  print('========================================');
  print('  Build Complete: $platform');
  print('========================================');
  print('');
  print('Output directory: $outputDir');
  print('Files:');

  final dir = Directory(outputDir);
  if (dir.existsSync()) {
    for (final file in dir.listSync(recursive: true)) {
      if (file is File) {
        final size = file.lengthSync();
        final sizeStr = _formatSize(size);
        print('  ${file.path} ($sizeStr)');
      }
    }
  }
  print('');
}

String _formatSize(int bytes) {
  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
}
