/// Build hook for downloading and bundling libsignal native libraries.
///
/// This hook is automatically invoked by the Dart/Flutter build system
/// when building applications that depend on the libsignal package.
///
/// The hook downloads pre-built native libraries from GitHub Releases
/// based on the target platform and architecture.
///
/// ## How it works
///
/// ### Native platforms (iOS, Android, macOS, Linux, Windows)
/// 1. Hook downloads the appropriate `libsignal_frb` binary for the target
/// 2. Registers it as a CodeAsset with asset ID `package:libsignal/libsignal`
/// 3. Dart runtime bundles and loads the asset automatically
///
/// ### Web platform
/// 1. Hook detects web build (no code_assets config)
/// 2. Downloads WASM files to `<app_root>/web/pkg/`
/// 3. FRB loads WASM at runtime from that location
///
/// ## For development
///
/// If you have Rust installed and want to build from source instead:
/// ```bash
/// # Native platforms
/// make build
///
/// # Web/WASM
/// make build-web
/// ```
/// Then create `.skip_libsignal_hook` file to skip downloading.
library;

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';

/// Package name for asset registration.
const _packageName = 'libsignal';

/// Asset ID used for looking up the library at runtime.
/// Full ID: package:libsignal/libsignal
const _assetId = 'libsignal';

/// GitHub repository for downloading releases.
const _githubRepo = 'djx-y-z/libsignal_dart';

/// Entry point for the build hook.
void main(List<String> args) async {
  await build(args, (input, output) async {
    final packageRoot = input.packageRoot;

    // Check for skip marker file (used during development with local builds)
    final skipMarkerUri = packageRoot.resolve('.skip_libsignal_hook');
    final skipFile = File.fromUri(skipMarkerUri);
    output.dependencies.add(skipMarkerUri);

    if (skipFile.existsSync()) {
      return;
    }

    // Handle web builds (no code_assets config means web or other non-native target)
    if (!input.config.buildCodeAssets) {
      await _handleWebBuild(input, packageRoot);
      return;
    }

    final codeConfig = input.config.code;
    final targetOS = codeConfig.targetOS;
    final targetArch = codeConfig.targetArchitecture;

    // Check if local build exists (development mode)
    final localLib = _findLocalBuild(packageRoot, targetOS);
    if (localLib != null) {
      // Use local build
      output.assets.code.add(
        CodeAsset(
          package: _packageName,
          name: _assetId,
          linkMode: DynamicLoadingBundled(),
          file: localLib,
        ),
      );
      return;
    }

    // Download from GitHub Releases
    final version = await _readVersion(packageRoot);
    final assetInfo = _resolveAssetInfo(codeConfig, version);

    // Output directory for cached downloads
    final archSubdir = '${targetOS.name}-${targetArch.name}';
    final cacheDir = input.outputDirectoryShared.resolve('$archSubdir/');
    final libFile = File.fromUri(cacheDir.resolve(assetInfo.fileName));

    // Download if not cached
    if (!libFile.existsSync()) {
      final baseUrl =
          'https://github.com/$_githubRepo/releases/download/libsignal_frb-$version';
      Map<String, String>? checksums;
      String? expectedChecksum;

      try {
        checksums = await _downloadChecksums(baseUrl, version);
        expectedChecksum = checksums[assetInfo.archiveFileName];

        if (expectedChecksum == null) {
          throw HookException(
            'Checksum not found for ${assetInfo.archiveFileName}. '
            'Available: ${checksums.keys.join(', ')}',
          );
        }
      } catch (e) {
        // ignore: avoid_print
        print(
          'Warning: Could not verify SHA256 checksum: $e\n'
          'Proceeding without verification.',
        );
      }

      await _downloadAndExtract(
        assetInfo.downloadUrl,
        cacheDir,
        assetInfo.archiveFileName,
        assetInfo.fileName,
        expectedChecksum: expectedChecksum,
      );
    }

    // Verify file exists
    if (!libFile.existsSync()) {
      throw HookException(
        'Failed to download libsignal library for $targetOS-$targetArch. '
        'File not found: ${libFile.path}',
      );
    }

    // Register native asset
    output.assets.code.add(
      CodeAsset(
        package: _packageName,
        name: _assetId,
        linkMode: DynamicLoadingBundled(),
        file: libFile.uri,
      ),
    );

    // Add dependency on rust/Cargo.toml for cache invalidation
    output.dependencies.add(packageRoot.resolve('rust/Cargo.toml'));
  });
}

// =============================================================================
// Web Build Support
// =============================================================================

/// WASM files required for web builds.
const _wasmFiles = ['libsignal_frb.js', 'libsignal_frb_bg.wasm'];

/// Handles web builds by downloading WASM files to the app's web/pkg directory.
Future<void> _handleWebBuild(BuildInput input, Uri packageRoot) async {
  // Find the app's root directory from the shared output directory
  // Path: <app_root>/.dart_tool/hooks_runner/shared/libsignal/build/
  final appRoot = _findAppRoot(input.outputDirectoryShared);
  if (appRoot == null) {
    // ignore: avoid_print
    print(
      'Warning: Could not determine app root for web build. '
      'Build WASM manually with "make build-web" in the libsignal package.',
    );
    return;
  }

  final webPkgDir = Directory.fromUri(appRoot.resolve('web/pkg/'));

  // Check if WASM files already exist
  if (_wasmFilesExist(webPkgDir)) {
    return;
  }

  // Check for local WASM build first
  final localWasm = _findLocalWasmBuild(packageRoot);
  if (localWasm != null) {
    await _copyWasmFiles(localWasm, webPkgDir);
    return;
  }

  // Download from GitHub Releases
  final version = await _readVersion(packageRoot);
  await _downloadWasmFiles(version, webPkgDir);
}

/// Finds the app's root directory from the shared output path.
Uri? _findAppRoot(Uri sharedOutputDir) {
  // sharedOutputDir: <app_root>/.dart_tool/hooks_runner/shared/<package>/build/
  // We need to go up to find <app_root>
  var dir = Directory.fromUri(sharedOutputDir);

  // Go up until we find pubspec.yaml (app root)
  for (var i = 0; i < 10; i++) {
    final parent = dir.parent;
    if (parent.path == dir.path) break;
    dir = parent;

    final pubspec = File('${dir.path}/pubspec.yaml');
    if (pubspec.existsSync()) {
      // Verify this is a Flutter project with web support
      final webDir = Directory('${dir.path}/web');
      if (webDir.existsSync()) {
        return dir.uri;
      }
    }
  }
  return null;
}

/// Checks if all required WASM files exist.
bool _wasmFilesExist(Directory webPkgDir) {
  if (!webPkgDir.existsSync()) return false;

  for (final fileName in _wasmFiles) {
    final file = File('${webPkgDir.path}/$fileName');
    if (!file.existsSync()) return false;
  }
  return true;
}

/// Finds local WASM build in the package's rust/target/wasm32 directory.
Directory? _findLocalWasmBuild(Uri packageRoot) {
  final localDir = Directory.fromUri(
    packageRoot.resolve('rust/target/wasm32/'),
  );
  if (_wasmFilesExist(localDir)) {
    return localDir;
  }
  return null;
}

/// Copies WASM files from source to destination directory.
Future<void> _copyWasmFiles(Directory source, Directory dest) async {
  await dest.create(recursive: true);

  for (final fileName in _wasmFiles) {
    final srcFile = File('${source.path}/$fileName');
    final dstFile = File('${dest.path}/$fileName');
    await srcFile.copy(dstFile.path);
  }

  // ignore: avoid_print
  print('Copied WASM files to ${dest.path}');
}

/// Downloads WASM files from GitHub Releases.
Future<void> _downloadWasmFiles(String version, Directory webPkgDir) async {
  await webPkgDir.create(recursive: true);

  final baseUrl =
      'https://github.com/$_githubRepo/releases/download/libsignal_frb-$version';
  final archiveFileName = 'libsignal_frb-$version-wasm32.tar.gz';
  final archiveUrl = '$baseUrl/$archiveFileName';
  final archiveFile = File('${webPkgDir.path}/$archiveFileName');

  // ignore: avoid_print
  print('Downloading WASM for web: $archiveUrl');

  try {
    await _downloadWithRetry(archiveUrl, archiveFile);

    // Extract archive
    final result = await Process.run('tar', [
      '-xzf',
      archiveFile.path,
      '-C',
      webPkgDir.path,
    ]);

    if (result.exitCode != 0) {
      throw HookException('tar extraction failed: ${result.stderr}');
    }

    // Clean up archive
    if (archiveFile.existsSync()) {
      await archiveFile.delete();
    }

    // ignore: avoid_print
    print('WASM files installed to ${webPkgDir.path}');
  } catch (e) {
    // ignore: avoid_print
    print(
      'Warning: Failed to download WASM: $e\n'
      'Build WASM manually with "make build-web" in the libsignal package.',
    );
  }
}

// =============================================================================
// Native Build Support
// =============================================================================

/// Checks for local Rust build (development mode).
Uri? _findLocalBuild(Uri packageRoot, OS targetOS) {
  final fileName = _getLibraryFileName(targetOS);
  final paths = [
    packageRoot.resolve('rust/target/release/$fileName'),
    packageRoot.resolve('rust/target/debug/$fileName'),
  ];

  for (final path in paths) {
    final file = File.fromUri(path);
    if (file.existsSync()) {
      return path;
    }
  }
  return null;
}

/// Gets the library filename for the target OS.
String _getLibraryFileName(OS targetOS) {
  switch (targetOS) {
    case OS.macOS:
    case OS.iOS:
      return 'liblibsignal_frb.dylib';
    case OS.linux:
    case OS.android:
      return 'liblibsignal_frb.so';
    case OS.windows:
      return 'libsignal_frb.dll';
    default:
      throw HookException('Unsupported OS: $targetOS');
  }
}

/// Reads the version from rust/Cargo.toml.
Future<String> _readVersion(Uri packageRoot) async {
  final cargoFile = File.fromUri(packageRoot.resolve('rust/Cargo.toml'));
  if (!cargoFile.existsSync()) {
    throw HookException('rust/Cargo.toml not found');
  }

  final content = await cargoFile.readAsString();

  // Extract version from Cargo.toml [package] section
  final versionMatch = RegExp(
    r'^version\s*=\s*"([^"]+)"',
    multiLine: true,
  ).firstMatch(content);

  if (versionMatch == null) {
    throw HookException('version not found in rust/Cargo.toml');
  }

  return versionMatch.group(1)!.trim();
}

/// Information about a native asset.
class _AssetInfo {
  final String downloadUrl;
  final String archiveFileName;
  final String fileName;

  const _AssetInfo({
    required this.downloadUrl,
    required this.archiveFileName,
    required this.fileName,
  });
}

/// Resolves asset information for the target platform.
_AssetInfo _resolveAssetInfo(CodeConfig codeConfig, String version) {
  final baseUrl =
      'https://github.com/$_githubRepo/releases/download/libsignal_frb-$version';
  final targetOS = codeConfig.targetOS;

  final fileName = _getLibraryFileName(targetOS);
  final platformArch = _getPlatformArchName(codeConfig);

  final archiveFileName = 'libsignal_frb-$version-$platformArch.tar.gz';

  return _AssetInfo(
    downloadUrl: '$baseUrl/$archiveFileName',
    archiveFileName: archiveFileName,
    fileName: fileName,
  );
}

/// Gets platform-architecture name for download URL.
String _getPlatformArchName(CodeConfig codeConfig) {
  final targetOS = codeConfig.targetOS;
  final targetArch = codeConfig.targetArchitecture;

  switch (targetOS) {
    case OS.linux:
      return 'linux-${_archName(targetArch)}';
    case OS.macOS:
      return 'macos-${_archName(targetArch)}';
    case OS.windows:
      return 'windows-x86_64';
    case OS.android:
      return 'android-${_androidAbi(targetArch)}';
    case OS.iOS:
      final isSimulator = codeConfig.iOS.targetSdk == IOSSdk.iPhoneSimulator;
      if (isSimulator) {
        return 'ios-simulator-${_archName(targetArch)}';
      }
      return 'ios-device-arm64';
    default:
      throw HookException('Unsupported OS: $targetOS');
  }
}

String _archName(Architecture arch) {
  switch (arch) {
    case Architecture.arm64:
      return 'arm64';
    case Architecture.x64:
      return 'x86_64';
    default:
      throw HookException('Unsupported architecture: $arch');
  }
}

String _androidAbi(Architecture arch) {
  switch (arch) {
    case Architecture.arm64:
      return 'arm64-v8a';
    case Architecture.arm:
      return 'armeabi-v7a';
    case Architecture.x64:
      return 'x86_64';
    default:
      throw HookException('Unsupported Android architecture: $arch');
  }
}

/// Downloads and extracts the native library.
Future<void> _downloadAndExtract(
  String url,
  Uri outputDir,
  String archiveFileName,
  String libFileName, {
  String? expectedChecksum,
}) async {
  final outDir = Directory.fromUri(outputDir);
  await outDir.create(recursive: true);

  final archiveFile = File('${outDir.path}/$archiveFileName');

  await _downloadWithRetry(url, archiveFile);

  if (expectedChecksum != null) {
    await _verifyChecksum(archiveFile, expectedChecksum, archiveFileName);
  }

  if (url.endsWith('.zip')) {
    await _extractZip(archiveFile, outDir);
  } else {
    await _extractTarGz(archiveFile, outDir);
  }

  if (archiveFile.existsSync()) {
    await archiveFile.delete();
  }

  final libFile = File('${outDir.path}/$libFileName');
  if (!libFile.existsSync()) {
    throw HookException('Extraction failed: $libFileName not found');
  }
}

Future<void> _downloadWithRetry(
  String url,
  File outputFile, {
  int maxRetries = 3,
}) async {
  final client = HttpClient();
  Exception? lastError;

  try {
    for (var attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        final request = await client.getUrl(Uri.parse(url));
        final response = await request.close();

        if (response.statusCode == 200) {
          final sink = outputFile.openWrite();
          await response.pipe(sink);
          return;
        } else if (response.statusCode == 404) {
          throw HookException(
            'Library not found at $url (HTTP 404). '
            'Make sure the GitHub Release exists.',
          );
        } else {
          throw HookException('HTTP ${response.statusCode} from $url');
        }
      } on HookException {
        rethrow;
      } catch (e) {
        lastError = e is Exception ? e : Exception(e.toString());
        if (attempt < maxRetries) {
          await Future.delayed(Duration(seconds: attempt * 2));
        }
      }
    }
  } finally {
    client.close();
  }

  throw HookException('Download failed after $maxRetries attempts: $lastError');
}

Future<void> _extractTarGz(File archive, Directory outDir) async {
  final result = await Process.run('tar', [
    '-xzf',
    archive.path,
    '-C',
    outDir.path,
  ]);
  if (result.exitCode != 0) {
    throw HookException('tar extraction failed: ${result.stderr}');
  }
}

Future<void> _extractZip(File archive, Directory outDir) async {
  ProcessResult result;
  if (Platform.isWindows) {
    result = await Process.run('powershell', [
      '-Command',
      'Expand-Archive',
      '-Path',
      archive.path,
      '-DestinationPath',
      outDir.path,
      '-Force',
    ]);
  } else {
    result = await Process.run('unzip', [
      '-o',
      archive.path,
      '-d',
      outDir.path,
    ]);
  }
  if (result.exitCode != 0) {
    throw HookException('zip extraction failed: ${result.stderr}');
  }
}

Future<Map<String, String>> _downloadChecksums(
  String baseUrl,
  String version,
) async {
  final url = '$baseUrl/libsignal_frb-$version-checksums.sha256';
  final client = HttpClient();

  try {
    final request = await client.getUrl(Uri.parse(url));
    final response = await request.close();

    if (response.statusCode != 200) {
      throw HookException(
        'Checksums download failed: HTTP ${response.statusCode}',
      );
    }

    final content = await response.transform(systemEncoding.decoder).join();
    return _parseChecksums(content);
  } finally {
    client.close();
  }
}

Map<String, String> _parseChecksums(String content) {
  final checksums = <String, String>{};
  for (final line in content.split('\n')) {
    final match = RegExp(r'^([a-fA-F0-9]{64})\s+(.+)$').firstMatch(line.trim());
    if (match != null) {
      checksums[match.group(2)!] = match.group(1)!.toLowerCase();
    }
  }
  return checksums;
}

Future<void> _verifyChecksum(File file, String expected, String name) async {
  final bytes = await file.readAsBytes();
  final actual = sha256.convert(bytes).toString();

  if (actual != expected.toLowerCase()) {
    await file.delete();
    throw HookException(
      'SHA256 mismatch for $name!\n'
      'Expected: $expected\n'
      'Actual:   $actual',
    );
  }
}

class HookException implements Exception {
  final String message;
  HookException(this.message);
  @override
  String toString() => 'HookException: $message';
}
