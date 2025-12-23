/// Build hook for downloading and bundling libsignal native libraries.
///
/// This hook is automatically invoked by the Dart/Flutter build system
/// when building applications that depend on the libsignal package.
///
/// The hook downloads pre-built native libraries from GitHub Releases
/// based on the target platform and architecture.
library;

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';

/// Package name for asset registration.
const _packageName = 'libsignal';

/// Asset ID used for looking up the library at runtime.
/// Note: This is just the name part; CodeAsset combines it with package
/// to form the full ID: package:libsignal/libsignal
const _assetId = 'libsignal';

/// GitHub repository for downloading releases.
const _githubRepo = 'djx-y-z/libsignal_dart';

/// Entry point for the build hook.
void main(List<String> args) async {
  await build(args, (input, output) async {
    // Only process if building code assets
    if (!input.config.buildCodeAssets) {
      return;
    }

    final codeConfig = input.config.code;
    final targetOS = codeConfig.targetOS;
    final targetArch = codeConfig.targetArchitecture;
    final packageRoot = input.packageRoot;

    // Check for skip marker file (used during library building via `make build`)
    // This avoids chicken-and-egg problem when building native libraries
    final skipMarkerUri = packageRoot.resolve('.skip_libsignal_hook');
    final skipFile = File.fromUri(skipMarkerUri);

    // Add marker file as dependency for cache invalidation
    // This ensures hook reruns when marker is created/deleted
    output.dependencies.add(skipMarkerUri);

    if (skipFile.existsSync()) {
      return;
    }

    // For all cases, download from GitHub Releases and bundle with the app
    final fullVersion = await _readFullVersion(packageRoot);
    final assetInfo = _resolveAssetInfo(codeConfig, fullVersion);

    // Output directory for cached downloads
    // Use architecture-specific subdirectory for each platform/arch combination
    final archSubdir = '${targetOS.name}-${targetArch.name}';
    final cacheDir = input.outputDirectoryShared.resolve('$archSubdir/');
    final libFile = File.fromUri(cacheDir.resolve(assetInfo.fileName));

    // Download if not cached
    if (!libFile.existsSync()) {
      // Download checksums file for SHA256 verification (supply chain security)
      final baseUrl =
          'https://github.com/$_githubRepo/releases/download/libsignal-$fullVersion';
      Map<String, String>? checksums;
      String? expectedChecksum;

      try {
        checksums = await _downloadChecksums(baseUrl, fullVersion);
        expectedChecksum = checksums[assetInfo.archiveFileName];

        if (expectedChecksum == null) {
          throw HookException(
            'Checksum not found for ${assetInfo.archiveFileName} in checksums file. '
            'Available files: ${checksums.keys.join(', ')}',
          );
        }
      } catch (e) {
        // If checksums download fails, log warning but continue
        // This allows builds to work even if checksums file is missing
        // (e.g., for older releases or local development)
        // ignore: avoid_print
        print(
          'Warning: Could not verify SHA256 checksum: $e\n'
          'Proceeding without verification (not recommended for production).',
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

    // Verify file exists after download
    if (!libFile.existsSync()) {
      throw HookException(
        'Failed to download libsignal library for $targetOS-$targetArch. '
        'File not found: ${libFile.path}',
      );
    }

    // Register native asset (Flutter converts .dylib to Framework for iOS)
    output.assets.code.add(
      CodeAsset(
        package: _packageName,
        name: _assetId,
        linkMode: assetInfo.linkMode,
        file: libFile.uri,
      ),
    );

    // Add dependency on version files for cache invalidation
    output.dependencies.add(packageRoot.resolve('LIBSIGNAL_VERSION'));
    output.dependencies.add(packageRoot.resolve('NATIVE_BUILD'));
  });
}

/// Reads the libsignal version from LIBSIGNAL_VERSION file.
Future<String> _readVersion(Uri packageRoot) async {
  final versionFile = File.fromUri(packageRoot.resolve('LIBSIGNAL_VERSION'));
  if (!versionFile.existsSync()) {
    throw HookException(
      'LIBSIGNAL_VERSION file not found at ${versionFile.path}',
    );
  }
  // Remove 'v' prefix if present for archive naming
  final version = (await versionFile.readAsString()).trim();
  return version.startsWith('v') ? version.substring(1) : version;
}

/// Reads the native build number from NATIVE_BUILD file.
Future<String> _readNativeBuild(Uri packageRoot) async {
  final buildFile = File.fromUri(packageRoot.resolve('NATIVE_BUILD'));
  if (!buildFile.existsSync()) {
    return '1'; // Default if file doesn't exist
  }
  final build = (await buildFile.readAsString()).trim();
  return build.isEmpty ? '1' : build;
}

/// Reads full version (libsignal version + native build).
Future<String> _readFullVersion(Uri packageRoot) async {
  final version = await _readVersion(packageRoot);
  final build = await _readNativeBuild(packageRoot);
  return '$version-$build';
}

/// Information about a native asset for a specific platform.
class _AssetInfo {
  final String downloadUrl;
  final String archiveFileName;
  final String fileName;
  final LinkMode linkMode;

  const _AssetInfo({
    required this.downloadUrl,
    required this.archiveFileName,
    required this.fileName,
    required this.linkMode,
  });
}

/// Resolves asset information for the target platform.
///
/// [fullVersion] is the complete version string including build number,
/// e.g., "0.86.9-1" (libsignal version + native build number).
_AssetInfo _resolveAssetInfo(CodeConfig codeConfig, String fullVersion) {
  final baseUrl =
      'https://github.com/$_githubRepo/releases/download/libsignal-$fullVersion';
  final targetOS = codeConfig.targetOS;
  final targetArch = codeConfig.targetArchitecture;

  switch (targetOS) {
    case OS.linux:
      final linuxArch = _linuxArchName(targetArch);
      return _AssetInfo(
        downloadUrl:
            '$baseUrl/libsignal-$fullVersion-linux-$linuxArch.tar.gz',
        archiveFileName: 'libsignal-$fullVersion-linux-$linuxArch.tar.gz',
        fileName: 'libsignal_ffi.so',
        linkMode: DynamicLoadingBundled(),
      );

    case OS.macOS:
      // Use architecture-specific binaries (Flutter will merge them with lipo)
      final arch = _macOSArchName(targetArch);
      return _AssetInfo(
        downloadUrl: '$baseUrl/libsignal-$fullVersion-macos-$arch.tar.gz',
        archiveFileName: 'libsignal-$fullVersion-macos-$arch.tar.gz',
        fileName: 'libsignal_ffi.dylib',
        linkMode: DynamicLoadingBundled(),
      );

    case OS.windows:
      return _AssetInfo(
        downloadUrl: '$baseUrl/libsignal-$fullVersion-windows-x86_64.zip',
        archiveFileName: 'libsignal-$fullVersion-windows-x86_64.zip',
        fileName: 'signal_ffi.dll',
        linkMode: DynamicLoadingBundled(),
      );

    case OS.android:
      final abi = _androidArchToAbi(targetArch);
      return _AssetInfo(
        downloadUrl: '$baseUrl/libsignal-$fullVersion-android-$abi.tar.gz',
        archiveFileName: 'libsignal-$fullVersion-android-$abi.tar.gz',
        fileName: 'libsignal_ffi.so',
        linkMode: DynamicLoadingBundled(),
      );

    case OS.iOS:
      // iOS: Use DynamicLoadingBundled - Flutter automatically converts
      // .dylib to Framework format required by App Store.
      //
      // We download architecture-specific .dylib files:
      // - device-arm64 for physical devices
      // - simulator-arm64 for Apple Silicon simulators
      // - simulator-x86_64 for Intel simulators
      final iosTarget = _iOSTargetName(codeConfig, targetArch);
      return _AssetInfo(
        downloadUrl: '$baseUrl/libsignal-$fullVersion-ios-$iosTarget.tar.gz',
        archiveFileName: 'libsignal-$fullVersion-ios-$iosTarget.tar.gz',
        fileName: 'libsignal_ffi.dylib',
        linkMode: DynamicLoadingBundled(),
      );

    default:
      throw HookException('Unsupported target OS: $targetOS');
  }
}

/// Converts Dart Architecture to Android ABI name.
String _androidArchToAbi(Architecture arch) {
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

/// Converts Dart Architecture to macOS architecture name.
String _macOSArchName(Architecture arch) {
  switch (arch) {
    case Architecture.arm64:
      return 'arm64';
    case Architecture.x64:
      return 'x86_64';
    default:
      throw HookException('Unsupported macOS architecture: $arch');
  }
}

/// Converts Dart Architecture to Linux architecture name.
String _linuxArchName(Architecture arch) {
  switch (arch) {
    case Architecture.arm64:
      return 'arm64';
    case Architecture.x64:
      return 'x86_64';
    default:
      throw HookException('Unsupported Linux architecture: $arch');
  }
}

/// Determines iOS target name based on CodeConfig.
///
/// For iOS, we need to determine if we're building for device or simulator,
/// and which architecture. The CodeConfig provides this information.
String _iOSTargetName(CodeConfig codeConfig, Architecture arch) {
  // Check if building for simulator by looking at the iOS SDK
  // iOS simulators use iphonesimulator SDK, devices use iphoneos SDK
  // The CodeConfig.iOS.targetSdk property tells us which one
  final isSimulator = codeConfig.iOS.targetSdk == IOSSdk.iPhoneSimulator;

  if (isSimulator) {
    // Simulator: can be arm64 (Apple Silicon) or x86_64 (Intel)
    switch (arch) {
      case Architecture.arm64:
        return 'simulator-arm64';
      case Architecture.x64:
        return 'simulator-x86_64';
      default:
        throw HookException('Unsupported iOS simulator architecture: $arch');
    }
  } else {
    // Device: always arm64
    if (arch != Architecture.arm64) {
      throw HookException(
        'Unsupported iOS device architecture: $arch (only arm64 is supported)',
      );
    }
    return 'device-arm64';
  }
}

/// Downloads and extracts the native library archive with SHA256 verification.
///
/// [expectedChecksum] is the expected SHA256 hash of the archive.
/// If null, verification is skipped (not recommended for production).
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

  // Download with retry
  await _downloadWithRetry(url, archiveFile);

  // Verify SHA256 checksum if provided
  if (expectedChecksum != null) {
    await _verifyChecksum(archiveFile, expectedChecksum, archiveFileName);
  }

  // Extract based on format
  if (url.endsWith('.zip')) {
    await _extractZip(archiveFile, outDir);
  } else {
    await _extractTarGz(archiveFile, outDir);
  }

  // Clean up archive
  if (archiveFile.existsSync()) {
    await archiveFile.delete();
  }

  // Verify extraction
  final libFile = File('${outDir.path}/$libFileName');
  if (!libFile.existsSync()) {
    throw HookException(
      'Extraction failed: $libFileName not found in archive from $url',
    );
  }
}

/// Downloads a file with retry logic.
Future<void> _downloadWithRetry(
  String url,
  File outputFile, {
  int maxRetries = 3,
  Duration retryDelay = const Duration(seconds: 2),
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
            'Native library not found at $url (HTTP 404). '
            'Ensure GitHub Release exists with the correct version.',
          );
        } else {
          throw HookException(
            'Failed to download from $url: HTTP ${response.statusCode}',
          );
        }
      } on HookException {
        rethrow;
      } catch (e) {
        lastError = e is Exception ? e : Exception(e.toString());
        if (attempt < maxRetries) {
          await Future.delayed(retryDelay * attempt);
        }
      }
    }
  } finally {
    client.close();
  }

  throw HookException(
    'Failed to download from $url after $maxRetries attempts. '
    'Last error: $lastError',
  );
}

/// Extracts a tar.gz archive.
Future<void> _extractTarGz(File archive, Directory outDir) async {
  final result = await Process.run('tar', [
    '-xzf',
    archive.path,
    '-C',
    outDir.path,
  ]);
  if (result.exitCode != 0) {
    throw HookException('Failed to extract tar.gz archive: ${result.stderr}');
  }
}

/// Extracts a zip archive.
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
    throw HookException('Failed to extract zip archive: ${result.stderr}');
  }
}

/// Downloads and verifies checksums file from GitHub Release.
///
/// Returns a map of filename -> expected SHA256 hash.
Future<Map<String, String>> _downloadChecksums(
  String baseUrl,
  String fullVersion,
) async {
  final checksumsUrl = '$baseUrl/libsignal-$fullVersion-checksums.sha256';
  final client = HttpClient();

  try {
    final request = await client.getUrl(Uri.parse(checksumsUrl));
    final response = await request.close();

    if (response.statusCode != 200) {
      throw HookException(
        'Failed to download checksums from $checksumsUrl: HTTP ${response.statusCode}',
      );
    }

    final content = await response.transform(systemEncoding.decoder).join();
    return _parseChecksums(content);
  } finally {
    client.close();
  }
}

/// Parses SHA256 checksums file content.
///
/// Expected format (standard sha256sum output):
/// ```
/// <hash>  <filename>
/// <hash>  <filename>
/// ```
Map<String, String> _parseChecksums(String content) {
  final checksums = <String, String>{};

  for (final line in content.split('\n')) {
    final trimmed = line.trim();
    if (trimmed.isEmpty) continue;

    // Format: "<hash>  <filename>" (two spaces between hash and filename)
    // Also support single space for compatibility
    final match = RegExp(r'^([a-fA-F0-9]{64})\s+(.+)$').firstMatch(trimmed);
    if (match != null) {
      final hash = match.group(1)!.toLowerCase();
      final filename = match.group(2)!;
      checksums[filename] = hash;
    }
  }

  return checksums;
}

/// Computes SHA256 hash of a file.
Future<String> _computeFileSha256(File file) async {
  final bytes = await file.readAsBytes();
  final digest = sha256.convert(bytes);
  return digest.toString();
}

/// Verifies file SHA256 hash against expected value.
///
/// Throws [HookException] if verification fails.
Future<void> _verifyChecksum(
  File file,
  String expectedHash,
  String filename,
) async {
  final actualHash = await _computeFileSha256(file);

  if (actualHash != expectedHash.toLowerCase()) {
    // Delete the corrupted/tampered file
    if (file.existsSync()) {
      await file.delete();
    }
    throw HookException(
      'SHA256 verification failed for $filename!\n'
      'Expected: $expectedHash\n'
      'Actual:   $actualHash\n'
      'This may indicate a corrupted download or supply chain attack. '
      'Please report this issue at https://github.com/$_githubRepo/issues',
    );
  }
}

/// Custom exception for hook errors.
class HookException implements Exception {
  final String message;
  HookException(this.message);

  @override
  String toString() => 'HookException: $message';
}
