/// IO-specific platform implementations for native platforms.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

/// Whether we're running on web.
const bool kIsWeb = false;

/// Get a unique identifier for the current isolate.
int getIsolateId() => Isolate.current.hashCode;

/// Try to load library via native assets.
///
/// First tries the native assets API directly (works in AOT mode).
/// Then falls back to reading native_assets.yaml (for JIT mode with dart run).
ExternalLibrary? tryLoadNativeAsset(String assetId) {
  // 1. Try native assets API directly (works in AOT mode)
  try {
    return ExternalLibrary.open(assetId);
  } catch (_) {}

  // 2. Try reading native_assets.yaml (JIT mode with dart run)
  final libraryPath = _findLibraryInNativeAssetsYaml(assetId);
  if (libraryPath != null) {
    try {
      return ExternalLibrary.open(libraryPath);
    } catch (_) {}
  }

  return null;
}

/// Read native_assets.yaml to find library path for JIT mode.
///
/// In JIT mode (dart run), Dart generates native_assets.yaml with mappings
/// from asset IDs to absolute file paths, but DynamicLibrary.open doesn't
/// automatically resolve these. We need to read the file manually.
///
/// Despite the .yaml extension, the file is actually JSON format.
String? _findLibraryInNativeAssetsYaml(String assetId) {
  // Try CWD first
  var assetsFile = File('.dart_tool/native_assets.yaml');

  // coverage:ignore-start
  if (!assetsFile.existsSync()) {
    // Try script location
    try {
      final scriptDir = File(Platform.script.toFilePath()).parent;
      var dir = scriptDir;
      for (var i = 0; i < 10; i++) {
        assetsFile = File('${dir.path}/.dart_tool/native_assets.yaml');
        if (assetsFile.existsSync()) break;
        final parent = dir.parent;
        if (parent.path == dir.path) return null;
        dir = parent;
      }
    } catch (_) {
      return null;
    }
  }
  // coverage:ignore-end

  if (!assetsFile.existsSync()) return null;

  try {
    var content = assetsFile.readAsStringSync();

    // Skip comment lines at the beginning (file has # comments before JSON)
    final lines = content.split('\n');
    final jsonStart = lines.indexWhere(
      (line) => line.trimLeft().startsWith('{'),
    );
    if (jsonStart > 0) {
      content = lines.skip(jsonStart).join('\n');
    }

    final json = jsonDecode(content) as Map<String, dynamic>;

    // Format:
    // {
    //   "native-assets": {
    //     "macos_arm64": {
    //       "package:libsignal/libsignal": ["absolute", "/path/to/lib.dylib"]
    //     }
    //   }
    // }
    final nativeAssets = json['native-assets'] as Map<String, dynamic>?;
    if (nativeAssets == null) return null;

    // Search across all platforms (usually just one for current OS)
    for (final platformAssets in nativeAssets.values) {
      if (platformAssets is! Map<String, dynamic>) continue;

      final assetEntry = platformAssets[assetId];
      if (assetEntry is List && assetEntry.length >= 2) {
        // ["absolute", "/path/to/lib.dylib"]
        if (assetEntry[0] == 'absolute') {
          return assetEntry[1] as String;
        }
      }
    }
  } catch (_) {}

  return null;
}

/// Load library from a file path.
ExternalLibrary openLibraryFromPath(String path) {
  return ExternalLibrary.open(path);
}

/// Find the native library in standard file locations.
String? findLibraryPath(String libraryName, String? packageRoot) {
  // 1. Try package directory
  if (packageRoot != null) {
    final paths = [
      '$packageRoot/rust/target/release/$libraryName',
      '$packageRoot/rust/target/debug/$libraryName',
    ];
    for (final path in paths) {
      if (File(path).existsSync()) {
        return path;
      }
    }
  }

  // coverage:ignore-start
  // 2. Try CWD
  final cwdPaths = [
    'rust/target/release/$libraryName',
    'rust/target/debug/$libraryName',
  ];
  for (final path in cwdPaths) {
    final file = File(path);
    if (file.existsSync()) {
      return file.absolute.path;
    }
  }

  // 3. Try script directory
  try {
    final scriptDir = File(Platform.script.toFilePath()).parent;
    var dir = scriptDir;
    for (var i = 0; i < 10; i++) {
      for (final subpath in [
        'rust/target/release/$libraryName',
        'rust/target/debug/$libraryName',
      ]) {
        final path = '${dir.path}/$subpath';
        if (File(path).existsSync()) {
          return path;
        }
      }
      final parent = dir.parent;
      if (parent.path == dir.path) break;
      dir = parent;
    }
  } catch (_) {}
  // coverage:ignore-end

  return null;
}

/// Find the libsignal package root via package_config.json.
String? findPackageRoot() {
  // Try CWD
  var configFile = File('.dart_tool/package_config.json');
  // coverage:ignore-start
  if (!configFile.existsSync()) {
    // Try script location
    try {
      final scriptDir = File(Platform.script.toFilePath()).parent;
      var dir = scriptDir;
      for (var i = 0; i < 10; i++) {
        configFile = File('${dir.path}/.dart_tool/package_config.json');
        if (configFile.existsSync()) break;
        final parent = dir.parent;
        if (parent.path == dir.path) return null;
        dir = parent;
      }
    } catch (_) {
      return null;
    }
  }
  // coverage:ignore-end

  if (!configFile.existsSync()) return null;

  try {
    final content = jsonDecode(configFile.readAsStringSync());
    final packages = content['packages'] as List?;
    if (packages == null) return null;

    for (final pkg in packages) {
      if (pkg['name'] == 'libsignal') {
        final rootUri = pkg['rootUri'] as String?;
        if (rootUri == null) continue;

        if (rootUri.startsWith('file://')) {
          return Uri.parse(rootUri).toFilePath(); // coverage:ignore-line
        } else if (rootUri.startsWith('../')) {
          final resolved = File('${configFile.parent.path}/$rootUri');
          return resolved.absolute.path;
        }
      }
    }
  } catch (_) {}

  return null;
}

/// Get the platform-specific library name.
String getLibraryName() {
  if (Platform.isMacOS) {
    return 'liblibsignal_frb.dylib';
  }
  // coverage:ignore-start
  if (Platform.isLinux) {
    return 'liblibsignal_frb.so';
  }
  if (Platform.isWindows) {
    return 'libsignal_frb.dll';
  }
  if (Platform.isAndroid) {
    return 'liblibsignal_frb.so';
  }
  if (Platform.isIOS) {
    return 'liblibsignal_frb.dylib';
  }
  throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
  // coverage:ignore-end
}
