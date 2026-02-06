/// IO-specific platform implementations for native platforms.
library;

import 'dart:io';
import 'dart:isolate';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

/// Whether we're running on web.
const bool kIsWeb = false;

/// Get a unique identifier for the current isolate.
int getIsolateId() => Isolate.current.hashCode;

/// Try to load library via native assets build hook.
///
/// The build hook (hook/build.dart) places the library in predictable locations:
/// - JIT mode (dart run): .dart_tool/lib/
/// - AOT mode (dart build cli): bundle/lib/ (relative to executable)
///
/// Note: DynamicLibrary.open(assetId) with 'package:' URIs doesn't work
/// in Dart - it tries to open the URI as a literal file path. We must
/// resolve the actual file path ourselves.
// ignore: avoid_unused_constructor_parameters
ExternalLibrary? tryLoadNativeAsset(String assetId) {
  // The assetId parameter is kept for API compatibility but not used.
  // We know where the build hook puts the library.

  final libraryName = getLibraryName();

  // 1. Try JIT mode location: .dart_tool/lib/
  // In JIT mode, the build hook copies the library to .dart_tool/lib/
  final jitLibPath = '.dart_tool/lib/$libraryName';
  if (File(jitLibPath).existsSync()) {
    try {
      return ExternalLibrary.open(File(jitLibPath).absolute.path);
    } catch (_) {}
  }

  // 2. Try AOT mode location: ../lib/ relative to executable
  // In AOT mode (dart build cli), library is in bundle/lib/
  try {
    final executableDir = File(Platform.resolvedExecutable).parent.path;
    final aotLibPath = '$executableDir/../lib/$libraryName';
    if (File(aotLibPath).existsSync()) {
      return ExternalLibrary.open(File(aotLibPath).absolute.path);
    }
  } catch (_) {}

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
    final content =
        jsonDecode(configFile.readAsStringSync()) as Map<String, dynamic>;
    final packages = content['packages'] as List<dynamic>?;
    if (packages == null) return null;

    for (final pkg in packages) {
      final pkgMap = pkg as Map<String, dynamic>;
      if (pkgMap['name'] == 'libsignal') {
        final rootUri = pkgMap['rootUri'] as String?;
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
