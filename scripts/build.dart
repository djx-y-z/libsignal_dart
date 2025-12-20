#!/usr/bin/env dart

/// Build libsignal native libraries for all platforms
///
/// Usage:
///   dart run scripts/build.dart <platform> [options]
///
/// Platforms:
///   linux      Build for Linux (x86_64 or arm64, native)
///   macos      Build for macOS (Universal Binary by default)
///   ios        Build for iOS (all targets by default)
///   android    Build for Android (all ABIs by default)
///   windows    Build for Windows x86_64
///   all        Build all platforms available on current OS
///
/// Examples:
///   dart run scripts/build.dart macos
///   dart run scripts/build.dart macos --arch arm64
///   dart run scripts/build.dart ios --target device
///   dart run scripts/build.dart android --abi arm64-v8a
///   dart run scripts/build.dart all

import 'dart:io';
import 'src/common.dart';
import 'src/build_linux.dart';
import 'src/build_macos.dart';
import 'src/build_ios.dart';
import 'src/build_android.dart';
import 'src/build_windows.dart';

void main(List<String> args) async {
  if (args.isEmpty || args.contains('--help') || args.contains('-h')) {
    _printUsage();
    exit(0);
  }

  final platform = args.first.toLowerCase();
  final options = args.skip(1).toList();

  try {
    switch (platform) {
      case 'linux':
        final linuxArch = _getOption(options, '--arch');
        await buildLinux(arch: linuxArch);

      case 'macos':
        final arch = _getOption(options, '--arch');
        await buildMacOS(arch: parseArch(arch));

      case 'ios':
        final target = _getOption(options, '--target');
        await buildIOS(target: parseTarget(target));

      case 'android':
        final abi = _getOption(options, '--abi');
        await buildAndroid(abi: parseAbi(abi));

      case 'windows':
        await buildWindows();

      case 'all':
        await _buildAll();

      case 'list':
        _listPlatforms();

      default:
        logError('Unknown platform: $platform');
        _printUsage();
        exit(1);
    }
  } catch (e) {
    logError(e.toString());
    exit(1);
  }
}

/// Build all available platforms
Future<void> _buildAll() async {
  final available = getAvailablePlatforms();

  print('');
  print('========================================');
  print('  libsignal Build: All Platforms');
  print('========================================');
  print('');
  print('OS: ${Platform.operatingSystem}');
  print('Platforms to build: ${available.map((p) => p.name).join(', ')}');
  print('');

  final failed = <BuildPlatform>[];
  final succeeded = <BuildPlatform>[];

  for (final platform in available) {
    try {
      switch (platform) {
        case BuildPlatform.linux:
          await buildLinux();
        case BuildPlatform.macos:
          await buildMacOS();
        case BuildPlatform.ios:
          await buildIOS();
        case BuildPlatform.android:
          await buildAndroid();
        case BuildPlatform.windows:
          await buildWindows();
      }
      succeeded.add(platform);
    } catch (e) {
      logError('Failed to build ${platform.name}: $e');
      failed.add(platform);
    }
  }

  // Summary
  print('');
  print('========================================');
  print('  Build Summary');
  print('========================================');
  print('');

  if (succeeded.isNotEmpty) {
    print(Colors.colorize('Succeeded:', Colors.green));
    for (final p in succeeded) {
      print('  - ${p.name}');
    }
  }

  if (failed.isNotEmpty) {
    print('');
    print(Colors.colorize('Failed:', Colors.red));
    for (final p in failed) {
      print('  - ${p.name}');
    }
    exit(1);
  }

  print('');
  logInfo('All builds completed successfully!');
}

/// List available platforms
void _listPlatforms() {
  final available = getAvailablePlatforms();

  print('Available platforms on ${Platform.operatingSystem}:');
  for (final p in available) {
    print('  - ${p.name}');
  }

  // Check for Android NDK
  if ((Platform.isMacOS || Platform.isLinux) &&
      !available.contains(BuildPlatform.android)) {
    print('');
    logWarn('Android NDK not found. To enable Android builds:');
    print('  export ANDROID_NDK_HOME=/path/to/ndk');
  }
}

/// Get option value from arguments
String? _getOption(List<String> options, String name) {
  for (var i = 0; i < options.length - 1; i++) {
    if (options[i] == name) {
      return options[i + 1];
    }
  }
  return null;
}

/// Print usage information
void _printUsage() {
  print('''
libsignal Native Library Builder

Usage:
  dart run scripts/build.dart <platform> [options]

Platforms:
  linux      Build for Linux (x86_64 or arm64, native)
  macos      Build for macOS (Universal Binary)
  ios        Build for iOS (all targets)
  android    Build for Android (all ABIs)
  windows    Build for Windows x86_64
  all        Build all platforms available on current OS
  list       List available platforms

Options:
  --arch <arch>      Linux/macOS architecture: arm64, x86_64 (native by default for Linux)
  --target <target>  iOS target: device, simulator-arm64, simulator-x86_64, all (default)
  --abi <abi>        Android ABI: arm64-v8a, armeabi-v7a, x86_64, all (default)

Examples:
  dart run scripts/build.dart macos
  dart run scripts/build.dart macos --arch arm64
  dart run scripts/build.dart ios --target device
  dart run scripts/build.dart android --abi arm64-v8a
  dart run scripts/build.dart all
  dart run scripts/build.dart list

Note: This uses Rust/Cargo to build libsignal (requires rustup, cargo installed).
''');
}
