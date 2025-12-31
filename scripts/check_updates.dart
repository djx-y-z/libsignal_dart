#!/usr/bin/env dart

/// Check for libsignal updates
///
/// This script checks for new libsignal releases and optionally updates
/// pubspec.yaml (version, libsignal.native_version, libsignal.native_build) and CHANGELOG.md.
///
/// Usage:
///   fvm dart run scripts/check_updates.dart [options]
///
/// Options:
///   --update          Update local files if new version available
///   --no-changelog    Skip CHANGELOG.md update (use with --update, for CI)
///   --version <ver>   Check/update to specific version
///   --bump <type>     Version bump type: major, minor, patch (default: minor)
///   --force           Force update even if versions match
///   --json            Output results as JSON (for CI integration)
///   --help, -h        Show this help
///
/// Examples:
///   # Just check for updates
///   fvm dart run scripts/check_updates.dart
///
///   # Check and update files
///   fvm dart run scripts/check_updates.dart --update
///
///   # Update to specific version
///   fvm dart run scripts/check_updates.dart --update --version v0.87.0
///
///   # Force major version bump
///   fvm dart run scripts/check_updates.dart --update --bump major
///
///   # Update without changelog (for CI, AI generates changelog separately)
///   fvm dart run scripts/check_updates.dart --update --no-changelog
///
///   # Output JSON for CI
///   fvm dart run scripts/check_updates.dart --json

import 'dart:io';

import 'src/check_updates.dart';
import 'src/common.dart';

void main(List<String> args) async {
  if (args.contains('--help') || args.contains('-h')) {
    _printUsage();
    exit(0);
  }

  // Parse arguments
  final doUpdate = args.contains('--update');
  final force = args.contains('--force');
  final jsonOutput = args.contains('--json');
  final noChangelog = args.contains('--no-changelog');

  String? targetVersion;
  final versionIndex = args.indexOf('--version');
  if (versionIndex != -1 && versionIndex + 1 < args.length) {
    targetVersion = args[versionIndex + 1];
  }

  var bumpType = 'minor';
  final bumpIndex = args.indexOf('--bump');
  if (bumpIndex != -1 && bumpIndex + 1 < args.length) {
    bumpType = args[bumpIndex + 1];
    if (!['major', 'minor', 'patch'].contains(bumpType)) {
      if (!jsonOutput) {
        logError('Invalid bump type: $bumpType. Use: major, minor, patch');
      }
      exit(1);
    }
  }

  if (!jsonOutput) {
    print('');
    print('========================================');
    print('  libsignal Update Checker');
    print('========================================');
    print('');
  }

  try {
    // Check for updates (suppress logs in JSON mode)
    final checkResult = await checkForUpdates(
      targetVersion: targetVersion,
      silent: jsonOutput,
    );

    PackageVersionResult? packageResult;

    if (checkResult.needsUpdate || force) {
      // Calculate new package version
      packageResult = calculatePackageVersion(
        currentLibsignal: checkResult.currentVersion,
        newLibsignal: checkResult.latestVersion,
        isPrerelease: checkResult.isPrerelease,
        bumpType: bumpType,
        silent: jsonOutput,
      );

      if (doUpdate) {
        // Update files
        await updateVersionFiles(
          newLibsignalVersion: checkResult.latestVersion,
          newPackageVersion: packageResult.newVersion,
          bumpType: packageResult.bumpType,
          isPrerelease: checkResult.isPrerelease,
          releaseUrl: checkResult.releaseUrl,
          silent: jsonOutput,
          skipChangelog: noChangelog,
        );
      }
    }

    final wasUpdated = doUpdate && (checkResult.needsUpdate || force);

    // Output results
    if (jsonOutput) {
      printJsonOutput(
        checkResult: checkResult,
        packageResult: packageResult,
        updated: wasUpdated,
      );
    } else {
      printUpdateSummary(
        checkResult: checkResult,
        packageResult: packageResult,
        updated: wasUpdated,
      );
    }

    // Exit code: 0 if up to date or updated, 1 if update available but not applied
    if (checkResult.needsUpdate && !doUpdate) {
      exit(1); // Signal that update is available
    }
  } catch (e) {
    if (!jsonOutput) {
      logError(e.toString());
    }
    exit(2);
  }
}

void _printUsage() {
  print('''
Check for libsignal Updates

Usage:
  fvm dart run scripts/check_updates.dart [options]

Options:
  --update          Update local files if new version available
  --no-changelog    Skip CHANGELOG.md update (use with --update, for CI)
  --version <ver>   Check/update to specific version
  --bump <type>     Version bump type: major, minor, patch (default: minor)
  --force           Force update even if versions match
  --json            Output results as JSON (for CI integration)
  --help, -h        Show this help

Examples:
  # Just check for updates
  fvm dart run scripts/check_updates.dart

  # Check and update files
  fvm dart run scripts/check_updates.dart --update

  # Update to specific version with major bump
  fvm dart run scripts/check_updates.dart --update --version v0.87.0 --bump major

  # Output JSON for CI
  fvm dart run scripts/check_updates.dart --json

Exit codes:
  0 - Up to date or successfully updated
  1 - Update available (use --update to apply)
  2 - Error occurred
''');
}
