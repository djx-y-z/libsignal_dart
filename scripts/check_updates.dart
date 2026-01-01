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
///   --no-changelog    Skip CHANGELOG.md update (use with --update)
///   --version <ver>   Check/update to specific version
///   --bump <type>     Version bump type: major, minor, patch (default: minor)
///   --force           Force update even if versions match
///   --json            Output results as JSON
///   --ai              Enable AI analysis of release notes (requires GITHUB_TOKEN)
///   --no-ai           Disable AI analysis (default for local runs)
///   --ci              CI mode: enable AI, write to GITHUB_OUTPUT
///   --help, -h        Show this help
///
/// Environment:
///   GITHUB_TOKEN      Required for AI analysis (GitHub Models API)
///
/// Examples:
///   # Just check for updates
///   fvm dart run scripts/check_updates.dart
///
///   # Check and update files
///   fvm dart run scripts/check_updates.dart --update
///
///   # Update with AI analysis (requires GITHUB_TOKEN)
///   GITHUB_TOKEN=xxx fvm dart run scripts/check_updates.dart --update --ai
///
///   # CI mode (auto-enables AI, writes to GITHUB_OUTPUT)
///   fvm dart run scripts/check_updates.dart --update --ci
///
///   # Update to specific version
///   fvm dart run scripts/check_updates.dart --update --version v0.87.0
///
///   # Force major version bump
///   fvm dart run scripts/check_updates.dart --update --bump major
///
///   # Output JSON for scripting
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
  final ciMode = args.contains('--ci');

  // AI flags: --ai enables, --no-ai disables, --ci enables by default
  final useAi = args.contains('--ai') || (ciMode && !args.contains('--no-ai'));

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

  // Get GitHub token from environment
  final githubToken = Platform.environment['GITHUB_TOKEN'];

  if (!jsonOutput) {
    print('');
    print('========================================');
    print('  libsignal Update Checker');
    print('========================================');
    print('');
    if (useAi) {
      if (githubToken != null && githubToken.isNotEmpty) {
        logInfo('AI analysis: enabled');
      } else {
        logWarning('AI analysis: requested but GITHUB_TOKEN not set');
      }
    }
  }

  try {
    // Perform the update check with all options
    final result = await performUpdateCheck(
      targetVersion: targetVersion,
      doUpdate: doUpdate,
      force: force,
      useAi: useAi,
      githubToken: githubToken,
      bumpType: bumpType,
      skipChangelog: noChangelog,
      silent: jsonOutput,
    );

    // Write to GITHUB_OUTPUT if in CI mode
    if (ciMode) {
      await writeGitHubOutputs(
        checkResult: result.checkResult,
        packageResult: result.packageResult,
        aiResult: result.aiResult,
        updated: result.updated,
      );
    }

    // Output results
    if (jsonOutput) {
      printJsonOutput(
        checkResult: result.checkResult,
        packageResult: result.packageResult,
        aiResult: result.aiResult,
        updated: result.updated,
      );
    } else {
      printUpdateSummary(
        checkResult: result.checkResult,
        packageResult: result.packageResult,
        updated: result.updated,
      );

      // Show AI analysis summary if available
      if (result.aiResult != null) {
        print('');
        print('AI Analysis:');
        print('  Model: ${result.aiResult!.modelUsed}');
        print('  Recommended bump: ${result.aiResult!.versionBump}');
        print('  Breaking changes: ${result.aiResult!.breakingChanges}');
        print('  Binding changes: ${result.aiResult!.bindingChanges}');
      }
    }

    // Exit code: 0 if up to date or updated, 1 if update available but not applied
    if (result.checkResult.needsUpdate && !doUpdate) {
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
  --no-changelog    Skip CHANGELOG.md update (use with --update)
  --version <ver>   Check/update to specific version
  --bump <type>     Version bump type: major, minor, patch (default: minor)
  --force           Force update even if versions match
  --json            Output results as JSON
  --ai              Enable AI analysis of release notes
  --no-ai           Disable AI analysis
  --ci              CI mode: enable AI, write to GITHUB_OUTPUT
  --help, -h        Show this help

Environment:
  GITHUB_TOKEN      Required for AI analysis (GitHub Models API)

Examples:
  # Just check for updates
  fvm dart run scripts/check_updates.dart

  # Check and update files
  fvm dart run scripts/check_updates.dart --update

  # Update with AI analysis
  GITHUB_TOKEN=xxx fvm dart run scripts/check_updates.dart --update --ai

  # CI mode (for GitHub Actions)
  fvm dart run scripts/check_updates.dart --update --ci

  # Update to specific version with major bump
  fvm dart run scripts/check_updates.dart --update --version v0.87.0 --bump major

  # Output JSON for scripting
  fvm dart run scripts/check_updates.dart --json

Exit codes:
  0 - Up to date or successfully updated
  1 - Update available (use --update to apply)
  2 - Error occurred
''');
}
