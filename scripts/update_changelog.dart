#!/usr/bin/env dart

/// Update CHANGELOG.md with AI-generated entry for libsignal update
///
/// This script uses GitHub Models API to analyze libsignal release notes
/// and generate an appropriate changelog entry.
///
/// Usage:
///   fvm dart run scripts/update_changelog.dart [options]
///
/// Options:
///   --version <ver>   libsignal version (e.g., v0.87.0)
///   --ci              CI mode: use GITHUB_TOKEN for API
///   --help, -h        Show this help
///
/// Environment:
///   GITHUB_TOKEN      Required for GitHub Models API authentication
///
/// Examples:
///   # Update changelog for specific version
///   GITHUB_TOKEN=xxx fvm dart run scripts/update_changelog.dart --version v0.87.0
///
///   # CI mode (token from environment)
///   fvm dart run scripts/update_changelog.dart --version v0.87.0 --ci

import 'dart:io';

import 'src/update_changelog.dart';

void main(List<String> args) async {
  if (args.contains('--help') || args.contains('-h')) {
    _printUsage();
    exit(0);
  }

  // Parse arguments
  final ciMode = args.contains('--ci');

  String? version;
  final versionIndex = args.indexOf('--version');
  if (versionIndex != -1 && versionIndex + 1 < args.length) {
    version = args[versionIndex + 1];
  }

  if (version == null) {
    print('Error: --version is required');
    print('');
    _printUsage();
    exit(1);
  }

  // Check for GitHub token
  final token = Platform.environment['GITHUB_TOKEN'];
  if (token == null || token.isEmpty) {
    print('Error: GITHUB_TOKEN environment variable is required');
    print('');
    print('Get a token from: https://github.com/settings/tokens');
    print('The token needs no special permissions for GitHub Models API.');
    exit(1);
  }

  print('');
  print('========================================');
  print('  CHANGELOG Update with AI');
  print('========================================');
  print('');

  try {
    await updateChangelog(version: version, token: token, ciMode: ciMode);
    print('');
    print('CHANGELOG.md updated successfully!');
  } catch (e) {
    print('Error: $e');
    exit(2);
  }
}

void _printUsage() {
  print('''
Update CHANGELOG.md with AI

Usage:
  fvm dart run scripts/update_changelog.dart [options]

Options:
  --version <ver>   libsignal version (e.g., v0.87.0) [required]
  --ci              CI mode
  --help, -h        Show this help

Environment:
  GITHUB_TOKEN      Required for GitHub Models API authentication

Examples:
  # Update changelog for specific version
  GITHUB_TOKEN=xxx fvm dart run scripts/update_changelog.dart --version v0.87.0

  # CI mode (token from environment)
  fvm dart run scripts/update_changelog.dart --version v0.87.0 --ci
''');
}
