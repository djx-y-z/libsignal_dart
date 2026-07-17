#!/usr/bin/env dart

/// Release a new `libsignal_frb` native crate version.
///
/// Bumps `rust/Cargo.toml`, stamps the CHANGELOG `[Unreleased]` Highlights line,
/// creates a signed commit + signed tag `libsignal_frb-<version>`, and pushes
/// (unless `--no-push`). The tag triggers the native build workflow, which
/// publishes the platform binaries. This is stage 1 of the two-stage release
/// flow (see CLAUDE.md); the Dart package release is stage 2.
///
/// The commit/tag/push run with an inherited terminal, so you enter your
/// signing passphrase interactively during the command — no separate manual
/// commit/tag step.
///
/// Usage:
///   make release-frb ARGS="--version X.Y.Z"
///   make release-frb ARGS="--version X.Y.Z --no-push"
///   make release-frb ARGS="--version X.Y.Z --yes"
library;

import 'dart:io';

import 'src/release_frb.dart';

void main(List<String> args) async {
  if (args.contains('--help') || args.contains('-h')) {
    _printUsage();
    exit(0);
  }

  String? version;
  final versionIndex = args.indexOf('--version');
  if (versionIndex != -1 && versionIndex + 1 < args.length) {
    version = args[versionIndex + 1];
  }

  final push = !args.contains('--no-push');
  final assumeYes = args.contains('--yes') || args.contains('-y');

  if (version == null) {
    print('Error: --version X.Y.Z is required');
    print('');
    _printUsage();
    exit(1);
  }

  print('');
  print('========================================');
  print('  Release libsignal_frb native crate');
  print('========================================');
  print('');

  try {
    await releaseFrb(version: version, push: push, assumeYes: assumeYes);
  } catch (e) {
    print('');
    print('Error: $e');
    exit(2);
  }
}

void _printUsage() {
  print('''
Release a new libsignal_frb native crate version

Usage:
  make release-frb ARGS="--version X.Y.Z [options]"

Options:
  --version <X.Y.Z>  New crate version [required]
  --no-push          Commit and tag locally, but do not push
  --yes, -y          Skip the confirmation prompt
  --help, -h         Show this help

What it does:
  1. Verifies you are on a clean, up-to-date main.
  2. Bumps the [package] version in rust/Cargo.toml.
  3. Stamps the "libsignal_frb vX.Y.Z" line into CHANGELOG [Unreleased].
  4. Creates a SIGNED commit and SIGNED tag "libsignal_frb-X.Y.Z"
     (you enter your passphrase during the command).
  5. Pushes main and the tag, which triggers the native build workflow.

After the native build succeeds, cut the Dart package release (stage 2).
''');
}
