#!/usr/bin/env dart
/// Get version information from pubspec.yaml
///
/// Usage:
///   dart run scripts/get_version.dart [--json] [--field <field>]
///
/// Options:
///   --json           Output as JSON
///   --field <field>  Output specific field: version, build, full
///
/// Examples:
///   dart run scripts/get_version.dart              # Output all versions
///   dart run scripts/get_version.dart --json       # Output as JSON
///   dart run scripts/get_version.dart --field version  # Only native version
///   dart run scripts/get_version.dart --field full     # Full version (v0.86.9-1)

import 'dart:convert';
import 'dart:io';

import 'src/common.dart';

void main(List<String> args) {
  final jsonOutput = args.contains('--json');
  String? field;

  final fieldIndex = args.indexOf('--field');
  if (fieldIndex != -1 && fieldIndex + 1 < args.length) {
    field = args[fieldIndex + 1];
  }

  try {
    final version = getLibsignalVersion();
    final build = getNativeBuild();
    final fullVersion = getFullVersion();

    if (field != null) {
      // Output specific field
      switch (field) {
        case 'version':
          stdout.write(version);
          break;
        case 'build':
          stdout.write(build);
          break;
        case 'full':
          stdout.write(fullVersion);
          break;
        default:
          stderr.writeln('Unknown field: $field');
          stderr.writeln('Available fields: version, build, full');
          exit(1);
      }
    } else if (jsonOutput) {
      // Output as JSON
      final output = {
        'native_version': version,
        'native_build': build,
        'full_version': fullVersion,
      };
      stdout.writeln(const JsonEncoder.withIndent('  ').convert(output));
    } else {
      // Human-readable output
      stdout.writeln('libsignal version: $version');
      stdout.writeln('Native build:      $build');
      stdout.writeln('Full version:      $fullVersion');
    }
  } catch (e) {
    stderr.writeln('Error: $e');
    exit(1);
  }
}
