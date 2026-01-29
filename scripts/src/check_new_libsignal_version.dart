/// Check for libsignal updates and optionally update rust/Cargo.toml
///
/// This module provides functionality to:
/// - Check for new libsignal releases on GitHub
/// - Compare versions using semver
/// - Update libsignal dependency tags in rust/Cargo.toml

import 'dart:convert';
import 'dart:io';

import 'common.dart';

/// Result of version check
class UpdateCheckResult {
  final String currentVersion;
  final String latestVersion;
  final bool needsUpdate;
  final bool isPrerelease;
  final String? releaseUrl;

  UpdateCheckResult({
    required this.currentVersion,
    required this.latestVersion,
    required this.needsUpdate,
    required this.isPrerelease,
    this.releaseUrl,
  });

  Map<String, dynamic> toJson() => {
    'current_version': currentVersion,
    'latest_version': latestVersion,
    'needs_update': needsUpdate,
    'is_prerelease': isPrerelease,
    'release_url': releaseUrl,
  };
}

/// Check for libsignal updates
Future<UpdateCheckResult> checkForUpdates({
  String? targetVersion,
  bool silent = false,
}) async {
  // Read current version from rust/Cargo.toml
  final currentVersion = getLibsignalVersion();
  if (!silent) logInfo('Current libsignal version: $currentVersion');

  // Get latest version from GitHub
  String latestVersion;
  bool isPrerelease;
  String? releaseUrl;

  if (targetVersion != null && targetVersion.isNotEmpty) {
    latestVersion = targetVersion;
    isPrerelease = latestVersion.contains('-');
    if (!silent) logInfo('Using specified version: $latestVersion');
  } else {
    if (!silent) logStep('Fetching latest libsignal release from GitHub...');
    final result = await _fetchLatestRelease();
    latestVersion = result['version']!;
    isPrerelease = result['isPrerelease'] == 'true';
    releaseUrl = result['releaseUrl'];
    if (!silent) {
      logInfo('Latest version: $latestVersion (prerelease: $isPrerelease)');
    }
  }

  // Compare versions
  final needsUpdate = _compareVersions(latestVersion, currentVersion);

  if (!silent) {
    if (needsUpdate) {
      logInfo('Update available: $currentVersion -> $latestVersion');
    } else {
      logInfo('Already up to date');
    }
  }

  return UpdateCheckResult(
    currentVersion: currentVersion,
    latestVersion: latestVersion,
    needsUpdate: needsUpdate,
    isPrerelease: isPrerelease,
    releaseUrl:
        releaseUrl ??
        'https://github.com/signalapp/libsignal/releases/tag/$latestVersion',
  );
}

/// Fetch latest release info from GitHub API
Future<Map<String, String>> _fetchLatestRelease() async {
  final result = await Process.run('curl', [
    '-s',
    'https://api.github.com/repos/signalapp/libsignal/releases',
  ]);

  if (result.exitCode != 0) {
    throw Exception('Failed to fetch releases from GitHub');
  }

  final releases = jsonDecode(result.stdout as String) as List;
  if (releases.isEmpty) {
    throw Exception('No releases found');
  }

  final latest = releases[0] as Map<String, dynamic>;
  final version = latest['tag_name'] as String;
  final isPrerelease = latest['prerelease'] as bool;
  final htmlUrl = latest['html_url'] as String?;

  return {
    'version': version,
    'isPrerelease': isPrerelease.toString(),
    'releaseUrl': htmlUrl ?? '',
  };
}

/// Number of semver components (major.minor.patch)
const _semverComponents = 3;

/// Compare two semver versions, returns true if v1 > v2
bool _compareVersions(String v1, String v2) {
  // Remove 'v' prefix and pre-release suffix for base comparison
  final v1Base = v1.replaceFirst(RegExp(r'^v'), '').split('-')[0];
  final v2Base = v2.replaceFirst(RegExp(r'^v'), '').split('-')[0];

  List<int> v1Parts;
  List<int> v2Parts;
  try {
    v1Parts = v1Base.split('.').map(int.parse).toList();
    v2Parts = v2Base.split('.').map(int.parse).toList();
  } catch (e) {
    throw Exception('Invalid version format: v1=$v1, v2=$v2. Error: $e');
  }

  // Pad with zeros if needed
  while (v1Parts.length < _semverComponents) {
    v1Parts.add(0);
  }
  while (v2Parts.length < _semverComponents) {
    v2Parts.add(0);
  }

  // Compare major.minor.patch
  for (var i = 0; i < _semverComponents; i++) {
    if (v1Parts[i] > v2Parts[i]) return true;
    if (v1Parts[i] < v2Parts[i]) return false;
  }

  // Base versions are equal, check pre-release
  // If v1 has no suffix and v2 has suffix, v1 is newer (stable > rc)
  // If both have same base but different suffix, consider them equal for update purposes
  return false;
}

/// Update libsignal version in all relevant files
///
/// Updates:
/// - rust/Cargo.toml (libsignal dependency tags)
/// - README.md (badge)
/// - CLAUDE.md (example)
/// - .claude/skills/update-libsignal/SKILL.md (example)
Future<void> updateVersionFiles({
  required String newLibsignalVersion,
  required String oldLibsignalVersion,
  bool silent = false,
}) async {
  final packageDir = getPackageDir();

  // 1. Update rust/Cargo.toml
  if (!silent) logStep('Updating rust/Cargo.toml...');
  final cargoFile = File('${packageDir.path}/rust/Cargo.toml');
  var cargoContent = cargoFile.readAsStringSync();

  // Update all libsignal dependency tags
  // Matches: { git = "...", tag = "vX.Y.Z" }
  final tagPattern = RegExp(
    r'((?:libsignal-protocol|libsignal-core|signal-crypto)\s*=\s*\{[^}]*tag\s*=\s*")[^"]+(")',
  );

  cargoContent = cargoContent.replaceAllMapped(
    tagPattern,
    (match) => '${match.group(1)}$newLibsignalVersion${match.group(2)}',
  );

  await cargoFile.writeAsString(cargoContent);
  if (!silent) {
    logInfo('Updated libsignal dependencies to: $newLibsignalVersion');
    logInfo('  - libsignal-protocol');
    logInfo('  - libsignal-core');
    logInfo('  - signal-crypto');
  }

  // 2. Update README.md badge
  if (!silent) logStep('Updating README.md badge...');
  final readmeFile = File('${packageDir.path}/README.md');
  if (readmeFile.existsSync()) {
    var readmeContent = readmeFile.readAsStringSync();
    // Match: [![libsignal](https://img.shields.io/badge/libsignal-vX.Y.Z-orange.svg)]
    final badgePattern = RegExp(
      r'(\[!\[libsignal\]\(https://img\.shields\.io/badge/libsignal-)v[0-9]+\.[0-9]+\.[0-9]+(-orange\.svg\)\])',
    );
    readmeContent = readmeContent.replaceAllMapped(
      badgePattern,
      (match) => '${match.group(1)}$newLibsignalVersion${match.group(2)}',
    );
    await readmeFile.writeAsString(readmeContent);
    if (!silent) logInfo('Updated README.md badge');
  }

  // 3. Update CLAUDE.md example
  if (!silent) logStep('Updating CLAUDE.md...');
  final claudeMdFile = File('${packageDir.path}/CLAUDE.md');
  if (claudeMdFile.existsSync()) {
    var claudeMdContent = claudeMdFile.readAsStringSync();
    claudeMdContent = claudeMdContent.replaceAll(
      'tag = "$oldLibsignalVersion"',
      'tag = "$newLibsignalVersion"',
    );
    await claudeMdFile.writeAsString(claudeMdContent);
    if (!silent) logInfo('Updated CLAUDE.md example');
  }

  // 4. Update skill documentation
  if (!silent) logStep('Updating .claude/skills/update-libsignal/SKILL.md...');
  final skillFile = File(
    '${packageDir.path}/.claude/skills/update-libsignal/SKILL.md',
  );
  if (skillFile.existsSync()) {
    var skillContent = skillFile.readAsStringSync();
    skillContent = skillContent.replaceAll(
      'tag = "$oldLibsignalVersion"',
      'tag = "$newLibsignalVersion"',
    );
    await skillFile.writeAsString(skillContent);
    if (!silent) logInfo('Updated SKILL.md example');
  }
}

/// Print update summary
void printUpdateSummary({
  required UpdateCheckResult checkResult,
  required bool updated,
}) {
  print('');
  print('========================================');
  print('  Update Check Summary');
  print('========================================');
  print('');
  print('libsignal:');
  print('  Current: ${checkResult.currentVersion}');
  print('  Latest:  ${checkResult.latestVersion}');
  print('  Update:  ${checkResult.needsUpdate ? "Available" : "Up to date"}');

  if (checkResult.isPrerelease) {
    print('  Note:    Pre-release version');
  }

  print('');
  if (updated) {
    print('Files updated:');
    print('  - rust/Cargo.toml (libsignal dependency tags)');
    print('  - README.md (badge)');
    print('  - CLAUDE.md (example)');
    print('  - .claude/skills/update-libsignal/SKILL.md (example)');
    print('');
    print('Next steps:');
    print('  1. Run: cd rust && cargo update (to update Cargo.lock)');
    print('  2. Run: make codegen (if API changed)');
    print('  3. Update CHANGELOG.md');
    print('  4. Run tests: make test');
    print('  5. Commit and push');
  } else if (checkResult.needsUpdate) {
    print('To update, run:');
    print('  make check-new-libsignal-version ARGS="--update"');
  }
  print('');
}

/// Output results as JSON (for CI integration)
void printJsonOutput({
  required UpdateCheckResult checkResult,
  required bool updated,
}) {
  final output = <String, dynamic>{
    'libsignal': checkResult.toJson(),
    'updated': updated,
  };

  // Pretty print JSON
  const encoder = JsonEncoder.withIndent('  ');
  print(encoder.convert(output));
}

/// Perform full update check
///
/// This is the main entry point that orchestrates the update process:
/// 1. Check for new libsignal version
/// 2. Optionally update rust/Cargo.toml
///
/// Returns a record with all results for further processing.
Future<({UpdateCheckResult checkResult, bool updated})> performUpdateCheck({
  String? targetVersion,
  bool doUpdate = false,
  bool force = false,
  bool silent = false,
}) async {
  // Step 1: Check for updates
  final checkResult = await checkForUpdates(
    targetVersion: targetVersion,
    silent: silent,
  );

  // Step 2: Update files if requested
  if (doUpdate && (checkResult.needsUpdate || force)) {
    await updateVersionFiles(
      newLibsignalVersion: checkResult.latestVersion,
      oldLibsignalVersion: checkResult.currentVersion,
      silent: silent,
    );
  }

  final wasUpdated = doUpdate && (checkResult.needsUpdate || force);

  return (checkResult: checkResult, updated: wasUpdated);
}

/// Write outputs to GitHub Actions output file
///
/// This allows the workflow to access the results without parsing JSON.
Future<void> writeGitHubOutputs({
  required UpdateCheckResult checkResult,
  required bool updated,
}) async {
  final githubOutput = Platform.environment['GITHUB_OUTPUT'];
  if (githubOutput == null) {
    return; // Not running in GitHub Actions
  }

  final file = File(githubOutput);
  final buffer = StringBuffer();

  // Check results
  buffer.writeln('current_version=${checkResult.currentVersion}');
  buffer.writeln('latest_version=${checkResult.latestVersion}');
  buffer.writeln('needs_update=${checkResult.needsUpdate}');
  buffer.writeln('is_prerelease=${checkResult.isPrerelease}');
  buffer.writeln('release_url=${checkResult.releaseUrl ?? ""}');
  buffer.writeln('updated=$updated');

  await file.writeAsString(buffer.toString(), mode: FileMode.append);
}
