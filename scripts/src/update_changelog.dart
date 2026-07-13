// Update CHANGELOG.md with AI-generated entry for libsignal update.
//
// Uses GitHub Models API (OpenAI-compatible) to analyze release notes
// and generate appropriate changelog entries.
library;

import 'dart:convert';
import 'dart:io';

import 'common.dart';

/// Update CHANGELOG.md with a new libsignal version entry
Future<void> updateChangelog({
  required String version,
  required String token,
  String? fromVersion,
  String? crateVersionBefore,
  bool ciMode = false,
}) async {
  final packageDir = getPackageDir();

  // Step 1: Read current libsignal_frb version from Cargo.toml
  logStep('Reading libsignal_frb version from rust/Cargo.toml...');
  var frbVersion = _readFrbVersion(packageDir);
  logInfo('Current libsignal_frb version: $frbVersion');

  // Step 2: Fetch release notes from GitHub
  logStep('Fetching release notes for $version...');
  final releaseNotes = await _fetchReleaseNotes(version);
  logInfo('Got ${releaseNotes.length} characters of release notes');

  // Step 2.5: Fetch the actual commit list between the two tags — release
  // notes alone are often terse, which produced incomplete changelog entries.
  var upstreamCommits = '';
  if (fromVersion != null && fromVersion != version) {
    logStep('Fetching upstream commits $fromVersion...$version...');
    try {
      upstreamCommits = await _fetchUpstreamCommits(fromVersion, version);
      logInfo('Got ${upstreamCommits.length} characters of commit history');
    } catch (e) {
      logWarning('Could not fetch upstream commit list: $e');
    }
  }

  // Step 3: Read current CHANGELOG
  logStep('Reading CHANGELOG.md...');
  final changelogFile = File('${packageDir.path}/CHANGELOG.md');
  final currentChangelog = changelogFile.readAsStringSync();

  // Step 4: Analyze with AI
  logStep('Analyzing with GitHub Models AI...');
  final aiResponse = await _generateChangelogEntry(
    version: version,
    frbVersion: frbVersion,
    releaseNotes: releaseNotes,
    upstreamCommits: upstreamCommits,
    currentChangelog: currentChangelog,
    token: token,
  );

  // Parse AI response
  final parsed = jsonDecode(aiResponse) as Map<String, dynamic>;
  var nativeHighlight = parsed['libsignal_highlight'] as String;
  var frbHighlight = parsed['frb_highlight'] as String;
  final changed = parsed['changed'] as String;
  logInfo('Generated libsignal highlight: $nativeHighlight');
  logInfo('Generated libsignal_frb highlight: $frbHighlight');
  logInfo('Generated changed entry');

  // Step 4.5: Reconcile the crate version with the AI severity verdict.
  // The deterministic SemVer-mirror bump (applied by check_updates) under-
  // bumps when a 0.x upstream ships breaking changes in a minor release; the
  // AI classifies severity from the release notes and commit list, and the
  // more severe of the two verdicts wins. `bump_verified=false` is emitted
  // when the AI verdict is missing/invalid so the PR flags a manual check.
  final aiBump = parsed['bump'] as String?;
  var bumpVerified = false;
  if (crateVersionBefore != null) {
    final adjusted = _reconcileCrateVersion(
      packageDir: packageDir,
      versionBefore: crateVersionBefore,
      mirrorBumped: frbVersion,
      aiBump: aiBump,
    );
    if (adjusted != null) {
      bumpVerified = true;
      if (adjusted != frbVersion) {
        // Keep the generated highlight consistent with the raised version.
        frbHighlight = frbHighlight.replaceAll('v$frbVersion', 'v$adjusted');
        nativeHighlight = nativeHighlight.replaceAll(
          'v$frbVersion',
          'v$adjusted',
        );
        frbVersion = adjusted;
      }
    }
  } else if (aiBump != null) {
    logInfo(
      'AI severity verdict: $aiBump (no --crate-version-before, '
      'version left unchanged)',
    );
  }
  _writeGitHubOutput('bump_verified', '$bumpVerified');
  _writeGitHubOutput('crate_version', frbVersion);

  // Step 5: Update CHANGELOG
  logStep('Updating CHANGELOG.md...');
  final updatedChangelog = _insertChangelogEntry(
    currentChangelog: currentChangelog,
    nativeHighlight: nativeHighlight,
    frbHighlight: frbHighlight,
    changed: changed,
    version: version,
  );

  await changelogFile.writeAsString(updatedChangelog);
  logInfo('CHANGELOG.md updated');
}

/// Applies the more severe of the SemVer-mirror bump and the AI verdict to
/// the crate version in rust/Cargo.toml (the AI never lowers the bump below
/// what the mirror already applied).
///
/// Returns the final version, or null when [aiBump] is not a valid severity
/// or the versions don't parse — the mirror bump then stands and the caller
/// reports an unverified bump.
String? _reconcileCrateVersion({
  required Directory packageDir,
  required String versionBefore,
  required String mirrorBumped,
  required String? aiBump,
}) {
  const severities = ['major', 'minor', 'patch'];
  final aiIndex = aiBump == null ? -1 : severities.indexOf(aiBump);
  if (aiIndex == -1) {
    logWarning(
      'AI did not return a valid bump verdict ("$aiBump") — '
      'keeping the SemVer-mirror bump, verify manually',
    );
    return null;
  }

  final before = _parseVersion(versionBefore);
  final mirrored = _parseVersion(mirrorBumped);
  if (before == null || mirrored == null) {
    logWarning(
      'Cannot parse crate versions ("$versionBefore" -> "$mirrorBumped") — '
      'verify the bump manually',
    );
    return null;
  }

  var mirrorIndex = 2;
  if (mirrored[0] != before[0]) {
    mirrorIndex = 0;
  } else if (mirrored[1] != before[1]) {
    mirrorIndex = 1;
  }

  final finalIndex = aiIndex < mirrorIndex ? aiIndex : mirrorIndex;
  final parts = [...before];
  parts[finalIndex]++;
  for (var i = finalIndex + 1; i < parts.length; i++) {
    parts[i] = 0;
  }
  final finalVersion = parts.join('.');

  logInfo(
    'Bump severity: AI says ${severities[aiIndex]}, mirror applied '
    '${severities[mirrorIndex]} -> using ${severities[finalIndex]} '
    '($versionBefore -> $finalVersion)',
  );

  if (finalVersion != mirrorBumped) {
    final cargoToml = File('${packageDir.path}/rust/Cargo.toml');
    final content = cargoToml.readAsStringSync();
    cargoToml.writeAsStringSync(
      content.replaceFirst(
        RegExp(r'^version\s*=\s*"[^"]+"', multiLine: true),
        'version = "$finalVersion"',
      ),
    );
    logInfo('Raised libsignal_frb version in rust/Cargo.toml to $finalVersion');
  }
  return finalVersion;
}

/// Parses a plain X.Y.Z version, or null if it doesn't match.
List<int>? _parseVersion(String version) {
  final match = RegExp(r'^(\d+)\.(\d+)\.(\d+)$').firstMatch(version.trim());
  if (match == null) return null;
  return [for (var i = 1; i <= 3; i++) int.parse(match.group(i)!)];
}

/// Appends a key=value line to the step's GITHUB_OUTPUT (no-op locally).
void _writeGitHubOutput(String key, String value) {
  final githubOutput = Platform.environment['GITHUB_OUTPUT'];
  if (githubOutput == null) return;
  File(githubOutput).writeAsStringSync('$key=$value\n', mode: FileMode.append);
}

/// Read libsignal_frb version from rust/Cargo.toml
String _readFrbVersion(Directory packageDir) {
  final cargoToml = File('${packageDir.path}/rust/Cargo.toml');
  final content = cargoToml.readAsStringSync();

  // Match version = "X.Y.Z" at the start of the file (package version)
  final match = RegExp(
    r'^version\s*=\s*"([^"]+)"',
    multiLine: true,
  ).firstMatch(content);

  if (match == null) {
    throw Exception('Could not find version in rust/Cargo.toml');
  }

  return match.group(1)!;
}

/// Fetch release notes from GitHub API
Future<String> _fetchReleaseNotes(String version) async {
  final result = await Process.run('curl', [
    '-s',
    'https://api.github.com/repos/signalapp/libsignal/releases/tags/$version',
  ]);

  if (result.exitCode != 0) {
    throw Exception('Failed to fetch release from GitHub');
  }

  final json = jsonDecode(result.stdout as String) as Map<String, dynamic>;

  if (json.containsKey('message') && json['message'] == 'Not Found') {
    throw Exception('Release $version not found');
  }

  return json['body'] as String? ?? 'No release notes available.';
}

/// Fetch the commit list between two upstream tags via the GitHub compare API.
///
/// Returns a newline-separated list of first-line commit messages (merge
/// commits excluded), capped to keep the AI prompt within limits.
Future<String> _fetchUpstreamCommits(String from, String to) async {
  final result = await Process.run('curl', [
    '-s',
    'https://api.github.com/repos/signalapp/libsignal/compare/$from...$to?per_page=250',
  ]);

  if (result.exitCode != 0) {
    throw Exception('Failed to fetch compare from GitHub');
  }

  final json = jsonDecode(result.stdout as String) as Map<String, dynamic>;
  if (json['commits'] == null) {
    throw Exception(json['message'] ?? 'No commits in compare response');
  }

  final commits = json['commits'] as List<Object?>;
  final totalCommits = json['total_commits'] as int? ?? commits.length;
  final messages = <String>[];
  for (final commit in commits) {
    final message =
        (((commit as Map<String, dynamic>)['commit']
                    as Map<String, dynamic>)['message']
                as String)
            .split('\n')
            .first
            .trim();
    if (message.startsWith('Merge ')) continue;
    messages.add('- $message');
  }

  const maxChars = 8000;
  var listing = messages.join('\n');
  if (listing.length > maxChars) {
    listing = '${listing.substring(0, maxChars)}\n- ... (truncated)';
  }
  if (totalCommits > commits.length) {
    listing += '\n- ... and ${totalCommits - commits.length} more commits';
  }
  return listing;
}

/// Generate changelog entry using GitHub Models API
Future<String> _generateChangelogEntry({
  required String version,
  required String frbVersion,
  required String releaseNotes,
  required String upstreamCommits,
  required String currentChangelog,
  required String token,
}) async {
  // Extract recent changelog entries for context (first 150 lines)
  final changelogContext = currentChangelog.split('\n').take(150).join('\n');

  final prompt =
      '''
You are updating CHANGELOG.md for a Dart library that wraps libsignal.

The library just updated its libsignal native dependency to $version.
The Rust FFI bindings crate (libsignal_frb) version is $frbVersion.

## libsignal Release Notes for $version:
$releaseNotes
${upstreamCommits.isEmpty ? '' : '''

## Upstream commits included in this update (first lines):
$upstreamCommits

Use BOTH the release notes and the commit list — release notes are often
incomplete, and the commit list shows what actually changed.'''}

## Current CHANGELOG.md format (for reference):
$changelogContext

## CHANGELOG Structure:
This project uses the following CHANGELOG structure:
- "### For Users" — changes that affect library users (API, behavior, dependencies)
  - "#### Highlights" — TWO lines: one for libsignal version, one for libsignal_frb version
  - "#### Added" — new features
  - "#### Changed" — updates to existing functionality (INCLUDING dependency updates like libsignal)
  - "#### Fixed" — bug fixes
  - "#### Security" — security-related changes
- "### For Contributors" — changes that only affect developers (CI, tooling, internal refactoring)

Updating libsignal version goes under "### For Users" with BOTH:
- "#### ✨ Highlights" — TWO brief one-liners (libsignal AND libsignal_frb)
- "#### Changed" — detailed description with release notes

## Your Task:
Generate a JSON object with FOUR fields:
1. "libsignal_highlight" — a single line for libsignal (format: "**libsignal vX.Y.Z** — brief description")
2. "frb_highlight" — a single line for libsignal_frb (format: "**libsignal_frb vX.Y.Z** — Rust FFI bindings")
3. "changed" — the detailed entry for Changed section
4. "bump" — SemVer severity of this update for the wrapper package: "major", "minor", or "patch"

## Example output format:
```json
{
  "libsignal_highlight": "**libsignal v1.0.0** — latest upstream native library",
  "frb_highlight": "**libsignal_frb v1.0.2** — Rust FFI bindings",
  "changed": "- Update libsignal native library to v1.0.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v1.0.0))\n  - Feature X: Description of feature\n  - **BREAKING:** Removed API Y — description\n  - Note: These changes improve performance and stability",
  "bump": "minor"
}
```

## Rules for "libsignal_highlight":
1. Format: "**libsignal $version** — [brief 3-7 word description]"
2. Keep it very short and scannable
3. Examples: "latest upstream native library", "security fixes and improvements", "new API support"

## Rules for "frb_highlight":
1. Format: "**libsignal_frb v$frbVersion** — Rust FFI bindings"
2. Always use exactly this format

## Rules for "changed":
1. Start with "- Update libsignal native library to $version ([release notes](...))
2. Add 2-7 bullet points summarizing key changes from the release notes AND the upstream commit list
3. Focus on changes relevant to library users (API changes, new features, bug fixes, security fixes)
4. Prefix every breaking change bullet with "**BREAKING:**"
5. For internal changes, add "Note: These changes do not affect this library's API"
6. Use technical but concise language
7. Mention specific components or modules changed

## Rules for "bump":
1. "major" — ANY breaking change: removed/renamed APIs, changed signatures or behavior, protocol/serialization format changes
2. "minor" — new backwards-compatible functionality
3. "patch" — bug fixes, security patches, internal/dependency-only changes
4. IMPORTANT: judge from the release notes and commit list, NOT from the upstream version numbers. Upstream packages with major version 0 routinely ship breaking changes in minor releases
5. When the information is insufficient to be confident, prefer the more severe verdict

Return ONLY valid JSON, no markdown code blocks.
''';

  final requestBody = jsonEncode({
    'model': 'gpt-4o-mini',
    'messages': [
      {'role': 'user', 'content': prompt},
    ],
    'temperature': 0.3,
    'max_tokens': 800,
  });

  final result = await Process.run('curl', [
    '-s',
    '-X',
    'POST',
    'https://models.github.ai/inference/chat/completions',
    '-H',
    'Content-Type: application/json',
    '-H',
    'Authorization: Bearer $token',
    '-d',
    requestBody,
  ]);

  if (result.exitCode != 0) {
    throw Exception('GitHub Models API request failed');
  }

  final response = jsonDecode(result.stdout as String) as Map<String, dynamic>;

  if (response.containsKey('error')) {
    final error = response['error'] as Map<String, dynamic>;
    throw Exception('API error: ${error['message']}');
  }

  final choices = response['choices'] as List<Object?>?;
  if (choices == null || choices.isEmpty) {
    throw Exception('No response from AI');
  }

  final firstChoice = choices[0];
  if (firstChoice is! Map<String, dynamic>) {
    throw Exception('Invalid response format from AI');
  }
  final message = firstChoice['message'] as Map<String, dynamic>?;
  if (message == null) {
    throw Exception('No message in AI response');
  }
  final content = (message['content'] as String).trim();

  // Parse JSON response
  try {
    final parsed = jsonDecode(content) as Map<String, dynamic>;
    return jsonEncode(parsed); // Return normalized JSON
  } catch (e) {
    // If AI didn't return valid JSON, try to extract it
    final jsonMatch = RegExp(r'\{[\s\S]*\}').firstMatch(content);
    if (jsonMatch != null) {
      return jsonMatch.group(0)!;
    }
    // Fallback: return default format. 'bump' is deliberately null so the
    // caller reports the version bump as unverified.
    return jsonEncode({
      'libsignal_highlight': '**libsignal $version** — upstream library update',
      'frb_highlight': '**libsignal_frb v$frbVersion** — Rust FFI bindings',
      'changed': content,
      'bump': null,
    });
  }
}

/// Insert the new changelog entry in the correct location
///
/// Strategy:
/// 1. If [Unreleased] section exists, add entry to Highlights and Changed
/// 2. If no [Unreleased] section, create it before first version
String _insertChangelogEntry({
  required String currentChangelog,
  required String nativeHighlight,
  required String frbHighlight,
  required String changed,
  required String version,
}) {
  final lines = currentChangelog.split('\n');

  // Check if [Unreleased] section exists
  final hasUnreleased = lines.any((l) => l.startsWith('## [Unreleased]'));

  if (hasUnreleased) {
    return _insertIntoUnreleased(lines, nativeHighlight, frbHighlight, changed);
  } else {
    return _createUnreleasedSection(
      lines,
      nativeHighlight,
      frbHighlight,
      changed,
    );
  }
}

/// Insert entry into existing [Unreleased] section
String _insertIntoUnreleased(
  List<String> lines,
  String nativeHighlight,
  String frbHighlight,
  String changed,
) {
  final result = <String>[];
  var inUnreleased = false;
  var inForUsers = false;
  var insertedHighlights = false;
  var insertedChanged = false;

  for (var i = 0; i < lines.length; i++) {
    final line = lines[i];

    // Check for ## [Unreleased] section
    if (line.startsWith('## [Unreleased]')) {
      inUnreleased = true;
      result.add(line);
      continue;
    }

    // Check for next version section (end of Unreleased)
    if (inUnreleased &&
        line.startsWith('## [') &&
        !line.contains('Unreleased')) {
      // If we haven't inserted yet, create the structure
      if (!insertedHighlights || !insertedChanged) {
        result.addAll([
          '',
          '### For Users',
          '',
          '#### ✨ Highlights',
          '',
          '- $nativeHighlight',
          '- $frbHighlight',
          '',
          '#### Changed',
          '',
          changed,
          '',
        ]);
        insertedHighlights = true;
        insertedChanged = true;
      }
      inUnreleased = false;
      inForUsers = false;
      result.add(line);
      continue;
    }

    // Check for ### For Users in Unreleased
    if (inUnreleased && line.startsWith('### For Users')) {
      inForUsers = true;
      result.add(line);
      continue;
    }

    // Check for next ### section (end of For Users)
    if (inForUsers && line.startsWith('### ') && !line.contains('For Users')) {
      // If we haven't inserted yet, insert before this section
      if (!insertedHighlights || !insertedChanged) {
        result.addAll([
          '',
          '#### ✨ Highlights',
          '',
          '- $nativeHighlight',
          '- $frbHighlight',
          '',
          '#### Changed',
          '',
          changed,
          '',
        ]);
        insertedHighlights = true;
        insertedChanged = true;
      }
      inForUsers = false;
      result.add(line);
      continue;
    }

    // Check for #### ✨ Highlights in For Users
    if (inForUsers && line.contains('Highlights')) {
      result.add(line);
      result.add('');
      result.add('- $nativeHighlight');
      result.add('- $frbHighlight');
      insertedHighlights = true;
      // Skip the next empty line if present
      if (i + 1 < lines.length && lines[i + 1].trim().isEmpty) {
        i++;
      }
      continue;
    }

    // Check for #### Changed in For Users
    if (inForUsers && line.startsWith('#### Changed')) {
      // If Highlights wasn't found, add it before Changed
      if (!insertedHighlights) {
        result.addAll([
          '',
          '#### ✨ Highlights',
          '',
          '- $nativeHighlight',
          '- $frbHighlight',
          '',
        ]);
        insertedHighlights = true;
      }
      result.addAll([line, '', changed]);
      insertedChanged = true;
      // Skip the next empty line if present
      if (i + 1 < lines.length && lines[i + 1].trim().isEmpty) {
        i++;
      }
      continue;
    }

    result.add(line);
  }

  return result.join('\n');
}

/// Create new [Unreleased] section at the top
String _createUnreleasedSection(
  List<String> lines,
  String nativeHighlight,
  String frbHighlight,
  String changed,
) {
  final result = <String>[];

  // Find the first version line (## [X.Y.Z])
  var insertIndex = 0;
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].startsWith('## [') && !lines[i].contains('Unreleased')) {
      insertIndex = i;
      break;
    }
  }

  // Add lines before first version, Unreleased section, and remaining lines
  result
    ..addAll(lines.sublist(0, insertIndex))
    ..addAll([
      '## [Unreleased]',
      '',
      '### For Users',
      '',
      '#### ✨ Highlights',
      '',
      '- $nativeHighlight',
      '- $frbHighlight',
      '',
      '#### Changed',
      '',
      changed,
      '',
    ])
    ..addAll(lines.sublist(insertIndex));

  return result.join('\n');
}
