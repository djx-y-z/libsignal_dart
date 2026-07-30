// Update CHANGELOG.md with AI-generated entry for a libsignal dependency
// update.
//
// Uses GitHub Models API (OpenAI-compatible) to analyze the release notes and
// the upstream commit list and generate a changelog entry that matches this
// project's house style.
//
// NOTE: This step does NOT touch the `libsignal_frb` crate version. The crate
// version is bumped as a deliberate release step (`make release-frb`), which
// also stamps the `libsignal_frb vX.Y.Z` Highlights line. The automatic update
// PR only records the libsignal dependency change (libsignal Highlight +
// Changed entry).
library;

import 'dart:convert';
import 'dart:io';

import 'common.dart';

/// Update CHANGELOG.md with a new libsignal version entry.
Future<void> updateChangelog({
  required String version,
  required String token,
  String? fromVersion,
  bool ciMode = false,
}) async {
  final packageDir = getPackageDir();

  // Step 1: Fetch release notes from GitHub.
  logStep('Fetching release notes for $version...');
  final releaseNotes = await _fetchReleaseNotes(version);
  logInfo('Got ${releaseNotes.length} characters of release notes');

  // Step 2: Fetch the actual commit list between the two tags — release notes
  // alone are often terse, which produced incomplete changelog entries.
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

  // Step 3: Read current CHANGELOG.
  logStep('Reading CHANGELOG.md...');
  final changelogFile = File('${packageDir.path}/CHANGELOG.md');
  final currentChangelog = changelogFile.readAsStringSync();

  // Step 4: Analyze with AI.
  logStep('Analyzing with GitHub Models AI...');
  final aiResponse = await _generateChangelogEntry(
    version: version,
    fromVersion: fromVersion,
    releaseNotes: releaseNotes,
    upstreamCommits: upstreamCommits,
    currentChangelog: currentChangelog,
    token: token,
  );

  // Parse AI response.
  final parsed = jsonDecode(aiResponse) as Map<String, dynamic>;
  final nativeHighlight = parsed['libsignal_highlight'] as String;
  final changed = parsed['changed'] as String;
  logInfo('Generated libsignal highlight: $nativeHighlight');
  logInfo('Generated changed entry');

  // Step 5: Update CHANGELOG.
  logStep('Updating CHANGELOG.md...');
  final updatedChangelog = insertChangelogEntry(
    currentChangelog: currentChangelog,
    nativeHighlight: nativeHighlight,
    changed: changed,
  );

  await changelogFile.writeAsString(updatedChangelog);
  logInfo('CHANGELOG.md updated');
}

/// Fetch release notes from the GitHub API.
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

/// Generate changelog entry using the GitHub Models API.
Future<String> _generateChangelogEntry({
  required String version,
  required String? fromVersion,
  required String releaseNotes,
  required String upstreamCommits,
  required String currentChangelog,
  required String token,
}) async {
  // Extract recent changelog entries for context (first 150 lines).
  final changelogContext = currentChangelog.split('\n').take(150).join('\n');

  // Prefer a compare link (the release notes are often incomplete); fall back
  // to the release-notes link when the previous version is unknown.
  final sourceLink = fromVersion != null && fromVersion != version
      ? '[compare](https://github.com/signalapp/libsignal/compare/$fromVersion...$version)'
      : '[release notes](https://github.com/signalapp/libsignal/releases/tag/$version)';

  final prompt =
      '''
You are updating CHANGELOG.md for **libsignal_dart**, a Dart package that wraps
a SUBSET of libsignal via Flutter Rust Bridge. It just updated its libsignal
native dependency to $version.

## What this library actually binds and exposes (CRITICAL for classification)
This wrapper builds ONLY these upstream crates and exposes ONLY the Signal
Protocol primitives on top of them:
- Crates bound: `libsignal-protocol`, `libsignal-core`, `signal-crypto`
- Exposed surface: identity / pre / signed-pre / Kyber keys, X3DH session
  establishment, Double Ratchet encrypt/decrypt, sealed sender, group messaging
  (SenderKey), and serialization of the above.

It does NOT bind or expose the following — treat any change here as INVISIBLE to
this package's users (never present it as a feature/change of this package):
- networking / chat / websocket transport (`libsignal-net`)
- key transparency (keytrans)
- username services (e.g. `AuthUsernamesService`)
- zkgroup, profile keys, credentials
- SVR / secure value recovery, registration, CDSI, backups
- language bindings for Swift / Java / Node, and CLI / bridge / codegen / CI
  tooling

## libsignal release notes for $version:
$releaseNotes
${upstreamCommits.isEmpty ? '' : '''

## Upstream commits included in this update (first lines):
$upstreamCommits

Use BOTH the release notes and the commit list — release notes are often
incomplete, and the commit list shows what actually changed.'''}

## Current CHANGELOG.md (match this house style exactly):
$changelogContext

## Your task
Return a JSON object with EXACTLY two string fields:
1. "libsignal_highlight" — a single Highlights line for libsignal.
2. "changed" — the "#### Changed" entry.

## Rules for "libsignal_highlight"
1. Format exactly: "**libsignal $version** — <brief 3-7 word description>".
2. If nothing in this update touches our exposed surface (the common case), use:
   "**libsignal $version** — internal/dependency update, no public-API impact".

## Rules for "changed" (THIS IS THE IMPORTANT PART — match the house style)
1. First line exactly: "- Update libsignal native library to $version ($sourceLink)".
2. Classify EVERY upstream change against the bind list above:
   - Changes OUTSIDE our exposed surface (net/chat/keytrans/username/zkgroup/
     Swift-Java-Node/tooling/CI): do NOT give them their own feature bullets.
     Summarize them together in ONE bullet that ends with
     "— none of which this library exposes".
   - Only changes to the crates we bind that affect our exposed API get their
     own bullets. Prefix breaking ones with "**BREAKING:**".
3. When the crates we bind had no API-affecting change, say so explicitly, e.g.
   "The crates we bind (`libsignal-protocol`, `signal-crypto`, `libsignal-core`)
   are unchanged apart from version strings".
4. End with "Note: These changes do not affect this library's public API" when
   true.
5. Judge relevance from the release notes AND the commit list, NOT from the
   version numbers.

## Example output (house style — follow this SHAPE):
```json
{
  "libsignal_highlight": "**libsignal v0.97.3** — internal/dependency update, no public-API impact",
  "changed": "- Update libsignal native library to v0.97.3 ([compare](https://github.com/signalapp/libsignal/compare/v0.97.2...v0.97.3))\\n  - Upstream changes are limited to username services, a chat transport error reclassification, and a key-transparency clock-skew tolerance — none of which this library exposes\\n  - The crates we bind (`libsignal-protocol`, `signal-crypto`, `libsignal-core`) are unchanged apart from version strings\\n  - Note: These changes do not affect this library's public API"
}
```

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

  // Parse JSON response.
  try {
    final parsed = jsonDecode(content) as Map<String, dynamic>;
    return jsonEncode(parsed); // Return normalized JSON.
  } catch (e) {
    // If AI didn't return valid JSON, try to extract it.
    final jsonMatch = RegExp(r'\{[\s\S]*\}').firstMatch(content);
    if (jsonMatch != null) {
      return jsonMatch.group(0)!;
    }
    // Fallback: minimal entry from the raw content.
    return jsonEncode({
      'libsignal_highlight':
          '**libsignal $version** — internal/dependency update, '
          'no public-API impact',
      'changed': content,
    });
  }
}

/// Insert the new changelog entry in the correct location. Pure; exposed for
/// testing.
///
/// Strategy:
/// 1. If [Unreleased] section exists, add entry to Highlights and Changed,
///    creating whichever are missing. A missing `### For Users` is created at the
///    top of the section, ahead of any `### For Contributors`, matching the order
///    of the released sections; missing subsections are placed by the same rule
///    inside it (Highlights → Changed (Breaking) → Changed → Security → Fixed).
///    `#### Changed` is matched exactly — `#### Changed (Breaking)` is a
///    different subsection and never receives the entry.
/// 2. If no [Unreleased] section, create it before first version (this is the
///    normal path after a release, which no longer leaves an empty
///    `## [Unreleased]` behind).
String insertChangelogEntry({
  required String currentChangelog,
  required String nativeHighlight,
  required String changed,
}) {
  final lines = currentChangelog.split('\n');

  final hasUnreleased = lines.any((l) => l.startsWith('## [Unreleased]'));

  if (hasUnreleased) {
    return _insertIntoUnreleased(lines, nativeHighlight, changed);
  } else {
    return _createUnreleasedSection(lines, nativeHighlight, changed);
  }
}

/// Insert entry into an existing [Unreleased] section.
String _insertIntoUnreleased(
  List<String> lines,
  String nativeHighlight,
  String changed,
) {
  final result = <String>[];
  var inUnreleased = false;
  var inForUsers = false;
  var insertedHighlights = false;
  var insertedChanged = false;
  // Index of the `## [Unreleased]` heading within [result], so a missing
  // `### For Users` can be spliced at the top of the section, not the bottom.
  var unreleasedIdx = -1;
  // Index of the `### For Users` heading within [result], so a missing
  // `#### ✨ Highlights` can be spliced at the top of that block.
  var forUsersIdx = -1;
  // Where a missing `#### Changed` belongs: just before the first For Users
  // subsection that follows it in the documented order. -1 until one is seen,
  // in which case the flush falls back to the end of the block.
  var changedAnchorIdx = -1;

  // The end of what has been emitted so far, backed up over trailing blanks so
  // an insertion there keeps the blank line separating it from what follows.
  int trimmedEnd() {
    var at = result.length;
    while (at > 0 && result[at - 1].trim().isEmpty) {
      at--;
    }
    return at;
  }

  // Splice whichever subsection is still missing into the existing
  // `### For Users` block. The later index goes first: inserting at the top of
  // the block would shift `changedAnchorIdx` out from under the second insert.
  void flushForUsers() {
    if (!insertedChanged) {
      final at = changedAnchorIdx >= 0 ? changedAnchorIdx : trimmedEnd();
      result.insertAll(at, ['', '#### Changed', '', changed]);
      insertedChanged = true;
    }
    if (!insertedHighlights) {
      result.insertAll(forUsersIdx + 1, [
        '',
        '#### ✨ Highlights',
        '',
        '- $nativeHighlight',
      ]);
      insertedHighlights = true;
    }
  }

  for (var i = 0; i < lines.length; i++) {
    final line = lines[i];

    // Check for ## [Unreleased] section.
    if (line.startsWith('## [Unreleased]')) {
      inUnreleased = true;
      result.add(line);
      unreleasedIdx = result.length - 1;
      continue;
    }

    // Check for next version section (end of Unreleased).
    if (inUnreleased &&
        line.startsWith('## [') &&
        !line.contains('Unreleased')) {
      // If we haven't inserted yet, create the structure.
      if (!insertedHighlights || !insertedChanged) {
        if (forUsersIdx >= 0) {
          // A `### For Users` heading exists and runs to the end of the
          // section, so only its missing subsections have to be created.
          // Adding another `### For Users` would duplicate the heading.
          flushForUsers();
        } else {
          // No `### For Users` anywhere in [Unreleased]. Create it at the TOP of
          // the section rather than here at the bottom: appending would file a
          // user-facing entry below every existing subsection (`### For
          // Contributors`), and every released section puts For Users first.
          result.insertAll(unreleasedIdx + 1, [
            '',
            '### For Users',
            '',
            '#### ✨ Highlights',
            '',
            '- $nativeHighlight',
            '',
            '#### Changed',
            '',
            changed,
          ]);
          insertedHighlights = true;
          insertedChanged = true;
        }
      }
      inUnreleased = false;
      inForUsers = false;
      result.add(line);
      continue;
    }

    // Check for ### For Users in Unreleased.
    if (inUnreleased && line.startsWith('### For Users')) {
      inForUsers = true;
      result.add(line);
      forUsersIdx = result.length - 1;
      continue;
    }

    // Check for next ### section (end of For Users).
    if (inForUsers && line.startsWith('### ') && !line.contains('For Users')) {
      // If we haven't inserted yet, insert before this section.
      if (!insertedHighlights || !insertedChanged) {
        flushForUsers();
      }
      inForUsers = false;
      result.add(line);
      continue;
    }

    // Check for #### ✨ Highlights in For Users.
    if (inForUsers && line.contains('Highlights')) {
      result.add(line);
      result.add('');
      result.add('- $nativeHighlight');
      insertedHighlights = true;
      // Skip the next empty line if present.
      if (i + 1 < lines.length && lines[i + 1].trim().isEmpty) {
        i++;
      }
      continue;
    }

    // Check for #### Changed in For Users. Matched exactly, because
    // `#### Changed (Breaking)` is a different subsection: filing a routine
    // native-library bump under it would announce it as a breaking change. A
    // missing `#### ✨ Highlights` is NOT created here — the flush puts it at
    // the top of the block, which is where the documented order wants it even
    // when `#### Changed` is preceded by the breaking one.
    if (inForUsers && line.trimRight() == '#### Changed') {
      result.addAll([line, '', changed]);
      insertedChanged = true;
      // Skip the next empty line if present.
      if (i + 1 < lines.length && lines[i + 1].trim().isEmpty) {
        i++;
      }
      continue;
    }

    // Any other `####` heading inside For Users (`#### Security`,
    // `#### Fixed`, …) follows `#### Changed` in the documented order, so a
    // `#### Changed` that has to be created belongs just before the first of
    // them. `#### Changed (Breaking)` precedes it and so does not anchor.
    if (inForUsers &&
        !insertedChanged &&
        changedAnchorIdx < 0 &&
        line.startsWith('#### ') &&
        !line.startsWith('#### Changed (')) {
      changedAnchorIdx = trimmedEnd();
    }

    result.add(line);
  }

  return result.join('\n');
}

/// Create a new [Unreleased] section at the top.
String _createUnreleasedSection(
  List<String> lines,
  String nativeHighlight,
  String changed,
) {
  final result = <String>[];

  // Find the first version line (## [X.Y.Z]).
  var insertIndex = 0;
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].startsWith('## [') && !lines[i].contains('Unreleased')) {
      insertIndex = i;
      break;
    }
  }

  // Add lines before first version, Unreleased section, and remaining lines.
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
      '',
      '#### Changed',
      '',
      changed,
      '',
    ])
    ..addAll(lines.sublist(insertIndex));

  return result.join('\n');
}
