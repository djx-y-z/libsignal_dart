/// Update CHANGELOG.md with AI-generated entry for libsignal update
///
/// Uses GitHub Models API (OpenAI-compatible) to analyze release notes
/// and generate appropriate changelog entries.

import 'dart:convert';
import 'dart:io';

import 'common.dart';

/// Update CHANGELOG.md with a new libsignal version entry
Future<void> updateChangelog({
  required String version,
  required String token,
  bool ciMode = false,
}) async {
  final packageDir = getPackageDir();

  // Step 1: Fetch release notes from GitHub
  logStep('Fetching release notes for $version...');
  final releaseNotes = await _fetchReleaseNotes(version);
  logInfo('Got ${releaseNotes.length} characters of release notes');

  // Step 2: Read current CHANGELOG
  logStep('Reading CHANGELOG.md...');
  final changelogFile = File('${packageDir.path}/CHANGELOG.md');
  final currentChangelog = changelogFile.readAsStringSync();

  // Step 3: Analyze with AI
  logStep('Analyzing with GitHub Models AI...');
  final aiResponse = await _generateChangelogEntry(
    version: version,
    releaseNotes: releaseNotes,
    currentChangelog: currentChangelog,
    token: token,
  );

  // Parse AI response
  final parsed = jsonDecode(aiResponse) as Map<String, dynamic>;
  final highlights = parsed['highlights'] as String;
  final changed = parsed['changed'] as String;
  logInfo('Generated highlights: $highlights');
  logInfo('Generated changed entry');

  // Step 4: Update CHANGELOG
  logStep('Updating CHANGELOG.md...');
  final updatedChangelog = _insertChangelogEntry(
    currentChangelog: currentChangelog,
    highlights: highlights,
    changed: changed,
    version: version,
  );

  await changelogFile.writeAsString(updatedChangelog);
  logInfo('CHANGELOG.md updated');
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

/// Generate changelog entry using GitHub Models API
Future<String> _generateChangelogEntry({
  required String version,
  required String releaseNotes,
  required String currentChangelog,
  required String token,
}) async {
  // Extract recent changelog entries for context (first 150 lines)
  final changelogContext = currentChangelog.split('\n').take(150).join('\n');

  final prompt =
      '''
You are updating CHANGELOG.md for a Dart library that wraps libsignal (Signal Protocol).

The library just updated its libsignal native dependency to $version.

## libsignal Release Notes for $version:
$releaseNotes

## Current CHANGELOG.md format (for reference):
$changelogContext

## CHANGELOG Structure:
This project uses the following CHANGELOG structure:
- "### For Users" — changes that affect library users (API, behavior, dependencies)
  - "#### Highlights" — only for major features or breaking changes (rarely used for dependency updates)
  - "#### Added" — new features
  - "#### Changed" — updates to existing functionality (INCLUDING dependency updates like libsignal)
  - "#### Fixed" — bug fixes
  - "#### Security" — security-related changes
- "### For Contributors" — changes that only affect developers (CI, tooling, internal refactoring)

Updating libsignal version goes under "### For Users" with BOTH:
- "#### ✨ Highlights" — a brief one-liner about the update
- "#### Changed" — detailed description with release notes

## Your Task:
Generate a JSON object with TWO fields:
1. "highlights" — a single line for Highlights section (format: "**libsignal vX.Y.Z** — brief description")
2. "changed" — the detailed entry for Changed section

## Example output format:
```json
{
  "highlights": "**libsignal v0.86.15** — latest upstream Signal Protocol library",
  "changed": "- Update libsignal native library to v0.86.15 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.86.15))\n  - SVR2: Updated production enclave\n  - SVRB: Added new production enclave to `current` set\n  - Note: These changes are server-side infrastructure updates, no API changes affect this library"
}
```

## Rules for "highlights":
1. Format: "**libsignal $version** — [brief 3-7 word description]"
2. Keep it very short and scannable
3. Examples: "latest upstream Signal Protocol library", "security fixes and enclave updates", "new backup API support"

## Rules for "changed":
1. Start with "- Update libsignal native library to $version ([release notes](...))
2. Add 2-5 bullet points summarizing key changes from release notes
3. Focus on changes relevant to library users (crypto, protocol, API changes)
4. For internal/server-side changes, add "Note: These changes do not affect this library's API"
5. Use technical but concise language
6. Mention specific components changed (e.g., "chat:", "SVR2:", "Backup:")

Return ONLY valid JSON, no markdown code blocks.
''';

  final requestBody = jsonEncode({
    'model': 'gpt-4o-mini',
    'messages': [
      {'role': 'user', 'content': prompt},
    ],
    'temperature': 0.3,
    'max_tokens': 500,
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

  final choices = response['choices'] as List;
  if (choices.isEmpty) {
    throw Exception('No response from AI');
  }

  final message = choices[0]['message'] as Map<String, dynamic>;
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
    // Fallback: return as changed-only format
    return jsonEncode({
      'highlights': '**libsignal $version** — upstream library update',
      'changed': content,
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
  required String highlights,
  required String changed,
  required String version,
}) {
  final lines = currentChangelog.split('\n');

  // Check if [Unreleased] section exists
  final hasUnreleased = lines.any((l) => l.startsWith('## [Unreleased]'));

  if (hasUnreleased) {
    return _insertIntoUnreleased(lines, highlights, changed);
  } else {
    return _createUnreleasedSection(lines, highlights, changed);
  }
}

/// Insert entry into existing [Unreleased] section
String _insertIntoUnreleased(
  List<String> lines,
  String highlights,
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
          '- $highlights',
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
          '- $highlights',
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
      result.add('- $highlights');
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
        result.addAll(['', '#### ✨ Highlights', '', '- $highlights', '']);
        insertedHighlights = true;
      }
      result.add(line);
      result.add('');
      result.add(changed);
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
  String highlights,
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

  // Add lines before first version
  result.addAll(lines.sublist(0, insertIndex));

  // Add Unreleased section with Highlights and Changed
  result.addAll([
    '## [Unreleased]',
    '',
    '### For Users',
    '',
    '#### ✨ Highlights',
    '',
    '- $highlights',
    '',
    '#### Changed',
    '',
    changed,
    '',
  ]);

  // Add remaining lines
  result.addAll(lines.sublist(insertIndex));

  return result.join('\n');
}
