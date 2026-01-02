/// AI-powered analysis of libsignal release notes
///
/// Uses GitHub Models API (GPT-4o) to analyze release notes and recommend:
/// - Version bump type (major/minor/patch)
/// - Breaking changes
/// - Changelog entries

import 'dart:convert';
import 'dart:io';

import 'common.dart';

/// Result of AI analysis
class AiAnalysisResult {
  final String versionBump;
  final String breakingChanges;
  final String newFeatures;
  final String securityNotes;
  final String bindingChanges;
  final String changelogEntry;
  final String? modelUsed;

  AiAnalysisResult({
    required this.versionBump,
    required this.breakingChanges,
    required this.newFeatures,
    required this.securityNotes,
    required this.bindingChanges,
    required this.changelogEntry,
    this.modelUsed,
  });

  /// Default result when AI is unavailable
  factory AiAnalysisResult.defaultResult(String newVersion) {
    return AiAnalysisResult(
      versionBump: 'minor',
      breakingChanges: 'Unable to analyze automatically',
      newFeatures: 'none',
      securityNotes: 'none',
      bindingChanges: 'unknown',
      changelogEntry: '- Updated libsignal native library to $newVersion',
      modelUsed: null,
    );
  }

  Map<String, dynamic> toJson() => {
    'version_bump': versionBump,
    'breaking_changes': breakingChanges,
    'new_features': newFeatures,
    'security_notes': securityNotes,
    'binding_changes': bindingChanges,
    'changelog_entry': changelogEntry,
    'model_used': modelUsed,
  };
}

/// GitHub Models API endpoint
const _githubModelsEndpoint =
    'https://models.github.ai/inference/chat/completions';

/// Available models (in order of preference)
const _primaryModel = 'openai/gpt-4o';
const _fallbackModel = 'openai/gpt-4o-mini';

/// Maximum characters for release notes (to fit in context)
const _maxReleaseNotesLength = 6000;

/// Analyze release notes using AI
///
/// Returns null if AI is unavailable or analysis fails.
/// [token] is the GitHub token for API access.
/// [releaseNotes] is the content of the release notes.
/// [currentVersion] and [newVersion] are version strings.
/// [silent] suppresses log output.
Future<AiAnalysisResult?> analyzeReleaseNotes({
  required String token,
  required String releaseNotes,
  required String currentVersion,
  required String newVersion,
  bool silent = false,
}) async {
  if (token.isEmpty) {
    if (!silent) {
      logWarning('No GitHub token provided, skipping AI analysis');
    }
    return null;
  }

  // Load prompt template
  final prompt = await _loadPrompt(currentVersion, newVersion, releaseNotes);
  if (prompt == null) {
    if (!silent) {
      logWarning('Could not load AI prompt template');
    }
    return null;
  }

  // Try primary model first, then fallback
  for (final model in [_primaryModel, _fallbackModel]) {
    if (!silent) {
      logStep('Trying AI model: $model');
    }

    final result = await _callModel(
      token: token,
      model: model,
      prompt: prompt,
      silent: silent,
    );

    if (result != null) {
      if (!silent) {
        logInfo('AI analysis completed with $model');
      }
      return result;
    }

    if (!silent) {
      logWarning('Model $model failed, trying next...');
    }
  }

  if (!silent) {
    logWarning('All AI models failed');
  }
  return null;
}

/// Load and prepare the prompt template
Future<String?> _loadPrompt(
  String currentVersion,
  String newVersion,
  String releaseNotes,
) async {
  final packageDir = getPackageDir();
  final promptFile = File(
    '${packageDir.path}/.github/prompts/ai-analysis-prompt.md',
  );

  String template;
  if (await promptFile.exists()) {
    template = await promptFile.readAsString();
  } else {
    // Fallback to embedded prompt
    template = _defaultPromptTemplate;
  }

  // Truncate release notes if too long
  var truncatedNotes = releaseNotes;
  if (truncatedNotes.length > _maxReleaseNotesLength) {
    truncatedNotes =
        '${truncatedNotes.substring(0, _maxReleaseNotesLength)}...';
  }

  // Replace placeholders
  return template
      .replaceAll('CURRENT_VERSION', currentVersion)
      .replaceAll('NEW_VERSION', newVersion)
      .replaceAll('RELEASE_NOTES_CONTENT', truncatedNotes);
}

/// Call the AI model API
Future<AiAnalysisResult?> _callModel({
  required String token,
  required String model,
  required String prompt,
  bool silent = false,
}) async {
  try {
    final client = HttpClient();

    try {
      final request = await client.postUrl(Uri.parse(_githubModelsEndpoint));
      request.headers.set('Authorization', 'Bearer $token');
      request.headers.set('Content-Type', 'application/json');

      final body = jsonEncode({
        'model': model,
        'messages': [
          {
            'role': 'system',
            'content':
                'You are a precise technical analyst. Your task is to '
                'analyze software release notes and extract ONLY factual '
                'information. Never invent or assume information not present '
                'in the source. When uncertain, be conservative and explicit '
                'about uncertainty. Follow the exact response format requested.',
          },
          {'role': 'user', 'content': prompt},
        ],
        'max_tokens': 2500,
        'temperature': 0.1,
      });

      request.write(body);
      final response = await request.close();

      if (response.statusCode != 200) {
        if (!silent) {
          logWarning('AI API returned status ${response.statusCode}');
        }
        return null;
      }

      final responseBody = await response.transform(utf8.decoder).join();
      final json = jsonDecode(responseBody) as Map<String, dynamic>;

      final choices = json['choices'] as List?;
      if (choices == null || choices.isEmpty) {
        return null;
      }

      final content = choices[0]['message']['content'] as String?;
      if (content == null || content.isEmpty) {
        return null;
      }

      return _parseAiResponse(content, model);
    } finally {
      client.close();
    }
  } catch (e) {
    if (!silent) {
      logWarning('AI API error: $e');
    }
    return null;
  }
}

/// Parse the AI response into structured data
AiAnalysisResult? _parseAiResponse(String content, String model) {
  try {
    // Extract fields using regex
    String extractField(String name, {String defaultValue = 'none'}) {
      final match = RegExp(
        '$name:\\s*(.+)',
        caseSensitive: false,
      ).firstMatch(content);
      return match?.group(1)?.trim() ?? defaultValue;
    }

    // Extract changelog entry (everything after CHANGELOG_ENTRY:)
    String extractChangelog() {
      final match = RegExp(
        r'CHANGELOG_ENTRY:\s*([\s\S]*?)(?=\n[A-Z_]+:|$)',
      ).firstMatch(content);
      if (match != null) {
        return match.group(1)?.trim() ?? '';
      }

      // Fallback: get everything after CHANGELOG_ENTRY:
      final lines = content.split('\n');
      final startIndex = lines.indexWhere(
        (l) => l.trim().startsWith('CHANGELOG_ENTRY:'),
      );
      if (startIndex == -1) return '';

      final changelogLines = <String>[];
      for (var i = startIndex + 1; i < lines.length; i++) {
        final line = lines[i];
        // Stop at next field or empty section
        if (RegExp(r'^[A-Z_]+:').hasMatch(line.trim())) break;
        if (line.trim().startsWith('-')) {
          changelogLines.add(line.trim());
        }
      }
      return changelogLines.join('\n');
    }

    final versionBump = extractField(
      'VERSION_BUMP',
      defaultValue: 'minor',
    ).toLowerCase();

    // Validate version bump
    final validBumps = ['major', 'minor', 'patch'];
    final normalizedBump = validBumps.contains(versionBump)
        ? versionBump
        : 'minor';

    return AiAnalysisResult(
      versionBump: normalizedBump,
      breakingChanges: extractField('BREAKING_CHANGES'),
      newFeatures: extractField('NEW_FEATURES'),
      securityNotes: extractField('SECURITY_NOTES'),
      bindingChanges: extractField('BINDING_CHANGES'),
      changelogEntry: extractChangelog(),
      modelUsed: model,
    );
  } catch (e) {
    return null;
  }
}

/// Default prompt template (used if file not found)
const _defaultPromptTemplate = '''
# Task: Analyze libsignal Release Notes

You are analyzing release notes for libsignal (Signal Protocol library).

## Version Information

- Current libsignal: CURRENT_VERSION
- New libsignal: NEW_VERSION

## Release Notes

```
RELEASE_NOTES_CONTENT
```

## Version Bump Rules

- **major**: Breaking API changes, removed functions, struct changes
- **minor**: New features that don't break existing code
- **patch**: Bug fixes, performance improvements, security patches

## Response Format

VERSION_BUMP: [major|minor|patch]
BREAKING_CHANGES: [list or "none"]
NEW_FEATURES: [list or "none"]
SECURITY_NOTES: [list or "none"]
BINDING_CHANGES: [yes|no] - [explanation]
CHANGELOG_ENTRY:
- [First bullet point]
- [Second bullet point if applicable]
''';
