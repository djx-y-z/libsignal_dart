import 'package:test/test.dart';

import '../../scripts/src/release.dart';

/// A CHANGELOG shaped like the real one: an `[Unreleased]` section with
/// in-progress content, two released sections, and compare links at the bottom.
const _changelog = '''
# Changelog

## [Unreleased]

### For Users

#### ✨ Highlights

- **libsignal v0.97.3** — internal/dependency update, no public-API impact

#### Changed

- Update libsignal native library to v0.97.3

## [6.0.0] - 2026-07-14

### For Users

- Identity-trust enforcement

## [5.0.9] - 2026-06-01

- Older release

[Unreleased]: https://github.com/djx-y-z/libsignal_dart/compare/v6.0.0...HEAD
[6.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.9...v6.0.0
[5.0.9]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.8...v5.0.9
''';

const _repoUrl = 'https://github.com/djx-y-z/libsignal_dart';

/// Index of the line that starts with [prefix]; -1 if none.
int _lineStarting(String content, String prefix) =>
    content.split('\n').indexWhere((l) => l.startsWith(prefix));

void main() {
  group('finalizeChangelog', () {
    test('renames [Unreleased] to the dated version heading', () {
      final result = finalizeChangelog(
        _changelog,
        version: '6.1.0',
        date: '2026-07-16',
      );
      expect(result, contains('## [6.1.0] - 2026-07-16'));
    });

    test('leaves a fresh empty [Unreleased] above the new version', () {
      final result = finalizeChangelog(
        _changelog,
        version: '6.1.0',
        date: '2026-07-16',
      );

      // Exactly one Unreleased heading remains.
      expect('## [Unreleased]'.allMatches(result).length, equals(1));

      final lines = result.split('\n');
      final unreleasedIdx = lines.indexWhere(
        (l) => l.startsWith('## [Unreleased]'),
      );
      final versionIdx = lines.indexWhere((l) => l.startsWith('## [6.1.0]'));
      // Unreleased comes first and is empty (only blank lines up to [6.1.0]).
      expect(unreleasedIdx, lessThan(versionIdx));
      final between = lines
          .sublist(unreleasedIdx + 1, versionIdx)
          .where((l) => l.trim().isNotEmpty);
      expect(between, isEmpty, reason: 'the new [Unreleased] must be empty');
    });

    test('moves in-progress content under the released heading', () {
      final result = finalizeChangelog(
        _changelog,
        version: '6.1.0',
        date: '2026-07-16',
      );
      final lines = result.split('\n');
      final versionIdx = lines.indexWhere((l) => l.startsWith('## [6.1.0]'));
      final prevIdx = lines.indexWhere((l) => l.startsWith('## [6.0.0]'));
      final highlightIdx = lines.indexWhere(
        (l) => l.contains('**libsignal v0.97.3**'),
      );
      // The formerly-unreleased highlight now sits inside the [6.1.0] section.
      expect(highlightIdx, greaterThan(versionIdx));
      expect(highlightIdx, lessThan(prevIdx));
    });

    test('rewrites the [Unreleased] compare link to the new version', () {
      final result = finalizeChangelog(
        _changelog,
        version: '6.1.0',
        date: '2026-07-16',
      );
      expect(result, contains('[Unreleased]: $_repoUrl/compare/v6.1.0...HEAD'));
      expect(
        result,
        isNot(contains('/compare/v6.0.0...HEAD')),
        reason: 'the old Unreleased range must be replaced',
      );
    });

    test('inserts the new version compare link spanning previous...new', () {
      final result = finalizeChangelog(
        _changelog,
        version: '6.1.0',
        date: '2026-07-16',
      );
      expect(result, contains('[6.1.0]: $_repoUrl/compare/v6.0.0...v6.1.0'));
      // The new link sits directly under the Unreleased link.
      final unreleasedLinkIdx = _lineStarting(result, '[Unreleased]:');
      final newLinkIdx = _lineStarting(result, '[6.1.0]:');
      expect(newLinkIdx, equals(unreleasedLinkIdx + 1));
    });

    test('derives the base URL and previous version from the link, not a '
        'hardcoded slug', () {
      const forked = '''
## [Unreleased]

- pending

## [2.0.0] - 2026-01-01

- prior

[Unreleased]: https://example.com/acme/widget/compare/v2.0.0...HEAD
[2.0.0]: https://example.com/acme/widget/compare/v1.9.0...v2.0.0
''';
      final result = finalizeChangelog(
        forked,
        version: '2.1.0',
        date: '2026-02-02',
      );
      expect(
        result,
        contains(
          '[Unreleased]: https://example.com/acme/widget/compare/v2.1.0...HEAD',
        ),
      );
      expect(
        result,
        contains(
          '[2.1.0]: https://example.com/acme/widget/compare/v2.0.0...v2.1.0',
        ),
      );
    });

    test('keeps the version heading awk-extractable and the [Unreleased] '
        'heading skipped', () {
      // publish.yml extracts the release notes with an awk pattern that keys on
      // `^## \\[?[0-9]...`: the dated version heading must match, and the fresh
      // empty [Unreleased] must NOT (else it would swallow the extraction).
      final result = finalizeChangelog(
        _changelog,
        version: '6.1.0',
        date: '2026-07-16',
      );
      final versionHeadings = result
          .split('\n')
          .where((l) => RegExp(r'^## \[?[0-9]+\.[0-9]+\.[0-9]+\]?').hasMatch(l))
          .toList();
      expect(versionHeadings, contains('## [6.1.0] - 2026-07-16'));
      expect(versionHeadings.any((l) => l.contains('Unreleased')), isFalse);
    });

    test('throws when there is no [Unreleased] heading', () {
      const noUnreleased = '''
## [6.0.0] - 2026-07-14

- something

[6.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.9...v6.0.0
''';
      expect(
        () => finalizeChangelog(noUnreleased, version: '6.1.0', date: 'x'),
        throwsA(isA<Exception>()),
      );
    });

    test('throws when there is no [Unreleased] compare link', () {
      const noLink = '''
## [Unreleased]

- pending

## [6.0.0] - 2026-07-14

- something
''';
      expect(
        () => finalizeChangelog(noLink, version: '6.1.0', date: '2026-07-16'),
        throwsA(isA<Exception>()),
      );
    });

    test(
      'throws when the version is already finalized (no double-finalize)',
      () {
        final once = finalizeChangelog(
          _changelog,
          version: '6.1.0',
          date: '2026-07-16',
        );
        expect(
          () => finalizeChangelog(once, version: '6.1.0', date: '2026-07-16'),
          throwsA(isA<Exception>()),
        );
      },
    );

    test('throws on a non X.Y.Z version', () {
      expect(
        () => finalizeChangelog(_changelog, version: 'v6.1', date: 'x'),
        throwsA(isA<Exception>()),
      );
    });
  });
}
