import 'package:test/test.dart';

import '../../scripts/src/release_frb.dart';

void main() {
  group('stampFrbHighlight', () {
    test('replaces an existing libsignal_frb highlight in place', () {
      const changelog = '''
## [Unreleased]

### For Users

#### ✨ Highlights

- **libsignal v0.97.3** — internal/dependency update, no public-API impact
- **libsignal_frb v5.1.0** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.97.3

## [6.0.0] - 2026-07-14
''';
      final result = stampFrbHighlight(changelog, '5.2.0');
      expect(result, contains('**libsignal_frb v5.2.0** — Rust FFI bindings'));
      expect(result, isNot(contains('libsignal_frb v5.1.0')));
      // The libsignal highlight is untouched.
      expect(result, contains('**libsignal v0.97.3**'));
    });

    test('inserts after the last highlight when no frb line exists', () {
      const changelog = '''
## [Unreleased]

### For Users

#### ✨ Highlights

- **libsignal v0.97.4** — internal/dependency update, no public-API impact

#### Changed

- Update libsignal native library to v0.97.4

## [6.0.0] - 2026-07-14
''';
      final result = stampFrbHighlight(changelog, '5.2.0');
      final lines = result.split('\n');
      final libsignalIdx = lines.indexWhere(
        (l) => l.contains('**libsignal v0.97.4**'),
      );
      final frbIdx = lines.indexWhere(
        (l) => l.contains('**libsignal_frb v5.2.0**'),
      );
      expect(libsignalIdx, greaterThanOrEqualTo(0));
      expect(
        frbIdx,
        equals(libsignalIdx + 1),
        reason: 'frb line should follow the libsignal highlight',
      );
      // Did not leak into the released section.
      final releasedIdx = lines.indexWhere((l) => l.startsWith('## [6.0.0]'));
      expect(frbIdx, lessThan(releasedIdx));
    });

    test('creates an [Unreleased] section when none exists', () {
      const changelog = '''
# Changelog

## [6.0.0] - 2026-07-14

### For Users

- something
''';
      final result = stampFrbHighlight(changelog, '5.2.0');
      expect(result, contains('## [Unreleased]'));
      expect(result, contains('#### ✨ Highlights'));
      expect(result, contains('**libsignal_frb v5.2.0** — Rust FFI bindings'));
      // Unreleased must come before the first released version.
      final lines = result.split('\n');
      expect(
        lines.indexWhere((l) => l.startsWith('## [Unreleased]')),
        lessThan(lines.indexWhere((l) => l.startsWith('## [6.0.0]'))),
      );
    });

    test('is idempotent across repeated runs (replace, not duplicate)', () {
      const changelog = '''
## [Unreleased]

### For Users

#### ✨ Highlights

- **libsignal v0.97.4** — internal/dependency update, no public-API impact

## [6.0.0] - 2026-07-14
''';
      final once = stampFrbHighlight(changelog, '5.2.0');
      final twice = stampFrbHighlight(once, '5.2.0');
      final count = '**libsignal_frb v5.2.0**'.allMatches(twice).length;
      expect(count, equals(1), reason: 'must not accumulate duplicate lines');
    });
  });
}
