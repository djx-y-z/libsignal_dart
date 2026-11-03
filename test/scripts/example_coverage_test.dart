import 'dart:io';

import 'package:test/test.dart';

import '../../scripts/src/example_coverage.dart';

/// A generated file with two bridged functions, in the generator's shape.
const _generated = '''
abstract class RustLibApi extends BaseApi {
  void crateApiFooOne();
  Future<void> crateApiFooTwo();
}

class RustLibApiImpl extends RustLibApiImplPlatform implements RustLibApi {
  @override
  void crateApiFooOne() {
    return handler.executeSync(
      SyncTask(),
    );
  }

  TaskConstMeta get kCrateApiFooOneConstMeta =>
      const TaskConstMeta(debugName: "one", argNames: []);

  @override
  Future<CreateResult>
  crateApiFooTwo() {
    return handler.executeNormal(
      NormalTask(),
    );
  }

  TaskConstMeta
  get kCrateApiFooTwoConstMeta =>
      const TaskConstMeta(debugName: "two", argNames: []);
}
''';

String _lcov(Map<String, Map<int, int>> files) => [
  for (final MapEntry(key: file, value: hits) in files.entries) ...[
    'SF:../$file',
    for (final MapEntry(key: line, value: count) in hits.entries)
      'DA:$line,$count',
    'end_of_record',
  ],
].join('\n');

void main() {
  group('parseLcov', () {
    test('takes the name from lib/ on and adds up repeats', () {
      final report = parseLcov(r'''
SF:..\lib\src\a.dart
DA:1,2
DA:1,3
end_of_record
SF:../lib/src/b.dart
DA:4,0
end_of_record
''');
      expect(report['lib/src/a.dart'], {1: 5});
      expect(report['lib/src/b.dart'], {4: 0});
    });
  });

  group('bridgedFunctions', () {
    test('finds each body, also under a return type on its own line', () {
      final functions = bridgedFunctions(_generated);
      expect(functions.keys, ['FooOne', 'FooTwo']);
      expect(functions['FooOne'], (8, 13));
      expect(functions['FooTwo'], (19, 25));
    });

    test('ignores the abstract declarations before the implementation', () {
      expect(
        bridgedFunctions('''
abstract class RustLibApi {
  void crateApiFooOne();
  TaskConstMeta get kCrateApiFooOneConstMeta;
}
'''),
        isEmpty,
      );
    });

    test('the real generated file has them, in this shape', () {
      // A generator that wrote them some other way would leave this check
      // reporting 0 uncalled over nothing it read.
      final functions = bridgedFunctions(
        File(generatedBindings).readAsStringSync(),
      );
      expect(functions.length, greaterThan(100));
      expect(functions, contains('KeysPrivateKeyGenerate'));
      expect(functions, contains('SessionCipherMessageEncryptWithCallbacks'));
    });
  });

  group('declaredBridgedFunctions', () {
    test('reads the abstract class, each name once', () {
      expect(declaredBridgedFunctions(_generated), {'FooOne', 'FooTwo'});
    });

    test('the real generated file declares exactly the bodies found', () {
      // Every function whose body the walk misses would go unmeasured.
      final generated = File(generatedBindings).readAsStringSync();
      expect(
        declaredBridgedFunctions(generated),
        bridgedFunctions(generated).keys.toSet(),
      );
    });
  });

  group('verifyExampleCoverage', () {
    const handWritten = {
      'lib/src/hand.dart': {1: 1, 2: 1},
    };

    ExampleCoverage verdict(Map<String, Map<int, int>> files) =>
        verifyExampleCoverage(lcov: _lcov(files), generated: _generated);

    test('a function with an executed line counts as called', () {
      final coverage = verdict({
        generatedBindings: {9: 1, 22: 3},
        ...handWritten,
      });
      expect(coverage.uncalled, isEmpty);
      expect(coverage.bridged, 2);
    });

    test('a function whose lines all report zero is uncalled', () {
      final coverage = verdict({
        generatedBindings: {9: 1, 22: 0},
        ...handWritten,
      });
      expect(coverage.uncalled, ['FooTwo']);
      expect(coverage.problems.join(), contains('crateApiFooTwo'));
    });

    test('a function missing from the report is uncalled', () {
      final coverage = verdict({
        generatedBindings: {9: 1},
        ...handWritten,
      });
      expect(coverage.uncalled, ['FooTwo']);
    });

    test('a report without the generated file fails on every function', () {
      expect(verdict(handWritten).uncalled, ['FooOne', 'FooTwo']);
    });

    test('generated files and the per-platform files do not count', () {
      final coverage = verdict({
        generatedBindings: {9: 1, 22: 1},
        'lib/src/rust/api/keys.dart': {1: 0},
        'lib/src/platform/platform_io.dart': {1: 0},
        ...handWritten,
      });
      expect(coverage.handWrittenLines, 2);
      expect(coverage.handWrittenHit, 2);
    });

    test('hand-written lines under the floor are a problem', () {
      final coverage = verdict({
        generatedBindings: {9: 1, 22: 1},
        'lib/src/hand.dart': {1: 1, 2: 0},
      });
      expect(coverage.handWrittenShare, 0.5);
      expect(coverage.problems.join(), contains('floor'));
    });

    test('a report that measured no hand-written line is a problem', () {
      final coverage = verdict({
        generatedBindings: {9: 1, 22: 1},
      });
      expect(coverage.problems.join(), contains('did not measure'));
    });

    test('an excuse for a function that is gone is a problem', () {
      final coverage = verifyExampleCoverage(
        lcov: _lcov({
          generatedBindings: {9: 1, 22: 1},
          ...handWritten,
        }),
        generated: _generated,
      );
      expect(coverage.staleExcuses, uncalledOnPurpose.keys);
      expect(coverage.problems.join(), contains('no longer has'));
    });

    test('nothing to read is a problem, not a pass', () {
      final coverage = verifyExampleCoverage(
        lcov: _lcov(handWritten),
        generated: 'class Other {}',
      );
      expect(coverage.problems.join(), contains('read nothing'));
    });

    test('a declared function whose body it cannot find is a problem', () {
      // The generator writing one function in a shape the walk does not know:
      // without the declarations to hold it to, that one would go unmeasured.
      final coverage = verifyExampleCoverage(
        lcov: _lcov({
          generatedBindings: {9: 1},
          ...handWritten,
        }),
        generated: _generated.replaceFirst(
          'get kCrateApiFooTwoConstMeta',
          'get kFooTwoMeta',
        ),
      );
      expect(coverage.bridged, 1);
      expect(coverage.unmeasured, ['FooTwo']);
      expect(coverage.problems.join(), contains('crateApiFooTwo is declared'));
    });
  });

  test('every excuse names a function the bindings still have', () {
    final functions = bridgedFunctions(
      File(generatedBindings).readAsStringSync(),
    );
    expect(functions.keys, containsAll(uncalledOnPurpose.keys));
  });
}
