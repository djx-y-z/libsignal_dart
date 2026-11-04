// What `make verify-example-coverage` holds the example's integration tests to.
//
// "Every capability of the library" is a claim that stops being true by itself:
// the library gains a function, nobody adds a test, and every check stays green.
// So it is measured. The tests run inside the app with coverage on, and every
// bridged function that reports no executed line fails here. A function can only
// get through by being called, or by a line in [uncalledOnPurpose] saying why not.
//
// Only [verifyExampleCoverage]'s caller touches the disk; everything else takes
// values, so the rules are testable without a coverage run.
library;

/// Bridged functions the tests do not call, and why that is right.
///
/// Keys are what follows `crateApi` in `lib/src/rust/frb_generated.dart`. A name
/// that no longer exists there is reported rather than ignored, so this list
/// cannot quietly outlive what it excuses.
const uncalledOnPurpose = {
  'InitInitLibsignal':
      'lib/src/rust/api/init.dart is not exported by the package.',
  'InitIsLibsignalInitialized':
      'lib/src/rust/api/init.dart is not exported by the package.',
};

/// The share of hand-written lines the tests have to execute. Not a target: the
/// misses that are fine, a `catch` for a library that cannot load and the like,
/// add up to well under this. It is there because a whole new class on top of
/// already-covered bridged functions moves nothing the check above can see.
const handWrittenFloor = 0.95;

/// The generated file holding every bridged function's Dart side.
const generatedBindings = 'lib/src/rust/frb_generated.dart';

/// Executed-line counts per file, from an lcov report.
///
/// File names are normalized to forward slashes and to the part from `lib/` on:
/// flutter_tools writes them relative to the app it ran.
Map<String, Map<int, int>> parseLcov(String lcov) {
  final files = <String, Map<int, int>>{};
  Map<int, int>? current;
  for (final line in lcov.split('\n')) {
    if (line.startsWith('SF:')) {
      final name = line.substring(3).trim().replaceAll(r'\', '/');
      final lib = name.lastIndexOf('lib/');
      final key = lib < 0 ? name : name.substring(lib);
      current = files.putIfAbsent(key, () => {});
    } else if (line.startsWith('DA:') && current != null) {
      final parts = line.substring(3).split(',');
      final number = int.parse(parts[0]);
      current[number] = (current[number] ?? 0) + int.parse(parts[1]);
    }
  }
  return files;
}

/// Each bridged function in [generated] (the text of [generatedBindings]), with
/// the 1-based lines of its body: name → (first, last).
///
/// It goes by `get kCrateApi<Name>ConstMeta`, which the generator writes straight
/// after each body in the implementation class, and walks back to the
/// declaration. Not by the whole `TaskConstMeta get ...`: a long name puts the
/// getter on a line of its own, and those are the callback functions.
Map<String, (int, int)> bridgedFunctions(String generated) {
  final lines = generated.split('\n');
  final implementation = lines.indexWhere(
    (line) => line.startsWith('class RustLibApiImpl'),
  );
  if (implementation < 0) return const {};

  final meta = RegExp(r'\bget kCrateApi(\w+)ConstMeta');
  final functions = <String, (int, int)>{};
  for (var i = implementation; i < lines.length; i++) {
    final match = meta.firstMatch(lines[i]);
    if (match == null) continue;
    final name = match.group(1)!;
    final declaration = RegExp('^  (.* )?crateApi$name\\(');
    for (var start = i - 1; start > implementation; start--) {
      if (declaration.hasMatch(lines[start])) {
        functions[name] = (start + 1, i);
        break;
      }
    }
  }
  return functions;
}

/// Every bridged function [generated] declares, named as [bridgedFunctions]
/// names them: what follows `crateApi` in `abstract class RustLibApi`, which
/// lists each one once.
///
/// The check against [bridgedFunctions]: a body that walk did not find is a
/// function nobody would have measured, and a layout the generator changed for
/// some functions only would otherwise pass over them in silence.
Set<String> declaredBridgedFunctions(String generated) {
  final lines = generated.split('\n');
  final start = lines.indexWhere(
    (line) => line.startsWith('abstract class RustLibApi '),
  );
  if (start < 0) return const {};
  final end = lines.indexWhere((line) => line.startsWith('}'), start + 1);
  final name = RegExp(r'\bcrateApi(\w+)\(');
  return {
    for (final line in lines.sublist(start, end < 0 ? lines.length : end))
      for (final match in name.allMatches(line)) match.group(1)!,
  };
}

/// The verdict on one coverage run.
class ExampleCoverage {
  const ExampleCoverage({
    required this.bridged,
    required this.uncalled,
    required this.unmeasured,
    required this.staleExcuses,
    required this.handWrittenLines,
    required this.handWrittenHit,
  });

  /// How many bridged functions the generated file has.
  final int bridged;

  /// Bridged functions that ran no line and have no excuse.
  final List<String> uncalled;

  /// Bridged functions the generated file declares but whose body this check
  /// did not find, so could not measure.
  final List<String> unmeasured;

  /// Names in [uncalledOnPurpose] the generated file no longer has.
  final List<String> staleExcuses;

  final int handWrittenLines;
  final int handWrittenHit;

  double get handWrittenShare =>
      handWrittenLines == 0 ? 0 : handWrittenHit / handWrittenLines;

  /// What is wrong with this run, one line each; empty when nothing is.
  List<String> get problems => [
    if (bridged == 0)
      'Found no bridged functions in $generatedBindings, so this check read '
          'nothing. Did the generator change how it writes them?',
    for (final name in unmeasured)
      'crateApi$name is declared in $generatedBindings, but this check found no '
          'body to measure it by. Did the generator change how it writes them?',
    for (final name in uncalled)
      'crateApi$name: no integration test calls it. Add one under '
          'example/integration_test/capabilities/, or a line in '
          'uncalledOnPurpose saying why not.',
    for (final name in staleExcuses)
      'uncalledOnPurpose names $name, which $generatedBindings no longer has.',
    if (handWrittenLines == 0)
      'The report has no hand-written lines, so it did not measure the package.'
    else if (handWrittenShare < handWrittenFloor)
      'The tests execute ${_percent(handWrittenShare)} of the hand-written '
          'lines, under the ${_percent(handWrittenFloor)} floor.',
  ];
}

String _percent(double share) => '${(share * 100).toStringAsFixed(1)}%';

/// Judges a coverage report against the generated bindings.
///
/// Files under `lib/src/rust/` are the generator's. `lib/src/platform/` holds one
/// file per platform, so one report can never reach them all.
ExampleCoverage verifyExampleCoverage({
  required String lcov,
  required String generated,
}) {
  final report = parseLcov(lcov);
  final functions = bridgedFunctions(generated);
  final generatedHits = report[generatedBindings] ?? const <int, int>{};

  final uncalled = <String>[];
  functions.forEach((name, range) {
    final (first, last) = range;
    var called = false;
    for (var line = first; line <= last && !called; line++) {
      called = (generatedHits[line] ?? 0) > 0;
    }
    if (!called && !uncalledOnPurpose.containsKey(name)) uncalled.add(name);
  });

  var lines = 0;
  var hit = 0;
  report.forEach((file, hits) {
    if (!file.startsWith('lib/') ||
        file.startsWith('lib/src/rust/') ||
        file.startsWith('lib/src/platform/')) {
      return;
    }
    lines += hits.length;
    hit += hits.values.where((count) => count > 0).length;
  });

  return ExampleCoverage(
    bridged: functions.length,
    uncalled: uncalled,
    unmeasured: [
      for (final name in declaredBridgedFunctions(generated))
        if (!functions.containsKey(name)) name,
    ]..sort(),
    staleExcuses: [
      for (final name in uncalledOnPurpose.keys)
        if (!functions.containsKey(name)) name,
    ],
    handWrittenLines: lines,
    handWrittenHit: hit,
  );
}

/// One line for the log saying what was measured.
String coverageSummary(ExampleCoverage coverage) {
  final called =
      coverage.bridged - coverage.uncalled.length - uncalledOnPurpose.length;
  return '$called of ${coverage.bridged} bridged functions called '
      '(${uncalledOnPurpose.length} excused), '
      '${coverage.handWrittenHit} of ${coverage.handWrittenLines} hand-written '
      'lines executed (${_percent(coverage.handWrittenShare)}).';
}
