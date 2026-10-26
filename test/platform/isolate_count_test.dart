// Every isolate that initializes libsignal must stay counted in the native
// library for as long as it lives: one that is not loses every async answer
// as soon as the last counted isolate shuts down (`countIsolateInLibrary` in
// lib/src/platform/platform_io.dart). Both ways flutter_rust_bridge 2.13.0
// leaves an isolate out are reproduced here.
//
// Each scenario runs in a child process (isolate_count_scenarios.dart, which
// says why), so this file only reads verdicts and never touches the library's
// process-wide state itself.
@TestOn('vm')
library;

import 'dart:io';

import 'package:test/test.dart';

/// Runs [scenario] in a child process and returns the verdict it printed.
Future<String> verdictOf(String scenario) async {
  final run = await Process.run(Platform.resolvedExecutable, [
    'run',
    'test/platform/isolate_count_scenarios.dart',
    scenario,
  ], workingDirectory: Directory.current.path);
  final out = run.stdout as String;
  final verdict = RegExp(
    r'verdict: (.*)$',
    multiLine: true,
  ).allMatches(out).map((m) => m.group(1)!.trim()).lastOrNull;
  if (run.exitCode != 0 || verdict == null) {
    fail(
      'scenario $scenario exited ${run.exitCode}\n'
      'stdout:\n$out\nstderr:\n${run.stderr}',
    );
  }
  return verdict;
}

void expectAnswered(String verdict) {
  if (verdict.startsWith('SKIP')) {
    markTestSkipped(verdict);
    return;
  }
  expect(verdict, startsWith('OK'));
}

void main() {
  test(
    'a worker that initializes only libsignal and exits leaves the main '
    'isolate answered, though another FRB library was initialized first',
    () async => expectAnswered(await verdictOf('second-library')),
    timeout: const Timeout(Duration(minutes: 3)),
  );

  test(
    'an isolate initializing while another keeps counting to zero is '
    'counted before the post function is installed',
    () async => expectAnswered(await verdictOf('init-race')),
    timeout: const Timeout(Duration(minutes: 3)),
  );
}
