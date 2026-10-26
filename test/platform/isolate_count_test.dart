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
///
/// The child is the bare VM (`--disable-dart-dev`), not `dart run`: `dart run`
/// runs the build hooks and copies the hooked library into .dart_tool/lib/
/// again, over the file this test runner has loaded. On Linux the copy
/// truncates a library mapped into the runner, which dies of SIGBUS in
/// whichever suite touches it next; on Windows the loaded DLL cannot be
/// replaced and the child fails. The bare VM runs no hooks, and the child
/// loads the copy the runner's own hook run left in .dart_tool/lib/, by the
/// search `LibSignal.init` makes.
Future<String> verdictOf(String scenario) async {
  final run = await Process.run(Platform.resolvedExecutable, [
    '--disable-dart-dev',
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
