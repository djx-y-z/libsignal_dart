// What `make test-example-ci` decides after each run of the example's
// integration tests: whether a test failed, or the run never got far enough to
// say.
//
// An emulator, a simulator, the connection to them and the network fail now and
// then, and a run they end proves nothing about the package either way. A test
// that fails proves something every time. So a run is judged on what the app
// reported, and never on how the command ended:
//
// - `flutter test` writes each test's outcome to a JSON file
//   (`--file-reporter json:<file>`). A test that ran in the app and failed there
//   has an `error` event of its own. A test the app never finished, because the
//   app, the device or the connection went away, is only marked done ("did not
//   complete"), with no error. Loading the suite, which builds, installs and
//   connects to the app, is a test of its own named `loading <file>`, and its
//   failure is never one of the package's tests: "Error waiting for a debug
//   connection" on a simulator is that test running out of its 12 minutes.
// - `flutter drive` reports nothing per test, so the driver,
//   `example/test_driver/integration_test.dart`, prints [reportedLine] when the
//   app hands its results over, whether they passed or not.
// - An app that crashed has failed, whatever else the run says: a native crash
//   ends the app like a device that went away does, and only the platform's own
//   crash record tells the two apart. Android keeps it in the device's crash
//   log, macOS in a report on the host, for a simulator's app too.
//
// Measured with Flutter 3.38.4 on macOS: a run that passed, a capability that
// failed, and an app that exited in the middle of the suite; and in CI, an iOS
// simulator the app never connected to.
//
// Only the script runs anything; everything here takes values.
library;

import 'dart:convert';

/// What one run of the tests came to.
enum Verdict {
  /// Every test passed.
  passed,

  /// A test failed in the app, or the app crashed. That is the package's doing
  /// or the tests', and a run that ends like this is never run again.
  failed,

  /// No test failed, and the run did not finish: the app never got to the
  /// tests, or it, the device or the connection went away. Run it again.
  unfinished,
}

/// The line the driver prints when the app has handed its results over.
///
/// `example/test_driver/integration_test.dart` prints the same text. It is a
/// package of its own, so a test reads that file to keep the two the same.
const reportedLine = 'The app handed its results over.';

/// One run, judged.
class RunOutcome {
  const RunOutcome(this.verdict, {this.failedTests = const [], this.reason});

  final Verdict verdict;

  /// The tests that failed in the app, in the order they ran.
  final List<String> failedTests;

  /// Why the run failed or did not finish, when no failed test says it.
  final String? reason;

  /// One line for the log.
  String describe() => switch (verdict) {
    Verdict.passed => 'Every test passed.',
    Verdict.failed when failedTests.isNotEmpty =>
      'Failed in the app: ${failedTests.join('; ')}.',
    Verdict.failed => 'Failed: ${reason ?? 'see the log above'}.',
    Verdict.unfinished =>
      'No test failed, and the run did not finish: '
          '${reason ?? 'see the log above'}.',
  };
}

/// Judges a `flutter test` run by its exit code and the JSON its file reporter
/// wrote, [results]: null when it wrote none. [crashed] is the platform's own
/// record that the app crashed.
RunOutcome judgeTestRun({
  required int exitCode,
  required String? results,
  bool crashed = false,
}) {
  final names = <Object, String>{};
  final failed = <String>[];
  var passed = 0;
  var suitePassed = false;
  String? loadingError;

  for (final line in const LineSplitter().convert(results ?? '')) {
    final Object? event;
    try {
      event = jsonDecode(line);
    } on FormatException {
      // A run that was killed can leave half a line at the end.
      continue;
    }
    switch (event) {
      case {
        'type': 'testStart',
        'test': {'id': final Object id, 'name': final String name},
      }:
        names[id] = name;
      // Not matched on its `error` field: an error event without one is still
      // a failed test, and must not read as a run that did not finish.
      case {'type': 'error', 'testID': final Object id}:
        final name = names[id];
        if (name == null) break;
        if (_isLoading(name)) {
          loadingError ??= _firstLine((event as Map<String, Object?>)['error']);
        } else if (!failed.contains(name)) {
          failed.add(name);
        }
      case {
        'type': 'testDone',
        'testID': final Object id,
        'result': 'success',
        'hidden': false,
      }:
        if (names[id] case final name? when !_isLoading(name)) passed++;
      case {'type': 'done', 'success': true}:
        suitePassed = true;
    }
  }

  if (exitCode == 0) return const RunOutcome(Verdict.passed);
  if (failed.isNotEmpty) {
    return RunOutcome(Verdict.failed, failedTests: failed);
  }
  if (crashed) {
    return const RunOutcome(Verdict.failed, reason: 'the app crashed');
  }

  final started = names.values.where((name) => !_isLoading(name)).length;
  return RunOutcome(
    Verdict.unfinished,
    reason: switch ((loadingError, started)) {
      (final String error, _) => 'the app never got to the tests: $error',
      (null, 0) =>
        'no test started (the build, the install, the launch or the '
            'connection)',
      _ when suitePassed => 'every test passed, and flutter failed after them',
      _ => 'the app stopped answering after $passed passed tests',
    },
  );
}

/// Judges a `flutter drive` run by its exit code and what it printed,
/// [output]. [crashed] is the platform's own record that the app crashed.
RunOutcome judgeDriveRun({
  required int exitCode,
  required String output,
  bool crashed = false,
}) {
  if (exitCode == 0) return const RunOutcome(Verdict.passed);
  final reported = const LineSplitter()
      .convert(output)
      .any((line) => line.trim() == reportedLine);
  if (reported) {
    return const RunOutcome(
      Verdict.failed,
      reason:
          'the app handed its results over, and the driver printed the '
          'failures above',
    );
  }
  if (crashed) {
    return const RunOutcome(Verdict.failed, reason: 'the app crashed');
  }
  return const RunOutcome(
    Verdict.unfinished,
    reason: 'the app never handed its results over',
  );
}

/// The application id an Android app's `android/app/build.gradle.kts`, or
/// `build.gradle`, gives it.
String? androidApplicationId(String gradle) => RegExp(
  r'''applicationId\s*=?\s*["']([\w.]+)["']''',
).firstMatch(gradle)?.group(1);

/// Whether Android's crash log, `adb logcat -b crash -d`, holds a crash of the
/// app [applicationId]. A Java crash names it as `Process: <id>, PID: …`, a
/// native one as `>>> <id> <<<`.
bool crashedOnAndroid(String crashLog, String applicationId) {
  final id = RegExp.escape(applicationId);
  return RegExp('Process: $id[,\\s]|>>> $id <<<').hasMatch(crashLog);
}

/// The bundle ids an iOS app's `ios/Runner.xcodeproj/project.pbxproj` gives
/// its targets: the app's, and its tests'.
Set<String> iosBundleIds(String pbxproj) => {
  for (final match in RegExp(
    r'PRODUCT_BUNDLE_IDENTIFIER = "?([\w.-]+)"?;',
  ).allMatches(pbxproj))
    match.group(1)!,
};

/// Whether a crash report macOS wrote, `~/Library/Logs/DiagnosticReports/*.ips`,
/// is of an app with one of [bundleIds] in a simulator. The first line of the
/// report is a JSON header, `{"app_name":"Runner",…,"platform":7,"bundleID":…}`,
/// platform 7 being the iOS simulator. macOS writes it for a simulator app too,
/// measured: a native abort in the example on an iOS 26.2 simulator, half a
/// minute after `flutter test` had given up on the app.
bool crashedOnSimulator(String report, Set<String> bundleIds) {
  final header = const LineSplitter().convert(report).firstOrNull;
  if (header == null) return false;
  try {
    return switch (jsonDecode(header)) {
      {'bundleID': final String id, 'platform': 7} => bundleIds.contains(id),
      _ => false,
    };
  } on FormatException {
    return false;
  }
}

bool _isLoading(String name) => name.startsWith('loading ');

String? _firstLine(Object? text) =>
    text is String ? const LineSplitter().convert(text).firstOrNull : null;
