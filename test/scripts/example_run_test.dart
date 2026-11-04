import 'dart:io';

import 'package:test/test.dart';

import '../../scripts/src/example_run.dart';

// `flutter test --file-reporter json:` output from real runs of the example on
// macOS with Flutter 3.38.4, cut down to a few tests, the paths shortened.
const _start = '''
{"protocolVersion":"0.1.1","runnerVersion":null,"pid":55455,"type":"start","time":0}
{"suite":{"id":0,"platform":"vm","path":"/repo/example/integration_test/libsignal_test.dart"},"type":"suite","time":0}
{"test":{"id":1,"name":"loading /repo/example/integration_test/libsignal_test.dart","suiteID":0,"groupIDs":[],"metadata":{"skip":false,"skipReason":null},"line":null,"column":null,"url":null},"type":"testStart","time":0}
{"count":1,"time":5,"type":"allSuites"}
''';

const _loaded = '''
{"testID":1,"result":"success","skipped":false,"hidden":true,"type":"testDone","time":21025}
{"test":{"id":4,"name":"LibSignal init is idempotent and survives cleanup","suiteID":0,"groupIDs":[2,3],"metadata":{"skip":false,"skipReason":null},"line":174,"column":5,"url":"package:flutter_test/src/widget_tester.dart","root_line":39,"root_column":3,"root_url":"file:///repo/example/integration_test/libsignal_test.dart"},"type":"testStart","time":21025}
{"testID":4,"result":"success","skipped":false,"hidden":false,"type":"testDone","time":21329}
''';

// Every test passed.
const _passed =
    '''
$_start$_loaded{"test":{"id":6,"name":"keys X25519 agreement matches RFC 7748 section 6.1","suiteID":0,"groupIDs":[2,5],"metadata":{"skip":false,"skipReason":null},"line":174,"column":5,"url":"package:flutter_test/src/widget_tester.dart","root_line":40,"root_column":3,"root_url":"file:///repo/example/integration_test/libsignal_test.dart"},"type":"testStart","time":21329}
{"testID":6,"result":"success","skipped":false,"hidden":false,"type":"testDone","time":21348}
{"test":{"id":77,"name":"(tearDownAll)","suiteID":0,"groupIDs":[2],"metadata":{"skip":false,"skipReason":null},"line":50,"column":5,"url":"package:integration_test/integration_test.dart"},"type":"testStart","time":23835}
{"testID":77,"result":"success","skipped":false,"hidden":true,"type":"testDone","time":23837}
{"success":true,"type":"done","time":23848}
''';

// A capability failed an `expect`, and the next one exited the app: the first
// has an error of its own, the second and the rest only "did not complete".
const _failedInApp =
    '''
$_start$_loaded{"test":{"id":5,"name":"a capability that fails","suiteID":0,"groupIDs":[2],"metadata":{"skip":false,"skipReason":null},"line":174,"column":5,"url":"package:flutter_test/src/widget_tester.dart","root_line":43,"root_column":3,"root_url":"file:///repo/example/integration_test/libsignal_test.dart"},"type":"testStart","time":33591}
{"testID":5,"error":"Test failed. See exception logs above.\\nThe test description was: a capability that fails","stackTrace":"","isFailure":false,"type":"error","time":33685}
{"testID":5,"result":"error","skipped":false,"hidden":false,"type":"testDone","time":33686}
{"test":{"id":6,"name":"the app exits","suiteID":0,"groupIDs":[2],"metadata":{"skip":false,"skipReason":null},"line":174,"column":5,"url":"package:flutter_test/src/widget_tester.dart","root_line":46,"root_column":3,"root_url":"file:///repo/example/integration_test/libsignal_test.dart"},"type":"testStart","time":33686}
{"testID":6,"result":"error","skipped":false,"hidden":false,"type":"testDone","time":33719}
{"test":{"id":79,"name":"(tearDownAll)","suiteID":0,"groupIDs":[2],"metadata":{"skip":false,"skipReason":null},"line":50,"column":5,"url":"package:integration_test/integration_test.dart"},"type":"testStart","time":33740}
{"testID":79,"result":"error","skipped":false,"hidden":false,"type":"testDone","time":33740}
{"success":false,"type":"done","time":33745}
''';

// A capability exited the app, and nothing failed before it: the tests after
// it are marked done, none with an error.
const _appWentAway =
    '''
$_start$_loaded{"test":{"id":5,"name":"the app exits","suiteID":0,"groupIDs":[2],"metadata":{"skip":false,"skipReason":null},"line":174,"column":5,"url":"package:flutter_test/src/widget_tester.dart","root_line":43,"root_column":3,"root_url":"file:///repo/example/integration_test/libsignal_test.dart"},"type":"testStart","time":22510}
{"testID":5,"result":"error","skipped":false,"hidden":false,"type":"testDone","time":22540}
{"test":{"id":7,"name":"keys X25519 agreement matches RFC 7748 section 6.1","suiteID":0,"groupIDs":[2,6],"metadata":{"skip":false,"skipReason":null},"line":174,"column":5,"url":"package:flutter_test/src/widget_tester.dart","root_line":46,"root_column":3,"root_url":"file:///repo/example/integration_test/libsignal_test.dart"},"type":"testStart","time":22545}
{"testID":7,"result":"error","skipped":false,"hidden":false,"type":"testDone","time":22545}
{"success":false,"type":"done","time":22575}
''';

// The app never connected. Written from the log of an iOS simulator run in CI
// (GitHub's reporter there, so the shape is the protocol's): the loading test
// failed after its 12 minutes, and no test of the suite started.
const _neverConnected =
    '''
$_start{"testID":1,"error":"TimeoutException after 0:12:00.000000: Test timed out after 12 minutes.","stackTrace":"package:test_api/src/backend/invoker.dart 362:28  Invoker._handleError.<fn>","isFailure":false,"type":"error","time":720010}
{"testID":1,"result":"error","skipped":false,"hidden":false,"type":"testDone","time":720011}
{"success":false,"type":"done","time":720020}
''';

void main() {
  group('judgeTestRun', () {
    test('a run that exited 0 passed', () {
      final outcome = judgeTestRun(exitCode: 0, results: _passed);
      expect(outcome.verdict, Verdict.passed);
    });

    test('a test that failed in the app fails the run, and is named', () {
      final outcome = judgeTestRun(exitCode: 1, results: _failedInApp);
      expect(outcome.verdict, Verdict.failed);
      // Not the test the app died in: it did not fail, it did not complete.
      expect(outcome.failedTests, ['a capability that fails']);
      expect(outcome.describe(), contains('a capability that fails'));
    });

    test('an app that went away before any test failed did not finish', () {
      final outcome = judgeTestRun(exitCode: 1, results: _appWentAway);
      expect(outcome.verdict, Verdict.unfinished);
      expect(outcome.failedTests, isEmpty);
      expect(outcome.reason, contains('after 1 passed tests'));
    });

    test('an app that never connected did not finish, and says why', () {
      final outcome = judgeTestRun(exitCode: 1, results: _neverConnected);
      expect(outcome.verdict, Verdict.unfinished);
      expect(
        outcome.reason,
        'the app never got to the tests: TimeoutException after '
        '0:12:00.000000: Test timed out after 12 minutes.',
      );
    });

    test('a run with no results file did not finish', () {
      final outcome = judgeTestRun(exitCode: 1, results: null);
      expect(outcome.verdict, Verdict.unfinished);
      expect(outcome.reason, startsWith('no test started'));
    });

    test('a half-written last line is skipped, not fatal', () {
      final outcome = judgeTestRun(
        exitCode: 1,
        results: '$_failedInApp{"testID":7,"res',
      );
      expect(outcome.verdict, Verdict.failed);
      expect(outcome.failedTests, ['a capability that fails']);
    });

    test('a crash fails a run in which no test failed', () {
      final outcome = judgeTestRun(
        exitCode: 1,
        results: _appWentAway,
        crashed: true,
      );
      expect(outcome.verdict, Verdict.failed);
      expect(outcome.reason, 'the app crashed');
    });

    test('an error event without its text is still a failed test', () {
      final results = _appWentAway.replaceFirst(
        '{"testID":7,"result":"error"',
        '{"testID":7,"type":"error","time":22544}\n'
            '{"testID":7,"result":"error"',
      );
      final outcome = judgeTestRun(exitCode: 1, results: results);
      expect(outcome.verdict, Verdict.failed);
      expect(outcome.failedTests, [
        'keys X25519 agreement matches RFC 7748 section 6.1',
      ]);
    });

    test('every test passed and the command failed after them: unfinished', () {
      final outcome = judgeTestRun(exitCode: 1, results: _passed);
      expect(outcome.verdict, Verdict.unfinished);
      expect(outcome.reason, contains('every test passed'));
    });
  });

  group('judgeDriveRun', () {
    test('a run that exited 0 passed', () {
      expect(judgeDriveRun(exitCode: 0, output: '').verdict, Verdict.passed);
    });

    test('the app handed over a failure: failed', () {
      final outcome = judgeDriveRun(
        exitCode: 1,
        output: 'Failure Details:\n...\n$reportedLine\r\nThe suite did not...',
      );
      expect(outcome.verdict, Verdict.failed);
    });

    test('the app never handed anything over: unfinished', () {
      final outcome = judgeDriveRun(
        exitCode: 1,
        output: 'Error waiting for a debug connection: The log reader stopped',
      );
      expect(outcome.verdict, Verdict.unfinished);
    });

    test('a crash fails it all the same', () {
      final outcome = judgeDriveRun(exitCode: 1, output: '', crashed: true);
      expect(outcome.verdict, Verdict.failed);
      expect(outcome.reason, 'the app crashed');
    });

    test('the driver prints the very line this looks for', () {
      final driver = File(
        'example/test_driver/integration_test.dart',
      ).readAsStringSync();
      expect(driver, contains("stdout.writeln('$reportedLine');"));
      expect(driver, contains('writeResponseOnFailure: true'));
    });
  });

  group('makeArguments', () {
    test('runs the target on the Flutter already first on PATH, not fvm', () {
      expect(
        makeArguments(
          'test-example',
          app: 'build/consumer',
          args: ['-d', 'emulator-5554', '--file-reporter', 'json:/t/r.json'],
        ),
        [
          'FVM=',
          'test-example',
          'EXAMPLE_DIR=build/consumer',
          'ARGS=-d emulator-5554 --file-reporter json:/t/r.json',
        ],
      );
    });
  });

  group('Android', () {
    test('reads the application id of the example', () {
      final gradle = File(
        'example/android/app/build.gradle.kts',
      ).readAsStringSync();
      expect(androidApplicationId(gradle), 'com.libsignal.example');
    });

    test('reads a Groovy build file too', () {
      expect(
        androidApplicationId('    applicationId "com.example.app"\n'),
        'com.example.app',
      );
    });

    test('finds a Java crash of the app', () {
      const log =
          '--------- beginning of crash\n'
          'E AndroidRuntime: FATAL EXCEPTION: main\n'
          'E AndroidRuntime: Process: com.libsignal.example, PID: 4321\n';
      expect(crashedOnAndroid(log, 'com.libsignal.example'), isTrue);
    });

    test('finds a native crash of the app', () {
      const log =
          'F DEBUG   : pid: 4321, tid: 4350, name: 1.ui  '
          '>>> com.libsignal.example <<<\n';
      expect(crashedOnAndroid(log, 'com.libsignal.example'), isTrue);
    });

    test('ignores a crash of another app, one with a longer id included', () {
      const log =
          'E AndroidRuntime: Process: com.android.systemui, PID: 99\n'
          'E AndroidRuntime: Process: com.libsignal.example2, PID: 98\n'
          'F DEBUG   : pid: 97, name: x  >>> com.libsignal.example2 <<<\n';
      expect(crashedOnAndroid(log, 'com.libsignal.example'), isFalse);
    });
  });

  group('iOS simulator', () {
    // The first line of the report macOS wrote when the example aborted on an
    // iOS 26.2 simulator.
    const header =
        '{"app_name":"Runner","timestamp":"2026-11-03 17:48:46.00 +0100","app_version":"1.0.0","sroute_id":16,"slice_uuid":"3e711a9d-7318-399a-9745-6b99c85e47bc","build_version":"1","platform":7,"bundleID":"com.libsignal.example","share_with_app_devs":0,"is_first_party":0,"bug_type":"309","os_version":"macOS 26.5 (25F71)","roots_installed":0,"name":"Runner","incident_id":"E8E1F9E4-82EC-4E6A-91BD-4024ACDF7C5B"}';

    test('reads the bundle ids of the example', () {
      final pbxproj = File(
        'example/ios/Runner.xcodeproj/project.pbxproj',
      ).readAsStringSync();
      expect(
        iosBundleIds(pbxproj),
        containsAll([
          'com.libsignal.example',
          'com.libsignal.example.RunnerTests',
        ]),
      );
    });

    test('finds a crash of the app in a simulator', () {
      expect(
        crashedOnSimulator('$header\n{\n  "uptime" : 2500000,', {
          'com.libsignal.example',
        }),
        isTrue,
      );
    });

    test('ignores another app, the same app on the Mac, and noise', () {
      const ids = {'com.libsignal.example'};
      expect(
        crashedOnSimulator(
          header.replaceFirst('com.libsignal.example', 'com.apple.Maps'),
          ids,
        ),
        isFalse,
      );
      expect(
        crashedOnSimulator(
          header.replaceFirst('"platform":7', '"platform":1'),
          ids,
        ),
        isFalse,
      );
      expect(crashedOnSimulator('', ids), isFalse);
      expect(crashedOnSimulator('not json\n', ids), isFalse);
    });
  });
}
