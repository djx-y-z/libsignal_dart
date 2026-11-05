/// Run the example's integration tests the way CI does: judge each run on what
/// the app reported, fail at once on a test that failed, and run again, up to
/// `--attempts`, only when a run never got that far. See
/// `scripts/src/example_run.dart`.
///
/// Usage: make test-example-ci ARGS="[options] -- <arguments for flutter>"
///
///   --drive             Under `flutter drive` (`make drive-example`), the way to
///                       run them in profile mode. Otherwise `flutter test`.
///   --attempts <n>      How many runs in all, at most. 1 by default.
///   --simulator <udid>  The tests run on this iOS simulator: after a run that
///                       did not finish, look for a crash report of the app,
///                       and reboot the simulator before the third run and each
///                       one after it.
///   --android <serial>  The tests run on this Android device: after a run that
///                       did not finish, read its crash log. An app that
///                       crashed has failed, whatever else the run says.
///   --verify=<args>     After a run that passed, `make verify-example-library
///                       ARGS="<args>"`. A run that loaded the wrong library
///                       has failed.
///   --verdict <file>    Write the last run's verdict there: passed, failed or
///                       unfinished, for a caller that runs it again itself.
///                       `unfinished` goes in first, so a run that was killed
///                       leaves that; `failed` goes in as soon as a test has
///                       failed, so a run killed after that leaves `failed`.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'src/example_run.dart';

Future<void> main(List<String> args) async {
  final split = args.indexOf('--');
  final options = split < 0 ? args : args.sublist(0, split);
  final flutterArgs = split < 0 ? const <String>[] : args.sublist(split + 1);

  const valued = {
    '--attempts',
    '--simulator',
    '--android',
    '--verdict',
    '--dir',
  };
  final values = <String, String>{};
  var drive = false;
  String? verify;
  for (var i = 0; i < options.length; i++) {
    final option = options[i];
    if (option == '--drive') {
      drive = true;
    } else if (option.startsWith('--verify=')) {
      verify = option.substring('--verify='.length);
    } else if (valued.contains(option) && i + 1 < options.length) {
      values[option] = options[++i];
    } else {
      _usage('Not an option here, or one without its value: $option');
    }
  }
  final attempts = int.tryParse(values['--attempts'] ?? '1');
  if (attempts == null || attempts < 1) {
    _usage('--attempts takes a whole number from 1.');
  }

  final verdict = values['--verdict'];
  final simulator = values['--simulator'];
  void record(Verdict value) => _writeVerdict(verdict, value);

  final run = _Run(
    app: values['--dir'] ?? 'example',
    flutterArgs: flutterArgs,
    drive: drive,
    android: values['--android'],
    simulator: simulator,
    verify: verify,
    results: Directory.systemTemp.createTempSync('example-run-'),
    record: record,
  );

  final outcome = await runAttempts(
    attempts: attempts,
    record: record,
    beforeRetry: (attempt) async {
      // What ended the run before, the network above all, is often over by now.
      await Future<void>.delayed(const Duration(seconds: 30));
      if (simulator != null && attempt >= 3) await _reboot(simulator);
    },
    run: (attempt) {
      stdout.writeln(
        '\nRun $attempt of $attempts, under flutter ${drive ? 'drive' : 'test'}: '
        '${flutterArgs.join(' ')}',
      );
      return run.once(attempt);
    },
    onUnfinished: (attempt, outcome) {
      // An error only for a single run: after several, the one below sums
      // them up, and with --verdict the caller decides.
      _annotate(
        attempts > 1 || verdict != null ? 'warning' : 'error',
        'Run $attempt of $attempts: ${outcome.describe()}'
        '${attempt < attempts ? ' Running the tests again.' : ''}',
      );
    },
  );
  switch (outcome.verdict) {
    case Verdict.passed:
      stdout.writeln(outcome.describe());
      exit(0);
    case Verdict.failed:
      // Once on the run's page: the run may have said it while it went.
      if (run.failureAnnounced) {
        stdout.writeln(outcome.describe());
      } else {
        _annotate(
          'error',
          '${outcome.describe()} A test that fails is not run again.',
        );
      }
      exit(1);
    case Verdict.unfinished:
      if (verdict == null && attempts > 1) {
        _annotate(
          'error',
          'None of the $attempts runs finished, and no test failed in any of '
              'them: the device, the connection or the runner. The log of each '
              'says why.',
        );
      }
      exit(1);
  }
}

class _Run {
  _Run({
    required this.app,
    required this.flutterArgs,
    required this.drive,
    required this.android,
    required this.simulator,
    required this.verify,
    required this.results,
    required this.record,
  });

  final String app;
  final List<String> flutterArgs;
  final bool drive;
  final String? android;
  final String? simulator;
  final String? verify;
  final Directory results;

  /// Writes the verdict down for a caller that runs the tests again itself.
  final void Function(Verdict verdict) record;

  /// Whether a run has already said, while it went, that a test failed.
  bool failureAnnounced = false;

  Future<RunOutcome> once(int attempt) async {
    final started = DateTime.now();
    final (code, judge) = drive ? await _drive() : await _test(attempt);
    // Before anything slow, which a time limit could cut short: a test that
    // failed is the verdict, whatever comes after.
    if (judge(false).verdict == Verdict.failed) record(Verdict.failed);
    if (code != 0 && android != null) await _printAndroidLog(android!);
    final library = verify;
    return settleRun(
      judge,
      crashed: () => _crashed(started),
      verify: library == null
          ? null
          : () async => await _make('verify-example-library', [library]) == 0,
    );
  }

  Future<(int, RunOutcome Function(bool crashed))> _test(int attempt) async {
    final file = File('${results.absolute.path}/run-$attempt.json');
    if (file.existsSync()) file.deleteSync();
    // CI stops a try that runs out of time without asking it, and one stopped
    // after a test had failed must not read as one that did not finish. So the
    // results are read while the run goes, and a failure recorded at once.
    final watch = Timer.periodic(const Duration(seconds: 2), (_) {
      if (failureAnnounced) return;
      final failed = failedSoFar(_read(file) ?? '');
      if (failed.isEmpty) return;
      record(Verdict.failed);
      failureAnnounced = true;
      _annotate(
        'error',
        'Failed in the app: ${failed.join('; ')}. A test that fails is not run '
            'again; this run goes on to its end.',
      );
    });
    final int code;
    try {
      code = await _make('test-example', [
        ...flutterArgs,
        '--file-reporter',
        'json:${file.path}',
      ]);
    } finally {
      watch.cancel();
    }
    final text = _read(file);
    return (
      code,
      (bool crashed) =>
          judgeTestRun(exitCode: code, results: text, crashed: crashed),
    );
  }

  Future<(int, RunOutcome Function(bool crashed))> _drive() async {
    final process = await Process.start(
      'make',
      makeArguments('drive-example', app: app, args: flutterArgs),
    );
    final output = StringBuffer();
    const decoder = Utf8Decoder(allowMalformed: true);
    final copied = [
      process.stdout.transform(decoder).forEach((text) {
        stdout.write(text);
        output.write(text);
      }),
      process.stderr.transform(decoder).forEach((text) {
        stderr.write(text);
        output.write(text);
      }),
    ];
    final code = await process.exitCode;
    await Future.wait(copied);
    final text = output.toString();
    return (
      code,
      (bool crashed) =>
          judgeDriveRun(exitCode: code, output: text, crashed: crashed),
    );
  }

  Future<int> _make(String target, List<String> args) async {
    final process = await Process.start(
      'make',
      makeArguments(target, app: app, args: args),
      mode: ProcessStartMode.inheritStdio,
    );
    return process.exitCode;
  }

  /// Whether the platform recorded a crash of the app since [since].
  Future<bool> _crashed(DateTime since) async {
    if (android case final serial?) return _crashedOnAndroid(serial);
    if (simulator != null) return _crashedOnSimulator(since);
    return false;
  }

  /// Android's crash log starts empty with each emulator, so whatever it holds
  /// of the app is this try's.
  Future<bool> _crashedOnAndroid(String serial) async {
    final gradle = ['build.gradle.kts', 'build.gradle']
        .map((name) => File('$app/android/app/$name'))
        .where((f) => f.existsSync());
    final id = gradle.isEmpty
        ? null
        : androidApplicationId(gradle.first.readAsStringSync());
    if (id == null) {
      stderr.writeln(
        'No application id in $app/android/app/: no crash log read.',
      );
      return false;
    }
    try {
      final result = await Process.run('adb', [
        '-s',
        serial,
        'logcat',
        '-b',
        'crash',
        '-d',
      ]).timeout(const Duration(minutes: 1));
      // A device that went away has no log to read, and no crash to show.
      if (result.exitCode != 0) return false;
      final log = result.stdout as String;
      if (!crashedOnAndroid(log, id)) return false;
      stdout.writeln('The crash log names $id:\n$log');
      return true;
    } on Object catch (e) {
      stderr.writeln('Could not read the crash log: $e');
      return false;
    }
  }

  /// macOS writes a simulator app's crash report on the host, and takes its
  /// time: measured, half a minute after `flutter test` had given up on the
  /// app. So this waits up to a minute and a half for one, which only a run that
  /// did not finish pays.
  Future<bool> _crashedOnSimulator(DateTime since) async {
    final pbxproj = File('$app/ios/Runner.xcodeproj/project.pbxproj');
    final ids = pbxproj.existsSync()
        ? iosBundleIds(pbxproj.readAsStringSync())
        : const <String>{};
    final home = Platform.environment['HOME'];
    if (ids.isEmpty || home == null) {
      stderr.writeln('No bundle id in $app/ios/: no crash report looked for.');
      return false;
    }
    final reports = Directory('$home/Library/Logs/DiagnosticReports');
    stdout.writeln('Looking for a crash report of ${ids.join(' or ')}.');
    final deadline = DateTime.now().add(const Duration(seconds: 90));
    while (true) {
      if (reports.existsSync()) {
        for (final entry in reports.listSync()) {
          if (entry is! File || !entry.path.endsWith('.ips')) continue;
          final String report;
          try {
            // A second of slack: the file system's clock and this one may not
            // agree to the millisecond.
            final written = entry.lastModifiedSync();
            if (written.isBefore(since.subtract(const Duration(seconds: 1)))) {
              continue;
            }
            report = entry.readAsStringSync();
          } on FileSystemException {
            // Gone, or moved aside, since the listing.
            continue;
          }
          if (crashedOnSimulator(report, ids)) {
            stdout.writeln('The app crashed: ${entry.path}');
            return true;
          }
        }
      }
      if (DateTime.now().isAfter(deadline)) return false;
      await Future<void>.delayed(const Duration(seconds: 5));
    }
  }
}

/// The end of the device's log, for whoever reads why the run failed.
Future<void> _printAndroidLog(String serial) async {
  final process = await Process.start('adb', [
    '-s',
    serial,
    'logcat',
    '-d',
    '-t',
    '500',
    '*:W',
  ], mode: ProcessStartMode.inheritStdio);
  await process.exitCode.timeout(
    const Duration(minutes: 1),
    onTimeout: () {
      process.kill();
      return -1;
    },
  );
}

Future<void> _reboot(String udid) async {
  stdout.writeln('Rebooting the simulator $udid first.');
  // Fails when it is already shut down, which is fine.
  await Process.run('xcrun', ['simctl', 'shutdown', udid]);
  for (final command in ['boot', 'bootstatus']) {
    final process = await Process.start('xcrun', [
      'simctl',
      command,
      udid,
    ], mode: ProcessStartMode.inheritStdio);
    final code = await process.exitCode;
    if (code != 0) stderr.writeln('xcrun simctl $command exited $code.');
  }
}

void _writeVerdict(String? path, Verdict verdict) {
  if (path != null) File(path).writeAsStringSync('${verdict.name}\n');
}

/// What [file] holds, or null when it is not there. A file still being written
/// can end in the middle of a character: decoded leniently, it ends in half a
/// line, which the judge skips like any other.
String? _read(File file) {
  try {
    return utf8.decode(file.readAsBytesSync(), allowMalformed: true);
  } on FileSystemException {
    return null;
  }
}

/// A message GitHub shows on the run, or a plain line anywhere else.
void _annotate(String level, String message) {
  if (Platform.environment['GITHUB_ACTIONS'] == 'true') {
    final escaped = message
        .replaceAll('%', '%25')
        .replaceAll('\r', '%0D')
        .replaceAll('\n', '%0A');
    stdout.writeln('::$level::$escaped');
  } else {
    (level == 'error' ? stderr : stdout).writeln(message);
  }
}

Never _usage(String problem) {
  stderr.writeln(problem);
  stderr.writeln(
    'Usage: make test-example-ci ARGS="[--drive] [--attempts <n>] '
    '[--simulator <udid>] [--android <serial>] [--verify=<args>] '
    '[--verdict <file>] -- <arguments for flutter>"',
  );
  exit(2);
}
