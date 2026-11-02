// What `flutter drive` runs on the host: it waits for the app to finish
// integration_test/libsignal_test.dart and turns the outcome into an exit code.
// `make test-example-web` and the profile-mode runs go through here.
import 'dart:io';

import 'package:integration_test/integration_test_driver.dart';

Future<void> main() => integrationDriver(
  // The binding counts only `testWidgets`, and a suite that never got to run
  // one reports "all tests passed" with nothing behind it. So the suite's last
  // test leaves this number, and its absence fails the run.
  responseDataCallback: (data) async {
    final capabilities = data?['capabilities'];
    if (capabilities is! int || capabilities < 1) {
      stderr.writeln(
        'The suite passed without reporting that it ran its capabilities '
        '(got: $data).',
      );
      exit(1);
    }
    stdout.writeln('$capabilities capabilities passed.');
  },
);
