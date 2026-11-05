import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:libsignal/libsignal.dart';

int _declared = 0;
int _ran = 0;

/// How long one capability may take, measured inside its body.
const capabilityTimeout = Duration(minutes: 3);

/// Runs [body], and fails the test that runs it when [body] takes longer than
/// [limit].
///
/// Inside the body, as well as in `testWidgets(timeout:)`, because the two are
/// not the same failure. test_api's timeout ends the test from outside: under
/// `flutter drive` the host reads the binding's results, which that never
/// reaches, so the slow test is missing from the failures, and the body goes on
/// and can still count itself as having run. Thrown in here, it is the test's own
/// failure, on every runner.
Future<void> withinLimit(Duration limit, Future<void> Function() body) =>
    body().timeout(
      limit,
      onTimeout: () => throw TestFailure('Took longer than $limit.'),
    );

/// Declares one capability of the library, checked inside this running app.
///
/// `testWidgets` rather than `test`, and that is not a style choice. Under
/// `flutter drive` — the only way to run this suite on the web — the result the
/// host reads holds `testWidgets` outcomes only, so a plain `test` could fail
/// there with the run still green.
///
/// For the same reason it initializes here rather than in `setUpAll`: a
/// `setUpAll` that throws under `flutter drive` leaves no failure and no tests
/// behind, and the host reads that as success.
void capability(String description, Future<void> Function() body) {
  _declared++;
  testWidgets(
    description,
    (tester) async {
      await withinLimit(capabilityTimeout, () async {
        await LibSignal.init();
        await body();
      });
      _ran++;
    },
    // A backstop only: the limit above fires first.
    timeout: Timeout(capabilityTimeout * 2),
  );
}

/// Whether this build carries [capabilityThatHangs]: only one asked for by
/// `gh workflow run integration.yml -f hang=true`.
const hangOnPurpose = bool.fromEnvironment('LIBSIGNAL_EXAMPLE_HANG');

/// How long [capabilityThatHangs] blocks the app: past the 8 minutes the
/// watchdog of `make test-example-ci` waits (`stallLimit` in
/// `scripts/src/example_run.dart`), so that it is the watchdog that ends it.
const hangFor = Duration(minutes: 12);

/// Declares a capability that blocks the app's isolate for [hangFor], as a call
/// that never returns would: the self-test of the watchdog. The jobs it runs in
/// fail, and should say that the app sent nothing for 8 minutes.
void capabilityThatHangs() {
  capability('blocks the app on purpose, for the watchdog to stop', () async {
    final clock = Stopwatch()..start();
    // Meanwhile nothing else runs on the isolate: no timer, no frame, and no
    // word to the host.
    while (clock.elapsed < hangFor) {}
    fail(
      'Blocked the app for $hangFor, and nothing stopped it: the watchdog of '
      'make test-example-ci did not.',
    );
  });
}

/// Declares the check that every [capability] above it really ran, and hands
/// the count to `test_driver/integration_test.dart`. Declare it last.
void capabilitiesAllRan(IntegrationTestWidgetsFlutterBinding binding) {
  final declared = _declared;
  testWidgets('every capability above ran', (tester) async {
    expect(_ran, declared);
    binding.reportData = {'capabilities': _ran};
  });
}
