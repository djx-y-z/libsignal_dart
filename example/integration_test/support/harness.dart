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

/// Declares the check that every [capability] above it really ran, and hands
/// the count to `test_driver/integration_test.dart`. Declare it last.
void capabilitiesAllRan(IntegrationTestWidgetsFlutterBinding binding) {
  final declared = _declared;
  testWidgets('every capability above ran', (tester) async {
    expect(_ran, declared);
    binding.reportData = {'capabilities': _ran};
  });
}
