import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:libsignal/libsignal.dart';

int _declared = 0;
int _ran = 0;

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
  testWidgets(description, (tester) async {
    await LibSignal.init();
    await body();
    _ran++;
  }, timeout: const Timeout(Duration(minutes: 3)));
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
