import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:libsignal_example/main.dart';

/// Waits until [finder] matches.
///
/// Not `pumpAndSettle`, and not `pump` either. A demo's spinner animates for as
/// long as its native call runs, so settling would never happen; and `pump`
/// waits for a frame, which never comes once the app is told it is hidden — a
/// desktop window covered by another one is enough — so the test would hang
/// without saying why. A forced frame is drawn regardless, and this loop ends
/// at its deadline whatever happens.
Future<void> _waitFor(WidgetTester tester, Finder finder) async {
  final deadline = DateTime.now().add(const Duration(minutes: 2));
  while (finder.evaluate().isEmpty) {
    if (DateTime.now().isAfter(deadline)) {
      throw TestFailure('Timed out waiting for $finder.');
    }
    tester.binding.scheduleForcedFrame();
    await tester.binding.delayed(const Duration(milliseconds: 50));
  }
}

/// Runs one tab's demo and returns what it printed.
Future<String> _runDemo(WidgetTester tester, String tab, String id) async {
  // The tab bar scrolls, and on a phone not every tab fits. Hit-testable, not just
  // present, for each tap here: a tap on something off screen lands nowhere.
  await tester.ensureVisible(find.text(tab));
  await _waitFor(tester, find.text(tab).hitTestable());
  await tester.tap(find.text(tab));

  // The same again for the button: its page ignores pointers until the transition
  // ends.
  final run = find.byKey(ValueKey('run-$id'));
  await _waitFor(tester, run);
  await tester.ensureVisible(run);
  await _waitFor(tester, run.hitTestable());
  await tester.tap(run);

  final result = find.byKey(ValueKey('result-$id'));
  await _waitFor(tester, result);
  return tester.widget<SelectableText>(result).data!;
}

void appCapabilities() {
  group('the example app', () {
    // Not `capability`: this one drives the widget tree, and it is the app's
    // own `initState` that calls `LibSignal.init()` here. Last among them,
    // because the app's `dispose` calls `LibSignal.cleanup()`.
    testWidgets(
      'initializes and runs every demo',
      (tester) async {
        // By default a live test only draws when it pumps. This one waits on
        // native calls instead, so the app has to draw on its own.
        IntegrationTestWidgetsFlutterBinding.instance.framePolicy =
            LiveTestWidgetsFlutterBindingFramePolicy.fullyLive;

        await tester.pumpWidget(const MyApp());

        // `init()` failing puts its error on the screen instead of the tabs. On
        // the web that is also what a missing `web/pkg/` looks like. Either way
        // the wait ends, and the message is in the failure.
        final failed = find.textContaining('failed to initialize');
        await _waitFor(
          tester,
          find.byWidgetPredicate(
            (widget) =>
                widget is TabBarView ||
                (widget is Text && (widget.data ?? '').contains('failed to')),
          ),
        );
        expect(failed, findsNothing);

        const demos = {
          ('Keys', 'keys'): ['Valid: true', 'Valid: false (expected: false)'],
          ('Crypto', 'crypto'): [
            'Match: true',
            'Same ciphertext: true',
            'Different ciphertext: true',
          ],
          ('Groups', 'groups'): ['Match: true'],
          ('Session', 'session'): [
            'PreKeySignalMessage',
            'Match: true',
            'Received: "How are you?"',
          ],
          ('Verify', 'verify'): [
            'Length: 60 digits',
            'Alice and Bob see same number: true',
          ],
        };
        for (final MapEntry(key: (tab, id), value: expected) in demos.entries) {
          final printed = await _runDemo(tester, tab, id);
          expect(printed, isNot(startsWith('Error:')), reason: tab);
          for (final line in expected) {
            expect(printed, contains(line), reason: tab);
          }
        }
      },
      timeout: const Timeout(Duration(minutes: 5)),
    );
  });
}
