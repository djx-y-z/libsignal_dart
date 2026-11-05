// Every capability of the package, inside this running Flutter app.
//
// `test/` checks what the library does; it runs on the Dart VM, with a library
// the VM found for itself. This checks that the same library gets there through
// what a consumer's app goes through — the build hook, the platform's way of
// bundling a native library, the loader, and on the web the wasm module — and
// then does its job on that platform's architecture.
//
// One file, because every test file is its own build, install and launch on a
// device. The families live under capabilities/, which is not named *_test.dart
// so that `flutter test integration_test` does not take them for entry points.
//
//   make test-example ARGS="-d macos"      a desktop, a simulator or an emulator
//   make test-example-web                  the web, in a real browser
//
// When the package gains a capability, it goes here too:
// `make verify-example-coverage` fails on a bridged function nothing here calls.
import 'package:integration_test/integration_test.dart';

import 'capabilities/app.dart';
import 'capabilities/bridge.dart';
import 'capabilities/crypto.dart';
import 'capabilities/errors.dart';
import 'capabilities/groups.dart';
import 'capabilities/init.dart';
import 'capabilities/keys.dart';
import 'capabilities/kyber.dart';
import 'capabilities/messages.dart';
import 'capabilities/prekeys.dart';
import 'capabilities/sealed_sender.dart';
import 'capabilities/security.dart';
import 'capabilities/sessions.dart';
import 'capabilities/stores.dart';
import 'support/harness.dart';

void main() {
  final binding = IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  // The watchdog's self-test, first, so that the run stops at once.
  if (hangOnPurpose) capabilityThatHangs();
  initCapabilities();
  keyCapabilities();
  kyberCapabilities();
  cryptoCapabilities();
  preKeyCapabilities();
  sessionCapabilities();
  messageCapabilities();
  groupCapabilities();
  sealedSenderCapabilities();
  errorCapabilities();
  storeCapabilities();
  securityCapabilities();
  bridgeCapabilities();
  appCapabilities();

  capabilitiesAllRan(binding);
}
