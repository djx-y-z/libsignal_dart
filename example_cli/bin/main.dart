import 'package:libsignal/libsignal.dart';
import 'package:libsignal_example_cli/demos/crypto_demo.dart';
import 'package:libsignal_example_cli/demos/fingerprint_demo.dart';
import 'package:libsignal_example_cli/demos/groups_demo.dart';
import 'package:libsignal_example_cli/demos/keys_demo.dart';

void main() async {
  print('');
  print('╔══════════════════════════════════════╗');
  print('║       libsignal CLI Example          ║');
  print('╚══════════════════════════════════════╝');

  LibSignal.init();

  try {
    await runKeysDemo();
    await runCryptoDemo();
    await runGroupsDemo();
    await runFingerprintDemo();

    print('');
    print('✓ All demos completed successfully!');
    print('');
  } catch (e, stackTrace) {
    print('');
    print('✗ Error: $e');
    print('Stack trace: $stackTrace');
    print('');
  } finally {
    LibSignal.cleanup();
  }
}
