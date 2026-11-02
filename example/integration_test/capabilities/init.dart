import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';

import '../support/harness.dart';

void initCapabilities() {
  group('LibSignal', () {
    capability('init is idempotent and survives cleanup', () async {
      expect(LibSignal.isInitialized, isTrue);
      await LibSignal.init();
      LibSignal.ensureInitialized();
      LibSignalBase.ensureInit();

      LibSignal.cleanup();
      expect(LibSignal.isInitialized, isFalse);
      expect(LibSignal.ensureInitialized, throwsStateError);

      // Without `dispose: true` the bridge stays up, so this comes back.
      await LibSignal.init();
      expect(LibSignal.isInitialized, isTrue);
      expect(PrivateKey.generate().serialize(), hasLength(32));
    });
  });
}
