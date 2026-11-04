import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';

import '../support/harness.dart';

void securityCapabilities() {
  group('secure bytes', () {
    capability('SecureBytes zeroes what it holds when disposed', () async {
      final source = Uint8List.fromList([1, 2, 3]);

      final copied = SecureBytes(source);
      expect(copied.bytes, source);
      expect(copied.length, 3);
      expect(copied.isDisposed, isFalse);
      final held = copied.bytes;
      copied.dispose();
      expect(copied.isDisposed, isTrue);
      expect(copied.length, 0);
      expect(() => copied.bytes, throwsStateError);
      expect(held, [0, 0, 0]);
      expect(source, [1, 2, 3], reason: 'the constructor copied it');

      final wrapped = SecureBytes.wrap(source);
      wrapped.dispose();
      expect(source, [0, 0, 0], reason: 'wrap() takes it as it is');

      final fromList = SecureBytes.fromList(const [4, 5]);
      expect(fromList.bytes, [4, 5]);
      fromList.dispose();
    });

    capability('Uint8List.zeroize clears in place', () async {
      final secret = Uint8List.fromList([9, 9, 9])..zeroize();
      expect(secret, [0, 0, 0]);
    });
  });
}
