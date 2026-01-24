import 'package:libsignal/libsignal.dart';
import 'package:libsignal/src/rust/api/init.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });

  group('api/init', () {
    group('initLibsignal', () {
      test('accepts any library path (no-op for API compatibility)', () {
        // This function is a no-op with pure Rust implementation
        // but kept for API compatibility
        expect(() => initLibsignal(libraryPath: '/some/path'), returnsNormally);
      });

      test('accepts empty library path', () {
        expect(() => initLibsignal(libraryPath: ''), returnsNormally);
      });
    });

    group('isLibsignalInitialized', () {
      test('always returns true with pure Rust implementation', () {
        // With pure Rust implementation, always returns true
        expect(isLibsignalInitialized(), isTrue);
      });
    });
  });
}
