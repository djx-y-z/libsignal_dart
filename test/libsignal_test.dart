import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  group('LibSignal', () {
    tearDown(() {
      // Clean up after each test to reset state
      LibSignal.cleanup();
    });

    group('init()', () {
      test('initializes successfully', () {
        expect(() => LibSignal.init(), returnsNormally);
      });

      test('sets isInitialized to true', () {
        LibSignal.init();
        expect(LibSignal.isInitialized, isTrue);
      });

      test('can be called multiple times without error', () {
        LibSignal.init();
        LibSignal.init();
        LibSignal.init();
        expect(LibSignal.isInitialized, isTrue);
      });
    });

    group('isInitialized', () {
      test('returns false before init', () {
        expect(LibSignal.isInitialized, isFalse);
      });

      test('returns true after init', () {
        LibSignal.init();
        expect(LibSignal.isInitialized, isTrue);
      });

      test('returns false after cleanup', () {
        LibSignal.init();
        LibSignal.cleanup();
        expect(LibSignal.isInitialized, isFalse);
      });
    });

    group('ensureInitialized()', () {
      test('initializes if not already initialized', () {
        expect(LibSignal.isInitialized, isFalse);
        LibSignal.ensureInitialized();
        expect(LibSignal.isInitialized, isTrue);
      });

      test('is idempotent when already initialized', () {
        LibSignal.init();
        expect(() => LibSignal.ensureInitialized(), returnsNormally);
        expect(LibSignal.isInitialized, isTrue);
      });
    });

    group('cleanup()', () {
      test('cleans up successfully', () {
        LibSignal.init();
        expect(() => LibSignal.cleanup(), returnsNormally);
      });

      test('sets isInitialized to false', () {
        LibSignal.init();
        LibSignal.cleanup();
        expect(LibSignal.isInitialized, isFalse);
      });

      test('can be called without init', () {
        expect(() => LibSignal.cleanup(), returnsNormally);
      });

      test('can be called multiple times', () {
        LibSignal.init();
        LibSignal.cleanup();
        LibSignal.cleanup();
        expect(LibSignal.isInitialized, isFalse);
      });
    });
  });

  group('LibSignalBase', () {
    tearDown(() {
      LibSignal.cleanup();
    });

    test('ensureInit initializes library', () {
      expect(LibSignal.isInitialized, isFalse);
      LibSignalBase.ensureInit();
      expect(LibSignal.isInitialized, isTrue);
    });
  });
}
