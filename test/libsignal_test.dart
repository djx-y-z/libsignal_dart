import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  group('LibSignal', () {
    tearDown(() {
      // Clean up after each test to reset state
      LibSignal.cleanup();
    });

    group('init()', () {
      test('initializes successfully', () async {
        await expectLater(LibSignal.init(), completes);
      });

      test('sets isInitialized to true', () async {
        await LibSignal.init();
        expect(LibSignal.isInitialized, isTrue);
      });

      test('can be called multiple times without error', () async {
        await LibSignal.init();
        await LibSignal.init();
        await LibSignal.init();
        expect(LibSignal.isInitialized, isTrue);
      });
    });

    group('isInitialized', () {
      test('returns false before init', () {
        expect(LibSignal.isInitialized, isFalse);
      });

      test('returns true after init', () async {
        await LibSignal.init();
        expect(LibSignal.isInitialized, isTrue);
      });

      test('returns false after cleanup', () async {
        await LibSignal.init();
        LibSignal.cleanup();
        expect(LibSignal.isInitialized, isFalse);
      });
    });

    group('ensureInitialized()', () {
      test('throws if not initialized', () {
        expect(LibSignal.isInitialized, isFalse);
        expect(() => LibSignal.ensureInitialized(), throwsA(isA<StateError>()));
      });

      test('does not throw when already initialized', () async {
        await LibSignal.init();
        expect(() => LibSignal.ensureInitialized(), returnsNormally);
        expect(LibSignal.isInitialized, isTrue);
      });
    });

    group('cleanup()', () {
      test('cleans up successfully', () async {
        await LibSignal.init();
        expect(() => LibSignal.cleanup(), returnsNormally);
      });

      test('sets isInitialized to false', () async {
        await LibSignal.init();
        LibSignal.cleanup();
        expect(LibSignal.isInitialized, isFalse);
      });

      test('can be called without init', () {
        expect(() => LibSignal.cleanup(), returnsNormally);
      });

      test('can be called multiple times', () async {
        await LibSignal.init();
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

    test('ensureInit throws if not initialized', () {
      expect(LibSignal.isInitialized, isFalse);
      expect(() => LibSignalBase.ensureInit(), throwsA(isA<StateError>()));
    });

    test('ensureInit does not throw when initialized', () async {
      await LibSignal.init();
      expect(LibSignal.isInitialized, isTrue);
      expect(() => LibSignalBase.ensureInit(), returnsNormally);
    });
  });
}
