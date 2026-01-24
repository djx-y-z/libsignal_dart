import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });
  tearDownAll(() => LibSignal.cleanup());

  group('Hkdf', () {
    late Uint8List inputKeyMaterial;
    late Uint8List info;

    setUp(() {
      inputKeyMaterial = randomBytes(32);
      info = testMessage('context info');
    });

    group('hkdfDerive()', () {
      test('derives key with specified length', () {
        final derived = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          salt: [],
          info: info.toList(),
          outputLength: 32,
        );

        expect(derived.length, equals(32));
      });

      test('derives different lengths correctly', () {
        for (final length in [16, 32, 48, 64, 128]) {
          final derived = hkdfDerive(
            inputKeyMaterial: inputKeyMaterial.toList(),
            salt: [],
            info: info.toList(),
            outputLength: length,
          );

          expect(derived.length, equals(length));
        }
      });

      test('is deterministic - same inputs produce same output', () {
        final derived1 = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          salt: [],
          info: info.toList(),
          outputLength: 32,
        );

        final derived2 = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          salt: [],
          info: info.toList(),
          outputLength: 32,
        );

        expect(derived1, equals(derived2));
      });

      test('different IKM produces different output', () {
        final derived1 = hkdfDerive(
          inputKeyMaterial: randomBytes(32).toList(),
          salt: [],
          info: info.toList(),
          outputLength: 32,
        );

        final derived2 = hkdfDerive(
          inputKeyMaterial: randomBytes(32).toList(),
          salt: [],
          info: info.toList(),
          outputLength: 32,
        );

        expect(derived1, isNot(equals(derived2)));
      });

      test('different info produces different output', () {
        final derived1 = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          salt: [],
          info: testMessage('info 1').toList(),
          outputLength: 32,
        );

        final derived2 = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          salt: [],
          info: testMessage('info 2').toList(),
          outputLength: 32,
        );

        expect(derived1, isNot(equals(derived2)));
      });

      test('longer outputs include shorter outputs as prefix', () {
        final short = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          salt: [],
          info: info.toList(),
          outputLength: 32,
        );

        final long = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          salt: [],
          info: info.toList(),
          outputLength: 64,
        );

        expect(long.sublist(0, 32), equals(short));
      });
    });

    group('with salt', () {
      test('derives key with salt', () {
        final salt = randomBytes(16);
        final derived = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          info: info.toList(),
          salt: salt.toList(),
          outputLength: 32,
        );

        expect(derived.length, equals(32));
      });

      test('different salt produces different output', () {
        final derived1 = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          info: info.toList(),
          salt: randomBytes(16).toList(),
          outputLength: 32,
        );

        final derived2 = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          info: info.toList(),
          salt: randomBytes(16).toList(),
          outputLength: 32,
        );

        expect(derived1, isNot(equals(derived2)));
      });

      test('with salt differs from without salt', () {
        final derivedWithSalt = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          salt: randomBytes(16).toList(),
          info: info.toList(),
          outputLength: 32,
        );

        final derivedWithoutSalt = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          salt: [],
          info: info.toList(),
          outputLength: 32,
        );

        expect(derivedWithSalt, isNot(equals(derivedWithoutSalt)));
      });
    });

    group('edge cases', () {
      test('works with empty info', () {
        final derived = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          salt: [],
          info: [],
          outputLength: 32,
        );

        expect(derived.length, equals(32));
      });

      test('works with small IKM', () {
        final derived = hkdfDerive(
          inputKeyMaterial: randomBytes(8).toList(),
          salt: [],
          info: info.toList(),
          outputLength: 32,
        );

        expect(derived.length, equals(32));
      });

      test('works with large IKM', () {
        final derived = hkdfDerive(
          inputKeyMaterial: randomBytes(1024).toList(),
          salt: [],
          info: info.toList(),
          outputLength: 32,
        );

        expect(derived.length, equals(32));
      });

      test('works with single byte output', () {
        final derived = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          salt: [],
          info: info.toList(),
          outputLength: 1,
        );

        expect(derived.length, equals(1));
      });
    });

    group('edge cases with zero output', () {
      test('zero output length returns empty', () {
        // Rust implementation returns empty array for zero length
        final derived = hkdfDerive(
          inputKeyMaterial: inputKeyMaterial.toList(),
          salt: [],
          info: info.toList(),
          outputLength: 0,
        );

        expect(derived, isEmpty);
      });
    });
  });
}
