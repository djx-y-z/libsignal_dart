import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('Hkdf', () {
    late Uint8List inputKeyMaterial;
    late Uint8List info;

    setUp(() {
      inputKeyMaterial = randomBytes(32);
      info = testMessage('context info');
    });

    group('deriveSecrets()', () {
      test('derives key with specified length', () {
        final derived = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          outputLength: 32,
        );

        expect(derived.length, equals(32));
      });

      test('derives different lengths correctly', () {
        for (final length in [16, 32, 48, 64, 128]) {
          final derived = Hkdf.deriveSecrets(
            inputKeyMaterial: inputKeyMaterial,
            info: info,
            outputLength: length,
          );

          expect(derived.length, equals(length));
        }
      });

      test('is deterministic - same inputs produce same output', () {
        final derived1 = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          outputLength: 32,
        );

        final derived2 = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          outputLength: 32,
        );

        expect(derived1, equals(derived2));
      });

      test('different IKM produces different output', () {
        final derived1 = Hkdf.deriveSecrets(
          inputKeyMaterial: randomBytes(32),
          info: info,
          outputLength: 32,
        );

        final derived2 = Hkdf.deriveSecrets(
          inputKeyMaterial: randomBytes(32),
          info: info,
          outputLength: 32,
        );

        expect(derived1, isNot(equals(derived2)));
      });

      test('different info produces different output', () {
        final derived1 = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: testMessage('info 1'),
          outputLength: 32,
        );

        final derived2 = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: testMessage('info 2'),
          outputLength: 32,
        );

        expect(derived1, isNot(equals(derived2)));
      });

      test('longer outputs include shorter outputs as prefix', () {
        final short = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          outputLength: 32,
        );

        final long = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          outputLength: 64,
        );

        expect(long.sublist(0, 32), equals(short));
      });
    });

    group('with salt', () {
      test('derives key with salt', () {
        final salt = randomBytes(16);
        final derived = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          salt: salt,
          outputLength: 32,
        );

        expect(derived.length, equals(32));
      });

      test('different salt produces different output', () {
        final derived1 = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          salt: randomBytes(16),
          outputLength: 32,
        );

        final derived2 = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          salt: randomBytes(16),
          outputLength: 32,
        );

        expect(derived1, isNot(equals(derived2)));
      });

      test('with salt differs from without salt', () {
        final derivedWithSalt = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          salt: randomBytes(16),
          outputLength: 32,
        );

        final derivedWithoutSalt = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          outputLength: 32,
        );

        expect(derivedWithSalt, isNot(equals(derivedWithoutSalt)));
      });

      test('null salt is same as no salt', () {
        final derivedNull = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          salt: null,
          outputLength: 32,
        );

        final derivedNone = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          outputLength: 32,
        );

        expect(derivedNull, equals(derivedNone));
      });

      test('empty salt is same as null salt', () {
        final derivedEmpty = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          salt: Uint8List(0),
          outputLength: 32,
        );

        final derivedNull = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          salt: null,
          outputLength: 32,
        );

        expect(derivedEmpty, equals(derivedNull));
      });
    });

    group('edge cases', () {
      test('works with empty info', () {
        final derived = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: Uint8List(0),
          outputLength: 32,
        );

        expect(derived.length, equals(32));
      });

      test('works with small IKM', () {
        final derived = Hkdf.deriveSecrets(
          inputKeyMaterial: randomBytes(8),
          info: info,
          outputLength: 32,
        );

        expect(derived.length, equals(32));
      });

      test('works with large IKM', () {
        final derived = Hkdf.deriveSecrets(
          inputKeyMaterial: randomBytes(1024),
          info: info,
          outputLength: 32,
        );

        expect(derived.length, equals(32));
      });

      test('works with single byte output', () {
        final derived = Hkdf.deriveSecrets(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          outputLength: 1,
        );

        expect(derived.length, equals(1));
      });
    });

    group('error handling', () {
      test('throws for zero output length', () {
        expect(
          () => Hkdf.deriveSecrets(
            inputKeyMaterial: inputKeyMaterial,
            info: info,
            outputLength: 0,
          ),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('throws for negative output length', () {
        expect(
          () => Hkdf.deriveSecrets(
            inputKeyMaterial: inputKeyMaterial,
            info: info,
            outputLength: -1,
          ),
          throwsA(isA<ArgumentError>()),
        );
      });
    });
  });
}
