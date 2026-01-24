import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });
  tearDownAll(() => LibSignal.cleanup());

  group('Aes256GcmSiv', () {
    late Uint8List validKey;
    late Uint8List validNonce;

    setUp(() {
      validKey = randomBytes(32);
      validNonce = randomBytes(12);
    });

    group('constructor', () {
      test('creates cipher with valid 32-byte key', () {
        final cipher = Aes256GcmSiv(key: validKey.toList());
        expect(cipher, isNotNull);
      });

      test('throws for key shorter than 32 bytes', () {
        final shortKey = randomBytes(16);

        expect(() => Aes256GcmSiv(key: shortKey.toList()), throwsA(anything));
      });

      test('throws for key longer than 32 bytes', () {
        final longKey = randomBytes(64);

        expect(() => Aes256GcmSiv(key: longKey.toList()), throwsA(anything));
      });

      test('throws for empty key', () {
        expect(() => Aes256GcmSiv(key: []), throwsA(anything));
      });
    });

    group('encrypt() / decrypt()', () {
      test('round-trip with plaintext only', () {
        final cipher = Aes256GcmSiv(key: validKey.toList());
        final plaintext = testMessage('Hello, Signal!');

        final ciphertext = cipher.encrypt(
          plaintext: plaintext.toList(),
          nonce: validNonce.toList(),
          associatedData: [],
        );
        final decrypted = cipher.decrypt(
          ciphertext: ciphertext.toList(),
          nonce: validNonce.toList(),
          associatedData: [],
        );

        expect(decrypted, equals(plaintext));
      });

      test('round-trip with associated data', () {
        final cipher = Aes256GcmSiv(key: validKey.toList());
        final plaintext = testMessage('Secret message');
        final associatedData = testMessage('Additional authenticated data');

        final ciphertext = cipher.encrypt(
          plaintext: plaintext.toList(),
          nonce: validNonce.toList(),
          associatedData: associatedData.toList(),
        );
        final decrypted = cipher.decrypt(
          ciphertext: ciphertext.toList(),
          nonce: validNonce.toList(),
          associatedData: associatedData.toList(),
        );

        expect(decrypted, equals(plaintext));
      });

      test('encrypts empty plaintext', () {
        final cipher = Aes256GcmSiv(key: validKey.toList());
        final plaintext = <int>[];

        final ciphertext = cipher.encrypt(
          plaintext: plaintext,
          nonce: validNonce.toList(),
          associatedData: [],
        );
        final decrypted = cipher.decrypt(
          ciphertext: ciphertext.toList(),
          nonce: validNonce.toList(),
          associatedData: [],
        );

        expect(decrypted, equals(plaintext));
      });

      test('ciphertext is longer than plaintext (includes auth tag)', () {
        final cipher = Aes256GcmSiv(key: validKey.toList());
        final plaintext = testMessage('Test message');

        final ciphertext = cipher.encrypt(
          plaintext: plaintext.toList(),
          nonce: validNonce.toList(),
          associatedData: [],
        );

        // GCM-SIV adds 16-byte auth tag
        expect(ciphertext.length, equals(plaintext.length + 16));
      });

      test(
        'same plaintext with different nonces produces different ciphertext',
        () {
          final cipher = Aes256GcmSiv(key: validKey.toList());
          final plaintext = testMessage('Test message');

          final nonce1 = randomBytes(12);
          final nonce2 = randomBytes(12);

          final ct1 = cipher.encrypt(
            plaintext: plaintext.toList(),
            nonce: nonce1.toList(),
            associatedData: [],
          );
          final ct2 = cipher.encrypt(
            plaintext: plaintext.toList(),
            nonce: nonce2.toList(),
            associatedData: [],
          );

          expect(ct1, isNot(equals(ct2)));
        },
      );

      test('same plaintext with same nonce is deterministic', () {
        final cipher = Aes256GcmSiv(key: validKey.toList());
        final plaintext = testMessage('Test message');

        final ct1 = cipher.encrypt(
          plaintext: plaintext.toList(),
          nonce: validNonce.toList(),
          associatedData: [],
        );
        final ct2 = cipher.encrypt(
          plaintext: plaintext.toList(),
          nonce: validNonce.toList(),
          associatedData: [],
        );

        expect(ct1, equals(ct2));
      });
    });

    group('nonce validation', () {
      test('throws for nonce shorter than 12 bytes', () {
        final cipher = Aes256GcmSiv(key: validKey.toList());
        final shortNonce = randomBytes(8);

        expect(
          () => cipher.encrypt(
            plaintext: testMessage('test').toList(),
            nonce: shortNonce.toList(),
            associatedData: [],
          ),
          throwsA(anything),
        );
      });

      test('throws for nonce longer than 12 bytes', () {
        final cipher = Aes256GcmSiv(key: validKey.toList());
        final longNonce = randomBytes(16);

        expect(
          () => cipher.encrypt(
            plaintext: testMessage('test').toList(),
            nonce: longNonce.toList(),
            associatedData: [],
          ),
          throwsA(anything),
        );
      });

      test('decrypt throws for wrong nonce length', () {
        final cipher = Aes256GcmSiv(key: validKey.toList());
        final ciphertext = cipher.encrypt(
          plaintext: testMessage('test').toList(),
          nonce: validNonce.toList(),
          associatedData: [],
        );

        expect(
          () => cipher.decrypt(
            ciphertext: ciphertext.toList(),
            nonce: randomBytes(8).toList(),
            associatedData: [],
          ),
          throwsA(anything),
        );
      });
    });
  });
}
