import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
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
        final cipher = Aes256GcmSiv(validKey);

        expect(cipher, isNotNull);
        expect(cipher.isDisposed, isFalse);

        cipher.dispose();
      });

      test('throws for key shorter than 32 bytes', () {
        final shortKey = randomBytes(16);

        expect(
          () => Aes256GcmSiv(shortKey),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws for key longer than 32 bytes', () {
        final longKey = randomBytes(64);

        expect(
          () => Aes256GcmSiv(longKey),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('throws for empty key', () {
        expect(
          () => Aes256GcmSiv(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('encrypt() / decrypt()', () {
      test('round-trip with plaintext only', () {
        final cipher = Aes256GcmSiv(validKey);
        final plaintext = testMessage('Hello, Signal!');

        final ciphertext = cipher.encrypt(
          plaintext: plaintext,
          nonce: validNonce,
        );
        final decrypted = cipher.decrypt(
          ciphertext: ciphertext,
          nonce: validNonce,
        );

        expect(decrypted, equals(plaintext));

        cipher.dispose();
      });

      test('round-trip with associated data', () {
        final cipher = Aes256GcmSiv(validKey);
        final plaintext = testMessage('Secret message');
        final associatedData = testMessage('Additional authenticated data');

        final ciphertext = cipher.encrypt(
          plaintext: plaintext,
          nonce: validNonce,
          associatedData: associatedData,
        );
        final decrypted = cipher.decrypt(
          ciphertext: ciphertext,
          nonce: validNonce,
          associatedData: associatedData,
        );

        expect(decrypted, equals(plaintext));

        cipher.dispose();
      });

      test('encrypts empty plaintext', () {
        final cipher = Aes256GcmSiv(validKey);
        final plaintext = Uint8List(0);

        final ciphertext = cipher.encrypt(
          plaintext: plaintext,
          nonce: validNonce,
        );
        final decrypted = cipher.decrypt(
          ciphertext: ciphertext,
          nonce: validNonce,
        );

        expect(decrypted, equals(plaintext));

        cipher.dispose();
      });

      test('ciphertext is longer than plaintext (includes auth tag)', () {
        final cipher = Aes256GcmSiv(validKey);
        final plaintext = testMessage('Test message');

        final ciphertext = cipher.encrypt(
          plaintext: plaintext,
          nonce: validNonce,
        );

        // GCM-SIV adds 16-byte auth tag
        expect(ciphertext.length, equals(plaintext.length + 16));

        cipher.dispose();
      });

      test('same plaintext with different nonces produces different ciphertext', () {
        final cipher = Aes256GcmSiv(validKey);
        final plaintext = testMessage('Test message');

        final nonce1 = randomBytes(12);
        final nonce2 = randomBytes(12);

        final ct1 = cipher.encrypt(plaintext: plaintext, nonce: nonce1);
        final ct2 = cipher.encrypt(plaintext: plaintext, nonce: nonce2);

        expect(ct1, isNot(equals(ct2)));

        cipher.dispose();
      });

      test('same plaintext with same nonce is deterministic', () {
        final cipher = Aes256GcmSiv(validKey);
        final plaintext = testMessage('Test message');

        final ct1 = cipher.encrypt(plaintext: plaintext, nonce: validNonce);
        final ct2 = cipher.encrypt(plaintext: plaintext, nonce: validNonce);

        expect(ct1, equals(ct2));

        cipher.dispose();
      });
    });

    group('nonce validation', () {
      test('throws for nonce shorter than 12 bytes', () {
        final cipher = Aes256GcmSiv(validKey);
        final shortNonce = randomBytes(8);

        expect(
          () => cipher.encrypt(
            plaintext: testMessage('test'),
            nonce: shortNonce,
          ),
          throwsA(isA<LibSignalException>()),
        );

        cipher.dispose();
      });

      test('throws for nonce longer than 12 bytes', () {
        final cipher = Aes256GcmSiv(validKey);
        final longNonce = randomBytes(16);

        expect(
          () => cipher.encrypt(
            plaintext: testMessage('test'),
            nonce: longNonce,
          ),
          throwsA(isA<LibSignalException>()),
        );

        cipher.dispose();
      });

      test('decrypt throws for wrong nonce length', () {
        final cipher = Aes256GcmSiv(validKey);
        final ciphertext = cipher.encrypt(
          plaintext: testMessage('test'),
          nonce: validNonce,
        );

        expect(
          () => cipher.decrypt(
            ciphertext: ciphertext,
            nonce: randomBytes(8),
          ),
          throwsA(isA<LibSignalException>()),
        );

        cipher.dispose();
      });
    });

    group('tamper detection', () {
      test('decryption fails with wrong key', () {
        final cipher1 = Aes256GcmSiv(validKey);
        final cipher2 = Aes256GcmSiv(randomBytes(32));

        final ciphertext = cipher1.encrypt(
          plaintext: testMessage('Secret'),
          nonce: validNonce,
        );

        expect(
          () => cipher2.decrypt(
            ciphertext: ciphertext,
            nonce: validNonce,
          ),
          throwsA(isA<LibSignalException>()),
        );

        cipher1.dispose();
        cipher2.dispose();
      });

      test('decryption fails with wrong nonce', () {
        final cipher = Aes256GcmSiv(validKey);
        final ciphertext = cipher.encrypt(
          plaintext: testMessage('Secret'),
          nonce: validNonce,
        );

        expect(
          () => cipher.decrypt(
            ciphertext: ciphertext,
            nonce: randomBytes(12),
          ),
          throwsA(isA<LibSignalException>()),
        );

        cipher.dispose();
      });

      test('decryption fails with tampered ciphertext', () {
        final cipher = Aes256GcmSiv(validKey);
        final ciphertext = cipher.encrypt(
          plaintext: testMessage('Secret'),
          nonce: validNonce,
        );

        // Tamper with first byte
        ciphertext[0] ^= 0xFF;

        expect(
          () => cipher.decrypt(
            ciphertext: ciphertext,
            nonce: validNonce,
          ),
          throwsA(isA<LibSignalException>()),
        );

        cipher.dispose();
      });

      test('decryption fails with wrong associated data', () {
        final cipher = Aes256GcmSiv(validKey);
        final aad = testMessage('correct AAD');

        final ciphertext = cipher.encrypt(
          plaintext: testMessage('Secret'),
          nonce: validNonce,
          associatedData: aad,
        );

        expect(
          () => cipher.decrypt(
            ciphertext: ciphertext,
            nonce: validNonce,
            associatedData: testMessage('wrong AAD'),
          ),
          throwsA(isA<LibSignalException>()),
        );

        cipher.dispose();
      });

      test('decryption fails when AAD is missing', () {
        final cipher = Aes256GcmSiv(validKey);
        final aad = testMessage('AAD');

        final ciphertext = cipher.encrypt(
          plaintext: testMessage('Secret'),
          nonce: validNonce,
          associatedData: aad,
        );

        expect(
          () => cipher.decrypt(
            ciphertext: ciphertext,
            nonce: validNonce,
            // No AAD provided
          ),
          throwsA(isA<LibSignalException>()),
        );

        cipher.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        final cipher = Aes256GcmSiv(validKey);
        expect(cipher.isDisposed, isFalse);
        cipher.dispose();
      });

      test('isDisposed is true after dispose', () {
        final cipher = Aes256GcmSiv(validKey);
        cipher.dispose();
        expect(cipher.isDisposed, isTrue);
      });

      test('double dispose is safe', () {
        final cipher = Aes256GcmSiv(validKey);
        cipher.dispose();
        expect(() => cipher.dispose(), returnsNormally);
      });

      test('encrypt throws after dispose', () {
        final cipher = Aes256GcmSiv(validKey);
        cipher.dispose();

        expect(
          () => cipher.encrypt(
            plaintext: testMessage('test'),
            nonce: validNonce,
          ),
          throwsStateError,
        );
      });

      test('decrypt throws after dispose', () {
        final cipher = Aes256GcmSiv(validKey);
        final ciphertext = cipher.encrypt(
          plaintext: testMessage('test'),
          nonce: validNonce,
        );

        cipher.dispose();

        expect(
          () => cipher.decrypt(
            ciphertext: ciphertext,
            nonce: validNonce,
          ),
          throwsStateError,
        );
      });
    });
  });
}
