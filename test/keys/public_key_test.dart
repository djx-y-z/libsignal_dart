import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });
  tearDownAll(() => LibSignal.cleanup());

  group('PublicKey', () {
    late PrivateKey privateKey;
    late PublicKey publicKey;

    setUp(() {
      privateKey = PrivateKey.generate();
      publicKey = privateKey.getPublicKey();
    });

    group('serialize() / deserialize()', () {
      test('serialize returns 33 bytes', () {
        final serialized = publicKey.serialize();
        expect(serialized.length, equals(33));
      });

      test('round-trip preserves key', () {
        final serialized = publicKey.serialize();
        final restored = PublicKey.deserialize(bytes: serialized.toList());

        expect(restored.equals(other: publicKey), isTrue);
        expect(restored.serialize(), equals(serialized));
      });

      test('deserialize rejects empty data', () {
        expect(() => PublicKey.deserialize(bytes: []), throwsA(anything));
      });

      test('deserialize rejects data with wrong length', () {
        final invalidData = [0x05, 1, 2, 3, 4, 5];
        expect(
          () => PublicKey.deserialize(bytes: invalidData),
          throwsA(anything),
        );
      });

      test('deserialize rejects data with wrong type byte', () {
        // 33 bytes but wrong type prefix
        final invalidData = List<int>.filled(33, 0);
        invalidData[0] = 0x99; // Wrong type
        expect(
          () => PublicKey.deserialize(bytes: invalidData),
          throwsA(anything),
        );
      });

      group('deserialize rejects low-order points', () {
        test('rejects zero point (order 4)', () {
          final data = List<int>.filled(33, 0);
          data[0] = 0x05; // Correct type prefix
          // Remaining 32 bytes are all zeros - low-order point
          expect(() => PublicKey.deserialize(bytes: data), throwsA(anything));
        });

        test('rejects one point (order 1)', () {
          final data = List<int>.filled(33, 0);
          data[0] = 0x05; // Correct type prefix
          data[1] = 0x01; // Low-order point: 1
          expect(() => PublicKey.deserialize(bytes: data), throwsA(anything));
        });

        test('rejects order-8 point', () {
          // Low-order point of order 8 from libsodium blocklist
          final data = [
            0x05, // type prefix
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, //
            0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
            0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
            0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
          ];
          expect(() => PublicKey.deserialize(bytes: data), throwsA(anything));
        });

        test('rejects p-1 point (order 2)', () {
          // p-1 is a low-order point of order 2
          final data = [
            0x05, // type prefix
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
          ];
          expect(() => PublicKey.deserialize(bytes: data), throwsA(anything));
        });

        test('rejects non-canonical p encoding (order 4)', () {
          // Non-canonical encoding of 0
          final data = [
            0x05, // type prefix
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
          ];
          expect(() => PublicKey.deserialize(bytes: data), throwsA(anything));
        });
      });

      test('first byte is key type prefix', () {
        final serialized = publicKey.serialize();
        // Type prefix for Curve25519 is 0x05
        expect(serialized[0], equals(0x05));
      });
    });

    group('getPublicKeyBytes()', () {
      test('returns 32 bytes', () {
        final bytes = publicKey.getPublicKeyBytes();
        expect(bytes.length, equals(32));
      });

      test('matches serialized data without prefix', () {
        final serialized = publicKey.serialize();
        final rawBytes = publicKey.getPublicKeyBytes();

        // Raw bytes should be serialized data minus the first byte
        expect(rawBytes, equals(serialized.sublist(1)));
      });
    });

    group('verify()', () {
      test('verifies valid signature', () {
        final message = testMessage('Test message');
        final signature = privateKey.sign(message: message.toList());

        expect(
          publicKey.verify(
            message: message.toList(),
            signature: signature.toList(),
          ),
          isTrue,
        );
      });

      test('rejects signature for wrong message', () {
        final message = testMessage('Test message');
        final wrongMessage = testMessage('Wrong message');
        final signature = privateKey.sign(message: message.toList());

        expect(
          publicKey.verify(
            message: wrongMessage.toList(),
            signature: signature.toList(),
          ),
          isFalse,
        );
      });

      test('rejects signature from different key', () {
        final message = testMessage('Test message');

        final otherPrivate = PrivateKey.generate();
        final signature = otherPrivate.sign(message: message.toList());

        expect(
          publicKey.verify(
            message: message.toList(),
            signature: signature.toList(),
          ),
          isFalse,
        );
      });

      test('rejects tampered signature', () {
        final message = testMessage('Test message');
        final signature = privateKey.sign(message: message.toList());

        // Tamper with signature
        final tamperedSig = Uint8List.fromList(signature);
        tamperedSig[0] ^= 0xFF;

        expect(
          publicKey.verify(
            message: message.toList(),
            signature: tamperedSig.toList(),
          ),
          isFalse,
        );
      });

      test('verifies empty message', () {
        final message = <int>[];
        final signature = privateKey.sign(message: message);

        expect(
          publicKey.verify(message: message, signature: signature.toList()),
          isTrue,
        );
      });

      test('rejects empty signature for non-empty message', () {
        final message = testMessage('Test message');
        final emptySignature = <int>[];

        expect(
          publicKey.verify(
            message: message.toList(),
            signature: emptySignature,
          ),
          isFalse,
        );
      });
    });

    group('equals()', () {
      test('same key equals itself', () {
        expect(publicKey.equals(other: publicKey), isTrue);
      });

      test('cloned key equals original', () {
        final cloned = publicKey.cloneKey();
        expect(publicKey.equals(other: cloned), isTrue);
      });

      test('different keys are not equal', () {
        final otherPrivate = PrivateKey.generate();
        final otherPublic = otherPrivate.getPublicKey();

        expect(publicKey.equals(other: otherPublic), isFalse);
      });

      test('deserialized key equals original', () {
        final serialized = publicKey.serialize();
        final restored = PublicKey.deserialize(bytes: serialized.toList());

        expect(publicKey.equals(other: restored), isTrue);
      });
    });

    group('compare()', () {
      test('key compares equal to itself', () {
        final cloned = publicKey.cloneKey();
        expect(publicKey.compare(other: cloned), equals(0));
      });

      test('different keys have non-zero comparison', () {
        final otherPrivate = PrivateKey.generate();
        final otherPublic = otherPrivate.getPublicKey();

        final comparison = publicKey.compare(other: otherPublic);
        expect(comparison, isNot(equals(0)));

        // Comparison should be consistent
        expect(otherPublic.compare(other: publicKey), equals(-comparison));
      });

      test('comparison is transitive', () {
        final key1 = PrivateKey.generate().getPublicKey();
        final key2 = PrivateKey.generate().getPublicKey();
        final key3 = PrivateKey.generate().getPublicKey();

        // Get all pairwise comparisons
        final cmp12 = key1.compare(other: key2);
        final cmp23 = key2.compare(other: key3);
        final cmp13 = key1.compare(other: key3);

        // If key1 < key2 and key2 < key3, then key1 < key3
        if (cmp12 < 0 && cmp23 < 0) {
          expect(cmp13, lessThan(0));
        }
        // If key1 > key2 and key2 > key3, then key1 > key3
        if (cmp12 > 0 && cmp23 > 0) {
          expect(cmp13, greaterThan(0));
        }
      });
    });

    group('cloneKey()', () {
      test('creates independent copy', () {
        final cloned = publicKey.cloneKey();

        expect(cloned.serialize(), equals(publicKey.serialize()));
        expect(cloned.equals(other: publicKey), isTrue);
      });
    });
  });
}
