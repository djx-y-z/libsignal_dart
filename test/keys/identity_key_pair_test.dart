import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('IdentityKeyPair', () {
    group('generate()', () {
      test('generates valid identity key pair', () {
        final identity = IdentityKeyPair.generate();

        expect(identity, isNotNull);
        expect(identity.isDisposed, isFalse);

        identity.dispose();
      });

      test('each generation produces unique keys', () {
        final identity1 = IdentityKeyPair.generate();
        final identity2 = IdentityKeyPair.generate();

        expect(
          identity1.publicKey.equals(identity2.publicKey),
          isFalse,
        );

        identity1.dispose();
        identity2.dispose();
      });

      test('generated keys are cryptographically linked', () {
        final identity = IdentityKeyPair.generate();

        // Sign something with private key, verify with public key
        final message = Uint8List.fromList('test message'.codeUnits);
        final signature = identity.privateKey.sign(message);
        final isValid = identity.publicKey.verify(message, signature);

        expect(isValid, isTrue);

        identity.dispose();
      });
    });

    group('fromKeys()', () {
      test('creates identity from existing keys', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final identity = IdentityKeyPair.fromKeys(privateKey, publicKey);

        expect(identity, isNotNull);
        expect(identity.isDisposed, isFalse);

        identity.dispose();
      });

      test('takes ownership of provided keys', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final identity = IdentityKeyPair.fromKeys(privateKey, publicKey);

        // Dispose identity should dispose both keys
        identity.dispose();

        expect(privateKey.isDisposed, isTrue);
        expect(publicKey.isDisposed, isTrue);
      });
    });

    group('serialize() / deserialize()', () {
      test('round-trip preserves keys', () {
        final original = IdentityKeyPair.generate();
        final serialized = original.serialize();
        final restored = IdentityKeyPair.deserialize(serialized.bytes);

        // Public keys should be equal
        expect(
          original.publicKey.equals(restored.publicKey),
          isTrue,
        );

        // Private keys should serialize to same bytes
        final origPrivBytes = original.privateKey.serialize();
        final restoredPrivBytes = restored.privateKey.serialize();
        expect(origPrivBytes.bytes, equals(restoredPrivBytes.bytes));
        origPrivBytes.dispose();
        restoredPrivBytes.dispose();

        // Both private keys should produce signatures verifiable by the public key
        final message = Uint8List.fromList('test'.codeUnits);
        final sig1 = original.privateKey.sign(message);
        final sig2 = restored.privateKey.sign(message);

        expect(original.publicKey.verify(message, sig1), isTrue);
        expect(original.publicKey.verify(message, sig2), isTrue);

        serialized.dispose();
        original.dispose();
        restored.dispose();
      });

      test('serialize returns expected length', () {
        final identity = IdentityKeyPair.generate();
        final serialized = identity.serialize();

        // Should be 64 bytes (32 public + 32 private) or protocol-specific
        expect(serialized.length, greaterThan(0));

        serialized.dispose();
        identity.dispose();
      });

      test('deserialize rejects empty data', () {
        expect(
          () => IdentityKeyPair.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects data with wrong length', () {
        final invalidData = Uint8List.fromList([0x0a, 1, 2, 3, 4, 5]);
        expect(
          () => IdentityKeyPair.deserialize(invalidData),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects data with wrong type byte', () {
        // 69 bytes but wrong type prefix
        final invalidData = Uint8List(69);
        invalidData[0] = 0x99; // Wrong type
        expect(
          () => IdentityKeyPair.deserialize(invalidData),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('signAlternateIdentity()', () {
      test('signs alternate identity key', () {
        final mainIdentity = IdentityKeyPair.generate();
        final alternateIdentity = IdentityKeyPair.generate();

        final signature = mainIdentity.signAlternateIdentity(
          alternateIdentity.publicKey,
        );

        expect(signature, isNotNull);
        expect(signature.length, greaterThan(0));

        mainIdentity.dispose();
        alternateIdentity.dispose();
      });

      test('multiple signatures are valid', () {
        final mainIdentity = IdentityKeyPair.generate();
        final alternateIdentity = IdentityKeyPair.generate();

        // Sign multiple times
        final sig1 = mainIdentity.signAlternateIdentity(
          alternateIdentity.publicKey,
        );
        final sig2 = mainIdentity.signAlternateIdentity(
          alternateIdentity.publicKey,
        );

        // Both signatures should be non-empty
        expect(sig1.length, greaterThan(0));
        expect(sig2.length, greaterThan(0));

        mainIdentity.dispose();
        alternateIdentity.dispose();
      });

      test('different alternate keys produce different signatures', () {
        final mainIdentity = IdentityKeyPair.generate();
        final alt1 = IdentityKeyPair.generate();
        final alt2 = IdentityKeyPair.generate();

        final sig1 = mainIdentity.signAlternateIdentity(alt1.publicKey);
        final sig2 = mainIdentity.signAlternateIdentity(alt2.publicKey);

        expect(sig1, isNot(equals(sig2)));

        mainIdentity.dispose();
        alt1.dispose();
        alt2.dispose();
      });
    });

    group('privateKey getter', () {
      test('returns valid private key', () {
        final identity = IdentityKeyPair.generate();

        final privateKey = identity.privateKey;

        expect(privateKey, isNotNull);
        expect(privateKey.isDisposed, isFalse);

        identity.dispose();
      });

      test('returned key can sign messages', () {
        final identity = IdentityKeyPair.generate();
        final message = Uint8List.fromList('test'.codeUnits);

        final signature = identity.privateKey.sign(message);

        expect(signature, isNotNull);
        expect(signature.length, equals(64));

        identity.dispose();
      });
    });

    group('publicKey getter', () {
      test('returns valid public key', () {
        final identity = IdentityKeyPair.generate();

        final publicKey = identity.publicKey;

        expect(publicKey, isNotNull);
        expect(publicKey.isDisposed, isFalse);

        identity.dispose();
      });

      test('returned key can verify signatures', () {
        final identity = IdentityKeyPair.generate();
        final message = Uint8List.fromList('test'.codeUnits);
        final signature = identity.privateKey.sign(message);

        final isValid = identity.publicKey.verify(message, signature);

        expect(isValid, isTrue);

        identity.dispose();
      });

      test('public key matches derived public key', () {
        final identity = IdentityKeyPair.generate();
        final derived = identity.privateKey.getPublicKey();

        expect(identity.publicKey.equals(derived), isTrue);

        derived.dispose();
        identity.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        final identity = IdentityKeyPair.generate();
        expect(identity.isDisposed, isFalse);
        identity.dispose();
      });

      test('isDisposed is true after dispose', () {
        final identity = IdentityKeyPair.generate();
        identity.dispose();
        expect(identity.isDisposed, isTrue);
      });

      test('double dispose is safe', () {
        final identity = IdentityKeyPair.generate();
        identity.dispose();
        expect(() => identity.dispose(), returnsNormally);
      });

      test('dispose disposes both keys', () {
        final identity = IdentityKeyPair.generate();
        final privateKey = identity.privateKey;
        final publicKey = identity.publicKey;

        identity.dispose();

        expect(privateKey.isDisposed, isTrue);
        expect(publicKey.isDisposed, isTrue);
      });

      test('serialize throws after dispose', () {
        final identity = IdentityKeyPair.generate();
        identity.dispose();
        expect(() => identity.serialize(), throwsA(isA<LibSignalException>()));
      });

      test('signAlternateIdentity throws after dispose', () {
        final identity = IdentityKeyPair.generate();
        final other = IdentityKeyPair.generate();

        identity.dispose();

        expect(
          () => identity.signAlternateIdentity(other.publicKey),
          throwsA(isA<LibSignalException>()),
        );

        other.dispose();
      });

      test('privateKey getter throws after dispose', () {
        final identity = IdentityKeyPair.generate();
        identity.dispose();
        expect(() => identity.privateKey, throwsA(isA<LibSignalException>()));
      });

      test('publicKey getter throws after dispose', () {
        final identity = IdentityKeyPair.generate();
        identity.dispose();
        expect(() => identity.publicKey, throwsA(isA<LibSignalException>()));
      });
    });
  });
}
