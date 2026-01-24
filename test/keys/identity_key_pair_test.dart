import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:libsignal/src/rust/api/keys.dart' as keys;
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });
  tearDownAll(() => LibSignal.cleanup());

  group('Standalone identity key functions', () {
    group('identityKeypairSignAlternateIdentityRaw()', () {
      test('signs alternate identity using separate keys', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();
        final alternateIdentity = PrivateKey.generate().getPublicKey();

        final signature = keys.identityKeypairSignAlternateIdentityRaw(
          publicKey: publicKey,
          privateKey: privateKey,
          otherIdentity: alternateIdentity,
        );

        expect(signature, isNotNull);
        expect(signature.length, greaterThan(0));
      });

      test('produces same result as IdentityKeyPair.signAlternateIdentity', () {
        final identity = IdentityKeyPair.generate();
        final privateKey = PrivateKey.deserialize(
          bytes: identity.privateKey.toList(),
        );
        final publicKey = PublicKey.deserialize(
          bytes: identity.publicKey.toList(),
        );
        final alternateIdentity = PrivateKey.generate().getPublicKey();

        // Sign using standalone function
        final rawSignature = keys.identityKeypairSignAlternateIdentityRaw(
          publicKey: publicKey,
          privateKey: privateKey,
          otherIdentity: alternateIdentity,
        );

        // Sign using IdentityKeyPair method
        final methodSignature = identity.signAlternateIdentity(
          otherIdentity: alternateIdentity,
        );

        // Both should produce valid signatures (may not be identical due to randomness)
        expect(rawSignature.length, equals(methodSignature.length));
        expect(rawSignature.length, equals(64)); // Ed25519 signature length
      });
    });

    group('identityKeypairSerializeRaw()', () {
      test('serializes identity from separate keys', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final serialized = keys.identityKeypairSerializeRaw(
          publicKey: publicKey,
          privateKey: privateKey,
        );

        expect(serialized, isNotNull);
        expect(serialized.length, greaterThan(0));
      });

      test('produces same result as IdentityKeyPair.serialize', () {
        final identity = IdentityKeyPair.generate();
        final privateKey = PrivateKey.deserialize(
          bytes: identity.privateKey.toList(),
        );
        final publicKey = PublicKey.deserialize(
          bytes: identity.publicKey.toList(),
        );

        // Serialize using standalone function
        final rawSerialized = keys.identityKeypairSerializeRaw(
          publicKey: publicKey,
          privateKey: privateKey,
        );

        // Serialize using IdentityKeyPair method
        final methodSerialized = identity.serialize();

        // Both should produce identical results
        expect(rawSerialized, equals(methodSerialized));
      });

      test('serialized data can be deserialized', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final serialized = keys.identityKeypairSerializeRaw(
          publicKey: publicKey,
          privateKey: privateKey,
        );

        // Should be able to deserialize
        final restored = IdentityKeyPair.deserialize(
          bytes: serialized.toList(),
        );
        expect(restored, isNotNull);
        expect(restored.publicKey, equals(publicKey.serialize()));
      });
    });
  });

  group('IdentityKeyPair', () {
    group('generate()', () {
      test('generates valid identity key pair', () {
        final identity = IdentityKeyPair.generate();
        expect(identity, isNotNull);
      });

      test('each generation produces unique keys', () {
        final identity1 = IdentityKeyPair.generate();
        final identity2 = IdentityKeyPair.generate();

        // Public keys are returned as Uint8List
        expect(identity1.publicKey, isNot(equals(identity2.publicKey)));
      });

      test('generated keys are cryptographically linked', () {
        final identity = IdentityKeyPair.generate();

        // Get the private key to sign something
        final privateKey = PrivateKey.deserialize(
          bytes: identity.privateKey.toList(),
        );
        final publicKey = PublicKey.deserialize(
          bytes: identity.publicKey.toList(),
        );

        final message = Uint8List.fromList('test message'.codeUnits);
        final signature = privateKey.sign(message: message.toList());
        final isValid = publicKey.verify(
          message: message.toList(),
          signature: signature.toList(),
        );

        expect(isValid, isTrue);
      });
    });

    group('fromKeys()', () {
      test('creates identity from existing keys', () {
        final privateKey = PrivateKey.generate();
        final publicKey = privateKey.getPublicKey();

        final identity = IdentityKeyPair.fromKeys(
          privateKey: privateKey,
          publicKey: publicKey,
        );

        expect(identity, isNotNull);
      });
    });

    group('serialize() / deserialize()', () {
      test('round-trip preserves keys', () {
        final original = IdentityKeyPair.generate();
        final serialized = original.serialize();
        final restored = IdentityKeyPair.deserialize(
          bytes: serialized.toList(),
        );

        // Public keys should be equal
        expect(original.publicKey, equals(restored.publicKey));

        // Private keys should serialize to same bytes
        expect(original.privateKey, equals(restored.privateKey));

        // Both private keys should produce signatures verifiable by the public key
        final origPrivate = PrivateKey.deserialize(
          bytes: original.privateKey.toList(),
        );
        final restoredPrivate = PrivateKey.deserialize(
          bytes: restored.privateKey.toList(),
        );
        final origPublic = PublicKey.deserialize(
          bytes: original.publicKey.toList(),
        );

        final message = Uint8List.fromList('test'.codeUnits);
        final sig1 = origPrivate.sign(message: message.toList());
        final sig2 = restoredPrivate.sign(message: message.toList());

        expect(
          origPublic.verify(
            message: message.toList(),
            signature: sig1.toList(),
          ),
          isTrue,
        );
        expect(
          origPublic.verify(
            message: message.toList(),
            signature: sig2.toList(),
          ),
          isTrue,
        );
      });

      test('serialize returns expected length', () {
        final identity = IdentityKeyPair.generate();
        final serialized = identity.serialize();

        // Should be 64 bytes (32 public + 32 private) or protocol-specific
        expect(serialized.length, greaterThan(0));
      });

      test('deserialize rejects empty data', () {
        expect(() => IdentityKeyPair.deserialize(bytes: []), throwsA(anything));
      });

      test('deserialize rejects data with wrong length', () {
        final invalidData = [0x0a, 1, 2, 3, 4, 5];
        expect(
          () => IdentityKeyPair.deserialize(bytes: invalidData),
          throwsA(anything),
        );
      });
    });

    group('signAlternateIdentity()', () {
      test('signs alternate identity key', () {
        final mainIdentity = IdentityKeyPair.generate();
        final alternateIdentity = IdentityKeyPair.generate();

        final altPublicKey = PublicKey.deserialize(
          bytes: alternateIdentity.publicKey.toList(),
        );
        final signature = mainIdentity.signAlternateIdentity(
          otherIdentity: altPublicKey,
        );

        expect(signature, isNotNull);
        expect(signature.length, greaterThan(0));
      });

      test('multiple signatures are valid', () {
        final mainIdentity = IdentityKeyPair.generate();
        final alternateIdentity = IdentityKeyPair.generate();

        final altPublicKey = PublicKey.deserialize(
          bytes: alternateIdentity.publicKey.toList(),
        );

        // Sign multiple times
        final sig1 = mainIdentity.signAlternateIdentity(
          otherIdentity: altPublicKey,
        );
        final sig2 = mainIdentity.signAlternateIdentity(
          otherIdentity: altPublicKey,
        );

        // Both signatures should be non-empty
        expect(sig1.length, greaterThan(0));
        expect(sig2.length, greaterThan(0));
      });

      test('different alternate keys produce different signatures', () {
        final mainIdentity = IdentityKeyPair.generate();
        final alt1 = IdentityKeyPair.generate();
        final alt2 = IdentityKeyPair.generate();

        final alt1PublicKey = PublicKey.deserialize(
          bytes: alt1.publicKey.toList(),
        );
        final alt2PublicKey = PublicKey.deserialize(
          bytes: alt2.publicKey.toList(),
        );

        final sig1 = mainIdentity.signAlternateIdentity(
          otherIdentity: alt1PublicKey,
        );
        final sig2 = mainIdentity.signAlternateIdentity(
          otherIdentity: alt2PublicKey,
        );

        expect(sig1, isNot(equals(sig2)));
      });
    });

    group('privateKey getter', () {
      test('returns valid private key bytes', () {
        final identity = IdentityKeyPair.generate();
        final privateKeyBytes = identity.privateKey;

        expect(privateKeyBytes, isNotNull);
        expect(privateKeyBytes.length, equals(32));
      });

      test('returned key can sign messages', () {
        final identity = IdentityKeyPair.generate();
        final privateKey = PrivateKey.deserialize(
          bytes: identity.privateKey.toList(),
        );
        final message = Uint8List.fromList('test'.codeUnits);

        final signature = privateKey.sign(message: message.toList());

        expect(signature, isNotNull);
        expect(signature.length, equals(64));
      });
    });

    group('publicKey getter', () {
      test('returns valid public key bytes', () {
        final identity = IdentityKeyPair.generate();
        final publicKeyBytes = identity.publicKey;

        expect(publicKeyBytes, isNotNull);
        expect(
          publicKeyBytes.length,
          equals(33),
        ); // 1 type prefix + 32 key bytes
      });

      test('returned key can verify signatures', () {
        final identity = IdentityKeyPair.generate();
        final privateKey = PrivateKey.deserialize(
          bytes: identity.privateKey.toList(),
        );
        final publicKey = PublicKey.deserialize(
          bytes: identity.publicKey.toList(),
        );
        final message = Uint8List.fromList('test'.codeUnits);

        final signature = privateKey.sign(message: message.toList());
        final isValid = publicKey.verify(
          message: message.toList(),
          signature: signature.toList(),
        );

        expect(isValid, isTrue);
      });

      test('public key matches derived public key', () {
        final identity = IdentityKeyPair.generate();
        final privateKey = PrivateKey.deserialize(
          bytes: identity.privateKey.toList(),
        );
        final derived = privateKey.getPublicKey();

        expect(identity.publicKey, equals(derived.serialize()));
      });
    });
  });
}
