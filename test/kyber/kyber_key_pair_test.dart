import 'dart:convert';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_party.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('KyberKeyPair', () {
    group('generate()', () {
      test('generates valid key pair', () {
        final keyPair = KyberKeyPair.generate();

        expect(keyPair, isNotNull);
      });

      test('generates unique key pairs', () {
        final keyPair1 = KyberKeyPair.generate();
        final keyPair2 = KyberKeyPair.generate();

        final pub1 = keyPair1.getPublicKey();
        final pub2 = keyPair2.getPublicKey();

        expect(pub1.serialize(), isNot(equals(pub2.serialize())));
      });
    });

    group('getPublicKey()', () {
      test('returns valid Kyber public key', () {
        final keyPair = KyberKeyPair.generate();
        final publicKey = keyPair.getPublicKey();

        expect(publicKey, isNotNull);
        // Kyber1024 public key is 1568 bytes (+ 1 format byte)
        expect(publicKey.serialize().length, greaterThan(1000));
      });

      test('multiple calls return equivalent public keys', () {
        final keyPair = KyberKeyPair.generate();

        final pub1 = keyPair.getPublicKey();
        final pub2 = keyPair.getPublicKey();

        expect(pub1.equals(other: pub2), isTrue);
        expect(pub1.serialize(), equals(pub2.serialize()));
      });
    });

    group('getSecretKey()', () {
      test('returns valid Kyber secret key', () {
        final keyPair = KyberKeyPair.generate();
        final secretKey = keyPair.getSecretKey();

        expect(secretKey, isNotNull);
        // Kyber1024 secret key is 3168 bytes (+ 1 format byte)
        expect(secretKey.serialize().length, greaterThan(3000));
      });

      test('multiple calls return equivalent secret keys', () {
        final keyPair = KyberKeyPair.generate();

        final secret1 = keyPair.getSecretKey();
        final secret2 = keyPair.getSecretKey();

        expect(secret1.serialize(), equals(secret2.serialize()));
      });
    });

    group('cloneKey()', () {
      test('creates independent copy', () {
        final original = KyberKeyPair.generate();
        final cloned = original.cloneKey();

        expect(cloned, isNotNull);

        // Cloned should still work
        final pub = cloned.getPublicKey();
        expect(pub, isNotNull);
      });

      test('cloned key pair has same keys', () {
        final original = KyberKeyPair.generate();
        final cloned = original.cloneKey();

        final origPub = original.getPublicKey();
        final clonedPub = cloned.getPublicKey();
        expect(clonedPub.equals(other: origPub), isTrue);

        final origSecret = original.getSecretKey();
        final clonedSecret = cloned.getSecretKey();
        expect(clonedSecret.serialize(), equals(origSecret.serialize()));
      });
    });

    group('fromKeys()', () {
      test('rebuilds the pair from its serialized halves', () {
        final original = KyberKeyPair.generate();
        final publicBytes = original.getPublicKey().serialize();
        final secretBytes = original.getSecretKey().serialize();

        final rebuilt = KyberKeyPair.fromKeys(
          publicKey: KyberPublicKey.deserialize(bytes: publicBytes.toList()),
          secretKey: KyberSecretKey.deserialize(bytes: secretBytes.toList()),
        );

        expect(rebuilt.getPublicKey().serialize(), equals(publicBytes));
        expect(rebuilt.getSecretKey().serialize(), equals(secretBytes));
      });

      test('rejects halves of two different pairs', () {
        final publicKey = KyberKeyPair.generate().getPublicKey();
        final secretKey = KyberKeyPair.generate().getSecretKey();

        expect(
          () =>
              KyberKeyPair.fromKeys(publicKey: publicKey, secretKey: secretKey),
          throwsA(
            predicate(
              (Object e) =>
                  e.toString().contains('not halves of the same key pair'),
              'throws a key pair mismatch error',
            ),
          ),
        );
        // Borrowed, so a failed check leaves both handles usable too.
        expect(publicKey.isDisposed, isFalse);
        expect(secretKey.isDisposed, isFalse);
      });

      // IdentityKeyPair.fromKeys moves its arguments, so the same name does
      // not promise the same ownership. This one borrows.
      test('consumes neither argument', () {
        final original = KyberKeyPair.generate();
        final publicKey = original.getPublicKey();
        final secretKey = original.getSecretKey();

        KyberKeyPair.fromKeys(publicKey: publicKey, secretKey: secretKey);

        expect(publicKey.isDisposed, isFalse);
        expect(secretKey.isDisposed, isFalse);
        expect(
          publicKey.serialize(),
          equals(original.getPublicKey().serialize()),
        );
        expect(
          secretKey.serialize(),
          equals(original.getSecretKey().serialize()),
        );
      });

      // The pair holds its own copy of the secret, which is what makes the
      // docstring's advice to dispose() the source handles safe to follow.
      test('the pair keeps working after its source handles are disposed', () {
        final original = KyberKeyPair.generate();
        final publicBytes = original.getPublicKey().serialize();
        final secretBytes = original.getSecretKey().serialize();
        final publicKey = KyberPublicKey.deserialize(
          bytes: publicBytes.toList(),
        );
        final secretKey = KyberSecretKey.deserialize(
          bytes: secretBytes.toList(),
        );

        final pair = KyberKeyPair.fromKeys(
          publicKey: publicKey,
          secretKey: secretKey,
        );
        publicKey.dispose();
        secretKey.dispose();

        expect(secretKey.isDisposed, isTrue);
        expect(pair.getPublicKey().serialize(), equals(publicBytes));
        expect(pair.getSecretKey().serialize(), equals(secretBytes));
      });

      test('builds the same pre-key record as the original pair', () {
        final identity = IdentityKeyPair.generate();
        final original = KyberKeyPair.generate();
        final signature = identity.sign(
          message: original.getPublicKey().serialize().toList(),
        );
        final rebuilt = KyberKeyPair.fromKeys(
          publicKey: KyberPublicKey.deserialize(
            bytes: original.getPublicKey().serialize().toList(),
          ),
          secretKey: KyberSecretKey.deserialize(
            bytes: original.getSecretKey().serialize().toList(),
          ),
        );

        KyberPreKeyRecord recordFor(KyberKeyPair keyPair) =>
            KyberPreKeyRecord.create(
              id: 7,
              timestamp: BigInt.from(1000000),
              keyPair: keyPair,
              signature: signature.toList(),
            );

        expect(
          recordFor(rebuilt).serialize(),
          equals(recordFor(original).serialize()),
        );
      });

      test(
        'a record rebuilt from stored halves decrypts a first message',
        () async {
          final alice = TestParty.create(name: 'alice', registrationId: 111);
          final bob = TestParty.create(name: 'bob', registrationId: 222)
            ..generatePreKeys(kyberPreKeyId: 9);

          // Take Bob's Kyber pre-key apart into the bytes a store keeping the
          // halves in separate columns would hold, and rebuild it from those.
          final stored = (await bob.kyberPreKeyStore.loadKyberPreKey(9))!;
          final rebuilt = KyberPreKeyRecord.create(
            id: 9,
            timestamp: stored.timestamp(),
            keyPair: KyberKeyPair.fromKeys(
              publicKey: KyberPublicKey.deserialize(
                bytes: stored.getPublicKey().serialize().toList(),
              ),
              secretKey: KyberSecretKey.deserialize(
                bytes: stored.getSecretKey().serialize().toList(),
              ),
            ),
            signature: stored.signature().toList(),
          );
          await bob.kyberPreKeyStore.storeKyberPreKey(9, rebuilt);

          await alice.sessionBuilder.processPreKeyBundle(
            bob.address,
            bob.getBundle(),
          );
          final ciphertext = await alice.sessionCipher.encrypt(
            bob.address,
            utf8.encode('hello'),
          );
          expect(ciphertext.isPreKeyMessage, isTrue);

          final plaintext = await bob.sessionCipher.decrypt(
            alice.address,
            ciphertext,
          );
          expect(utf8.decode(plaintext), equals('hello'));
        },
      );

      // The control for the test above, and the failure the pairing check in
      // fromKeys() exists to stop at construction: a record whose secret key is
      // not the partner of the public key the peer encapsulated to is accepted
      // by the store, and fails only when the peer's first message arrives —
      // as a plain "decryption failed" that names no key.
      test(
        'a record with a mismatched secret key fails a first message',
        () async {
          final alice = TestParty.create(name: 'alice', registrationId: 111);
          final bob = TestParty.create(name: 'bob', registrationId: 222)
            ..generatePreKeys(kyberPreKeyId: 9);

          final stored = (await bob.kyberPreKeyStore.loadKyberPreKey(9))!;
          await bob.kyberPreKeyStore.storeKyberPreKey(
            9,
            KyberPreKeyRecord.create(
              id: 9,
              timestamp: stored.timestamp(),
              keyPair: KyberKeyPair.generate(),
              signature: stored.signature().toList(),
            ),
          );

          await alice.sessionBuilder.processPreKeyBundle(
            bob.address,
            bob.getBundle(),
          );
          final ciphertext = await alice.sessionCipher.encrypt(
            bob.address,
            utf8.encode('hello'),
          );

          await expectLater(
            bob.sessionCipher.decrypt(alice.address, ciphertext),
            throwsA(
              predicate(
                (Object e) => e.toString().contains('decryption failed'),
                'fails to decrypt',
              ),
            ),
          );
        },
      );
    });
  });
}
