import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';

import '../support/harness.dart';
import '../support/party.dart';

void keyCapabilities() {
  group('keys', () {
    // Fixed answers from the specification: a generate-and-round-trip test
    // would pass on a platform whose curve arithmetic was simply wrong.
    capability('X25519 agreement matches RFC 7748 section 6.1', () async {
      final alice = PrivateKey.deserialize(
        bytes: hexBytes(
          '77076d0a7318a57d3c16c17251b26645'
          'df4c2f87ebc0992ab177fba51db92c2a',
        ),
      );
      expect(
        alice.getPublicKey().getPublicKeyBytes(),
        hexBytes(
          '8520f0098930a754748b7ddcb43ef75a'
          '0dbf3a0d26381af4eba4a98eaa9b4e6a',
        ),
      );

      final bob = PublicKey.deserialize(
        bytes: [
          0x05,
          ...hexBytes(
            'de9edb7d7b7dc1b4d35b61c2ece43537'
            '3f8343c85b78674dadfc7e146f882b4f',
          ),
        ],
      );
      expect(
        alice.agree(publicKey: bob),
        hexBytes(
          '4a5d9d5ba4ce2de1728e3bf480350f25'
          'e07e21c947d19e3376f09b3c1e161742',
        ),
      );
    });

    capability('PrivateKey signs, serializes and clones', () async {
      final key = PrivateKey.generate();
      final message = bytesOf('signed in a Flutter app');
      final signature = key.sign(message: message);

      expect(signature, hasLength(64));
      expect(
        key.getPublicKey().verify(message: message, signature: signature),
        isTrue,
      );
      expect(
        key.getPublicKey().verify(
          message: bytesOf('something else'),
          signature: signature,
        ),
        isFalse,
      );

      final restored = PrivateKey.deserialize(bytes: key.serialize());
      expect(restored.serialize(), key.serialize());
      expect(key.cloneKey().serialize(), key.serialize());
    });

    capability('PublicKey compares, serializes and clones', () async {
      final a = PrivateKey.generate().getPublicKey();
      final b = PrivateKey.generate().getPublicKey();

      expect(a.serialize(), hasLength(33));
      expect(a.getPublicKeyBytes(), a.serialize().sublist(1));
      expect(
        PublicKey.deserialize(bytes: a.serialize()).equals(other: a),
        isTrue,
      );
      expect(a.cloneKey().equals(other: a), isTrue);
      expect(a.equals(other: b), isFalse);
      expect(a.compare(other: a), 0);
      expect(a.compare(other: b), -b.compare(other: a));
    });

    capability('IdentityKeyPair signs and round-trips', () async {
      final identity = IdentityKeyPair.generate();
      final publicKey = PublicKey.deserialize(bytes: identity.publicKey);
      final privateKey = PrivateKey.deserialize(bytes: identity.privateKey);
      final message = bytesOf('signed by an identity');

      expect(
        publicKey.verify(
          message: message,
          signature: identity.sign(message: message),
        ),
        isTrue,
      );

      final restored = IdentityKeyPair.deserialize(bytes: identity.serialize());
      expect(restored.publicKey, identity.publicKey);
      expect(restored.privateKey, identity.privateKey);

      expect(
        identityKeypairSerializeRaw(
          publicKey: publicKey,
          privateKey: privateKey,
        ),
        identity.serialize(),
      );

      // Last, because it takes ownership of both keys: on the Dart side they
      // are disposed once it returns.
      final rebuilt = IdentityKeyPair.fromKeys(
        privateKey: privateKey,
        publicKey: publicKey,
      );
      expect(rebuilt.serialize(), identity.serialize());
    });

    capability('IdentityKeyPair signs an alternate identity', () async {
      final identity = IdentityKeyPair.generate();
      final other = PrivateKey.generate().getPublicKey();

      expect(
        identity.signAlternateIdentity(otherIdentity: other),
        hasLength(64),
      );
      expect(
        identityKeypairSignAlternateIdentityRaw(
          publicKey: PublicKey.deserialize(bytes: identity.publicKey),
          privateKey: PrivateKey.deserialize(bytes: identity.privateKey),
          otherIdentity: other,
        ),
        hasLength(64),
      );
    });
  });
}
