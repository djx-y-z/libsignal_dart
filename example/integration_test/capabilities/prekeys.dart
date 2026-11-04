import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';

import '../support/harness.dart';
import '../support/party.dart';

void preKeyCapabilities() {
  group('pre-keys', () {
    capability('PreKeyRecord round-trips', () async {
      final key = PrivateKey.generate();
      final record = PreKeyRecord(
        id: 5,
        publicKey: key.getPublicKey(),
        privateKey: key,
      );
      final restored = PreKeyRecord.deserialize(bytes: record.serialize());

      expect(restored.id(), 5);
      expect(restored.publicKey(), key.getPublicKey().serialize());
      expect(restored.serialize(), record.serialize());
    });

    capability(
      'SignedPreKeyRecord round-trips a full 64-bit timestamp',
      () async {
        // One past 2^53: the first integer a JavaScript number cannot hold, so a
        // u64 that crossed the wasm bridge as a double would come back changed.
        final timestamp = BigInt.parse('9007199254740993');
        final key = PrivateKey.generate();
        final signature = IdentityKeyPair.generate().sign(
          message: key.getPublicKey().serialize(),
        );
        final record = SignedPreKeyRecord(
          id: 6,
          timestamp: timestamp,
          publicKey: key.getPublicKey(),
          privateKey: key,
          signature: signature,
        );
        final restored = SignedPreKeyRecord.deserialize(
          bytes: record.serialize(),
        );

        expect(restored.id(), 6);
        expect(restored.timestamp(), timestamp);
        expect(restored.publicKey(), key.getPublicKey().serialize());
        expect(restored.signature(), signature);
        expect(restored.serialize(), record.serialize());
      },
    );

    capability('PreKeyBundle gives back what it was built from', () async {
      final party = Party('bundle-owner', 1234, deviceId: 3);
      final bundle = await party.publishBundle();
      // The keys the bundle was made from are the ones the owner stored.
      final preKey = (await party.preKeys.loadPreKey(42))!;
      final signedPreKey = (await party.signedPreKeys.loadSignedPreKey(7))!;
      final kyberPreKey = (await party.kyberPreKeys.loadKyberPreKey(3))!;

      expect(bundle.registrationId(), 1234);
      expect(bundle.deviceId(), 3);
      expect(bundle.preKeyId(), 42);
      expect(bundle.preKeyPublic(), preKey.publicKey());
      expect(bundle.signedPreKeyId(), 7);
      expect(bundle.signedPreKeyPublic(), signedPreKey.publicKey());
      expect(bundle.signedPreKeySignature(), signedPreKey.signature());
      expect(bundle.identityKey(), party.identity.publicKey);
      expect(bundle.kyberPreKeyId(), 3);
      expect(
        bundle.kyberPreKeyPublic(),
        kyberPreKey.getPublicKey().serialize(),
      );
      expect(bundle.kyberPreKeySignature(), kyberPreKey.signature());

      final withoutOneTimeKey = await party.publishBundle(oneTimePreKey: false);
      expect(withoutOneTimeKey.preKeyId(), isNull);
      expect(withoutOneTimeKey.preKeyPublic(), isNull);
    });
  });
}
