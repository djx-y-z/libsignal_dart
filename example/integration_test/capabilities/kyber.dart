import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';

import '../support/harness.dart';
import '../support/party.dart';

void kyberCapabilities() {
  group('Kyber', () {
    capability('keys generate, split, rejoin and round-trip', () async {
      final pair = KyberKeyPair.generate();
      final publicKey = pair.getPublicKey();
      final secretKey = pair.getSecretKey();

      final restoredPublic = KyberPublicKey.deserialize(
        bytes: publicKey.serialize(),
      );
      final restoredSecret = KyberSecretKey.deserialize(
        bytes: secretKey.serialize(),
      );
      expect(restoredPublic.equals(other: publicKey), isTrue);
      expect(restoredSecret.serialize(), secretKey.serialize());
      expect(publicKey.cloneKey().equals(other: publicKey), isTrue);
      expect(secretKey.cloneKey().serialize(), secretKey.serialize());
      expect(
        publicKey.equals(other: KyberKeyPair.generate().getPublicKey()),
        isFalse,
      );

      final rejoined = KyberKeyPair.fromKeys(
        publicKey: restoredPublic,
        secretKey: restoredSecret,
      );
      expect(rejoined.getPublicKey().equals(other: publicKey), isTrue);
      expect(rejoined.getSecretKey().serialize(), secretKey.serialize());
      expect(pair.cloneKey().getPublicKey().equals(other: publicKey), isTrue);
    });

    capability('KyberPreKeyRecord round-trips', () async {
      final pair = KyberKeyPair.generate();
      final identity = IdentityKeyPair.generate();
      final signature = identity.sign(message: pair.getPublicKey().serialize());
      final timestamp = nowMillis();

      final record = KyberPreKeyRecord.create(
        id: 9,
        timestamp: timestamp,
        keyPair: pair,
        signature: signature,
      );
      final restored = KyberPreKeyRecord.deserialize(bytes: record.serialize());

      expect(restored.id(), 9);
      expect(restored.timestamp(), timestamp);
      expect(restored.signature(), signature);
      expect(
        restored.getPublicKey().equals(other: pair.getPublicKey()),
        isTrue,
      );
      expect(
        restored.getSecretKey().serialize(),
        pair.getSecretKey().serialize(),
      );
      expect(
        restored.getKeyPair().getPublicKey().equals(other: pair.getPublicKey()),
        isTrue,
      );
      expect(record.cloneRecord().serialize(), record.serialize());
    });
  });
}
