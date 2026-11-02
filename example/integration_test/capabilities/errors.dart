import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';

import '../support/harness.dart';
import '../support/party.dart';

/// The failure of [call], which must throw a [LibSignalException] with [code].
///
/// An error has to reach Dart as its code on every platform: that mapping runs
/// through generated decoders, and on the web through a different set of them.
Matcher _failsWith(LibSignalErrorCode code) =>
    throwsA(isA<LibSignalException>().having((e) => e.code, 'code', code));

void errorCapabilities() {
  group('errors', () {
    capability('a synchronous call fails with its code', () async {
      expect(
        () => PublicKey.deserialize(bytes: const [1, 2, 3]),
        _failsWith(LibSignalErrorCode.invalidKey),
      );
      expect(
        () => SignalMessage.deserialize(data: const [1, 2, 3]),
        _failsWith(LibSignalErrorCode.invalidMessage),
      );
      expect(
        () => PlaintextContent.deserialize(data: const [1, 2, 3]),
        _failsWith(LibSignalErrorCode.unrecognizedMessageVersion),
      );
      expect(
        () => DecryptionErrorMessage.deserialize(bytes: const [0x99, 0x88]),
        _failsWith(LibSignalErrorCode.protobufError),
      );
    });

    capability('an asynchronous call fails with its code', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);

      await expectLater(
        alice.cipher.encrypt(bob.address, bytesOf('no session yet')),
        _failsWith(LibSignalErrorCode.sessionNotFound),
      );
    });

    capability('a pre-key the store no longer holds is named', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await establish(alice, bob);
      final opening = await alice.cipher.encrypt(bob.address, bytesOf('hello'));
      await bob.signedPreKeys.removeSignedPreKey(7);

      await expectLater(
        bob.cipher.decrypt(alice.address, opening),
        _failsWith(LibSignalErrorCode.invalidKeyIdentifier),
      );
    });

    capability('a tampered message is refused', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await converse(alice, bob);

      final sent = await alice.cipher.encrypt(bob.address, bytesOf('intact'));
      final tampered = sent.ciphertext.sublist(0);
      tampered[tampered.length - 1] ^= 0xff;
      await expectLater(
        bob.cipher.decryptSignalMessage(alice.address, tampered),
        _failsWith(LibSignalErrorCode.invalidMessage),
      );

      // Refused without harm: the real one still decrypts.
      expect(
        utf8.decode(await bob.cipher.decrypt(alice.address, sent)),
        'intact',
      );
    });

    capability('a bundle with a forged signature is refused', () async {
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      final real = await bob.publishBundle();

      await expectLater(
        alice.builder.processPreKeyBundle(
          bob.address,
          PreKeyBundle(
            registrationId: real.registrationId(),
            deviceId: real.deviceId(),
            preKeyId: real.preKeyId(),
            preKeyPublic: real.preKeyPublic(),
            signedPreKeyId: real.signedPreKeyId(),
            signedPreKeyPublic: real.signedPreKeyPublic(),
            signedPreKeySignature: List.filled(64, 1),
            identityKey: real.identityKey(),
            kyberPreKeyId: real.kyberPreKeyId(),
            kyberPreKeyPublic: real.kyberPreKeyPublic(),
            kyberPreKeySignature: real.kyberPreKeySignature(),
          ),
        ),
        _failsWith(LibSignalErrorCode.invalidSignature),
      );
    });

    capability('fingerprints of different versions do not compare', () async {
      Fingerprint fingerprint(int version) => Fingerprint(
        iterations: 5200,
        version: version,
        localIdentifier: bytesOf('local'),
        localPublicKey: IdentityKeyPair.generate().publicKey,
        remoteIdentifier: bytesOf('remote'),
        remotePublicKey: IdentityKeyPair.generate().publicKey,
      );

      expect(
        () => fingerprintCompare(
          fingerprint1: fingerprint(1).scannableEncoding(),
          fingerprint2: fingerprint(2).scannableEncoding(),
        ),
        _failsWith(LibSignalErrorCode.fingerprintVersionMismatch),
      );
    });

    capability('an exception prints and compares by value', () async {
      const failure = LibSignalException(
        code: LibSignalErrorCode.invalidKey,
        message: 'bad',
      );
      expect(failure.toString(), 'LibSignalException(invalidKey): bad');
      expect(
        failure,
        const LibSignalException(
          code: LibSignalErrorCode.invalidKey,
          message: 'bad',
        ),
      );
    });
  });
}
