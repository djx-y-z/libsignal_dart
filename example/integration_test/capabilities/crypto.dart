import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';

import '../support/harness.dart';
import '../support/party.dart';

void cryptoCapabilities() {
  group('crypto', () {
    // Fixed answers throughout: each of these runs on every architecture and
    // on wasm32, where a wrong word size or endianness would still round-trip.
    capability('AES-256-GCM-SIV matches RFC 8452 appendix C.2', () async {
      final cipher = Aes256GcmSiv(
        key: hexBytes(
          '0100000000000000000000000000000000000000000000000000000000000000',
        ),
      );
      final nonce = hexBytes('030000000000000000000000');
      final plaintext = hexBytes('0100000000000000');
      final ciphertext = hexBytes(
        'c2ef328e5c71c83b843122130f7364b761e0b97427e3df28',
      );

      expect(
        cipher.encrypt(
          plaintext: plaintext,
          nonce: nonce,
          associatedData: const [],
        ),
        ciphertext,
      );
      expect(
        cipher.decrypt(
          ciphertext: ciphertext,
          nonce: nonce,
          associatedData: const [],
        ),
        plaintext,
      );
      expect(
        () => cipher.decrypt(
          ciphertext: ciphertext,
          nonce: nonce,
          associatedData: bytesOf('other associated data'),
        ),
        throwsA(
          isA<LibSignalException>().having(
            (e) => e.code,
            'code',
            LibSignalErrorCode.invalidMessage,
          ),
        ),
      );
    });

    capability('HKDF matches RFC 5869 appendix A.1', () async {
      expect(
        hkdfDerive(
          outputLength: 42,
          inputKeyMaterial: List.filled(22, 0x0b),
          salt: hexBytes('000102030405060708090a0b0c'),
          info: hexBytes('f0f1f2f3f4f5f6f7f8f9'),
        ),
        hexBytes(
          '3cb25f25faacd57a90434f64d0362f2a'
          '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
          '34007208d5b887185865',
        ),
      );
    });

    capability('Fingerprint matches libsignal\'s own vectors', () async {
      // `fingerprint_test_v2` in rust/protocol/src/fingerprint.rs upstream.
      final alice = hexBytes(
        '0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868',
      );
      final bob = hexBytes(
        '05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b',
      );
      final aliceId = bytesOf('+14152222222');
      final bobId = bytesOf('+14153333333');

      final alicesView = Fingerprint(
        iterations: 5200,
        version: 2,
        localIdentifier: aliceId,
        localPublicKey: alice,
        remoteIdentifier: bobId,
        remotePublicKey: bob,
      );
      final bobsView = Fingerprint(
        iterations: 5200,
        version: 2,
        localIdentifier: bobId,
        localPublicKey: bob,
        remoteIdentifier: aliceId,
        remotePublicKey: alice,
      );

      const displayed =
          '300354477692869396892869876765458257569162576843440918079131';
      expect(alicesView.displayString(), displayed);
      expect(bobsView.displayString(), displayed);
      expect(
        alicesView.scannableEncoding(),
        hexBytes(
          '080212220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada30'
          '5d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b8'
          '4d12bca631e9d4fb3a4d',
        ),
      );
      expect(
        fingerprintCompare(
          fingerprint1: alicesView.scannableEncoding(),
          fingerprint2: bobsView.scannableEncoding(),
        ),
        isTrue,
      );
      expect(alicesView.cloneFingerprint().displayString(), displayed);
    });

    capability('Fingerprint comparison notices a different key', () async {
      // Each side's own view, so that only the keys can make them differ: two
      // fingerprints made from the same side never compare equal, whatever
      // keys they hold, since each half hashes its identifier too.
      final alice = IdentityKeyPair.generate().publicKey;
      final bob = IdentityKeyPair.generate().publicKey;
      final mallory = IdentityKeyPair.generate().publicKey;
      Uint8List viewOf(
        String local,
        List<int> localKey,
        String remote,
        List<int> remoteKey,
      ) => Fingerprint(
        iterations: 5200,
        version: 2,
        localIdentifier: bytesOf(local),
        localPublicKey: localKey,
        remoteIdentifier: bytesOf(remote),
        remotePublicKey: remoteKey,
      ).scannableEncoding();

      final alicesView = viewOf('alice', alice, 'bob', bob);
      expect(
        fingerprintCompare(
          fingerprint1: alicesView,
          fingerprint2: viewOf('bob', bob, 'alice', alice),
        ),
        isTrue,
      );
      expect(
        fingerprintCompare(
          fingerprint1: alicesView,
          fingerprint2: viewOf('bob', bob, 'alice', mallory),
        ),
        isFalse,
        reason: 'Bob was shown another key for Alice',
      );
      expect(
        fingerprintCompare(
          fingerprint1: alicesView,
          fingerprint2: viewOf('bob', mallory, 'alice', alice),
        ),
        isFalse,
        reason: 'Alice was shown another key for Bob',
      );
    });
  });
}
