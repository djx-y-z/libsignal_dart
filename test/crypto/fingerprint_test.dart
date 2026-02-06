import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('Fingerprint', () {
    late IdentityKeyPair localIdentity;
    late IdentityKeyPair remoteIdentity;
    late Uint8List localId;
    late Uint8List remoteId;

    setUp(() {
      localIdentity = IdentityKeyPair.generate();
      remoteIdentity = IdentityKeyPair.generate();
      localId = testMessage('local-uuid-12345');
      remoteId = testMessage('remote-uuid-67890');
    });

    group('constructor', () {
      test('creates fingerprint with default parameters', () {
        final fingerprint = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        expect(fingerprint, isNotNull);
      });

      test('creates fingerprint with custom iterations', () {
        final fingerprint = Fingerprint(
          iterations: 1024,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        expect(fingerprint, isNotNull);
      });

      test('creates fingerprint with custom version', () {
        final fingerprint = Fingerprint(
          iterations: 5200,
          version: 1,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        expect(fingerprint, isNotNull);
      });
    });

    group('displayString()', () {
      test('returns 60-digit string', () {
        final fingerprint = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        final display = fingerprint.displayString();

        // 60 digits total (12 groups of 5)
        expect(display.length, equals(60));
        expect(display, matches(RegExp(r'^[0-9]+$')));
      });

      test('is deterministic', () {
        final fp1 = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        final fp2 = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        expect(fp1.displayString(), equals(fp2.displayString()));
      });

      test('different keys produce different display strings', () {
        final fp1 = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        final otherIdentity = IdentityKeyPair.generate();
        final fp2 = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: otherIdentity.publicKey.toList(),
        );

        expect(fp1.displayString(), isNot(equals(fp2.displayString())));
      });
    });

    group('scannableEncoding()', () {
      test('returns non-empty bytes', () {
        final fingerprint = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        final scannable = fingerprint.scannableEncoding();

        expect(scannable, isNotEmpty);
      });

      test('is deterministic', () {
        final fp1 = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        final fp2 = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        expect(fp1.scannableEncoding(), equals(fp2.scannableEncoding()));
      });
    });

    group('symmetry', () {
      test('swapping local/remote produces same display string', () {
        final fpAlice = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        final fpBob = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: remoteId.toList(),
          localPublicKey: remoteIdentity.publicKey.toList(),
          remoteIdentifier: localId.toList(),
          remotePublicKey: localIdentity.publicKey.toList(),
        );

        expect(fpAlice.displayString(), equals(fpBob.displayString()));
      });
    });

    group('fingerprintCompare()', () {
      test('scannableEncoding returns consistent data', () {
        final fp = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        // Same fingerprint should return same encoding
        final encoding1 = fp.scannableEncoding();
        final encoding2 = fp.scannableEncoding();

        expect(encoding1, equals(encoding2));
      });

      test('returns true for matching fingerprints', () {
        // Alice's view
        final fpAlice = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        // Bob's view (local/remote swapped)
        final fpBob = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: remoteId.toList(),
          localPublicKey: remoteIdentity.publicKey.toList(),
          remoteIdentifier: localId.toList(),
          remotePublicKey: localIdentity.publicKey.toList(),
        );

        // Compare scannable encodings
        final result = fingerprintCompare(
          fingerprint1: fpAlice.scannableEncoding().toList(),
          fingerprint2: fpBob.scannableEncoding().toList(),
        );

        expect(result, isTrue);
      });

      test('returns false for different fingerprints', () {
        final fp1 = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        final otherIdentity = IdentityKeyPair.generate();
        final fp2 = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: otherIdentity.publicKey.toList(),
        );

        // Different fingerprints should not match
        final result = fingerprintCompare(
          fingerprint1: fp1.scannableEncoding().toList(),
          fingerprint2: fp2.scannableEncoding().toList(),
        );

        expect(result, isFalse);
      });

      test('symmetric fingerprints have same display string', () {
        // Alice's view
        final fpAlice = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        // Bob's view (local/remote swapped)
        final fpBob = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: remoteId.toList(),
          localPublicKey: remoteIdentity.publicKey.toList(),
          remoteIdentifier: localId.toList(),
          remotePublicKey: localIdentity.publicKey.toList(),
        );

        // Both should see the same safety number
        expect(fpAlice.displayString(), equals(fpBob.displayString()));
      });

      test('different keys produce different fingerprints', () {
        final fp1 = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        final otherIdentity = IdentityKeyPair.generate();
        final fp2 = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: otherIdentity.publicKey.toList(),
        );

        // Different remote key = different fingerprint
        expect(fp1.displayString(), isNot(equals(fp2.displayString())));
      });
    });

    group('cloneFingerprint()', () {
      test('creates independent copy', () {
        final original = Fingerprint(
          iterations: 5200,
          version: 2,
          localIdentifier: localId.toList(),
          localPublicKey: localIdentity.publicKey.toList(),
          remoteIdentifier: remoteId.toList(),
          remotePublicKey: remoteIdentity.publicKey.toList(),
        );

        final cloned = original.cloneFingerprint();

        expect(cloned.displayString(), equals(original.displayString()));
        expect(
          cloned.scannableEncoding(),
          equals(original.scannableEncoding()),
        );
      });
    });
  });
}
