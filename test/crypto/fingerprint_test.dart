import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

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

    tearDown(() {
      localIdentity.dispose();
      remoteIdentity.dispose();
    });

    group('create()', () {
      test('creates fingerprint with default parameters', () {
        final fingerprint = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        expect(fingerprint, isNotNull);
        expect(fingerprint.isDisposed, isFalse);

        fingerprint.dispose();
      });

      test('creates fingerprint with custom iterations', () {
        final fingerprint = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
          iterations: 1024,
        );

        expect(fingerprint, isNotNull);

        fingerprint.dispose();
      });

      test('creates fingerprint with custom version', () {
        final fingerprint = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
          version: 1,
        );

        expect(fingerprint, isNotNull);

        fingerprint.dispose();
      });
    });

    group('displayString', () {
      test('returns 60-digit string', () {
        final fingerprint = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        final display = fingerprint.displayString;

        // 60 digits total (12 groups of 5)
        expect(display.length, equals(60));
        expect(display, matches(RegExp(r'^[0-9]+$')));

        fingerprint.dispose();
      });

      test('is deterministic', () {
        final fp1 = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        final fp2 = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        expect(fp1.displayString, equals(fp2.displayString));

        fp1.dispose();
        fp2.dispose();
      });

      test('different keys produce different display strings', () {
        final fp1 = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        final otherIdentity = IdentityKeyPair.generate();
        final fp2 = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: otherIdentity.publicKey,
        );

        expect(fp1.displayString, isNot(equals(fp2.displayString)));

        fp1.dispose();
        fp2.dispose();
        otherIdentity.dispose();
      });
    });

    group('scannableEncoding', () {
      test('returns non-empty bytes', () {
        final fingerprint = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        final scannable = fingerprint.scannableEncoding;

        expect(scannable, isNotEmpty);

        fingerprint.dispose();
      });

      test('is deterministic', () {
        final fp1 = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        final fp2 = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        expect(fp1.scannableEncoding, equals(fp2.scannableEncoding));

        fp1.dispose();
        fp2.dispose();
      });
    });

    group('symmetry', () {
      test('swapping local/remote produces same display string', () {
        final fpAlice = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        final fpBob = Fingerprint.create(
          localIdentifier: remoteId,
          localKey: remoteIdentity.publicKey,
          remoteIdentifier: localId,
          remoteKey: localIdentity.publicKey,
        );

        expect(fpAlice.displayString, equals(fpBob.displayString));

        fpAlice.dispose();
        fpBob.dispose();
      });
    });

    group('compare()', () {
      test('scannableEncoding returns consistent data', () {
        final fp = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        // Same fingerprint should return same encoding
        final encoding1 = fp.scannableEncoding;
        final encoding2 = fp.scannableEncoding;

        expect(encoding1, equals(encoding2));

        fp.dispose();
      });

      test('symmetric fingerprints have same display string', () {
        // Alice's view
        final fpAlice = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        // Bob's view (local/remote swapped)
        final fpBob = Fingerprint.create(
          localIdentifier: remoteId,
          localKey: remoteIdentity.publicKey,
          remoteIdentifier: localId,
          remoteKey: localIdentity.publicKey,
        );

        // Both should see the same safety number
        expect(fpAlice.displayString, equals(fpBob.displayString));

        fpAlice.dispose();
        fpBob.dispose();
      });

      test('different keys produce different fingerprints', () {
        final fp1 = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        final otherIdentity = IdentityKeyPair.generate();
        final fp2 = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: otherIdentity.publicKey,
        );

        // Different remote key = different fingerprint
        expect(fp1.displayString, isNot(equals(fp2.displayString)));

        fp1.dispose();
        fp2.dispose();
        otherIdentity.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final original = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        final cloned = original.clone();

        expect(cloned.displayString, equals(original.displayString));
        expect(cloned.scannableEncoding, equals(original.scannableEncoding));

        original.dispose();

        // Cloned should still work
        expect(cloned.isDisposed, isFalse);
        expect(() => cloned.displayString, returnsNormally);

        cloned.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        final fingerprint = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        expect(fingerprint.isDisposed, isFalse);

        fingerprint.dispose();
      });

      test('isDisposed is true after dispose', () {
        final fingerprint = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        fingerprint.dispose();

        expect(fingerprint.isDisposed, isTrue);
      });

      test('double dispose is safe', () {
        final fingerprint = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        fingerprint.dispose();

        expect(() => fingerprint.dispose(), returnsNormally);
      });

      test('displayString throws after dispose', () {
        final fingerprint = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        fingerprint.dispose();

        expect(() => fingerprint.displayString, throwsA(isA<LibSignalException>()));
      });

      test('scannableEncoding throws after dispose', () {
        final fingerprint = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        fingerprint.dispose();

        expect(() => fingerprint.scannableEncoding, throwsA(isA<LibSignalException>()));
      });

      test('clone throws after dispose', () {
        final fingerprint = Fingerprint.create(
          localIdentifier: localId,
          localKey: localIdentity.publicKey,
          remoteIdentifier: remoteId,
          remoteKey: remoteIdentity.publicKey,
        );

        fingerprint.dispose();

        expect(() => fingerprint.clone(), throwsA(isA<LibSignalException>()));
      });
    });
  });
}
