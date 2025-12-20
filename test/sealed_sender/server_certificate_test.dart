import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_helpers.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('ServerCertificate', () {
    late PrivateKey trustRootPrivate;
    late PublicKey serverKey;

    setUp(() {
      trustRootPrivate = PrivateKey.generate();
      serverKey = PrivateKey.generate().getPublicKey();
    });

    tearDown(() {
      trustRootPrivate.dispose();
      serverKey.dispose();
    });

    group('create()', () {
      test('creates valid server certificate', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        expect(cert, isNotNull);
        expect(cert.isDisposed, isFalse);
        expect(cert.keyId, equals(1));

        final key = cert.getKey();
        expect(key.equals(serverKey), isTrue);

        key.dispose();
        cert.dispose();
      });

      test('creates certificate with various key IDs', () {
        for (final keyId in [0, 1, 100, 0xFFFF, 0xFFFFFFFF]) {
          final cert = ServerCertificate.create(
            keyId: keyId,
            serverKey: serverKey,
            trustRoot: trustRootPrivate,
          );

          expect(cert.keyId, equals(keyId));
          cert.dispose();
        }
      });

      test('created certificate has valid signature', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        final signature = cert.signature;
        expect(signature, isNotEmpty);
        expect(signature.length, equals(64)); // Ed25519 signature

        cert.dispose();
      });

      test('created certificate has certificate data', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        final certData = cert.certificate;
        expect(certData, isNotEmpty);

        cert.dispose();
      });
    });

    group('serialize() / deserialize()', () {
      test('round-trip preserves certificate', () {
        final original = ServerCertificate.create(
          keyId: 42,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        final serialized = original.serialize();
        expect(serialized, isNotEmpty);

        final restored = ServerCertificate.deserialize(serialized);

        expect(restored.keyId, equals(original.keyId));
        expect(restored.signature, equals(original.signature));
        expect(restored.certificate, equals(original.certificate));

        final origKey = original.getKey();
        final restoredKey = restored.getKey();
        expect(restoredKey.equals(origKey), isTrue);

        original.dispose();
        restored.dispose();
        origKey.dispose();
        restoredKey.dispose();
      });

      test('deserialize rejects empty data', () {
        expect(
          () => ServerCertificate.deserialize(Uint8List(0)),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects invalid data', () {
        final invalidData = Uint8List.fromList([1, 2, 3, 4, 5]);
        expect(
          () => ServerCertificate.deserialize(invalidData),
          throwsA(isA<LibSignalException>()),
        );
      });

      test('deserialize rejects garbage data', () {
        final garbage = randomBytes(100);
        expect(
          () => ServerCertificate.deserialize(garbage),
          throwsA(isA<LibSignalException>()),
        );
      });
    });

    group('getKey()', () {
      test('returns valid public key', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        final key = cert.getKey();

        expect(key, isNotNull);
        expect(key.isDisposed, isFalse);
        expect(key.serialize().length, equals(33));

        key.dispose();
        cert.dispose();
      });

      test('multiple calls return equivalent keys', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        final key1 = cert.getKey();
        final key2 = cert.getKey();

        expect(key1.equals(key2), isTrue);

        key1.dispose();
        key2.dispose();
        cert.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final original = ServerCertificate.create(
          keyId: 42,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        final cloned = original.clone();

        expect(cloned.keyId, equals(original.keyId));
        expect(cloned.serialize(), equals(original.serialize()));

        original.dispose();

        // Cloned should still work
        expect(cloned.isDisposed, isFalse);
        expect(cloned.keyId, equals(42));

        cloned.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        expect(cert.isDisposed, isFalse);
        cert.dispose();
      });

      test('isDisposed is true after dispose', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        cert.dispose();
        expect(cert.isDisposed, isTrue);
      });

      test('double dispose is safe', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        cert.dispose();
        expect(() => cert.dispose(), returnsNormally);
      });

      test('keyId throws after dispose', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        cert.dispose();
        expect(() => cert.keyId, throwsStateError);
      });

      test('serialize throws after dispose', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        cert.dispose();
        expect(() => cert.serialize(), throwsStateError);
      });

      test('getKey throws after dispose', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        cert.dispose();
        expect(() => cert.getKey(), throwsStateError);
      });

      test('certificate throws after dispose', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        cert.dispose();
        expect(() => cert.certificate, throwsStateError);
      });

      test('signature throws after dispose', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        cert.dispose();
        expect(() => cert.signature, throwsStateError);
      });

      test('clone throws after dispose', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        cert.dispose();
        expect(() => cert.clone(), throwsStateError);
      });

      test('pointer throws after dispose', () {
        final cert = ServerCertificate.create(
          keyId: 1,
          serverKey: serverKey,
          trustRoot: trustRootPrivate,
        );

        cert.dispose();
        expect(() => cert.pointer, throwsStateError);
      });
    });
  });
}
