import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  group('LibSignal', () {
    test('can be initialized', () {
      LibSignal.init();
      expect(LibSignal.isInitialized, isTrue);
    });

    test('init is idempotent', () {
      LibSignal.init();
      LibSignal.init();
      LibSignal.init();
      expect(LibSignal.isInitialized, isTrue);
    });

    test('cleanup works', () {
      LibSignal.init();
      expect(LibSignal.isInitialized, isTrue);

      LibSignal.cleanup();
      expect(LibSignal.isInitialized, isFalse);
    });

    test('getVersion returns a string', () {
      LibSignal.init();
      final version = LibSignal.getVersion();
      expect(version, isA<String>());
    });

    test('getSupportedAlgorithms returns algorithm map', () {
      final algorithms = LibSignal.getSupportedAlgorithms();

      expect(algorithms, isA<Map<String, List<String>>>());
      expect(algorithms['key_agreement'], contains('X25519'));
      expect(algorithms['signature'], contains('Ed25519'));
      expect(algorithms['encryption'], contains('AES-256-GCM-SIV'));
    });
  });

  group('LibSignalException', () {
    test('basic exception', () {
      final exception = LibSignalException('Test error');

      expect(exception.message, equals('Test error'));
      expect(exception.errorCode, isNull);
      expect(exception.context, isNull);
      expect(exception.toString(), contains('Test error'));
    });

    test('exception with error code and context', () {
      final exception = LibSignalException(
        'Operation failed',
        errorCode: 42,
        context: 'test_operation',
      );

      expect(exception.message, equals('Operation failed'));
      expect(exception.errorCode, equals(42));
      expect(exception.context, equals('test_operation'));
      expect(exception.toString(), contains('42'));
      expect(exception.toString(), contains('test_operation'));
    });

    test('invalidArgument factory', () {
      final exception = LibSignalException.invalidArgument('key', 'too short');

      expect(exception.message, contains('Invalid argument'));
      expect(exception.message, contains('key'));
      expect(exception.message, contains('too short'));
    });

    test('nullPointer factory', () {
      final exception = LibSignalException.nullPointer('generateKey');

      expect(exception.message, contains('Null pointer'));
      expect(exception.context, equals('generateKey'));
    });

    test('unsupported factory', () {
      final exception = LibSignalException.unsupported(
        'oldAlgorithm',
        reason: 'deprecated',
      );

      expect(exception.message, contains('Unsupported'));
      expect(exception.message, contains('oldAlgorithm'));
      expect(exception.message, contains('deprecated'));
    });

    test('serialization factory', () {
      final exception = LibSignalException.serialization(
        'PrivateKey',
        reason: 'invalid format',
      );

      expect(exception.message, contains('serialize'));
      expect(exception.message, contains('PrivateKey'));
    });

    test('cryptoError factory', () {
      final exception = LibSignalException.cryptoError(
        'decrypt',
        errorCode: -1,
      );

      expect(exception.message, contains('Cryptographic'));
      expect(exception.message, contains('decrypt'));
      expect(exception.errorCode, equals(-1));
    });
  });
}
