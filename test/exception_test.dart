import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  group('LibSignalException', () {
    group('constructor', () {
      test('creates exception with message only', () {
        final exception = LibSignalException('Test error');

        expect(exception.message, equals('Test error'));
        expect(exception.errorCode, isNull);
        expect(exception.context, isNull);
        expect(exception.stackTrace, isNull);
      });

      test('creates exception with all parameters', () {
        final trace = StackTrace.current;
        final exception = LibSignalException(
          'Test error',
          errorCode: 42,
          context: 'test_context',
          stackTrace: trace,
        );

        expect(exception.message, equals('Test error'));
        expect(exception.errorCode, equals(42));
        expect(exception.context, equals('test_context'));
        expect(exception.stackTrace, equals(trace));
      });
    });

    group('invalidArgument factory', () {
      test('creates exception with correct message format', () {
        final exception = LibSignalException.invalidArgument(
          'testArg',
          'must be positive',
        );

        expect(
          exception.message,
          equals('Invalid argument "testArg": must be positive'),
        );
        expect(exception.context, equals('argument_validation'));
        expect(exception.errorCode, isNull);
      });
    });

    group('nullPointer factory', () {
      test('creates exception with correct message format', () {
        final exception = LibSignalException.nullPointer('signal_test_func');

        expect(
          exception.message,
          equals('Null pointer returned from native library'),
        );
        expect(exception.context, equals('signal_test_func'));
        expect(exception.errorCode, isNull);
      });
    });

    group('unsupported factory', () {
      test('creates exception without reason', () {
        final exception = LibSignalException.unsupported('testOperation');

        expect(
          exception.message,
          equals('Unsupported operation: testOperation'),
        );
        expect(exception.context, equals('testOperation'));
      });

      test('creates exception with reason', () {
        final exception = LibSignalException.unsupported(
          'testOperation',
          reason: 'not implemented yet',
        );

        expect(
          exception.message,
          equals('Unsupported operation: testOperation (not implemented yet)'),
        );
        expect(exception.context, equals('testOperation'));
      });
    });

    group('serialization factory', () {
      test('creates exception without reason', () {
        final exception = LibSignalException.serialization('PublicKey');

        expect(
          exception.message,
          equals('Failed to serialize/deserialize PublicKey'),
        );
        expect(exception.context, equals('serialization'));
      });

      test('creates exception with reason', () {
        final exception = LibSignalException.serialization(
          'PublicKey',
          reason: 'invalid length',
        );

        expect(
          exception.message,
          equals('Failed to serialize/deserialize PublicKey: invalid length'),
        );
        expect(exception.context, equals('serialization'));
      });
    });

    group('cryptoError factory', () {
      test('creates exception without error code', () {
        final exception = LibSignalException.cryptoError('key generation');

        expect(
          exception.message,
          equals('Cryptographic operation failed: key generation'),
        );
        expect(exception.context, equals('crypto'));
        expect(exception.errorCode, isNull);
      });

      test('creates exception with error code', () {
        final exception = LibSignalException.cryptoError(
          'decryption',
          errorCode: -1,
        );

        expect(
          exception.message,
          equals('Cryptographic operation failed: decryption'),
        );
        expect(exception.context, equals('crypto'));
        expect(exception.errorCode, equals(-1));
      });
    });

    group('toString()', () {
      test('formats message only', () {
        final exception = LibSignalException('Simple error');

        expect(
          exception.toString(),
          equals('LibSignalException: Simple error'),
        );
      });

      test('formats message with error code', () {
        final exception = LibSignalException('Error', errorCode: 123);

        expect(
          exception.toString(),
          equals('LibSignalException: Error (error code: 123)'),
        );
      });

      test('formats message with context', () {
        final exception = LibSignalException('Error', context: 'test_func');

        expect(
          exception.toString(),
          equals('LibSignalException: Error [context: test_func]'),
        );
      });

      test('formats message with error code and context', () {
        final exception = LibSignalException(
          'Error',
          errorCode: 42,
          context: 'test_func',
        );

        expect(
          exception.toString(),
          equals(
            'LibSignalException: Error (error code: 42) [context: test_func]',
          ),
        );
      });
    });

    group('implements Exception', () {
      test('can be thrown and caught as Exception', () {
        expect(
          () => throw LibSignalException('test'),
          throwsA(isA<Exception>()),
        );
      });

      test('can be thrown and caught as LibSignalException', () {
        expect(
          () => throw LibSignalException('test'),
          throwsA(isA<LibSignalException>()),
        );
      });
    });
  });
}
