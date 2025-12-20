import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('ProtocolAddress', () {
    group('constructor', () {
      test('creates address with name and deviceId', () {
        final address = ProtocolAddress('alice-uuid', 1);

        expect(address, isNotNull);
        expect(address.isDisposed, isFalse);

        address.dispose();
      });

      test('accepts device ID 0', () {
        final address = ProtocolAddress('user', 0);

        expect(address.deviceId, equals(0));

        address.dispose();
      });

      test('accepts large device IDs', () {
        final address = ProtocolAddress('user', 999999);

        expect(address.deviceId, equals(999999));

        address.dispose();
      });

      test('accepts empty name', () {
        final address = ProtocolAddress('', 1);

        expect(address.name, equals(''));

        address.dispose();
      });

      test('accepts UUID-like names', () {
        const uuid = '550e8400-e29b-41d4-a716-446655440000';
        final address = ProtocolAddress(uuid, 1);

        expect(address.name, equals(uuid));

        address.dispose();
      });

      test('accepts names with special characters', () {
        const name = 'user@example.com';
        final address = ProtocolAddress(name, 1);

        expect(address.name, equals(name));

        address.dispose();
      });
    });

    group('name getter', () {
      test('returns correct name', () {
        final address = ProtocolAddress('test-user', 5);

        expect(address.name, equals('test-user'));

        address.dispose();
      });
    });

    group('deviceId getter', () {
      test('returns correct deviceId', () {
        final address = ProtocolAddress('user', 42);

        expect(address.deviceId, equals(42));

        address.dispose();
      });
    });

    group('clone()', () {
      test('creates independent copy', () {
        final original = ProtocolAddress('user', 1);
        final cloned = original.clone();

        expect(cloned.name, equals(original.name));
        expect(cloned.deviceId, equals(original.deviceId));

        original.dispose();

        // Cloned should still work
        expect(cloned.isDisposed, isFalse);
        expect(cloned.name, equals('user'));
        expect(cloned.deviceId, equals(1));

        cloned.dispose();
      });
    });

    group('toString()', () {
      test('formats as ProtocolAddress(name:deviceId)', () {
        final address = ProtocolAddress('alice', 3);

        expect(address.toString(), equals('ProtocolAddress(alice:3)'));

        address.dispose();
      });

      test('shows disposed state', () {
        final address = ProtocolAddress('alice', 3);
        address.dispose();

        expect(address.toString(), equals('ProtocolAddress(disposed)'));
      });
    });

    group('== and hashCode', () {
      test('equal addresses have same hashCode', () {
        final addr1 = ProtocolAddress('user', 1);
        final addr2 = ProtocolAddress('user', 1);

        expect(addr1.hashCode, equals(addr2.hashCode));

        addr1.dispose();
        addr2.dispose();
      });

      test('operator == returns true for same name and deviceId', () {
        final addr1 = ProtocolAddress('user', 1);
        final addr2 = ProtocolAddress('user', 1);

        expect(addr1 == addr2, isTrue);

        addr1.dispose();
        addr2.dispose();
      });

      test('operator == returns false for different name', () {
        final addr1 = ProtocolAddress('alice', 1);
        final addr2 = ProtocolAddress('bob', 1);

        expect(addr1 == addr2, isFalse);

        addr1.dispose();
        addr2.dispose();
      });

      test('operator == returns false for different deviceId', () {
        final addr1 = ProtocolAddress('user', 1);
        final addr2 = ProtocolAddress('user', 2);

        expect(addr1 == addr2, isFalse);

        addr1.dispose();
        addr2.dispose();
      });

      test('disposed addresses return hashCode 0', () {
        final address = ProtocolAddress('user', 1);
        address.dispose();

        expect(address.hashCode, equals(0));
      });

      test('disposed addresses are not equal', () {
        final addr1 = ProtocolAddress('user', 1);
        final addr2 = ProtocolAddress('user', 1);

        addr1.dispose();

        expect(addr1 == addr2, isFalse);
        expect(addr2 == addr1, isFalse);

        addr2.dispose();
      });

      test('address equals itself', () {
        final address = ProtocolAddress('user', 1);

        // ignore: unnecessary_statements
        expect(address == address, isTrue);

        address.dispose();
      });
    });

    group('disposal', () {
      test('isDisposed is false initially', () {
        final address = ProtocolAddress('user', 1);

        expect(address.isDisposed, isFalse);

        address.dispose();
      });

      test('isDisposed is true after dispose', () {
        final address = ProtocolAddress('user', 1);
        address.dispose();

        expect(address.isDisposed, isTrue);
      });

      test('double dispose is safe', () {
        final address = ProtocolAddress('user', 1);
        address.dispose();

        expect(() => address.dispose(), returnsNormally);
      });

      test('name throws after dispose', () {
        final address = ProtocolAddress('user', 1);
        address.dispose();

        expect(() => address.name, throwsStateError);
      });

      test('deviceId throws after dispose', () {
        final address = ProtocolAddress('user', 1);
        address.dispose();

        expect(() => address.deviceId, throwsStateError);
      });

      test('clone throws after dispose', () {
        final address = ProtocolAddress('user', 1);
        address.dispose();

        expect(() => address.clone(), throwsStateError);
      });

      test('pointer throws after dispose', () {
        final address = ProtocolAddress('user', 1);
        address.dispose();

        expect(() => address.pointer, throwsStateError);
      });
    });
  });
}
