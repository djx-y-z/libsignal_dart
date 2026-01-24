import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });
  tearDownAll(() => LibSignal.cleanup());

  group('ProtocolAddress', () {
    group('constructor', () {
      test('creates address with name and deviceId', () {
        final address = ProtocolAddress(name: 'alice-uuid', deviceId: 1);

        expect(address, isNotNull);
      });

      test('rejects device ID 0', () {
        // libsignal requires device ID > 0
        expect(
          () => ProtocolAddress(name: 'user', deviceId: 0),
          throwsA(anything),
        );
      });

      test('accepts device ID 1 (minimum valid)', () {
        final address = ProtocolAddress(name: 'user', deviceId: 1);

        expect(address.deviceId(), equals(1));
      });

      test('accepts device ID 100', () {
        final address = ProtocolAddress(name: 'user', deviceId: 100);
        expect(address.deviceId(), equals(100));
      });

      test('accepts UUID-like names', () {
        const uuid = '550e8400-e29b-41d4-a716-446655440000';
        final address = ProtocolAddress(name: uuid, deviceId: 1);

        expect(address.name(), equals(uuid));
      });

      test('accepts names with special characters', () {
        const name = 'user@example.com';
        final address = ProtocolAddress(name: name, deviceId: 1);

        expect(address.name(), equals(name));
      });

      test('accepts device ID 127 (maximum valid)', () {
        final address = ProtocolAddress(name: 'user', deviceId: 127);
        expect(address.deviceId(), equals(127));
      });
    });

    group('name()', () {
      test('returns correct name', () {
        final address = ProtocolAddress(name: 'test-user', deviceId: 5);

        expect(address.name(), equals('test-user'));
      });
    });

    group('deviceId()', () {
      test('returns correct deviceId', () {
        final address = ProtocolAddress(name: 'user', deviceId: 42);

        expect(address.deviceId(), equals(42));
      });
    });
  });
}
