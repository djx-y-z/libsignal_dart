import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() => LibSignal.init());
  tearDownAll(() => LibSignal.cleanup());

  group('InMemoryIdentityKeyStore', () {
    late IdentityKeyPair identityKeyPair;
    late InMemoryIdentityKeyStore store;
    late ProtocolAddress aliceAddress;
    late ProtocolAddress bobAddress;
    late PublicKey aliceIdentity;
    late PublicKey bobIdentity;

    setUp(() {
      identityKeyPair = IdentityKeyPair.generate();
      store = InMemoryIdentityKeyStore(identityKeyPair, 12345);
      aliceAddress = ProtocolAddress('alice', 1);
      bobAddress = ProtocolAddress('bob', 1);
      aliceIdentity = PrivateKey.generate().getPublicKey();
      bobIdentity = PrivateKey.generate().getPublicKey();
    });

    tearDown(() {
      identityKeyPair.dispose();
      aliceAddress.dispose();
      bobAddress.dispose();
      aliceIdentity.dispose();
      bobIdentity.dispose();
    });

    group('getIdentityKeyPair()', () {
      test('returns configured identity key pair', () async {
        final keyPair = await store.getIdentityKeyPair();
        expect(keyPair, equals(identityKeyPair));
      });
    });

    group('getLocalRegistrationId()', () {
      test('returns configured registration ID', () async {
        final regId = await store.getLocalRegistrationId();
        expect(regId, equals(12345));
      });

      test('works with various registration IDs', () async {
        final keyPair = IdentityKeyPair.generate();

        for (final regId in [0, 1, 100, 0xFFFF, 0x3FFF]) {
          final store = InMemoryIdentityKeyStore(keyPair, regId);
          final result = await store.getLocalRegistrationId();
          expect(result, equals(regId));
        }

        keyPair.dispose();
      });
    });

    group('saveIdentity() / getIdentity()', () {
      test('saves and retrieves identity', () async {
        await store.saveIdentity(aliceAddress, aliceIdentity);

        final retrieved = await store.getIdentity(aliceAddress);
        expect(retrieved, isNotNull);
        expect(retrieved, equals(aliceIdentity));
      });

      test('returns null for non-existent identity', () async {
        final retrieved = await store.getIdentity(aliceAddress);
        expect(retrieved, isNull);
      });

      test('saves identities for multiple addresses', () async {
        await store.saveIdentity(aliceAddress, aliceIdentity);
        await store.saveIdentity(bobAddress, bobIdentity);

        final aliceRetrieved = await store.getIdentity(aliceAddress);
        final bobRetrieved = await store.getIdentity(bobAddress);

        expect(aliceRetrieved, equals(aliceIdentity));
        expect(bobRetrieved, equals(bobIdentity));
      });

      test('saveIdentity returns true for new identity', () async {
        final result = await store.saveIdentity(aliceAddress, aliceIdentity);
        expect(result, isTrue);
      });

      test('saveIdentity returns false for same identity', () async {
        await store.saveIdentity(aliceAddress, aliceIdentity);

        final result = await store.saveIdentity(aliceAddress, aliceIdentity);
        expect(result, isFalse);
      });

      test('saveIdentity returns true for changed identity', () async {
        await store.saveIdentity(aliceAddress, aliceIdentity);

        final newIdentity = PrivateKey.generate().getPublicKey();
        final result = await store.saveIdentity(aliceAddress, newIdentity);
        expect(result, isTrue);

        final retrieved = await store.getIdentity(aliceAddress);
        expect(retrieved, equals(newIdentity));

        newIdentity.dispose();
      });

      test('overwrites existing identity', () async {
        await store.saveIdentity(aliceAddress, aliceIdentity);

        final newIdentity = PrivateKey.generate().getPublicKey();
        await store.saveIdentity(aliceAddress, newIdentity);

        final retrieved = await store.getIdentity(aliceAddress);
        expect(retrieved, equals(newIdentity));

        newIdentity.dispose();
      });
    });

    group('isTrustedIdentity()', () {
      test('trusts first-seen identity (TOFU)', () async {
        final isTrusted = await store.isTrustedIdentity(
          aliceAddress,
          aliceIdentity,
          Direction.receiving,
        );
        expect(isTrusted, isTrue);
      });

      test('trusts first-seen identity for sending', () async {
        final isTrusted = await store.isTrustedIdentity(
          aliceAddress,
          aliceIdentity,
          Direction.sending,
        );
        expect(isTrusted, isTrue);
      });

      test('trusts matching stored identity', () async {
        await store.saveIdentity(aliceAddress, aliceIdentity);

        final isTrusted = await store.isTrustedIdentity(
          aliceAddress,
          aliceIdentity,
          Direction.receiving,
        );
        expect(isTrusted, isTrue);
      });

      test('does not trust changed identity', () async {
        await store.saveIdentity(aliceAddress, aliceIdentity);

        final newIdentity = PrivateKey.generate().getPublicKey();
        final isTrusted = await store.isTrustedIdentity(
          aliceAddress,
          newIdentity,
          Direction.receiving,
        );
        expect(isTrusted, isFalse);

        newIdentity.dispose();
      });

      test('does not trust changed identity for sending', () async {
        await store.saveIdentity(aliceAddress, aliceIdentity);

        final newIdentity = PrivateKey.generate().getPublicKey();
        final isTrusted = await store.isTrustedIdentity(
          aliceAddress,
          newIdentity,
          Direction.sending,
        );
        expect(isTrusted, isFalse);

        newIdentity.dispose();
      });
    });

    group('clear()', () {
      test('clears all identities', () async {
        await store.saveIdentity(aliceAddress, aliceIdentity);
        await store.saveIdentity(bobAddress, bobIdentity);

        expect(store.length, equals(2));

        store.clear();

        expect(store.length, equals(0));
        expect(await store.getIdentity(aliceAddress), isNull);
        expect(await store.getIdentity(bobAddress), isNull);
      });

      test('clear on empty store is safe', () {
        expect(() => store.clear(), returnsNormally);
        expect(store.length, equals(0));
      });
    });

    group('length', () {
      test('tracks number of stored identities', () async {
        expect(store.length, equals(0));

        await store.saveIdentity(aliceAddress, aliceIdentity);
        expect(store.length, equals(1));

        await store.saveIdentity(bobAddress, bobIdentity);
        expect(store.length, equals(2));
      });

      test('does not increase for duplicate saves', () async {
        await store.saveIdentity(aliceAddress, aliceIdentity);
        expect(store.length, equals(1));

        await store.saveIdentity(aliceAddress, aliceIdentity);
        expect(store.length, equals(1));
      });

      test('does not increase for updated identity', () async {
        await store.saveIdentity(aliceAddress, aliceIdentity);
        expect(store.length, equals(1));

        final newIdentity = PrivateKey.generate().getPublicKey();
        await store.saveIdentity(aliceAddress, newIdentity);
        expect(store.length, equals(1));

        newIdentity.dispose();
      });
    });
  });
}
