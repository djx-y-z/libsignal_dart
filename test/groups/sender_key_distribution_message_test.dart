import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });
  tearDownAll(() => LibSignal.cleanup());

  // Note: Distribution message operations are now handled via GroupCipher class:
  // - GroupCipher.createDistributionMessage() creates a distribution message
  // - GroupCipher.processDistributionMessage() processes one from another member

  group('Sender Key Distribution Message', () {
    late InMemorySenderKeyStore senderKeyStore;
    late InMemoryIdentityKeyStore identityKeyStore;
    late GroupCipher cipher;
    late ProtocolAddress address;
    const distributionId = '00000000-0000-0000-0000-000000000001';

    setUp(() {
      final identityKeyPair = IdentityKeyPair.generate();
      senderKeyStore = InMemorySenderKeyStore();
      identityKeyStore = InMemoryIdentityKeyStore(identityKeyPair, 12345);
      cipher = GroupCipher(
        senderKeyStore: senderKeyStore,
        identityKeyStore: identityKeyStore,
      );
      address = ProtocolAddress(name: 'sender', deviceId: 1);
    });

    group('createDistributionMessage', () {
      test('creates distribution message', () async {
        final distMessage = await cipher.createDistributionMessage(
          address,
          distributionId,
        );

        expect(distMessage, isNotEmpty);
        expect(distMessage.length, greaterThan(50));
      });

      test('creates different messages for different groups', () async {
        const distributionId2 = '00000000-0000-0000-0000-000000000002';

        final distMessage1 = await cipher.createDistributionMessage(
          address,
          distributionId,
        );
        final distMessage2 = await cipher.createDistributionMessage(
          address,
          distributionId2,
        );

        // Distribution messages for different groups should differ
        expect(distMessage1, isNot(equals(distMessage2)));
      });
    });

    group('processDistributionMessage', () {
      test('processes distribution message', () async {
        // Create another party's cipher
        final senderIdentity = IdentityKeyPair.generate();
        final senderSenderKeyStore = InMemorySenderKeyStore();
        final senderIdentityStore = InMemoryIdentityKeyStore(
          senderIdentity,
          54321,
        );
        final senderCipher = GroupCipher(
          senderKeyStore: senderSenderKeyStore,
          identityKeyStore: senderIdentityStore,
        );
        final senderAddress = ProtocolAddress(name: 'other', deviceId: 1);

        // Sender creates distribution message
        final distMessage = await senderCipher.createDistributionMessage(
          senderAddress,
          distributionId,
        );

        // We process it
        await cipher.processDistributionMessage(
          senderAddress,
          distributionId,
          distMessage,
        );

        // We should now have their sender key stored
        final senderKeyName = SenderKeyName(senderAddress, distributionId);
        final storedKey = await senderKeyStore.loadSenderKey(senderKeyName);
        expect(storedKey, isNotNull);
      });

      test('rejects empty message', () async {
        final senderAddress = ProtocolAddress(name: 'other', deviceId: 1);
        expect(
          () async => cipher.processDistributionMessage(
            senderAddress,
            distributionId,
            Uint8List(0),
          ),
          throwsA(anything),
        );
      });

      test('rejects garbage data', () async {
        final senderAddress = ProtocolAddress(name: 'other', deviceId: 1);
        final garbage = Uint8List.fromList([0x99, 0x88, 0x77, 0x66, 0x55]);
        expect(
          () async => cipher.processDistributionMessage(
            senderAddress,
            distributionId,
            garbage,
          ),
          throwsA(anything),
        );
      });
    });

    // Note: Tests for SenderKeyDistributionMessage class are not applicable
    // because the API now returns raw bytes rather than a structured class.
  });
}
