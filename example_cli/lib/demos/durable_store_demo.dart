import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

import '../stores/durable_file_stores.dart';
import '../utils.dart';

/// Demonstrates **durable** stores: a conversation that survives a restart.
///
/// The Double Ratchet derives message keys deterministically, so losing (or
/// rolling back) a session write makes the next send reuse a message key and IV.
/// [DurableFileStores] therefore flushes every write to stable storage before
/// its future completes — which is what the library awaits before handing back a
/// ciphertext or plaintext.
///
/// The proof is step 7 onwards: the stores are closed, every object is dropped,
/// and the conversation continues from what is on disk alone. With
/// `InMemory*Store` the same sequence fails at step 8: reopening produces empty
/// stores, so `encrypt` finds no session to advance and throws.
///
/// Note that all cipher calls go through [AddressLocks]: durability is only half
/// the contract, the other half is never running two operations for one address
/// concurrently.
Future<void> runDurableStoreDemo() async {
  printHeader('Durable Store Demo');

  final root = await Directory.systemTemp.createTemp('libsignal_durable_');
  final aliceDir = '${root.path}/alice';
  final bobDir = '${root.path}/bob';

  final aliceAddress = ProtocolAddress(name: 'alice', deviceId: 1);
  final bobAddress = ProtocolAddress(name: 'bob', deviceId: 1);

  const preKeyId = 42;
  const signedPreKeyId = 7;
  const kyberPreKeyId = 1;

  try {
    // 1. Open the stores. The identity key pair and registration ID are
    //    generated on first open and durably persisted; every later open
    //    restores them.
    var alice = await DurableFileStores.open(aliceDir);
    var bob = await DurableFileStores.open(bobDir);
    final bobRegistrationId = await bob.identity.getLocalRegistrationId();
    final bobIdentity = await bob.identity.getIdentityKeyPair();
    printStep(1, 'Durable stores opened (journal per participant)', [
      'Alice: $aliceDir/stores.journal',
      'Bob:   $bobDir/stores.journal',
      'Bob registration ID: $bobRegistrationId (persisted on first open)',
      'Bob identity: ${bytesToHex(bobIdentity.publicKey, maxLength: 24)}',
    ]);
    print('');

    // 2. Bob publishes pre-keys. Each store call returns only after the record
    //    is on disk, so a crash here cannot leave a bundle advertising keys Bob
    //    no longer has.
    final bobPrivate = PrivateKey.deserialize(
      bytes: bobIdentity.privateKey.toList(),
    );
    final timestamp = BigInt.from(
      DateTime.now().toUtc().millisecondsSinceEpoch,
    );

    final preKeyPrivate = PrivateKey.generate();
    final preKeyPublic = preKeyPrivate.getPublicKey();
    await bob.preKey.storePreKey(
      preKeyId,
      PreKeyRecord(
        id: preKeyId,
        publicKey: preKeyPublic,
        privateKey: preKeyPrivate,
      ),
    );

    final signedPreKeyPrivate = PrivateKey.generate();
    final signedPreKeyPublic = signedPreKeyPrivate.getPublicKey();
    final signedPreKeySignature = bobPrivate.sign(
      message: signedPreKeyPublic.serialize().toList(),
    );
    await bob.signedPreKey.storeSignedPreKey(
      signedPreKeyId,
      SignedPreKeyRecord(
        id: signedPreKeyId,
        publicKey: signedPreKeyPublic,
        privateKey: signedPreKeyPrivate,
        signature: signedPreKeySignature.toList(),
        timestamp: timestamp,
      ),
    );

    final kyberKeyPair = KyberKeyPair.generate();
    final kyberPreKeyPublic = kyberKeyPair.getPublicKey();
    final kyberPreKeySignature = bobPrivate.sign(
      message: kyberPreKeyPublic.serialize().toList(),
    );
    await bob.kyberPreKey.storeKyberPreKey(
      kyberPreKeyId,
      KyberPreKeyRecord.create(
        id: kyberPreKeyId,
        keyPair: kyberKeyPair,
        signature: kyberPreKeySignature.toList(),
        timestamp: timestamp,
      ),
    );

    printStep(2, "Bob's pre-keys persisted durably", [
      'One-time pre-key: $preKeyId',
      'Signed pre-key: $signedPreKeyId',
      'Kyber pre-key: $kyberPreKeyId (post-quantum)',
      'Journal size: ${await bob.journal.sizeInBytes()} bytes',
    ]);
    print('');

    // 3. Alice establishes the session from Bob's bundle. The lock is held
    //    around the whole call, not inside the store.
    final bobBundle = PreKeyBundle(
      registrationId: bobRegistrationId,
      deviceId: bobAddress.deviceId(),
      preKeyId: preKeyId,
      preKeyPublic: preKeyPublic.serialize(),
      signedPreKeyId: signedPreKeyId,
      signedPreKeyPublic: signedPreKeyPublic.serialize().toList(),
      signedPreKeySignature: signedPreKeySignature.toList(),
      identityKey: bobIdentity.publicKey.toList(),
      kyberPreKeyId: kyberPreKeyId,
      kyberPreKeyPublic: kyberPreKeyPublic.serialize().toList(),
      kyberPreKeySignature: kyberPreKeySignature.toList(),
    );

    await alice.locks.synchronized(
      AddressLocks.forAddress(bobAddress),
      () => SessionBuilder(
        localAddress: aliceAddress,
        sessionStore: alice.session,
        identityKeyStore: alice.identity,
      ).processPreKeyBundle(bobAddress, bobBundle),
    );
    printStep(3, 'Alice established a session (X3DH/PQXDH)', [
      'Session + remote identity written to disk before returning',
      'Has session with Bob: ${await alice.session.containsSession(bobAddress)}',
    ]);
    print('');

    // 4. First exchange. `send`/`receive` below wrap each cipher call in the
    //    per-address lock — copy that pattern, not a lock inside the store.
    Future<CiphertextMessage> send(
      DurableFileStores stores,
      ProtocolAddress from,
      ProtocolAddress to,
      String text,
    ) => stores.locks.synchronized(
      AddressLocks.forAddress(to),
      () => _cipherFor(
        stores,
        from,
      ).encrypt(to, Uint8List.fromList(utf8.encode(text))),
    );

    Future<String> receive(
      DurableFileStores stores,
      ProtocolAddress self,
      ProtocolAddress from,
      CiphertextMessage message,
    ) => stores.locks.synchronized(
      AddressLocks.forAddress(from),
      () async =>
          utf8.decode(await _cipherFor(stores, self).decrypt(from, message)),
    );

    const message1 = 'Hello Bob! Written to disk before it was sent.';
    final encrypted1 = await send(alice, aliceAddress, bobAddress, message1);
    final decrypted1 = await receive(bob, bobAddress, aliceAddress, encrypted1);
    printStep(4, 'Alice → Bob (pre-key message)', [
      'Decrypted: "$decrypted1"',
      'Match: ${decrypted1 == message1}',
      'Bob consumed pre-key $preKeyId durably: '
          '${!await bob.preKey.containsPreKey(preKeyId)}',
    ]);
    print('');

    const message2 = 'Hi Alice! The ratchet advanced on both sides.';
    final encrypted2 = await send(bob, bobAddress, aliceAddress, message2);
    final decrypted2 = await receive(
      alice,
      aliceAddress,
      bobAddress,
      encrypted2,
    );
    printStep(5, 'Bob → Alice (reply)', [
      'Decrypted: "$decrypted2"',
      'Match: ${decrypted2 == message2}',
    ]);
    print('');

    final aliceBytes = await alice.journal.sizeInBytes();
    final bobBytes = await bob.journal.sizeInBytes();

    // 6/7. Simulate a restart: close the journals and drop every object. Only
    //      what was flushed to disk survives.
    await alice.close();
    await bob.close();
    printStep(6, 'Stores closed — simulating process exit', [
      "Alice's journal: $aliceBytes bytes",
      "Bob's journal: $bobBytes bytes",
      'All in-memory state discarded',
    ]);
    print('');

    alice = await DurableFileStores.open(aliceDir);
    bob = await DurableFileStores.open(bobDir);
    printStep(7, 'Stores reopened from disk (journal replayed)', [
      'Alice still has a session with Bob: '
          '${await alice.session.containsSession(bobAddress)}',
      'Bob still knows the pre-key was consumed: '
          '${!await bob.preKey.containsPreKey(preKeyId)}',
      'Bob refuses to serve the consumed Kyber pre-key: '
          '${await bob.kyberPreKey.loadKyberPreKey(kyberPreKeyId) == null}',
      'Bob kept his identity: '
          '${bytesToHex((await bob.identity.getIdentityKeyPair()).publicKey, maxLength: 24)}',
      'Bob kept his registration ID: '
          '${await bob.identity.getLocalRegistrationId() == bobRegistrationId}',
    ]);
    print('');

    // 8. The real test: continue the conversation using only restored state.
    //    The ratchet picks up where it left off — no key is reused, and no
    //    session has to be re-established.
    const message3 = 'Still the same session, after a restart.';
    final encrypted3 = await send(alice, aliceAddress, bobAddress, message3);
    final decrypted3 = await receive(bob, bobAddress, aliceAddress, encrypted3);

    // Enforce the claim rather than just printing it: a resumed session emits a
    // plain SignalMessage. A pre-key message would mean the session had been
    // rebuilt from the bundle instead of restored from disk.
    if (encrypted3.isPreKeyMessage) {
      throw StateError(
        'Session was not resumed from disk: Alice sent a PreKeySignalMessage, '
        'which means a fresh session was established.',
      );
    }

    printStep(8, 'Alice → Bob, after the restart', [
      'Message type: '
          '${encrypted3.isPreKeyMessage ? "PreKeySignalMessage" : "SignalMessage"}'
          ' (a fresh session would have been a pre-key message)',
      'Decrypted: "$decrypted3"',
      'Match: ${decrypted3 == message3}',
    ]);
    print('');

    const message4 = 'And the reply chain survived too.';
    final encrypted4 = await send(bob, bobAddress, aliceAddress, message4);
    final decrypted4 = await receive(
      alice,
      aliceAddress,
      bobAddress,
      encrypted4,
    );
    printStep(9, 'Bob → Alice, after the restart', [
      'Decrypted: "$decrypted4"',
      'Match: ${decrypted4 == message4}',
    ]);
    print('');

    // 10. What a *last-resort* Kyber key can still catch. The one-time key from
    //     step 2 is retired once used, so a replay of that message simply fails
    //     to decrypt. A last-resort key is designed to be reused and therefore
    //     cannot be retired — its only defence is the (kyberPreKeyId,
    //     signedPreKeyId, baseKey) triple `markKyberPreKeyUsed` now carries.
    //     Seeing that triple twice means one pre-key message was processed
    //     twice, which is exactly what the missing rollback protection above
    //     makes possible.
    const lastResortKyberId = 2;
    const davePreKeyId = 43;
    final daveAddress = ProtocolAddress(name: 'dave', deviceId: 1);
    final dave = await DurableFileStores.open('${root.path}/dave');

    final davePreKeyPrivate = PrivateKey.generate();
    final davePreKeyPublic = davePreKeyPrivate.getPublicKey();
    await bob.preKey.storePreKey(
      davePreKeyId,
      PreKeyRecord(
        id: davePreKeyId,
        publicKey: davePreKeyPublic,
        privateKey: davePreKeyPrivate,
      ),
    );

    final lastResortKeyPair = KyberKeyPair.generate();
    final lastResortPublic = lastResortKeyPair.getPublicKey();
    final lastResortSignature = bobPrivate.sign(
      message: lastResortPublic.serialize().toList(),
    );
    // The flag lives here, not in the record: libsignal does not carry it, so
    // the store that generated the key is the only place that knows.
    await bob.kyberPreKey.storeKyberPreKey(
      lastResortKyberId,
      KyberPreKeyRecord.create(
        id: lastResortKyberId,
        keyPair: lastResortKeyPair,
        signature: lastResortSignature.toList(),
        timestamp: timestamp,
      ),
      lastResort: true,
    );

    await dave.locks.synchronized(
      AddressLocks.forAddress(bobAddress),
      () =>
          SessionBuilder(
            localAddress: daveAddress,
            sessionStore: dave.session,
            identityKeyStore: dave.identity,
          ).processPreKeyBundle(
            bobAddress,
            PreKeyBundle(
              registrationId: bobRegistrationId,
              deviceId: bobAddress.deviceId(),
              preKeyId: davePreKeyId,
              preKeyPublic: davePreKeyPublic.serialize(),
              signedPreKeyId: signedPreKeyId,
              signedPreKeyPublic: signedPreKeyPublic.serialize().toList(),
              signedPreKeySignature: signedPreKeySignature.toList(),
              identityKey: bobIdentity.publicKey.toList(),
              kyberPreKeyId: lastResortKyberId,
              kyberPreKeyPublic: lastResortPublic.serialize().toList(),
              kyberPreKeySignature: lastResortSignature.toList(),
            ),
          ),
    );

    const message5 = 'Hello Bob, this one used your last-resort Kyber key.';
    final encrypted5 = await send(dave, daveAddress, bobAddress, message5);
    final decrypted5 = await receive(bob, bobAddress, daveAddress, encrypted5);
    final marksAfterFirst = bob.kyberPreKey.replayedAgreements.length;

    // Simulate the rollback this example does not protect against: Bob's state
    // is restored from a backup taken before the message arrived.
    await bob.session.deleteSession(daveAddress);
    await bob.preKey.storePreKey(
      davePreKeyId,
      PreKeyRecord(
        id: davePreKeyId,
        publicKey: davePreKeyPublic,
        privateKey: davePreKeyPrivate,
      ),
    );

    // The very same ciphertext now establishes a session all over again — the
    // last-resort key is still served, as intended.
    final replayed = await receive(bob, bobAddress, daveAddress, encrypted5);

    printStep(10, 'Rollback + replay against a last-resort Kyber key', [
      'Dave → Bob decrypted: "$decrypted5"',
      'Match: ${decrypted5 == message5}',
      'Last-resort key still served after use: '
          '${await bob.kyberPreKey.loadKyberPreKey(lastResortKyberId) != null}',
      'Replays detected before the rollback: $marksAfterFirst',
      'Same message decrypted again after the rollback: '
          '${replayed == message5}',
      'Replays detected now: ${bob.kyberPreKey.replayedAgreements.length} '
          '(the identical PQXDH agreement was marked twice)',
      'Nothing in the library rejected it — the store reports the repeat and',
      'the application decides to drop the message.',
    ]);
    print('');

    await dave.close();
    await alice.close();
    await bob.close();

    print('   Takeaways:');
    print('   - Every store write is flushed before its future completes, so');
    print('     the library never releases output whose state could be lost.');
    print('   - Cipher calls are serialized per address at the call site; a');
    print('     lock inside the store would not cover load → ratchet → store.');
    print('   - This example is NOT encrypted at rest and has no rollback');
    print('     protection: see SECURITY.md before shipping it.');
    print('');
  } finally {
    await root.delete(recursive: true);
  }
}

SessionCipher _cipherFor(DurableFileStores stores, ProtocolAddress self) =>
    SessionCipher(
      localAddress: self,
      sessionStore: stores.session,
      identityKeyStore: stores.identity,
      preKeyStore: stores.preKey,
      signedPreKeyStore: stores.signedPreKey,
      kyberPreKeyStore: stores.kyberPreKey,
    );
