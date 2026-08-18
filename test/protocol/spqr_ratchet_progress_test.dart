// Diagnostic for issue #62: does the sparse post-quantum ratchet (SPQR)
// actually progress through a long conversation over the Dart bindings?
//
// SPQR spreads ML-KEM-768 material over many messages, 32 bytes per message
// (`CHUNK_SIZE = 32` in spqr's polynomial encoder). The initiator has to ship a
// 64-byte header + 32-byte MAC (3 chunks) and a 1152-byte encapsulation key
// (36 chunks); the responder answers with a 960-byte CT1 (30 chunks) and a
// 128-byte CT2 + MAC (5 chunks). So a full epoch takes ~40 messages per side,
// and every one of them is the same ~37 bytes on the wire. Sizes alone
// therefore say nothing — the epoch and the payload type do.
//
// Wire format (spqr v1, src/v1/chunked/states/serialize.rs):
//   [version:1][epoch:varint][index:varint][message_type:1]
//   optionally followed by [chunk index:varint][chunk data:32]
// message_type: 0=None 1=Hdr 2=Ek 3=EkCt1Ack 4=Ct1Ack 5=Ct1 6=Ct2
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

import '../test_helpers/test_party.dart';

const _typeNames = <int, String>{
  0: 'None',
  1: 'Hdr',
  2: 'Ek',
  3: 'EkCt1Ack',
  4: 'Ct1Ack',
  5: 'Ct1',
  6: 'Ct2',
};

/// A decoded SPQR frame header (everything except the chunk payload).
class PqFrame {
  PqFrame({
    required this.version,
    required this.epoch,
    required this.index,
    required this.type,
    required this.chunkIndex,
    required this.length,
  });

  final int version;
  final int epoch;
  final int index;
  final int type;

  /// Index of the 32-byte chunk carried by this frame, or null for the
  /// payload types that carry no chunk (`None`, `Ct1Ack`).
  final int? chunkIndex;
  final int length;

  String get typeName => _typeNames[type] ?? 'type($type)';

  @override
  String toString() =>
      'v$version epoch=$epoch index=$index $typeName'
      '${chunkIndex == null ? '' : ' chunk=$chunkIndex'} ${length}B';
}

(int value, int next) _varint(Uint8List bytes, int at) {
  var out = 0;
  var shift = 0;
  var i = at;
  while (i < bytes.length) {
    final b = bytes[i];
    out |= (b & 0x7f) << shift;
    i++;
    if (b & 0x80 == 0) return (out, i);
    shift += 7;
  }
  throw FormatException('truncated varint at $at');
}

PqFrame decodePq(Uint8List pq) {
  final version = pq[0];
  final (epoch, afterEpoch) = _varint(pq, 1);
  final (index, afterIndex) = _varint(pq, afterEpoch);
  final type = pq[afterIndex];
  // `None` (0) and `Ct1Ack` (4) are the two payloads with no chunk attached.
  final carriesChunk = type != 0 && type != 4;
  return PqFrame(
    version: version,
    epoch: epoch,
    index: index,
    type: type,
    chunkIndex: carriesChunk ? _varint(pq, afterIndex + 1).$1 : null,
    length: pq.length,
  );
}

void main() {
  setUpAll(LibSignal.init);

  test(
    'SPQR advances past epoch 1 over a long conversation',
    () async {
      // bob is the initiator (Alice role in libsignal terms),
      // alice is the responder (Bob role) publishing the bundle.
      final bob = TestParty.create(name: 'bob', registrationId: 222);
      final alice = TestParty.create(name: 'alice', registrationId: 111)
        ..generatePreKeys(preKeyId: 42, signedPreKeyId: 7);

      await bob.sessionBuilder.processPreKeyBundle(
        alice.address,
        alice.getBundle(),
      );

      // #0 — the PreKey message. Its inner SignalMessage carries chunk 0 of the
      // initiator's SPQR header.
      final preKey = await bob.sessionCipher.encrypt(
        alice.address,
        utf8.encode('hello'),
      );
      expect(preKey.isPreKeyMessage, isTrue);
      final preKeyFrame = decodePq(
        PreKeySignalMessage.deserialize(
          data: preKey.ciphertext,
        ).message().pqRatchet()!,
      );
      expect(preKeyFrame.typeName, equals('Hdr'));
      expect(preKeyFrame.chunkIndex, equals(0));
      expect(
        utf8.decode(await alice.sessionCipher.decrypt(bob.address, preKey)),
        equals('hello'),
      );

      final bobFrames = <PqFrame>[];
      final aliceFrames = <PqFrame>[];

      Future<PqFrame> send(TestParty from, TestParty to, String body) async {
        final ct = await from.sessionCipher.encrypt(
          to.address,
          utf8.encode(body),
        );
        expect(
          ct.isPreKeyMessage,
          isFalse,
          reason: 'session should be established by now',
        );
        final pq = SignalMessage.deserialize(data: ct.ciphertext).pqRatchet();
        expect(pq, isNotNull, reason: 'SPQR must be active on every message');
        expect(
          utf8.decode(await to.sessionCipher.decrypt(from.address, ct)),
          equals(body),
        );
        return decodePq(pq!);
      }

      // Strictly alternating conversation, both directions, 200 round trips.
      // alice replies first — until the initiator sees a reply it keeps
      // wrapping its sends in PreKey messages, whose inner SignalMessage Dart
      // cannot open.
      const rounds = 200;
      for (var i = 0; i < rounds; i++) {
        aliceFrames.add(await send(alice, bob, 'alice $i'));
        bobFrames.add(await send(bob, alice, 'bob $i'));
      }

      String firstAt(List<PqFrame> frames, bool Function(PqFrame) p) {
        final idx = frames.indexWhere(p);
        return idx < 0 ? 'never' : 'msg #$idx (${frames[idx]})';
      }

      // ignore: avoid_print
      print('''
bob   (initiator): types=${bobFrames.map((f) => f.typeName).toSet().toList()}
                   sizes=${bobFrames.map((f) => f.length).toSet().toList()}
                   first Ek: ${firstAt(bobFrames, (f) => f.type == 2)}
                   first epoch>=2: ${firstAt(bobFrames, (f) => f.epoch >= 2)}
                   last: ${bobFrames.last}
alice (responder): types=${aliceFrames.map((f) => f.typeName).toSet().toList()}
                   sizes=${aliceFrames.map((f) => f.length).toSet().toList()}
                   first non-None: ${firstAt(aliceFrames, (f) => f.type != 0)}
                   first Ct2: ${firstAt(aliceFrames, (f) => f.type == 6)}
                   first epoch>=2: ${firstAt(aliceFrames, (f) => f.epoch >= 2)}
                   last: ${aliceFrames.last}''');

      // The responder's header decoder needs HEADER_SIZE + MACSIZE = 96 bytes
      // (the `PolyDecoder::new` argument in spqr's `send_ct.rs` — if a future
      // spqr bump moves that or CHUNK_SIZE, these indices move with it), i.e.
      // exactly 3 chunks, before it can answer with Ct1. Chunk 0 arrived in the
      // PreKey message (asserted above) and chunks 1 and 2 in bob's sends #0
      // and #1, so Ct1 on alice's send #2 proves the PreKey decrypt path
      // applied and persisted its inbound chunk — had it been dropped, alice
      // would still be one chunk short and this would slip to #3.
      expect(
        bobFrames.take(2).map((f) => f.chunkIndex).toList(),
        equals([1, 2]),
        reason: 'the initiator continues the header it started in the PreKey',
      );
      expect(
        aliceFrames.indexWhere((f) => f.type != 0),
        equals(2),
        reason: 'PreKey decrypt must apply its inbound SPQR chunk',
      );

      // The discriminator: reaching epoch 2 means a full ML-KEM encapsulation
      // completed and a fresh PQ secret was mixed in — which is only possible
      // if the SPQR state survived every store round-trip on both sides.
      expect(
        bobFrames.map((f) => f.epoch).reduce((a, b) => a > b ? a : b),
        greaterThanOrEqualTo(2),
        reason: 'initiator never advanced past epoch 1',
      );
      expect(
        aliceFrames.map((f) => f.epoch).reduce((a, b) => a > b ? a : b),
        greaterThanOrEqualTo(2),
        reason: 'responder never advanced past epoch 1',
      );
    },
    timeout: const Timeout(Duration(minutes: 10)),
  );

  test('responder emits empty SPQR frames until the header is complete', () async {
    // The scenario from issue #62: the responder replies several times in a row
    // without the initiator sending anything in between. The header takes three
    // 32-byte chunks, and only one has arrived (inside the PreKey message), so
    // the responder is still in `NoHeaderReceived` and has nothing to
    // encapsulate against yet.
    final bob = TestParty.create(name: 'bob', registrationId: 222);
    final alice = TestParty.create(name: 'alice', registrationId: 111)
      ..generatePreKeys(preKeyId: 42, signedPreKeyId: 7);

    await bob.sessionBuilder.processPreKeyBundle(
      alice.address,
      alice.getBundle(),
    );
    final preKey = await bob.sessionCipher.encrypt(
      alice.address,
      utf8.encode('hello'),
    );
    final preKeyFrame = decodePq(
      PreKeySignalMessage.deserialize(
        data: preKey.ciphertext,
      ).message().pqRatchet()!,
    );
    expect(preKeyFrame.chunkIndex, equals(0), reason: '1 of 3 header chunks');
    await alice.sessionCipher.decrypt(bob.address, preKey);

    for (var i = 0; i < 5; i++) {
      final ct = await alice.sessionCipher.encrypt(
        bob.address,
        utf8.encode('alice $i'),
      );
      final frame = decodePq(
        SignalMessage.deserialize(data: ct.ciphertext).pqRatchet()!,
      );
      expect(frame.length, equals(4));
      expect(frame.typeName, equals('None'));
      expect(frame.epoch, equals(1));
    }
  });
}
