import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';

import '../support/harness.dart';
import '../support/party.dart';

/// A session store that really suspends, as one backed by a database does: an
/// in-memory store answers before the bridge has finished waiting for it.
class _SlowSessionStore implements SessionStore {
  final _inner = InMemorySessionStore();

  Future<void> _wait() => Future<void>.delayed(const Duration(milliseconds: 5));

  @override
  Future<SessionRecord?> loadSession(ProtocolAddress address) async {
    await _wait();
    return _inner.loadSession(address);
  }

  @override
  Future<void> storeSession(
    ProtocolAddress address,
    SessionRecord record,
  ) async {
    await _wait();
    return _inner.storeSession(address, record);
  }

  @override
  Future<bool> containsSession(ProtocolAddress address) =>
      _inner.containsSession(address);

  @override
  Future<void> deleteSession(ProtocolAddress address) =>
      _inner.deleteSession(address);

  @override
  Future<void> deleteAllSessions(String name) => _inner.deleteAllSessions(name);

  @override
  Future<List<int>> getSubDeviceSessions(String name) =>
      _inner.getSubDeviceSessions(name);
}

/// What a worker isolate does for itself. Top-level, as `compute` requires.
Future<String> _roundTripInWorker(String text) async {
  await LibSignal.init();

  // A synchronous call, which posts nothing back to Dart...
  if (PrivateKey.generate().getPublicKey().serialize().length != 33) {
    throw StateError('A public key came back the wrong size.');
  }

  // ...and an asynchronous one with store callbacks, which does. That second
  // path is what an isolate left out of the library's count loses.
  final alice = Party('alice', 1111);
  final bob = Party('bob', 2222);
  await establish(alice, bob);
  final sent = await alice.cipher.encrypt(bob.address, bytesOf(text));
  return utf8.decode(await bob.cipher.decrypt(alice.address, sent));
}

void bridgeCapabilities() {
  group('the bridge', () {
    capability('store callbacks may suspend', () async {
      final slow = _SlowSessionStore();
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      final builder = SessionBuilder(
        localAddress: alice.address,
        sessionStore: slow,
        identityKeyStore: alice.identities,
      );
      final cipher = SessionCipher(
        localAddress: alice.address,
        sessionStore: slow,
        identityKeyStore: alice.identities,
        preKeyStore: alice.preKeys,
        signedPreKeyStore: alice.signedPreKeys,
        kyberPreKeyStore: alice.kyberPreKeys,
      );
      await builder.processPreKeyBundle(bob.address, await bob.publishBundle());

      final sent = await cipher.encrypt(bob.address, bytesOf('eventually'));
      expect(
        utf8.decode(await bob.cipher.decrypt(alice.address, sent)),
        'eventually',
      );
      final answer = await bob.cipher.encrypt(alice.address, bytesOf('yes'));
      expect(utf8.decode(await cipher.decrypt(bob.address, answer)), 'yes');
    });

    capability('independent conversations run concurrently', () async {
      Future<void> conversation(int n) async {
        final alice = Party('alice$n', 1000 + n);
        final bob = Party('bob$n', 2000 + n);
        await converse(alice, bob);
        for (var i = 0; i < 3; i++) {
          final sent = await alice.cipher.encrypt(
            bob.address,
            bytesOf('$n/$i'),
          );
          expect(
            utf8.decode(await bob.cipher.decrypt(alice.address, sent)),
            '$n/$i',
          );
        }
      }

      await Future.wait([for (var n = 0; n < 8; n++) conversation(n)]);
    });

    capability('large payloads cross intact', () async {
      final payload = Uint8List(1024 * 1024);
      for (var i = 0; i < payload.length; i++) {
        payload[i] = i & 0xff;
      }

      final key = hkdfDerive(
        outputLength: 32,
        inputKeyMaterial: bytesOf('input'),
        salt: const [],
        info: const [],
      );
      final nonce = Uint8List(12);
      final cipher = Aes256GcmSiv(key: key);
      final sealed = cipher.encrypt(
        plaintext: payload,
        nonce: nonce,
        associatedData: const [],
      );
      expect(sealed, hasLength(payload.length + 16));
      expect(
        cipher.decrypt(
          ciphertext: sealed,
          nonce: nonce,
          associatedData: const [],
        ),
        payload,
      );

      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await establish(alice, bob);
      final large = payload.sublist(0, 256 * 1024);
      final sent = await alice.cipher.encrypt(bob.address, large);
      expect(await bob.cipher.decrypt(alice.address, sent), large);
    });

    capability('a worker isolate has the library too', () async {
      // `compute` is a real isolate on native platforms; on the web, which has
      // none, it runs here and still has to give the same answer.
      expect(
        await compute(_roundTripInWorker, 'from a worker'),
        'from a worker',
      );

      // And this isolate keeps working after that one has gone: every async
      // answer goes through one function pointer per library, which is torn
      // down when the last isolate it knows about shuts down. (What makes the
      // package count this isolate itself is a SECOND bridged library in the
      // process, which this app does not have; test/platform/ covers that.)
      final alice = Party('alice', 1111);
      final bob = Party('bob', 2222);
      await establish(alice, bob);
      final sent = await alice.cipher.encrypt(bob.address, bytesOf('still'));
      expect(
        utf8.decode(await bob.cipher.decrypt(alice.address, sent)),
        'still',
      );
    });
  });
}
