/// Reference implementation of **durable** Signal Protocol stores.
///
/// The point of this file is one rule from `SECURITY.md`:
///
/// > State that a cryptographic operation advanced must be durably persisted
/// > before that operation's output is released — before a ciphertext leaves
/// > the device, and before a plaintext is acted upon.
///
/// libsignal derives message keys deterministically from stored state and has
/// no per-message random nonce guard, so a store write that is lost to a crash
/// makes the next send reuse a message key and IV. Every write below therefore
/// reaches stable storage (`fsync`) *before* its future completes, which is what
/// the library awaits before handing back a ciphertext or plaintext.
///
/// Design, in one paragraph: all state lives in a single append-only journal of
/// length-prefixed `key → value` frames (a `null` value is a tombstone). Writes
/// are serialized, appended and flushed; the in-memory map is only updated once
/// the flush succeeded, so memory never runs ahead of disk. Opening replays the
/// journal and drops a torn tail left by an interrupted write. Appending to a
/// file created once also side-steps the fact that `dart:io` cannot `fsync` a
/// directory, so a fresh file's directory entry may not be durable.
///
/// What this example deliberately does **not** do, and a production store must:
///
/// - **Encrypt at rest.** The journal holds session records and the identity
///   private key in the clear. Use SQLCipher, or a database key wrapped by the
///   platform keystore, and keep identity keys in platform secure storage.
/// - **Protect against rollback.** Bind the store to a marker in non-backed-up
///   storage and treat a restored copy as a session reset (`SECURITY.md`).
/// - **Compact and checksum the journal.** It grows without bound here, and
///   nothing detects corruption. A frame whose payload is damaged but whose
///   header is intact is replayed as-is. Worse, a frame whose *header* is
///   damaged stops the replay dead, and [DurableJournal.open] then truncates
///   the file there — destroying every later frame, including ones that were
///   flushed and whose ciphertext had already been sent. That is precisely the
///   rollback this file exists to prevent, and it is why a real implementation
///   adds a per-frame checksum (so a torn tail can be told apart from
///   corruption) and rewrites a snapshot periodically. A database gives you
///   both.
/// - **Fully flush on Apple platforms.** `dart:io`'s `flush()` is `fsync(2)`,
///   which is not a power-loss barrier on macOS/iOS — see `SECURITY.md`.
/// - **Version the key schema.** Keys here are plain strings with no schema
///   version, so changing the layout orphans an existing journal. Record a
///   version and migrate; a shipped store cannot simply start over.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

/// A value length of `0xFFFFFFFF` marks a deletion rather than a payload.
const int _tombstoneMarker = 0xFFFFFFFF;

/// Sanity bounds used to recognise a torn or corrupt frame during replay.
const int _maxKeyLength = 1024;
const int _maxValueLength = 16 * 1024 * 1024;

/// Serializes async work so that appends can never interleave.
class _Serializer {
  Future<void> _last = Future<void>.value();

  Future<T> run<T>(Future<T> Function() action) {
    final result = _last.then((_) => action());
    // Swallow errors on the chain itself so one failure does not poison the
    // queue; the error is still delivered to the caller through `result`.
    _last = result.then<void>((_) {}, onError: (Object _) {});
    return result;
  }
}

/// Append-only, crash-tolerant `key → bytes` journal.
///
/// Every [put] appends one frame and `fsync`s it before returning.
class DurableJournal {
  DurableJournal._(this._handle, this._entries);

  final RandomAccessFile _handle;
  final Map<String, Uint8List> _entries;
  final _Serializer _writes = _Serializer();

  /// Opens (or creates) the journal at [path], replaying its contents.
  ///
  /// A torn tail from an interrupted write is truncated: the frames before it
  /// were flushed, so they are the last state the protocol was allowed to act
  /// on.
  ///
  /// Without per-frame checksums this cannot tell a torn tail from a corrupted
  /// header, and it truncates either way — see the "compact and checksum" note
  /// in the library documentation before copying this.
  static Future<DurableJournal> open(String path) async {
    final file = File(path);
    final bytes = file.existsSync() ? await file.readAsBytes() : Uint8List(0);
    final entries = <String, Uint8List>{};
    final complete = _replay(bytes, entries);
    if (complete != bytes.length) {
      await file.writeAsBytes(
        Uint8List.sublistView(bytes, 0, complete),
        flush: true,
      );
    }
    return DurableJournal._(await file.open(mode: FileMode.append), entries);
  }

  /// Returns the value for [key], or `null` if absent or deleted.
  Uint8List? get(String key) => _entries[key];

  /// Returns the keys starting with [prefix] (a copy, safe to mutate under).
  List<String> keysWithPrefix(String prefix) =>
      _entries.keys.where((key) => key.startsWith(prefix)).toList();

  /// Writes [value] for [key] — or deletes [key] when [value] is `null` — and
  /// does not complete until the change is durable.
  ///
  /// This is the whole contract: a caller that awaits this future knows the
  /// record survives a crash. Deletions go through the same path, because a
  /// lost delete resurrects state whose keys were already used.
  Future<void> put(String key, Uint8List? value) {
    return _writes.run(() async {
      final keyBytes = utf8.encode(key);
      final header = ByteData(8)
        ..setUint32(0, keyBytes.length)
        ..setUint32(4, value?.length ?? _tombstoneMarker);
      final frame = BytesBuilder(copy: false)
        ..add(header.buffer.asUint8List())
        ..add(keyBytes);
      if (value != null) frame.add(value);

      await _handle.writeFrom(frame.takeBytes());
      await _handle.flush(); // fsync: the write is on stable storage here

      // Only now, after the flush succeeded, may in-memory state advance.
      if (value == null) {
        _entries.remove(key);
      } else {
        _entries[key] = value;
      }
    });
  }

  /// Number of bytes the journal occupies on disk.
  Future<int> sizeInBytes() => _handle.length();

  /// Flushes any queued write and closes the file.
  Future<void> close() => _writes.run(_handle.close);

  static int _replay(Uint8List bytes, Map<String, Uint8List> out) {
    final data = ByteData.sublistView(bytes);
    var offset = 0;
    while (offset + 8 <= bytes.length) {
      final keyLength = data.getUint32(offset);
      final valueLength = data.getUint32(offset + 4);
      final deleted = valueLength == _tombstoneMarker;
      if (keyLength == 0 || keyLength > _maxKeyLength) break;
      if (!deleted && valueLength > _maxValueLength) break;

      final keyEnd = offset + 8 + keyLength;
      final frameEnd = deleted ? keyEnd : keyEnd + valueLength;
      if (frameEnd > bytes.length) break; // torn tail

      final key = _decodeKey(Uint8List.sublistView(bytes, offset + 8, keyEnd));
      if (key == null) break;

      if (deleted) {
        out.remove(key);
      } else {
        out[key] = Uint8List.fromList(
          Uint8List.sublistView(bytes, keyEnd, frameEnd),
        );
      }
      offset = frameEnd;
    }
    return offset;
  }

  static String? _decodeKey(Uint8List bytes) {
    try {
      return utf8.decode(bytes);
    } on FormatException {
      return null;
    }
  }
}

/// Per-key lock, for serializing whole cipher operations.
///
/// The `load → ratchet → store` cycle spans an entire `SessionCipher` /
/// `GroupCipher` call, so a lock *inside* a store cannot protect it: two
/// concurrent `encrypt` calls for one address would both load the same record
/// and derive the same message key. Hold this lock around the whole call, keyed
/// per remote address (per sender key for groups), and keep one instance
/// alongside the stores — not per short-lived cipher object.
///
/// A real app would use `package:synchronized`; this is the dependency-free
/// equivalent.
///
/// Entries are never evicted, so the map grows with the number of addresses the
/// app has ever talked to. That is bounded by the contact list and each entry is
/// tiny, but evict on conversation deletion if that matters to you.
class AddressLocks {
  final Map<String, _Serializer> _locks = {};

  /// Runs [action] with exclusive access to [key].
  Future<T> synchronized<T>(String key, Future<T> Function() action) =>
      _locks.putIfAbsent(key, _Serializer.new).run(action);

  /// Lock key for a protocol address.
  static String forAddress(ProtocolAddress address) =>
      '${address.name()}:${address.deviceId()}';

  /// Lock key for a sender key (group messaging).
  static String forSenderKey(ProtocolAddress sender, String distributionId) =>
      '${sender.name()}:${sender.deviceId()}:$distributionId';
}

/// The six Signal Protocol stores, all backed by one [DurableJournal].
///
/// Sharing a journal is what makes the writes of a single operation land in one
/// place; a database-backed store would share a connection and could go one
/// better by wrapping each cipher call in a transaction (see `SECURITY.md`).
class DurableFileStores {
  DurableFileStores._({
    required this.journal,
    required this.session,
    required this.identity,
    required this.preKey,
    required this.signedPreKey,
    required this.kyberPreKey,
    required this.senderKey,
  });

  /// Opens the stores in [directory], creating the journal and an identity on
  /// first use and restoring both afterwards.
  static Future<DurableFileStores> open(String directory) async {
    await Directory(directory).create(recursive: true);
    final journal = await DurableJournal.open('$directory/stores.journal');
    return DurableFileStores._(
      journal: journal,
      session: DurableSessionStore(journal),
      identity: await DurableIdentityKeyStore.open(journal),
      preKey: DurablePreKeyStore(journal),
      signedPreKey: DurableSignedPreKeyStore(journal),
      kyberPreKey: DurableKyberPreKeyStore(journal),
      senderKey: DurableSenderKeyStore(journal),
    );
  }

  /// The shared journal.
  final DurableJournal journal;

  /// Session records (Double Ratchet state).
  final DurableSessionStore session;

  /// Our identity key pair, registration ID and known remote identities.
  final DurableIdentityKeyStore identity;

  /// One-time pre-keys.
  final DurablePreKeyStore preKey;

  /// Signed pre-keys.
  final DurableSignedPreKeyStore signedPreKey;

  /// Post-quantum Kyber pre-keys.
  final DurableKyberPreKeyStore kyberPreKey;

  /// Group messaging sender keys.
  final DurableSenderKeyStore senderKey;

  /// Serializes cipher operations per address; see [AddressLocks].
  final AddressLocks locks = AddressLocks();

  /// Closes the journal. Simulate a restart by closing and opening again.
  Future<void> close() => journal.close();
}

/// Durable [SessionStore]: the Double Ratchet state.
class DurableSessionStore implements SessionStore {
  DurableSessionStore(this._journal);

  final DurableJournal _journal;

  static const String _prefix = 'session/';

  /// Key prefix for every device of [name].
  ///
  /// The name is application-controlled and may contain the `/` separator, so
  /// it is percent-encoded. Concatenating it raw would make
  /// `deleteAllSessions('al')` delete the session of a user named `al/ice`, and
  /// `getSubDeviceSessions('al')` try to parse `ice/1` as a device ID.
  String _namePrefix(String name) => '$_prefix${Uri.encodeComponent(name)}/';

  String _key(ProtocolAddress address) =>
      '${_namePrefix(address.name())}${address.deviceId()}';

  @override
  Future<SessionRecord?> loadSession(ProtocolAddress address) async {
    final bytes = _journal.get(_key(address));
    return bytes == null ? null : SessionRecord.deserialize(bytes: bytes);
  }

  @override
  Future<void> storeSession(ProtocolAddress address, SessionRecord record) =>
      // Durable before this future completes — the library awaits it before
      // returning the ciphertext/plaintext that this record produced.
      _journal.put(_key(address), record.serialize());

  @override
  Future<bool> containsSession(ProtocolAddress address) async =>
      _journal.get(_key(address)) != null;

  @override
  Future<void> deleteSession(ProtocolAddress address) =>
      _journal.put(_key(address), null);

  @override
  Future<void> deleteAllSessions(String name) async {
    for (final key in _journal.keysWithPrefix(_namePrefix(name))) {
      await _journal.put(key, null);
    }
  }

  @override
  Future<List<int>> getSubDeviceSessions(String name) async {
    final prefix = _namePrefix(name);
    return _journal
        .keysWithPrefix(prefix)
        .map((key) => int.parse(key.substring(prefix.length)))
        .toList();
  }
}

/// Durable [IdentityKeyStore].
///
/// The identity key pair is created once, on first open, and restored on every
/// later open — losing it would change our safety number for every contact.
/// Remote identities are keyed by user name (all devices of a user share one
/// identity key), matching `InMemoryIdentityKeyStore`.
class DurableIdentityKeyStore implements IdentityKeyStore {
  DurableIdentityKeyStore._(this._journal, this._self, this._registrationId);

  final DurableJournal _journal;
  final IdentityKeyPair _self;
  final int _registrationId;

  static const String _selfKey = 'identity/self';
  static const String _registrationKey = 'identity/registration';
  static const String _remotePrefix = 'identity/remote/';

  /// Loads our identity, generating and persisting one on first open.
  static Future<DurableIdentityKeyStore> open(DurableJournal journal) async {
    var selfBytes = journal.get(_selfKey);
    var registrationBytes = journal.get(_registrationKey);

    if (selfBytes == null || registrationBytes == null) {
      selfBytes = IdentityKeyPair.generate().serialize();
      // Signal registration IDs are 14-bit.
      final registrationId = Random.secure().nextInt(16380) + 1;
      registrationBytes = Uint8List(4)
        ..buffer.asByteData().setUint32(0, registrationId);
      await journal.put(_selfKey, selfBytes);
      await journal.put(_registrationKey, registrationBytes);
    }

    return DurableIdentityKeyStore._(
      journal,
      IdentityKeyPair.deserialize(bytes: selfBytes),
      ByteData.sublistView(registrationBytes).getUint32(0),
    );
  }

  String _key(ProtocolAddress address) => '$_remotePrefix${address.name()}';

  @override
  Future<IdentityKeyPair> getIdentityKeyPair() async => _self;

  @override
  Future<int> getLocalRegistrationId() async => _registrationId;

  @override
  Future<bool> saveIdentity(
    ProtocolAddress address,
    PublicKey identityKey,
  ) async {
    final key = _key(address);
    final incoming = identityKey.serialize();
    final existing = _journal.get(key);
    if (existing != null && _sameBytes(existing, incoming)) return false;
    // Durable before returning: a lost write silently drops this address back
    // to trust-on-first-use, disabling safety-number-change detection for it.
    await _journal.put(key, incoming);
    return true;
  }

  @override
  Future<PublicKey?> getIdentity(ProtocolAddress address) async {
    final bytes = _journal.get(_key(address));
    return bytes == null ? null : PublicKey.deserialize(bytes: bytes);
  }

  @override
  Future<bool> isTrustedIdentity(
    ProtocolAddress address,
    PublicKey identityKey,
    Direction direction,
  ) async {
    final existing = _journal.get(_key(address));
    // Trust on first use; afterwards the key must match. A production app
    // surfaces a mismatch to the user as a safety-number change.
    return existing == null || _sameBytes(existing, identityKey.serialize());
  }

  static bool _sameBytes(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

/// Durable [PreKeyStore]: one-time pre-keys.
class DurablePreKeyStore implements PreKeyStore {
  DurablePreKeyStore(this._journal);

  final DurableJournal _journal;

  static const String _prefix = 'prekey/';

  String _key(int id) => '$_prefix$id';

  @override
  Future<PreKeyRecord?> loadPreKey(int preKeyId) async {
    final bytes = _journal.get(_key(preKeyId));
    return bytes == null ? null : PreKeyRecord.deserialize(bytes: bytes);
  }

  @override
  Future<void> storePreKey(int preKeyId, PreKeyRecord record) =>
      _journal.put(_key(preKeyId), record.serialize());

  @override
  Future<bool> containsPreKey(int preKeyId) async =>
      _journal.get(_key(preKeyId)) != null;

  @override
  Future<void> removePreKey(int preKeyId) =>
      // Consuming a one-time pre-key is a durable write: if it is lost, the
      // key is offered again as unused and a replayed pre-key message can
      // re-establish a session whose message keys were already used.
      _journal.put(_key(preKeyId), null);

  @override
  Future<List<int>> getAllPreKeyIds() async => _journal
      .keysWithPrefix(_prefix)
      .map((key) => int.parse(key.substring(_prefix.length)))
      .toList();
}

/// Durable [SignedPreKeyStore]: medium-term, reusable pre-keys.
class DurableSignedPreKeyStore implements SignedPreKeyStore {
  DurableSignedPreKeyStore(this._journal);

  final DurableJournal _journal;

  static const String _prefix = 'signed_prekey/';

  String _key(int id) => '$_prefix$id';

  @override
  Future<SignedPreKeyRecord?> loadSignedPreKey(int signedPreKeyId) async {
    final bytes = _journal.get(_key(signedPreKeyId));
    return bytes == null ? null : SignedPreKeyRecord.deserialize(bytes: bytes);
  }

  @override
  Future<void> storeSignedPreKey(
    int signedPreKeyId,
    SignedPreKeyRecord record,
  ) => _journal.put(_key(signedPreKeyId), record.serialize());

  @override
  Future<bool> containsSignedPreKey(int signedPreKeyId) async =>
      _journal.get(_key(signedPreKeyId)) != null;

  @override
  Future<void> removeSignedPreKey(int signedPreKeyId) =>
      _journal.put(_key(signedPreKeyId), null);

  @override
  Future<List<int>> getAllSignedPreKeyIds() async => _journal
      .keysWithPrefix(_prefix)
      .map((key) => int.parse(key.substring(_prefix.length)))
      .toList();
}

/// Durable [KyberPreKeyStore]: post-quantum pre-keys.
///
/// Kyber pre-keys come in two flavours and the record does not say which one it
/// is: **one-time** keys must be retired once used, **last-resort** keys are
/// meant to be reused. A store has to remember that distinction from the moment
/// it generates the key (see [storeKyberPreKey]), otherwise
/// [markKyberPreKeyUsed] is a durable write that buys nothing, because nothing
/// ever refuses to serve the key again.
///
/// The two flavours need different handling, and this store implements both:
///
/// - **One-time:** retired on the first mark — [loadKyberPreKey] stops serving
///   it, so a replayed pre-key message no longer decrypts.
/// - **Last-resort:** kept in service, but every
///   `(kyberPreKeyId, signedPreKeyId, baseKey)` agreement is recorded. A repeat
///   is the replay libsignal's own trait documents, surfaced through
///   [replayedAgreements] rather than thrown — see [markKyberPreKeyUsed].
///
/// Both `SessionCipher.decrypt` and `SealedSenderCipher.decrypt` mark through
/// this store, so neither path can consume a key without it being recorded.
class DurableKyberPreKeyStore implements KyberPreKeyStore {
  DurableKyberPreKeyStore(this._journal);

  final DurableJournal _journal;

  static const String _prefix = 'kyber_prekey/';
  static const String _usedPrefix = 'kyber_prekey_used/';
  static const String _lastResortPrefix = 'kyber_prekey_last_resort/';
  static const String _agreementPrefix = 'kyber_prekey_agreement/';

  static final Uint8List _marker = Uint8List.fromList(const [1]);

  /// Agreements seen twice, for the application to inspect after a decrypt.
  ///
  /// Kept in memory on purpose: it is a report about this run, not state the
  /// protocol depends on. The journal holds the durable record.
  final List<({int kyberPreKeyId, int signedPreKeyId, String baseKey})>
  replayedAgreements = [];

  String _key(int id) => '$_prefix$id';
  String _usedKey(int id) => '$_usedPrefix$id';
  String _lastResortKey(int id) => '$_lastResortPrefix$id';

  String _agreementKey(int kyberPreKeyId, int signedPreKeyId, String baseKey) =>
      '$_agreementPrefix$kyberPreKeyId/$signedPreKeyId/$baseKey';

  @override
  Future<KyberPreKeyRecord?> loadKyberPreKey(int kyberPreKeyId) async {
    final bytes = _journal.get(_key(kyberPreKeyId));
    if (bytes == null) return null;
    // A consumed one-time key must not be served again — this is what gives the
    // durable `markKyberPreKeyUsed` write its teeth. A pre-key message replayed
    // after consumption then fails to decrypt, which is the intended outcome.
    // Last-resort keys are exempt: they are designed to be reused.
    if (isKyberPreKeyUsed(kyberPreKeyId) && !isLastResort(kyberPreKeyId)) {
      return null;
    }
    return KyberPreKeyRecord.deserialize(bytes: bytes);
  }

  /// Stores a Kyber pre-key.
  ///
  /// Pass [lastResort] for a last-resort key, so that marking it used does not
  /// retire it. The interface has no such parameter because libsignal does not
  /// carry the flag inside the record — the store that generated the key is the
  /// only place that knows.
  @override
  Future<void> storeKyberPreKey(
    int kyberPreKeyId,
    KyberPreKeyRecord record, {
    bool lastResort = false,
  }) async {
    await _journal.put(_key(kyberPreKeyId), record.serialize());
    if (lastResort) {
      await _journal.put(_lastResortKey(kyberPreKeyId), _marker);
    }
  }

  @override
  Future<bool> containsKyberPreKey(int kyberPreKeyId) async =>
      _journal.get(_key(kyberPreKeyId)) != null;

  /// Records that [kyberPreKeyId] was consumed in one PQXDH agreement.
  ///
  /// For a one-time key the durable `used` mark is the whole story: it retires
  /// the key, and [loadKyberPreKey] enforces that. A last-resort key stays in
  /// service, so the defence has to be narrower — the exact
  /// `(kyberPreKeyId, signedPreKeyId, baseKey)` triple identifies one
  /// agreement, and seeing it twice means one pre-key message was processed
  /// twice.
  ///
  /// A repeat is appended to [replayedAgreements] rather than thrown: this
  /// callback runs after libsignal produced the plaintext, so throwing cannot
  /// prevent the decryption — and the bridge treats the callback as infallible,
  /// so an exception panics the Rust worker instead of surfacing cleanly. The
  /// caller checks the list and drops the message.
  @override
  Future<void> markKyberPreKeyUsed(
    int kyberPreKeyId,
    int signedPreKeyId,
    PublicKey baseKey,
  ) async {
    // Same reasoning as `removePreKey`: consumption must be durable.
    await _journal.put(_usedKey(kyberPreKeyId), _marker);

    final encodedBaseKey = base64Encode(baseKey.serialize());
    final agreement = _agreementKey(
      kyberPreKeyId,
      signedPreKeyId,
      encodedBaseKey,
    );
    if (_journal.get(agreement) != null) {
      replayedAgreements.add((
        kyberPreKeyId: kyberPreKeyId,
        signedPreKeyId: signedPreKeyId,
        baseKey: encodedBaseKey,
      ));
      return;
    }
    await _journal.put(agreement, _marker);
  }

  @override
  Future<void> removeKyberPreKey(int kyberPreKeyId) async {
    await _journal.put(_key(kyberPreKeyId), null);
    await _journal.put(_usedKey(kyberPreKeyId), null);
    await _journal.put(_lastResortKey(kyberPreKeyId), null);
    for (final key in _journal.keysWithPrefix(
      '$_agreementPrefix$kyberPreKeyId/',
    )) {
      await _journal.put(key, null);
    }
  }

  @override
  Future<List<int>> getAllKyberPreKeyIds() async => _journal
      .keysWithPrefix(_prefix)
      .map((key) => int.parse(key.substring(_prefix.length)))
      .toList();

  /// Whether [kyberPreKeyId] has been consumed.
  bool isKyberPreKeyUsed(int kyberPreKeyId) =>
      _journal.get(_usedKey(kyberPreKeyId)) != null;

  /// Whether [kyberPreKeyId] was stored as a last-resort (reusable) key.
  bool isLastResort(int kyberPreKeyId) =>
      _journal.get(_lastResortKey(kyberPreKeyId)) != null;
}

/// Durable [SenderKeyStore]: group messaging chains.
///
/// A sender key record is a chain key plus an iteration counter, so losing a
/// write here reuses a message key exactly as a lost session record does.
class DurableSenderKeyStore implements SenderKeyStore {
  DurableSenderKeyStore(this._journal);

  final DurableJournal _journal;

  static const String _prefix = 'senderkey/';

  // Percent-encoded for the same reason as in [DurableSessionStore]: both parts
  // are application-controlled and could otherwise contain the separator.
  String _key(SenderKeyName name) =>
      '$_prefix${Uri.encodeComponent(name.sender.name())}/'
      '${name.sender.deviceId()}/'
      '${Uri.encodeComponent(name.distributionId)}';

  @override
  Future<Uint8List?> loadSenderKey(SenderKeyName senderKeyName) async =>
      _journal.get(_key(senderKeyName));

  @override
  Future<void> storeSenderKey(SenderKeyName senderKeyName, Uint8List record) =>
      _journal.put(_key(senderKeyName), record);
}
