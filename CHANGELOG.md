## [Unreleased]

### For Users

#### ✨ Highlights

- **Encrypting saves the recipient's identity, as libsignal does** —
  **(breaking)** for code calling `messageEncryptWithCallbacks` or
  `sealedSenderEncryptWithCallbacks` directly, which now take a
  `saveIdentity` callback; `SessionCipher` and `SealedSenderCipher` keep
  their signatures and call your `IdentityKeyStore.saveIdentity` on every
  message they encrypt
- **`SessionRecord.hasUsableSenderChain` asks what Signal's clients ask** —
  **(breaking)** a session nobody answered is no longer usable once it is
  30 days old
- **`PreKeyRecord.privateKey()` and `SignedPreKeyRecord.privateKey()` are
  gone** — **(breaking)** a record travels whole, private half included,
  through `serialize()`
- **No storage migration** — none of the breaking changes needs one: the
  store interfaces are unchanged and records are still persisted whole
  through `serialize()`. Session records gain fields under Tahini, which
  libsignal writes on the next save and earlier versions still read.
- **libsignal v0.106.0** — session management moves from Sesame to Tahini:
  an archived session is never made current again, and a record keeps at
  most 3 of them instead of 40

#### Changed (Breaking)

- **`messageEncryptWithCallbacks` and `sealedSenderEncryptWithCallbacks`
  take a `saveIdentity` callback** (`rust/src/api/session_cipher.rs`,
  `rust/src/api/sealed_sender.rs`, `rust/src/recording_stores.rs`,
  `lib/src/rust/api/`, `lib/src/protocol/session_cipher.dart`,
  `lib/src/sealed_sender/sealed_sender_cipher.dart`,
  `lib/src/stores/identity_key_store.dart`) — libsignal's `message_encrypt`,
  and `sealed_sender_encrypt` through it, save the recipient's identity on
  every message, right after checking it against the stored one. The bridge
  had no callback to pass that write on, so the per-call store libsignal
  wrote to dropped it. While the identity is stored that changes nothing;
  for an address whose stored identity the application deleted, libsignal
  stores it again on the next message, and this package did not until the
  next decryption. Both functions now take `saveIdentity`, called with the
  key libsignal saved and before `storeSession`, in libsignal's order.
  `SessionCipher.encrypt` and `SealedSenderCipher.encrypt` keep their
  signatures and pass your `IdentityKeyStore.saveIdentity`, which is
  therefore called on every message you send. **Action required:** code
  that calls either function directly passes `saveIdentity`; and an
  `IdentityKeyStore.saveIdentity` that writes even when the key is unchanged
  now writes on every send, so make that case cheap.
- **`SessionRecord.hasUsableSenderChain` requires what Signal's clients
  require** (`rust/src/api/session.rs`) — it handed libsignal no
  requirements, so it answered whether the current session has a sender
  chain at all. It now asks for `NotStale`, `EstablishedWithPqxdh` and
  `Spqr`, the set libsignal's own Java, Swift and Node bindings use: a
  session nobody answered is unusable once it is 30 days old, which is also
  when libsignal stops encrypting on it, and a session established without
  PQXDH or without SPQR is unusable. The sessions this package builds from a
  bundle are PQXDH and SPQR, so in practice the difference is the 30 days.
  libsignal warns that `Spqr` also accepts an unanswered session whose
  pre-key message carries SPQR, which a peer that answers without it turns
  unusable; the docstring repeats that. **Action required:** where
  `hasUsableSenderChain` decides whether to send, `false` now comes where a
  Signal client archives the session and builds a new one with
  `SessionBuilder.processPreKeyBundle`.
- **`PreKeyRecord.privateKey()` and `SignedPreKeyRecord.privateKey()` are
  removed** (`rust/src/api/prekey.rs`, `rust/src/api/signed_prekey.rs`,
  `lib/src/rust/api/`) — nothing in the package used them: libsignal reads
  a record's private half inside its own calls, and a store persists the
  record whole through `serialize()`, private half included. They handed
  raw private-key bytes to Dart, and only their own tests called them, so
  they go with this major. **Action required:** keep a record and
  pass it whole (`serialize()` / `deserialize()`); the private key itself is
  a `PrivateKey` where you generated it. `IdentityKeyPair.privateKey`,
  `PrivateKey.serialize()` and `KyberSecretKey.serialize()` stay.

#### Changed

- **The update to libsignal v0.105.1 leaves the exposed protocol surface
  unchanged** — of the range's twenty commits
  ([compare](https://github.com/signalapp/libsignal/compare/v0.105.0...v0.105.1)),
  the ones its release notes name — simpler zkcredential presentations, the
  `Donations` and `AuthAccountsService.getAccountEntitlements` APIs, and a
  flattened `FavoriteSticker` backup message — live in crates outside this
  package's dependency graph. In the four libsignal crates that are in it,
  `libsignal-protocol`'s `Timestamp` gains a `TryFrom<SystemTime>` conversion
  and an `UnrepresentableTimestamp` error, added for the account-entitlements
  API, which this package neither calls nor exposes; the rest is the version
  constant in `rust/core/src/version.rs`, and `libsignal-debug` moves to
  0.105.1 by its version number alone. The upstream workspace keeps
  `rust-version` at 1.93.1, this package's floor, `spqr` stays at 1.6.0
  (`06959b4`), and regenerating the bindings changed nothing in
  `lib/src/rust/`.

  Third-party crates move with it, none added or removed. Each of these
  reaches every binary, the web module included: `libc` 0.2.191, `sha2`
  0.11.1, `tokio` 1.53.3, `uuid` 1.28.0, `zerocopy` 0.8.63, `smallvec`
  1.16.3, `inout` 0.2.3 (yanked since; see the `inout` entry below) and
  `equivalent` 1.0.3; `unicode-ident` 1.0.27
  reaches only the web module. `sha2` 0.11.1 fixes how its AArch64 backends
  load the round constants, to satisfy the Stacked Borrows model. `libc`
  0.2.191 ends the hold 8.0.0 put on 0.2.189: 0.2.190 had put the dyld
  functions `backtrace` calls behind `target_os = "macos"`, which broke every
  iOS build, and 0.2.191 makes them available to iOS again — the three iOS
  targets type-check against it, and a full `cargo update` no longer brings
  the break back. `cc`, `syn`, `serde_json`, `toml_edit`, `toml_parser`,
  `toml_datetime` and `zerocopy-derive` move too and only run at compile time.
- **`inout` 0.2.2 → 0.2.5** (`rust/Cargo.lock`, `THIRD_PARTY_NOTICES.txt`)
  — Dependabot's bump (#122). It reaches every binary, the web module
  included, through `cipher` and `aead` (`aes`, `cbc`, `ctr`,
  `aes-gcm-siv`). Crate 7.0.0 shipped 0.2.2; the v0.105.1 update above moved
  it to 0.2.3, which was yanked two days after its release: refactoring a
  Stacked Borrows fix had dropped the check that the output buffer of
  `InOutBufReserved::into_padded_blocks` has room for the padding block, and
  the unsafe code behind it relies on that check
  ([RustCrypto/utils#1560](https://github.com/RustCrypto/utils/pull/1560)).
  0.2.4 restores it, and 0.2.5 also returns `PadError` when a `Padding`
  implementation breaks the block count the unsafe code assumes
  ([RustCrypto/utils#1563](https://github.com/RustCrypto/utils/pull/1563)).
  0.2.3 could not overrun a buffer here either: the only padded encryption
  in this package is libsignal's AES-256-CBC with PKCS #7, the body of every
  1:1 and group message, and it goes through `encrypt_padded_vec`, which
  allocates one block more than the input's whole blocks — the room the
  restored check asks for. No released version of this package carried
  0.2.3, and no RustSec advisory covers it. Its floor stays at Rust 1.85,
  below this crate's 1.93.1.
- **`tokio` 1.53.3 → 1.54.1** (`rust/Cargo.lock`, `THIRD_PARTY_NOTICES.txt`)
  — Dependabot's bump (#129). flutter_rust_bridge builds on it in every
  binary: the lock behind each opaque Rust object is a `tokio::sync::RwLock`,
  the web module included, and on native platforms its async functions run on
  tokio's multi-threaded runtime. In the features compiled here (`rt`,
  `rt-multi-thread`, `sync`, `time`), 1.54.0 reworks the runtime's injection
  queue, makes `Notify` use acquire/release orderings, keeps locks in FIFO
  order when a task's cooperative budget runs out, fixes a `spawn_blocking`
  hang when only scheduler workers exist, and handles two timer edge cases;
  1.54.1 reverts one timer change of 1.54.0
  ([tokio's notes](https://github.com/tokio-rs/tokio/blob/tokio-1.54.1/tokio/CHANGELOG.md)).
  tokio's minimum Rust version rises to 1.85, below this crate's 1.93.1.
  `cc` 1.8.0 → 1.10.0 and `find-msvc-tools` 0.1.14 → 0.1.15 move with it and
  run only at build time.
- **`uuid` 1.28.0 → 1.29.0** (`rust/Cargo.lock`, `THIRD_PARTY_NOTICES.txt`) —
  in the same bump. It reaches every binary through `libsignal-core`,
  `libsignal-protocol` and this crate. 1.29.0 adds versioned constructors to
  `NonNilUuid`, which nothing here calls; the rest of the range changes tests
  and version strings in the documentation
  ([release](https://github.com/uuid-rs/uuid/releases/tag/v1.29.0)).
- **The Linux libraries are built on Ubuntu 26.04 and still need only glibc
  2.34** — the release build moves from Ubuntu 24.04 along with every other
  Ubuntu job (see For Contributors). A Linux library records the glibc symbol
  versions of the image that built it, so a newer image can raise the oldest
  glibc it loads on; this one does not. Built on 26.04 (glibc 2.43), the
  library needs GLIBC_2.34 at most, measured on x86_64 and arm64, as crate
  7.0.0's libraries do — Ubuntu 22.04, Debian 12, RHEL 9 or newer.
- **The v0.105.2 update leaves this package's protocol surface unchanged** — the range ([compare](https://github.com/signalapp/libsignal/compare/v0.105.1...v0.105.2)) adds an accounts-capabilities API in `rust/net/chat` and changes its language bindings; this package does not build the networking crate or expose those bindings. SVR2/B changes are in `rust/attest` and the SVR2 bridge, which are not among the crates this package builds or the protocol primitives it exposes. Node and Java build and documentation changes are in language-binding and build tooling outside this package's exposed surface.

  The range changes exactly one file in the crates we bind, `rust/core/src/version.rs`, updating only the `VERSION` string from `0.105.1` to `0.105.2`. `make codegen` produced no change in `lib/src/rust/`, so these changes do not affect this library's public API.

  No third-party crate moves with it. None is added or removed. `spqr` stays at 1.6.0 (`06959b4`).
- **The certificate-verification update leaves this package's protocol surface unchanged** — the range ([compare](https://github.com/signalapp/libsignal/compare/v0.105.2...v0.105.4)) includes changes to certificate verification in `rust/net/infra/src/certs.rs`, outside this package's dependency graph, and to Java's `CertificateVerifier.kt`, a language binding this package does not expose.

  Within the crates we bind, the range changes exactly one file, `rust/core/src/version.rs`, updating only the `VERSION` string from `0.105.2` to `0.105.4`. `make codegen` produced no change in `lib/src/rust/`, so these changes do not affect this library's public API.

  No third-party crate moves with it. None is added or removed. `spqr` stays at 1.6.0 (`06959b4`).
- **libsignal v0.106.0 replaces Sesame session management with Tahini** —
  as upstream's notes for the release put it
  ([compare](https://github.com/signalapp/libsignal/compare/v0.105.4...v0.106.0)),
  an archived session is never made current again, a tiebreaker picks the
  current session when both sides start one at the same time, and a
  conversation that keeps switching back and forth between sessions is
  detected and settled. A session record keeps at most 3 archived sessions
  instead of 40, and one holding more is trimmed the next time a session is
  archived. Messages on the wire do not change; stored session records gain
  fields, which earlier libsignal versions still read. What an application
  sees: a message on an archived session still decrypts, but answering it
  takes a new session — in 8.0.0 decrypting it made that session current
  again. A record can also be left with no current session: after
  `SessionRecord.archiveCurrentState`, or once libsignal archives the current
  session itself to settle a conversation. `SessionCipher.encrypt` and
  `SealedSenderCipher.encrypt` then throw `LibSignalErrorCode.sessionNotFound`,
  as do `localRegistrationId` and `remoteRegistrationId`, until
  `SessionBuilder.processPreKeyBundle` or the peer's next pre-key message
  establishes a new session.

  In the four libsignal crates in this package's graph, the range rewrites
  session management in `libsignal-protocol` (`session_management.rs`, the new
  `tahini.rs`, `state/session.rs`, `proto/storage.proto`), and the other three
  change no source beyond `libsignal-core`'s version constant. The Rust API
  changes are the two the notes name: `process_prekey` is no longer public,
  which this package never called, and `message_decrypt_prekey` returns a
  `PreKeyDecryptResult` instead of the plaintext, which the bridge now takes
  from it, as upstream's own `message_decrypt` does. The new
  `initiate_session` wraps `process_prekey_bundle`, which this package keeps
  calling. Regenerating the bindings changed only documentation in
  `lib/src/rust/`.

  No third-party crate moves with it. None is added or removed. `spqr` stays
  at 1.6.0 (`06959b4`).
- **`saveIdentity` runs only when libsignal saves the identity, on every
  decryption path** — the bridge now forwards the save libsignal made instead
  of choosing a key itself. libsignal v0.106.0 saves nothing for a message
  that decrypts on an archived session, so that a delayed message cannot roll
  the stored identity back. 8.0.0 called `saveIdentity` on every decryption:
  `SessionCipher.decrypt` with the identity of the record's current session —
  a read that fails with `sessionNotFound` once a decryption can leave the
  record without one, after libsignal has already decrypted — and
  `SealedSenderCipher.decrypt` with the key its sender certificate names.
  Sealed sender now saves the key the inner message's session is bound to,
  which a genuine sender's certificate repeats;
  `SealedSenderDecryptionResult.senderIdentityKey` is still the
  certificate's. Encrypting follows the same rule, and libsignal saves there
  on every message: see Changed (Breaking).

- **`hooks` and `code_assets` admit 2.x as well as 1.x** (`pubspec.yaml`,
  `.github/dependabot.yml`) — `^1.0.0` held every app on 1.x, on a Flutter
  that ships 2.x itself as well. The range is now `>=1.0.0 <3.0.0`, so each
  Flutter resolves the major it supports: on 3.38 to 3.44, which pin `meta`
  below the 1.19.0 that `hooks` 2.1 needs, an app resolves `hooks` 2.0.x
  with `code_assets` 1.x, and from 3.47 `hooks` 2.2 with `code_assets` 2.1.
  The build hook needs no change: the one breaking change of `code_assets`
  2.0 — `OS`, `Architecture` and `Sanitizer` define `==` and no longer key
  a const map — touches nothing it uses. Measured on Flutter 3.38.4 and
  3.47.4 in a project generated from the same template: the example app
  builds and the package's tests pass on both. Here, the suite passes on
  `hooks` 2.2.0 with `code_assets` 2.1.0, and `example/` resolves 2.0.2 with
  1.2.1 on Flutter 3.38.4 and analyzes clean. Dependabot still holds back
  3.x. From template v4.18.0.

#### Fixed

- **Every isolate that initializes libsignal is counted by it, whichever
  flutter_rust_bridge library the isolate initialized first**
  (`lib/src/libsignal.dart`, `lib/src/platform/`,
  `test/platform/isolate_count_test.dart`) — 8.0.0 named this hang and left
  it: flutter_rust_bridge keeps one shutdown watcher per isolate for all of
  its libraries, so an isolate was counted only by the first library it
  initialized, and a worker that initialized libsignal alone and exited could
  switch libsignal's Rust-to-Dart channel off for the whole process; every
  async call from the main isolate then waited forever. `LibSignal.init()` now
  registers the isolate with libsignal's own native library, through a
  finalizer of its own, before `RustLib.init()` runs, so the rule 8.0.0 gave
  — initialize the flutter_rust_bridge libraries in the same order in every
  isolate — is no longer needed for libsignal. Counting the isolate before
  `RustLib.init()` installs its pointer also closes the initialization race
  8.0.0 fixed, so `init()` no longer installs the pointer a second time.
  Measured on a bench of two libraries and with the race hammer: the hang and
  the race are both gone, and moving the count after `RustLib.init()` brings
  the race back in 6 rounds of 6. The tests run both scenarios in a process
  of their own. The count calls an internal flutter_rust_bridge symbol, so a
  release that changes it makes `init()` fail rather than hang. From template
  v4.18.0.
- **On the web, `LibSignal.init()` throws instead of waiting forever when the
  WASM module is not served** (`lib/src/libsignal.dart`,
  `lib/src/platform/platform_web.dart`, `README.md`) — flutter_rust_bridge
  loads `pkg/libsignal_frb.js` with a `<script>` tag and waits for its `load`
  event with no error path, so a missing module — a 404, or the app's HTML
  page that a dev server returns in its place with a 200 — left `init()`
  pending. `init()` now fetches the script first and throws a `StateError`
  naming it, with the HTTP status, the content type and the remedy, when it
  is not served as a script. A fetch that fails outright, under a strict
  content security policy for instance, throws nothing, and loading goes on
  as before. The usual cause is `flutter run -d chrome` on Flutter 3.38 to
  3.41 after a run for another platform, which skips the build hook; README's
  Known Limitations now says Flutter 3.44 and later are not affected. From
  template v4.18.0.

#### Documentation

- **`SECURITY.md`: only repository Admins can create a release tag**
  (`SECURITY.md`) — 8.0.0's text said the tag ruleset did not stop a `write`
  collaborator, because its bypass list held the `write` role as well as
  `admin`. The list now holds `admin` only (see For Contributors), and the
  section says so.
- **`SECURITY.md`: the dependency check refuses yanked crate versions** —
  its Dependency Auditing section now says that `rust/deny.toml` fails on a
  crate version its publisher has yanked, beside the source and license rules
  it already described.
- **`IdentityKeyStore.isTrustedIdentity` says the ciphers never call it**
  (`lib/src/stores/identity_key_store.dart`,
  `lib/src/stores/in_memory/in_memory_identity_key_store.dart`) — trust is
  enforced through `getIdentity`: libsignal is handed the identity it
  returns and refuses a key that differs from it, and an address it returns
  `null` for is trusted on first use. A policy written into
  `isTrustedIdentity` was applied to no message, and nothing said so;
  `InMemoryIdentityKeyStore` even described its trust-on-first-use rule as
  living there. The interface now says where trust is decided and how to
  apply a stricter policy, and `saveIdentity` lists when it is called.
- **Releases 7.3.0 to 7.4.1 moved to `CHANGELOG-ARCHIVE.md`**
  (`CHANGELOG.md`, `CHANGELOG-ARCHIVE.md`) — this file was 169 KB with this
  release's 56 KB still open, and the releases before it added 20 to 45 KB
  each, small patches aside, so the next one would likely have crossed the
  200 KiB at which `make verify-pub-limits` warns of pub.dev's 256 KiB
  limit. It keeps 8.0.0 onward now, at 86 KB, and the archive, which pub.dev
  does not receive, holds everything up to 7.4.1, the moved sections and
  their compare links unchanged.

### For Contributors

#### Added

- **A template update reports text it merged in twice**
  (`scripts/src/update_template.dart`, `scripts/update_template.dart`,
  `test/scripts/update_template_test.dart`,
  `.github/workflows/check-template-updates.yml`,
  `.claude/skills/update-template/SKILL.md`) — adopting template v4.17.0 put
  the `describeFrbTreeDrift`, `parseLsTree` and `parseContentsListing` groups
  into `test/scripts/release_test.dart` a second time, with every gate green:
  the template had taken them from here and filed them elsewhere, and copier
  kept both copies without a conflict. It was found by hand. After merging,
  `make update-template` — which the template bot runs — now renders the new
  version afresh with this project's answers and flags each line of 25
  characters or more that the merge left more often than both the file at
  `HEAD` and the render have it, both having it at least once; in a conflicted
  file, only when it stays repeated whichever side of its conflicts is kept.
  The bot's pull request then opens as a draft, lists the files with the line
  numbers of the first repeated line and carries the label `merged-twice`; when
  the render cannot be made, its table says the check did not run. Replayed on
  this repository's twelve resolved adoptions and three raw updates, it found
  that case and the two under *Changed* below, and nothing else; a version
  without the render, counting blocks that occur more often than at `HEAD`,
  raised fourteen false alarms on the same adoptions. Written here and in the
  template together, because the bot runs the script it finds on `main`: the
  next adoption here is already checked. `scripts/src/update_changelog.dart`
  takes the template's wrapping of one doc comment, so the file is the
  template's render byte for byte.
- **A differential test holds the session bridge to libsignal's own API**
  (`rust/src/session_equivalence_tests.rs`) — the bridge does not hand
  libsignal the application's stores: it loads per-call in-memory copies,
  calls libsignal, reads the record back and replays the writes to Dart, and
  each of those steps rests on what libsignal does inside the call. v0.106.0
  changed that without changing a signature the bridge depended on, and the
  whole suite stayed green over a bridge that failed every message on an
  archived session. The test runs each operation twice from one snapshot —
  once through the FRB entry point, against stores standing in for the Dart
  ones, and once through libsignal's own function against its reference
  stores — and requires the same outcome, the same consuming and trusting
  writes, and the same session, identity and pre-key state, across the six
  session entry points: fetching a bundle, sending plain or sealed, and
  delivering in order, out of order, twice or never, through sealed sender
  as well, which runs against libsignal's `sealed_sender_encrypt` and
  `sealed_sender_decrypt` with a trust root and certificates of its own.
  Between the steps an application archives a session, forgets the identity
  it stored for a peer, or trusts a peer's new identity after the peer
  reinstalled. Those steps change the state both runs start from, so they
  need no libsignal counterpart. Seven scripted conversations and forty
  seeded random ones reach all of it: across the seeds about 508
  decryptions, 100 of them sealed, 48 that leave no current session, 17
  identities stored again on encrypt and 20 refused identities.
  libsignal's behaviour is the expectation, so an upstream change moves it;
  only a bridge that stops following fails. On the repair commit alone
  (`84b3691`) three of the first five tests fail, naming the step:
  `sessionNotFound` where libsignal decrypted, and an identity saved where
  libsignal saved none. The identity encryption writes (see Changed
  (Breaking)) is compared too: dropping it again fails seven of the eight
  tests on the plain path and four on the sealed one. The random scripts
  assert that they still reach the states they exist for. Runs in `make
  rust-test`, in about seven seconds.
- **The update pull request says whether it could be merged unread**
  (`scripts/src/update_changelog.dart`, `scripts/update_changelog.dart`,
  `test/scripts/update_changelog_test.dart`,
  `.github/workflows/check-libsignal-updates.yml`, `README.md`, `CLAUDE.md`)
  — a first step toward handing routine updates to the bot, and a report
  only: nothing merges on it. The CHANGELOG script, which already holds every
  input, decides it before the model is asked and publishes `merge_eligible`
  and `merge_blockers` on both outcomes; the pull request shows it under
  *Merge without review?*. Eligible means the bindings were regenerated and
  the FFI surface held, the upstream range was read in full, every file the
  range touched in the four libsignal crates in the graph changed in quoted
  version strings only — read off the diff, so a protocol version, an
  integer, never passes, nor does a raised `rust-version` — no registry crate
  moved, was added or removed, and no git dependency from another repository,
  `spqr` among them, moved. A pre-release is never eligible. Each blocker
  names what it found. Replayed on the last nine updates (v0.102.3 to
  v0.106.0): v0.105.2 and v0.105.4 pass, and the other seven are blocked for
  what a reviewer had to read there — session code, `spqr`, or third-party
  crates a full `cargo update` moved along, the `libc` that broke iOS and the
  since-yanked `inout` 0.2.3 among them. No label yet: a label is what a merge
  job would key on, and the rule should be measured on real updates first.
  The template carries the same change.
- **`make check-msrv` keeps the minimum Rust version at the graph's floor**
  (`scripts/check_msrv.dart`, `scripts/src/msrv.dart`,
  `test/scripts/msrv_test.dart`, `Makefile`,
  `scripts/src/update_changelog.dart`,
  `test/scripts/update_changelog_test.dart`,
  `.github/workflows/check-libsignal-updates.yml`,
  `.github/workflows/test-reusable.yml`, `README.md`, `CONTRIBUTING.md`,
  `CLAUDE.md`, `.claude/skills/update-libsignal/SKILL.md`) — it compares
  `rust-version` in `rust/Cargo.toml`, the `rust_version` answer and
  CONTRIBUTING's toolchain line with the highest `rust-version` a crate of the
  resolved graph declares, and `--update` raises all three. They agree today at
  1.93.1, and the crate that sets the graph's floor is `libsignal-debug`
  0.106.0 — libsignal's own workspace floor. So the next upstream MSRV raise
  would have reached the update pull request as a red MSRV job, which the
  build repair leaves alone, and a hand edit in three files. The update
  workflow now raises it after `make rust-update` and says so in the pull
  request, the CHANGELOG entry gains a sentence naming the crate that set it,
  a moved floor keeps the update from being eligible to merge unread, and CI
  checks it on the Linux x86_64 leg. It reads what crates declare: one that
  uses a feature newer than its own floor is still found only by the MSRV job.
  The template carries the same change.
- **`make update-evidence` writes down what an upstream update changed**
  (`scripts/update_evidence.dart`, `scripts/src/update_changelog.dart`,
  `test/scripts/update_changelog_test.dart`, `Makefile`,
  `.github/workflows/check-libsignal-updates.yml`,
  `.github/workflows/repair-build.yml`, `.github/agent-prompts/repair-build.md`,
  `README.md`, `CLAUDE.md`) — the release notes, the libsignal range with its
  patches to the crates we build, the lockfile diff, and the range of every git
  dependency from another repository that moved, `spqr` among them: until now
  CLAUDE.md told whoever finished the update pull request to fetch that range
  by hand with `gh api`. The update workflow attaches it to its run as the
  `update-evidence` artifact and links it from the pull request; the build
  repair writes the same into `.agent-scratch/evidence/`, and its prompt starts
  "ask what moved underneath" from those release notes and patches — #125's
  agent had the new source but not the diff that said what moved. The
  CHANGELOG script gathers its facts through the same code
  (`gatherUpdateEvidence`), unchanged. Measured: v0.105.4 → v0.106.0 gives the
  26 KB of patches to the crates we build and no other range, which is right,
  since `spqr` did not move there; on the v0.102.3 → v0.103.0 locks the
  selector names exactly `spqr` 1.5.3 → 1.6.0, and its range carries the
  `serialize.rs` patch the old instruction said to diff by hand. The repair
  step's shell, run under a stubbed `gh`, read the range from the copier
  answers at both ends. A real repair run first exercises it at the next one.
  The template carries the same change.

#### Changed

- **copier template adopted: v4.18.0 -> v4.19.0** — fixes build and release code.
  `rust/build.rs` now passes `-headerpad_max_install_names` when linking Apple
  cdylibs, leaving room for `install_name_tool -id` to set the copied library's
  install name. `scripts/verify_release_artifacts.py` rejects Mach-O libraries
  with less than 1,024 characters of header padding; `CLAUDE.md` documents the
  change.

  `scripts/src/update_changelog.dart` now checks HTTP status when fetching
  upstream notes: it accepts files only on 200, treats 404 as absence, and
  reports other statuses as unknown rather than claiming no notes were
  published. `test/scripts/update_changelog_test.dart` covers the behavior.

  `CONTRIBUTING.md` names the bot branches excluded from the signed-commit
  ruleset and explains that their commits are still signed by GitHub.
  `scripts/src/release.dart` now requires exactly one `[Unreleased]:` compare
  link below every release heading; `test/scripts/release_test.dart` covers
  invalid placement and duplicates.

  `.github/workflows/publish.yml` uses a random delimiter for the multiline
  release-notes output, so a notes line reading `EOF` cannot truncate it.
  `.github/workflows/repair-build.yml` refuses a named run whose
  `head_repository` is not this repository, before proceeding with the repair.

  `scripts/src/ai_client.dart` rejects keys containing non-printable ASCII and
  reports header errors without exposing header values; its tests were extended
  in `test/scripts/ai_client_test.dart`.

- **copier template adopted: v4.17.0 → v4.18.0** (`.copier-answers.yml` and
  the files named here and in the For Users entries above) — beyond the
  isolate count, the web check and the `hooks` range above, it brings:
  - `make check-upstream-advisories`, which holds signalapp/libsignal's own
    published security advisories against the crates `rust/Cargo.lock`
    resolves: neither `make rust-audit` (RustSec) nor Dependabot (GitHub's
    global database) is guaranteed to see them. `check-libsignal-updates.yml`
    runs it daily in a job of its own, so a finding never stops the update
    pull request, which is often the fix, and the job fails as well when the
    advisories cannot be fetched (`scripts/check_upstream_advisories.dart`,
    `scripts/src/upstream_advisories.dart`,
    `test/scripts/upstream_advisories_test.dart`, `Makefile`; the new answer
    `enable_upstream_advisories: true`). `compareVersions` in
    `scripts/src/common.dart` now orders prereleases as SemVer 2.0 does and
    ignores build metadata, since the check decides by it whether a locked
    version is affected. Run on this lock file before merging, it passes:
    signalapp/libsignal has published no advisory yet.
  - `--data key=value` for `make update-template`, to answer a question a new
    template version adds; the run then names any answer
    `.copier-answers.yml` did not record (`scripts/src/update_template.dart`,
    `scripts/update_template.dart`, `test/scripts/update_template_test.dart`,
    `.claude/skills/update-template/SKILL.md`).

  The rest of the range was here already — the merge-eligibility report, the
  minimum Rust version check, the evidence artifact, the Highlights fix and
  the scan for text merged in twice, each with its own entry — and the
  adoption leaves those files as they were. Eight files conflicted where both
  sides had changed the same lines. The template's
  `scripts/src/update_changelog.dart` and its test differ from this
  repository's only in line breaks, which `dart format` decides here, so ours
  stay; `CONTRIBUTING.md` keeps its own text, which never carried the
  template's list of what the update automation does; the other five take the
  template's side, which contains ours. The scan for text merged in twice, on
  its first live run, found one block: `scripts/src/update_template.dart`
  printed its summary of duplicates twice. It is kept once, in the template's
  order, and the file equals the template's render.
- **A local build made from another `rust/Cargo.lock` is refused, and
  `make build` drops the build hook's cache** (`hook/build.dart`, `Makefile`,
  `CLAUDE.md`, `test/hook/build_hook_test.dart`) — the hook took a local
  library in `rust/target/release/` or `rust/target/wasm32/` whenever its
  stamp named the current crate version, and the crate version does not move
  with the dependencies, so after a dependency update the previous build
  passed. `make build` and `make build-web` now copy `rust/Cargo.lock` beside
  the stamp as `.cargo-lock`, and the hook refuses a local build whose copy
  is missing or differs from the tree's, with a `HookException` that names
  the remedy. `make build` also removes `.dart_tool/hooks_runner/libsignal/`:
  a hook run that took the download path declares only `rust/Cargo.toml`, so
  a local build made after it went unnoticed until that cache was dropped.
  ⚠ A local build made before this has no copy and is refused: run
  `make build` (and `make build-web`) once. From template v4.18.0.

- **Only an Admin can create, move or delete a tag**
  (`.github/rulesets/protect-release-tags.json`, `.github/rulesets/README.md`,
  `CONTRIBUTING.md`, `CLAUDE.md`, `.claude/skills/release-package/SKILL.md`,
  `.claude/skills/release-frb-crate/SKILL.md`) — the `Protect release tags`
  ruleset's bypass list also held `actor_id` 4, which GitHub names `write`
  (read back through GraphQL on 2026-10-07), so any collaborator with `write`
  could create, move and delete tags, the release tags included, unsigned.
  Only `admin` (5) is on it now, which is what the rulesets README always
  described. No automation creates tags: the workflows react to them and
  create GitHub Releases for tags that already exist, and GitHub Apps,
  Dependabot and `GITHUB_TOKEN` were never on the list. The README also shows
  how to update one ruleset without `make setup-repo-protections
  ARGS="--update"`, which sends every file.
- **Repair Build no longer picks a draft pull request**
  (`.github/workflows/repair-build.yml`) — from 2026-10-09 every scheduled run
  failed on one unchanged commit: the draft template update (#113) was the
  oldest red bot pull request, copier's conflict markers in its `Makefile`
  stopped `make get` before the agent started, and with no verdict nothing
  marked the head as answered, so the next run picked it again. Being the
  oldest, it also kept the libsignal update (#115) from ever being picked. A
  draft is a pull request a human has to finish, so the scheduled search now
  skips drafts; a run named through `workflow_dispatch` can still target one.
- **Every job names its image: `ubuntu-26.04`, `macos-26` and
  `windows-2025-vs2026`** (every workflow with an Ubuntu, macOS or Windows
  job, `.github/actions/setup-rust/action.yml`, `.github/actionlint.yaml`,
  `CLAUDE.md`) — GitHub moves `ubuntu-latest` from 24.04 to 26.04 job by job
  between 2026-10-19 and 2026-11-19, so a job could change image, and go red,
  with no commit to blame, and `macos-latest` and `windows-latest` move the
  same way. Every job on `ubuntu-latest` now names `ubuntu-26.04`, and the
  Linux ARM64 test leg and both Linux release builds move from
  `ubuntu-24.04` and `ubuntu-24.04-arm` to `ubuntu-26.04` and
  `ubuntu-26.04-arm`. The macOS and Windows jobs, the release builds among
  them, name the images `-latest` resolved to on 2026-10-21: `macos-26`
  (macOS 26 arm64) and `windows-2025-vs2026` (Windows Server 2025 with Visual
  Studio 2026, the label that names the compiler as well as the system). Each
  is one of the labels of the very image it replaces, so only the label
  changes, and so does nothing in the cache keys, which carry `ImageOS`.
  Measured on a throwaway branch first, from a cold cache: Tests
  (the whole matrix), Fuzz and a Repair Build dry run pass on 26.04 (GCC 15,
  glibc 2.43, Python 3.14), with wasm-pack, cargo-ndk, cargo-audit,
  cargo-deny, the FRB codegen and cargo-fuzz compiled there, and
  `verify_release_artifacts.py`, whose tar extraction changes default on
  Python 3.14, passes on 3.14 against crate 7.0.0's archives. The release
  workflows, the scheduled update checks and the pull-request-only workflows
  were not run; each first runs on 26.04 at its next trigger, the release
  ones at the next tag. The Rust cache now keys on the image too (`ImageOS`,
  in setup-rust and `fuzz.yml`): rust-cache keys on the OS family alone, and
  the first 26.04 runs restored what 24.04 had compiled, wasm-pack and
  cargo-ndk included. actionlint 1.7.12 does not know the two 26.04 labels
  yet, so `.github/actionlint.yaml` ignores exactly those until it does; it
  knows `macos-26` and `windows-2025-vs2026`, and still reports an unknown
  `macos-99`.
- **The update bot's CHANGELOG entry is written from what the update
  changed** (`scripts/src/update_changelog.dart`,
  `test/scripts/update_changelog_test.dart`,
  `.github/agent-prompts/changelog-scope.md`) — the entries for v0.104.0,
  v0.105.0 and v0.105.1 were each rewritten by hand, for reasons the prompt
  could not have avoided. It told the model, twice, to say that "the material
  does not carry it", while rule 7 forbade narrating the inputs, and the
  v0.105.1 entry did as told ("the material does not identify…"); both now
  say to make no claim, as does the `spqr` paragraph of the scope file. A
  12 000-character cap marked v0.105.1's file list TRUNCATED although the API
  had returned all 228 files, and the entry said so; the cap is 60 000 now,
  above anything the API's 300 files reach. The files of the upstream crates
  this package builds are listed apart and first, with the compare API's own
  patch for each — the one that shows `Timestamp` gaining
  `TryFrom<SystemTime>` — and those crates now come from `cargo metadata`,
  which names `libsignal-debug` as well; the scope file lists it too. The
  third-party paragraph every rewrite added is now written by the script from
  the `rust/Cargo.lock` diff against `HEAD` and appended to the entry — every
  registry crate that moved, was added or was removed, and `spqr` with its
  revision, moved or not — so no model copies the list, and none can again
  invent a `spqr` move. The libsignal Highlights line goes above the
  `libsignal_frb` line, or last, rather than above the release's headline
  bullets, and the `#### Changed` entry goes last in its block. Measured on
  v0.105.1's real inputs without a model: four crates, a COMPLETE list with
  the two bound files first, the patch, and a paragraph naming the sixteen
  crates the human's rewrite named, with `spqr` staying at 1.6.0
  (`06959b4`). Then replayed through gpt-5.6-luna and gpt-6-luna on all three
  bumps' real inputs: no entry narrated its inputs or repeated the crate list,
  and on v0.105.1 both named the `timestamp.rs` change and left out the
  no-impact sentence, as rule 4 requires. What the replay still caught is
  settled in code: the model's typographic quotes and apostrophes are made
  straight, as everywhere else in this file (gpt-6-luna wrote `’` beside the
  rule-4 phrase's `'` in two entries of three), and an entry whose last
  sentence the model left open is closed before the paragraph is appended
  (one of six ran "…public API" into "Third-party crates move with it").
- **The AI reviewer is told where each file starts in the diff, and that a
  bot's CHANGELOG entry is a model's** (`.github/workflows/ai-review.yml`,
  `.github/agent-prompts/pr-review.md`) — on the v0.105.1 bump it called the
  bot's entry "consistent with a refresh" while the entry narrated its own
  inputs and named none of the crates the lockfile moved, crates the same
  finding listed. Its read tool returns 50 KB a call, and the lockfile hunk
  began at line 2 656 of the diff, past where the first read stopped. The
  context file now gives the line each file's hunks start on and each
  commit's author, so a person's rewrite of a bot's entry shows, and on a
  bot's pull request that touches `CHANGELOG.md` it says the entry was
  written by a model and what to hold it to. The prompt's rule 6 now covers
  an entry that names a version or crate no hunk shows, or narrates its
  inputs. A file the reviewer lists as read but saw only as hunks of the diff
  is now reported as seen in the diff rather than as "claimed but never
  opened": still not a file it read, but no longer worded as though it had
  not looked. Only the lines each read of the diff returned count, cut as
  OpenCode's read tool cuts them (2 000 lines or 51 200 bytes), so a
  `CHANGELOG.md` hunk near the top counts and a lockfile hunk past the first
  read does not.
- **Repair Build passes over what it has answered, re-runs a first failure,
  and counts a repair that never finished** (`.github/workflows/repair-build.yml`,
  `CONTRIBUTING.md`) — three ways the scheduled repair could stall or loop. It
  asked whether a pull request had been answered only after picking the
  oldest red one, so one answered pull request blocked every newer one; each
  candidate is asked now, and the `repair-build-*` branches the workflow opens
  itself are never candidates. A `main` it had reported as unfixable went
  back to the agent on every run — on `f68354ddc64b`, four nights of
  `cannot-fix` and then a fifth answer that hand-edited generated code (#67)
  — and now counts as answered by that report. Only a verdict marked a commit
  answered, so a job that failed before reaching one (#113's `make get`, 19
  runs) repeated twice a day: a new `record` job counts each such attempt as
  an artifact keyed by the commit, and after two the commit is left to a
  person, with a comment on the pull request or an issue for `main` saying
  so. And a red run on its first attempt has its failed jobs re-run once,
  by a new `rerun` job, before any agent sees it — the commonest red here has
  been a flaky runner, and the agent's correct answer to one spent the only
  answer that commit gets. `rerun` holds the file's one `actions: write`, at
  job level, runs nothing else, and keeps a marker before it asks, so a
  re-run GitHub refuses is asked for once and the run then goes to the
  agent. A `main` red at its tip still holds the
  pull-request search, answered or not, because a branch cut from it inherits
  the failure; a named run behaves as before, and a dry run with no run named
  now picks what the schedule would. Replayed over fourteen fixture cases
  through the old and new selector: the old one stalls behind the answered
  pull request, re-asks the reported `main`, and repairs its own
  `repair-build-*` branch; the new one does none of these.
- **The update bot moves only what the new upstream tag requires**
  (`Makefile`, `README.md`, `.github/dependabot.yml`, `CONTRIBUTING.md`,
  `scripts/README.md`) — `make rust-update`,
  which the bot runs, was a bare `cargo update` that moved every crate in the
  lockfile: 41 registry crates over the last four bumps, none of them required
  by the new tag, and twice that broke a platform the bump never touched —
  wasm-bindgen 0.2.113 under FRB 2.11.1, and `libc` 0.2.190 on iOS in
  v0.105.1's, which undid the hold put there for it. It is
  `cargo update --workspace` now; replayed on those four bumps, it moved
  exactly the four upstream crates. The rest of the graph moves in
  Dependabot's weekly cargo pull request, which now takes transitive crates
  too (`allow: dependency-type: all`) — until now it offered only what
  `rust/Cargo.toml` names, so the comment there saying it is how a vulnerable
  transitive crate's fix arrives was not true. The manual-update steps in
  `CONTRIBUTING.md` and `scripts/README.md` now say `make rust-update` too:
  they said `cd rust && cargo update`, which also skipped the notices
  regeneration `make verify-third-party-notices` checks.
- **The repair job can run `make rust-doc`** (`.github/workflows/repair-build.yml`)
  — its toolchain had no `wasm32-unknown-unknown`, so the wasm32 half of a
  gate the prompt has the agent run stopped before documenting anything; a
  dry run's agent reported it as a gate it could not complete.
- **OpenCode is pinned at 1.18.35 in both agent workflows**
  (`.github/workflows/repair-build.yml`, `.github/workflows/ai-review.yml`) —
  1.18.15 looks a model up in a catalogue built into the binary that predates
  gpt-6-luna, which the agents now run, and a run on it died with
  `ProviderModelNotFoundError`, shown in the transcript only as
  `UnknownError`. On 1.18.35 both agents' permission assertions pass
  unchanged, locally and in a dry run of each workflow. The repository
  variable `AGENT_OPENCODE_VERSION` already said 1.18.35; now the default
  does as well.
- **The agents call no model nobody named** (`.github/agent-config/opencode.json`,
  `.github/workflows/repair-build.yml`, `.github/workflows/ai-review.yml`,
  `CONTRIBUTING.md`) — OpenCode titles each session through a second, "small"
  model that it picks from the provider's catalogue when none is set: on
  OpenRouter, `google/gemini-3.6-flash` on 1.18.15, `google/gemini-3.8-flash`
  on 1.18.35, and an image model on the catalogue it downloads today —
  through the same key, with the run's opening message in the request. A
  title is thrown away with the runner, so the call is off; the repository
  variable `AGENT_OPENCODE_TITLE_MODEL` turns it back on with a named model.
  Both workflows assert what OpenCode resolved — off, or exactly that model —
  as they assert each agent's permissions, and on 1.18.15 and 1.18.35 alike
  those permission assertions still pass unchanged. A default-branch config
  with no title entry only warns: `ai-review.yml` runs as a pull request's
  own copy, so the pull request that brings the check meets the old config.
- **copier template adopted: v4.15.2 → v4.17.0** (`.copier-answers.yml`,
  `Makefile`, `CLAUDE.md`, `scripts/src/pub_limits.dart`,
  `scripts/verify_pub_limits.dart`, `scripts/src/release.dart`,
  `scripts/src/upstream_source.dart`, `scripts/src/check_updates.dart`,
  `scripts/src/common.dart`, `scripts/src/update_changelog.dart`,
  `scripts/check_exists_frb_release.dart` and their tests,
  `.github/workflows/test-reusable.yml`,
  `.github/workflows/check-libsignal-updates.yml`,
  `.github/workflows/check-template-updates.yml`,
  `.github/workflows/refresh-notices.yml`,
  `.github/rulesets/signing-commit.json`, `.github/rulesets/README.md`,
  `.claude/skills/release-package/SKILL.md`,
  `.claude/skills/update-libsignal/SKILL.md`) — `make verify-pub-limits`
  arrives. pub.dev refuses a README, CHANGELOG, LICENSE or example over
  256 KiB, and a pubspec over 128 KiB, only at upload — after the tag, which is
  how 7.4.0 was spent — and the dry-run measures none of them. The check now
  runs before `make publish-dry-run`, inside `make release` once the CHANGELOG
  is finalized, and in CI on every push, warning from 200 KiB; `CHANGELOG.md`
  is at about 131 KB. The two update checkers no longer check out with the App
  token and keep no credential in `.git/config` while project code and copier
  run. **Signing commit** now excludes `update-libsignal-*` and
  `update-template-v*`, so `force_update` can refresh an open update pull
  request — a force-push that ruleset refused, measured in a generated
  project; the ruleset was re-applied on GitHub on 2026-10-21 with the
  single-ruleset `PUT` in `.github/rulesets/README.md`. That README now also
  says what `refresh-notices.yml` does: it commits through
  `createCommitOnBranch`, which signs. The update scripts are reorganised
  around `upstream_source` (`git_tag` here; `crates_io` is the template's new
  alternative): a manual `target_version` is held to shell-safe characters and
  validated by the checker, the release reads the crate pin strictly, and
  `upstream_version` is validated. The agent, repair, lockfile and Dependabot
  changes of 2026-10-19 were written here first and arrive as no diff. Kept
  ours: `hook/build.dart` and its test (this project's 6.3.0 → 6.3.1 example),
  `SECURITY.md` (it already lists the tag protection), the rulesets README's
  dates and its notes on the required checks, and `CLAUDE.md`'s two-stage
  release docs, which gain the size check by hand.
- **`test / Test (Linux ARM64)` is a required check again**
  (`.github/rulesets/protect-main.json`, `.github/rulesets/README.md`) — it
  was left out when the test matrix became required on 2026-09-07, over a
  30-second timeout that hit a different test each run. The cause was a
  flutter_rust_bridge race that could drop Rust's replies to Dart while a test
  file's isolate was starting; `LibSignal.init` has worked around it since
  2026-09-30, released in 8.0.0. Of the 31 `Tests` runs from 2026-10-01 to
  2026-10-21 the leg failed three, each time with every other test leg at the
  same step (`Analyze` twice, `Get dependencies` once). `main` now requires
  twelve checks, the template's list. The live ruleset was updated the same
  day by a single-ruleset `PUT` of the live ruleset plus this one context, so
  the parameters GitHub added to it stay as they were. The runbook's advice on
  dropping a flaky leg is now the template's, followed by this project's case.
- **Two repeats a template merge left on 2026-08-31 are gone** (`CLAUDE.md`,
  `.githooks/pre-commit`) — adopting v4.4.0 → v4.6.0 put the `AI_MODELS` table
  and the paragraphs after it into `CLAUDE.md` a second time, inside *Stage 2
  — release the Dart package*, and took *What the entry is judged against*
  there with them; that section is back under *AI-Powered Changelog*, as in
  the template. The same merge kept this repository's first fix for the
  pre-commit hook's `GIT_DIR` problem, an `unset GIT_DIR GIT_WORK_TREE
  GIT_INDEX_FILE` at the top of the file, beside the template's, which unsets
  them for the checks alone. The one at the top also hid the temporary index
  `git commit -a` hands the hook, so the hook's own `git diff --cached` saw
  nothing staged and `make rust-check` was skipped on every `git commit -a`
  that changed `rust/` (measured with a hook that prints both). The hook is
  the template's now. The check above found both.
- **The update bot's CHANGELOG entry no longer leaves two blank lines under
  Highlights** (`scripts/src/update_changelog.dart`,
  `test/scripts/update_changelog_test.dart`) — when the previous bump's
  default Highlights line was the only line in its block, dropping it left
  the blank line from either side of it, and the new line went in above
  both. #119 (v0.105.2) arrived with two blank lines before `#### Changed`,
  removed by hand when `main` was merged into it, and every bump after the
  first in a release window would have needed the same edit. The emptied
  block is now written with one blank line on each side of the new line.
  Replayed on #119's real input, the generator produces the `CHANGELOG.md`
  that was merged, byte for byte; the same replay before the fix gives the
  extra line.
- **The AI reviewer holds a bot entry's upstream claims against the upstream
  range, not against this diff** (`.github/workflows/ai-review.yml`,
  `.github/agent-prompts/pr-review.md`) — the rule added on 2026-10-19 said
  that every file a bot's CHANGELOG entry names must appear in a hunk. An
  entry that describes the upstream release names upstream files, which no
  hunk here can show, so on #119 the reviewer reported `rust/net/chat`,
  `rust/attest` and `rust/core/src/version.rs` as named by no hunk although
  every claim was true, and it would have on every bump. The workflow now
  reads the range the entry links from GitHub and lists the files it changed
  in `pr-context.md`. It takes the link only when it points at `native_repo`
  from `.copier-answers.yml` and both refs are plain, and nothing in it can
  fail the step: without a link nothing is added, and a range GitHub will
  not return is reported as unreadable. Only that section, and rule 6 of the
  prompt, exempt claims about that one repository's files from the hunks and
  hold them against the list. Every other claim is held against the diff as
  before, so a template adoption's entry, whose link points at the template,
  is still checked against the diff in full. Run on #119's real diff, the
  section lists the range's 49 files, the three paths above among them. Nine
  more variants each finish the step and write what they should: no link, a
  link to another repository or to the template, an unreadable range, a ref
  with `..`, a pull request opened by a person, a missing or malformed
  `native_repo`, and a range past GitHub's 300-file cap, which the section
  then states. No model was run: what the reviewer makes of the list shows on
  the next libsignal bump.
- **`signal-crypto` is no longer a direct dependency** (`rust/Cargo.toml`,
  `rust/Cargo.lock`, `.copier-answers.yml`, `.github/dependabot.yml`,
  `.github/agent-prompts/changelog-scope.md`,
  `scripts/src/upstream_source.dart`, `scripts/src/update_changelog.dart`,
  `.claude/skills/update-libsignal/SKILL.md`) — nothing in `rust/src` or the
  fuzz targets calls it, as with `thiserror` before it. It was a direct
  dependency only because `upstream_crates` named it, which also gave it a
  Dependabot ignore and a place in each of the update scripts' crate lists.
  The answer now names `libsignal-protocol` and `libsignal-core`, and the
  files that depend on it were re-rendered from the same template version
  (`copier update --vcs-ref=v4.17.0`), so nothing else moved: a three-way
  merge of every rendered file gives the same result outside
  `.github/dependabot.yml`, which it conflicts on as copier did, and the scope
  file, which this project owns, and nothing was merged in twice.
  `signal-crypto` itself stays in the graph, through
  `libsignal-protocol`, so `Cargo.lock` loses one line, the dependency edge,
  and `THIRD_PARTY_NOTICES.txt` is unchanged. The changelog bot still names
  it: it lists the crates from `cargo metadata`, and the answer's list is
  only its fallback. The scope file now says how it arrives, as it already
  did for `libsignal-debug`.
- **A `coverage` minor no longer drags majors into the pub group**
  (`.github/dependabot.yml`) — #117 and #118 were each the pub group's pull
  request, red on every OS: `coverage` 1.16.0, a minor the group may take,
  with the `ffigen`, `hooks` and `code_assets` majors, although the `hooks`
  and `code_assets` majors are ignored and the group admits only minors and
  patches. The minor resolves one way only: it needs `cli_util ^0.6.0`,
  every `ffigen` below 23.0.0 needs `^0.4.2`, and `ffigen` 23 needs `hooks`
  and `code_assets` 2.x. pub's resolver, given the four unlocked, lands on
  exactly #118's set, so Dependabot moved what the update had to move, past
  both rules; the raised `hooks ^2.2.0` is what broke `example/`, where
  Flutter 3.38.4 pins `meta` 1.17.0 and `hooks` from 2.1.0 needs `^1.19.0`.
  `coverage` is now ignored from 1.16.0, and `ffigen` majors on their own
  account: `ffigen` generates part of `lib/src/rust/frb_generated.io.dart`,
  `make codegen` runs the version this package depends on, and
  flutter_rust_bridge's own `frb_dart` pins `^20.1.1`, so a major moves
  generated code and belongs with the FRB version, not with a bump. Both
  lift once `ffigen` has moved. The same block goes into the template.
- **`protect-main.json` names the unattributed-changes approval**
  (`.github/rulesets/protect-main.json`, `.github/rulesets/README.md`) — the
  live `Protect main branch` carries
  `require_extra_approval_for_unattributed_changes: true`, which the file did
  not name, and the README warned that `make setup-repo-protections
  ARGS="--update"` might reset it. It does not: GitHub stores `true` for a
  payload that leaves the parameter out, and the ruleset's own history shows
  it `true` after the `--update` of 2026-09-07, sent from a file without it.
  GitHub documents the parameter nowhere, neither in its REST description
  nor in its GraphQL schema. Others report, and nothing here has measured,
  that with `true` a pull request carrying commits not linked to a GitHub
  account waits for one human approval even when none is required. The file
  now says `true`, so it says what GitHub enforces: compared field by field,
  the four live rulesets now differ from their files only in the two
  defaults GitHub adds itself, which the README names. The template's file
  and README change the same way.
- **Only their release tags may enter the two release environments**
  (`scripts/setup_repo_protections.dart`, `scripts/src/repo_protections.dart`,
  `test/scripts/repo_protections_test.dart`, `.github/workflows/publish.yml`,
  `.github/rulesets/README.md`, `Makefile`, `CLAUDE.md`) — a run of
  `build-libsignal.yml` or `publish.yml` started from any branch reached the
  approval prompt, so one mistaken approval could publish a native binary or
  the package, and `make setup-repo-protections` set up only `native-build`,
  sending nothing but its reviewer. It now configures `native-build` and
  `pub.dev` in full: you as the one required reviewer, no admin bypass,
  approving one's own run allowed, and a deployment policy that lets in only
  `libsignal_frb-*` tags and `v*` tags respectively. A re-run converges on the
  same settings, each environment is read back afterwards, and
  `ARGS="--dry-run"` only reads and prints what would change. `publish.yml`'s
  `publish` job now runs on a tag only, since from a branch the environment
  would refuse it and `validate-package` already makes the dry run;
  `create-release` is left to its policy. The dry run against this
  repository found `native-build` letting admins bypass and both environments
  letting every ref in, the reviewer and self-review settings already right.
  The template's script, module and tests are the same files.
- **Every test that expects a call to fail names the code it fails with**
  (13 files under `test/groups/`, `test/protocol/` and `test/sealed_sender/`)
  — 37 expectations accepted any throw at all (`throwsA(anything)`), so a
  call failing for another reason, or with a plain Dart error, passed them as
  readily as the failure they were written for. What each one catches was
  measured first, with a probe in place of the matcher: all 37 throw a
  `LibSignalException`, and each now asserts its code with `failsWith` —
  `protobufError` 20 times, `invalidMessage` 9, `verificationFailure` 3,
  `sessionNotFound` 2, and `invalidArgument`, `legacyCiphertextVersion` and
  `unrecognizedMessageVersion` once each, every one the failure its test is
  named for. With a wrong code put into one of them, that test fails and
  names the code it got. A comment that said the error type "varies by
  implementation" now says which it is.
- **The build repair's agent sees the update it is repairing**
  (`.github/workflows/repair-build.yml`) — `Describe the update under repair`
  gives the agent the pin that moved and the files the bot changed, from the
  merge base of `main` and the commit under repair. It computed that base
  locally, on a checkout one commit deep, and git treats a shallow commit as
  having no parents: on every repair of a pull request the base came back
  empty, and the file the agent reads said only that the bot's diff could not
  be shown. It now asks the API (`compare/main...<sha>`, as ai-review takes
  its diff), which needs no history and no anonymous fetch. Run on real heads,
  the step shows #119's v0.105.1 → v0.105.2 pin move, and the API's merge base
  equals local git's for #119, #122 and #123. Found by a rehearsal: a draft
  pull request (#123, closed) broke one upstream call in
  `rust/src/api/keys.rs`, and Repair Build was dispatched on its red Tests run
  with `dry_run: true`. The agent (gpt-6-luna) repaired it with the one-word
  change back, rejecting a wider public API because the value was in scope,
  and the surface classifier ran for the first time and measured `unchanged`,
  agreeing with the agent. The template carries the same change.
- **`make rust-deny` fails on a yanked crate version** (`rust/deny.toml`) —
  `[advisories]` gains `yanked = "deny"`; the default only warns. `inout`
  0.2.3, yanked for losing the output-buffer check its unsafe padding code
  relies on, sat in `rust/Cargo.lock` from #115 (18 October) to #122
  (24 October) with this job green and `warning[yanked]` in every log.
  Measured with cargo-deny 0.19.4 (CI installs 0.20.2): with the field,
  `make rust-deny` fails on the tree that carried 0.2.3 (exit 2, `advisories
  FAILED`) and passes on `main` with 0.2.5. The comment beside the field says
  how to clear one: Dependabot's weekly cargo pull request, which moves
  transitive crates here, or `cargo update -p`; `make rust-update` runs
  `cargo update --workspace`, which leaves a transitive crate where it is,
  measured on the same tree. The template carries the same change.
- **The build repair asks what moved behind an upstream signature, not only
  how to make it fit** (`.github/agent-prompts/repair-build.md`,
  `.github/workflows/repair-build.yml`) — its first live repair of an update
  branch, on #125 (libsignal v0.106.0), adapted to `message_decrypt_prekey`
  returning a `PreKeyDecryptResult` by taking its `plaintext`, as upstream's
  own `message_decrypt` does. It compiled, the matrix went green, and the
  repair was incomplete: v0.106.0 no longer makes an archived session current
  again when a message decrypts on it, and `SessionCipher.decrypt` read the
  identity to save off the current session afterwards, so every such message
  failed with `sessionNotFound` — after the application archived a session,
  and after libsignal archived one itself to settle a conversation. The
  release notes said so in their first line, and the update bot's CHANGELOG
  entry, in the agent's own tree, repeated it; no test produced that state,
  and the prompt sent the agent to the upstream source "to learn what shape a
  function now has, and for nothing else". A new section, "When it compiles
  again, ask what moved underneath", has the agent read the changed
  function's documented behaviour and the bot's entry, find everything here
  that rests on the old behaviour, drive each change through the public API
  with a test run against its first compiling adaptation, write down what a
  consumer can observe, and report it in `notes`. The path allowlist the
  workflow enforces gains `CHANGELOG.md`, `README.md` and `SECURITY.md`: the
  prompt already asked an agent that widens the API for a README update and
  a CHANGELOG entry, and the allowlist refused both. The template carries the
  same change.
- **The update bot replaces the libsignal Highlights line, whoever last wrote
  it** (`scripts/src/update_changelog.dart`,
  `test/scripts/update_changelog_test.dart`,
  `.github/workflows/check-libsignal-updates.yml`) — the line names the version
  a release section ships, one per section, and the bot replaced only its own
  default wording. The v0.106.0 line rewritten by hand in #125 would have been
  kept by the next bump, which would have added its own beside it and left the
  section naming two versions for someone to collapse. The first upstream
  bullet is now replaced whole, continuation lines included, and the prompt
  hands the model the line it replaces: keep what still holds for the whole
  release, add what the new update changes, name its version, and use the
  default wording only when the replaced line was the default too. Replayed on
  this `[Unreleased]` with a v0.106.1 line, the three-line v0.106.0 bullet goes
  and the `ctutils` headline then above it stays byte for byte. Only a
  section that already carries two upstream lines keeps the rest and raises
  `highlights_stacked`. What the model writes when it merges two lines is
  first seen on the next bump. The template carries the same change.

## [8.0.1] - 2026-10-26

### For Users

#### ✨ Highlights

- **`ctutils` 0.4.5** — fixes RUSTSEC-2026-0385 in the native library:
  constant-time masks and `u128` comparisons (see Security). Nothing else
  moves: this is 8.0.0 with that one crate replaced
- **libsignal v0.105.0** — unchanged this release
- **libsignal_frb v7.0.1** — Rust FFI bindings

#### Security

- **`ctutils` 0.4.3 → 0.4.5, for RUSTSEC-2026-0385** (`rust/Cargo.lock`,
  `THIRD_PARTY_NOTICES.txt`) — `ctutils` is RustCrypto's constant-time
  toolkit, and it reaches every binary, the web module included, through
  `digest` (and so HMAC, HKDF, SHA-2 and `curve25519-dalek`), `aes-gcm-siv`
  and `universal-hash`. Before 0.4.4 the mask functions of its `Choice` type
  (`Choice::to_*_mask`) could compile to a branch on a secret value on common
  platforms, and its `u128` comparisons branched on every target whose
  pointers are 32 bits wide, this package's `armeabi-v7a` and `wasm32`
  builds among them
  ([RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385)).
  0.4.4 routes the masks through an optimization barrier and checks the
  generated code with BINSEC in its CI; 0.4.5 also hardens Thumb-1
  comparisons and `Choice` composition. Crate 7.0.0, the native library of
  8.0.0, was built with 0.4.3; whether its machine code contains such a
  branch was not measured. `cargo update -p ctutils --precise 0.4.5` on
  8.0.0's lock file moves no other crate, so the native library differs from
  7.0.0's by this one dependency. Floor: Rust 1.87, below this crate's
  1.93.1.
- **RUSTSEC-2026-0386 (`tokio` 1.53.2, unsound) does not reach the library,
  so `tokio` stays** — the advisory concerns the safe constructors of
  `tokio::io::unix::AsyncFd`
  ([RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386)),
  which tokio compiles only with its `net` feature. What pulls tokio in here
  enables `rt`, `rt-multi-thread`, `sync` and `time`, on every target, so no
  binary contains `AsyncFd`. `cargo audit` still lists it, as an allowed
  warning. `main` is on 1.53.3 already.

### For Contributors

#### Changed

- **The release scripts also cut a release from a `release/<line>` branch**
  (`scripts/src/release_common.dart`, `scripts/src/release_frb.dart`,
  `scripts/src/release.dart`, `scripts/release_frb.dart`,
  `scripts/release.dart`, `test/scripts/release_common_test.dart`) — this
  release is cut from `release/8.0.x`, a branch from the `v8.0.0` tag,
  because `main` already carries libsignal v0.106.0 and changes meant for the
  next major. Both scripts refused every branch but `main`, and fetched,
  compared with and pushed `main` by name. They now accept `main` or
  `release/<line>` (`isReleaseBranch`), use the branch they run on for all
  three, and refuse a branch origin does not have yet, so "push first, CI
  green, then tag" holds on a maintenance branch as on `main`. The change
  exists on this branch only.

## [8.0.0] - 2026-10-08

### For Users

#### ✨ Highlights

- **A failed call throws a `LibSignalException` with a `LibSignalErrorCode`** —
  **(breaking)** an application can now decide by `code`, whose values change
  only in a major release, instead of matching the text of a thrown `String`.
  Code that catches a `String`, compares the thrown value with a string, or
  relies on `on Exception` not matching needs the changes listed under Changed
  (Breaking) ([#106](https://github.com/djx-y-z/libsignal_dart/issues/106))
- **Async calls no longer wait forever when another isolate shuts down during
  `LibSignal.init()`** — see Fixed
- **libsignal v0.105.0** (from v0.103.1, through v0.104.0) — internal/dependency
  update, no public-API impact
- **libsignal_frb v7.0.0** — Rust FFI bindings

#### Changed (Breaking)

- **A failed call throws a `LibSignalException` carrying a
  `LibSignalErrorCode`, where it used to throw the error's text as a `String`**
  ([#106](https://github.com/djx-y-z/libsignal_dart/issues/106))
  (`rust/src/api/error.rs`, every file in `rust/src/api/`, `lib/libsignal.dart`,
  `README.md`) — the native layer passed libsignal's errors to Dart as their
  `Display` text and nothing else, so code that needed to tell, say, a
  duplicate from a missing session had to search text that libsignal does not
  treat as an API. Each failed call now throws a `LibSignalException`: its
  `code` classifies the failure, and its `message` is, with one correction
  listed under Fixed, the text the call threw before.

  The codes, and the way libsignal's error variants are grouped into them, come
  from libsignal's own app bindings: one code per decision a caller makes, not
  one per failing line. Codes change only in a major release, so a `switch`
  over all of them keeps compiling through minor and patch releases; a
  condition libsignal introduces in between gets the nearest existing code.
  Every libsignal variant is mapped by hand with no wildcard, so a new one is a
  compile error until it has a code. Nothing converts text into an exception:
  an error this package raises names its code, and a libsignal error given a
  prefix keeps its own.

  Three choices differ from libsignal's bindings. A sender certificate that
  fails validation (expired, not signed by the trust root or by its server
  certificate, or revoked) is `verificationFailure` wherever this package
  checks one, including inside the sealed-sender decrypt functions, where
  libsignal reports it as an invalid message; the code says nothing about who
  sent the envelope, since anyone who knows your public identity key can seal
  one that fails this check. (A certificate naming an unknown server
  certificate is `verificationFailure` in libsignal's bindings too.)
  libsignal's `InvalidProtocolAddress` has no code of its own:
  libsignal-protocol never raises it (libsignal's bindings use it for a device
  id out of range), and this package reports a device id out of range as
  `invalidArgument` everywhere. And libsignal's `ApplicationCallbackError` is
  `internalError` rather than a callback code, since nothing here can produce
  it. Separately, a check this package adds — a sender-key distribution message
  whose distribution id differs from the one passed in — is `invalidMessage`,
  because the id inside the message comes from the peer.

  `message` is the text these calls threw before (except the `Aes256GcmSiv`
  key-length message, see Fixed), and `toString()` returns
  `LibSignalException(<code>): <message>`. A store callback that throws still
  cannot be reported this way, because the store interfaces cannot return an
  error across the bridge: on native platforms the call fails with
  `flutter_rust_bridge`'s `PanicException`, and on the web, where every call
  that takes store callbacks is asynchronous, the WebAssembly module traps and
  the call never completes.

  **Action required:**
  - Code that catches with `on String`, tests the thrown value with `is String`
    or `as String`, or compares it with a string breaks; catch
    `LibSignalException` and branch on `code`.
  - `on Exception` and `on FrbException` clauses now catch these errors too — a
    bare `String` never matched them — so check what such a clause does with a
    decryption failure.
  - `e.toString()` now starts with `LibSignalException(<code>): `. Checks with
    `==` or `startsWith` no longer match. Checks with `contains(...)` still find
    the message part, but now see the code name too: `contains('duplicate')`
    matches every `duplicatedMessage`.
  - The native library changes with it, to `libsignal_frb` 7.0.0, which the
    build hook downloads by itself. If you pass `libraryPath` to
    `LibSignal.init()` or ship the native library yourself, replace that
    library with a 7.0.0 build. 6.4.0, the one 7.4.1 uses, still passes
    `init()`, and every error then fails to decode as a `TypeError`, which
    `on LibSignalException` does not catch; an older 6.x stops at `init()`.

#### Changed

- **The native dependency update leaves this package's exposed protocol
  surface unchanged** — the range
  ([compare](https://github.com/signalapp/libsignal/compare/v0.103.1...v0.104.0))
  changes backup, chat, key-transparency, zkgroup, and language-binding files
  outside this package's bound crates or exposed surface; those locations are
  not built or called by this wrapper. In the four libsignal crates that reach
  the binaries — `libsignal-protocol`, `libsignal-core`, `signal-crypto` and
  `libsignal-debug` — the complete file list changes one file,
  `rust/core/src/version.rs`, whose only change is the version constant, and
  `libsignal-debug` moves to 0.104.0 by its version number alone, so these
  changes do not affect this library's public API. Regenerating the bindings
  for this update on its own changed nothing in `lib/src/rust/`; the bindings
  this release does change come from the coded errors above. `spqr`, the
  post-quantum ratchet that runs inside the Double Ratchet, stays at 1.6.0
  (`06959b4`).

  Third-party crates move with it, and each of these reaches every binary, the
  web module included: `uuid` 1.27.0, `tokio` 1.53.2, `zerocopy` 0.8.59,
  `smallvec` 1.16.2 and `lazy_static` 1.5.1. The web module also gets
  `wasm-bindgen` 0.2.129 with `js-sys`/`web-sys` 0.3.106 and
  `wasm-bindgen-futures` 0.4.79. `uuid` 1.27.0 also changes what the sender-key
  group calls accept as a distribution id: it reads the `urn:uuid:` prefix in
  any letter case, so an id written as `URN:UUID:<id>`, which used to fail with
  `invalidArgument`, is now accepted as `<id>`, as the lowercase form already
  was. `cc` 1.6.0 is not build-only either: it compiles C that is linked into
  the native libraries — `dart-sys`'s `dart_api_dl.c` on every native platform
  and `oslog`'s `wrapper.c` on iOS and macOS. `find-msvc-tools`, which `cc`
  uses to find the MSVC tools on Windows, and `wasm-bindgen-test` move too, and
  only build or test the crate.
- **The update to libsignal v0.105.0 leaves the exposed protocol surface
  unchanged as well** — the range
  ([compare](https://github.com/signalapp/libsignal/compare/v0.104.0...v0.105.0))
  is four commits: the changes its release notes name — chat connection info
  that says whether a connection is direct, now also in Java, and an
  `expectedLevel` argument to `createLoginReceiptCredential()` — which live in
  `rust/net/chat/`, `rust/bridge/shared/` and the Java, Node and Swift
  clients, plus formatting and a version reset. None of those crates is in
  this package's dependency graph. In the four libsignal crates that are, the
  only change is again the version constant in `rust/core/src/version.rs`,
  which this package does not expose, and `libsignal-debug` moves to 0.105.0
  by its version number alone. The upstream workspace keeps `rust-version` at
  1.93.1, this package's floor, `spqr` stays at 1.6.0 (`06959b4`), and
  regenerating the bindings on top of it changed nothing in `lib/src/rust/`.

  Third-party crates move with it, and each of these reaches every binary, the
  web module included: `zeroize` 1.9.1, `zerocopy` 0.8.61, `ctutils` 0.4.3 and
  `either` 1.19.0; `zerocopy-derive` 0.8.61 moves too and only runs at compile
  time. `zeroize` 1.9.1 is the one that changes behaviour: its zeroing no
  longer passes through `optimization_barrier`, so on `wasm32`, which has no
  assembly barrier in 1.9.0, the web module no longer runs that function's
  fallback, which upstream fixed in the same release for values whose first
  byte may be uninitialized; and `Zeroizing`'s `Debug` output is now
  `Zeroizing { .. }` instead of the secret it holds. `libc` stays at 0.2.189
  (see For Contributors).

#### Fixed

- **`Aes256GcmSiv` reports the key length it was actually given**
  (`rust/src/api/crypto.rs`) — a key of the wrong length threw
  "Key must be 32 bytes, got 0 bytes" whatever its length, because the key was
  zeroized before its length was read, and zeroizing a `Vec` also truncates it.
  The length is read first now.

- **An async call no longer waits forever when another isolate shuts down
  during `LibSignal.init()`** (`lib/src/libsignal.dart`, `lib/src/platform/`)
  — flutter_rust_bridge sends every Rust-to-Dart message (the result of an
  async call, the invocation of a store callback) through one process-wide
  `Dart_PostCObject` pointer, and replaces it with a no-op once its count of
  initialized isolates drops to zero. `RustLib.init()` installs the real
  pointer *before* it counts the new isolate, so when the last other counted
  isolate group shut down inside that window, the new isolate was left alive
  with the no-op: its async calls waited for answers that had been dropped,
  while sync calls kept working. `init()` now installs the real pointer again
  once the isolate is counted.

  Who could reach it: `dart test` runs every test file as an isolate group of
  one process, so a consumer's own suite could hang on the first async call
  of a file. `flutter test` starts a process per file and cannot. An
  application that initializes libsignal only in short-lived worker isolates
  could hit it; one that initializes it in its main isolate keeps that isolate
  counted for its whole life — **provided libsignal is the first
  flutter_rust_bridge library that isolate initializes**, see below.

  ⚠ **Not fixed by this change: several flutter_rust_bridge libraries in one
  isolate.** flutter_rust_bridge keeps one shutdown watcher per isolate for
  all of its libraries, while every native library counts isolates on its own
  — so an isolate is counted only by the *first* library it initializes.
  Measured with two libraries: when the main isolate initializes libsignal
  second, and any other isolate — a `compute()` / `Isolate.run` worker
  included — initializes libsignal alone and exits, libsignal's channel is
  switched off for the whole process and every async call from the main
  isolate waits forever, while sync calls keep working. No timing is
  involved, and installing the pointer again in `init()` cannot help: nothing
  is initializing when it happens. With libsignal initialized first in the
  main isolate the same worker is harmless, and so is a worker that
  initializes the libraries in the same order as the main isolate before it
  uses libsignal — which is the rule to follow until this is fixed:
  **initialize the flutter_rust_bridge libraries in the same order in every
  isolate.** flutter_rust_bridge 2.13.0 behaves this way and the fix belongs
  there.

  Here it was the CI flake that picked a different test every time — a
  `TimeoutException` on 7.5% of Windows runs and 4.5% of Linux ARM64 runs,
  always on the first test of a file to make an async call. Reproduced
  outside the test runner by shutting one isolate group down while another
  initializes, timed across the window: 85 hung calls in 600 before this
  change, none after, and in every hung isolate a new call was answered once
  the pointer was installed again. flutter_rust_bridge
  2.13.0 and 2.14.0-beta.2 share the ordering. What remains is a finalizer
  that has already counted to zero and not yet written the no-op, which only
  a lock inside flutter_rust_bridge can close.

- **A local native build left over from an older crate version is no longer
  loaded silently** (`hook/build.dart`, `Makefile`, `README.md`,
  `CONTRIBUTING.md`, `CLAUDE.md`) — the build hook prefers a host library in
  `rust/target/release/` (or `debug/`) over the released one, and took it on
  the sole condition that the file existed, while the local WASM build has had
  to carry a crate stamp since 7.4.0 (published as 7.4.1). `make build` now
  stamps a host build the same way, in `rust/target/release/.crate-version`
  (a `--target` build lands elsewhere, is never read, and gets none), and the
  hook refuses a library whose stamp is missing or names another version,
  saying how to fix it: run `make build`, or delete `rust/target/release/` to
  use the released library.
  `rust/target/debug/` is no longer read: nothing here builds there, and
  nothing would stamp it. Measured on this tree: a library built before the
  change is refused as "an unknown crate version", one stamped 6.3.9 as
  "crate 6.3.9" against 6.4.0, a freshly built one passes, and a `--target`
  build leaves the stamp untouched.

  It matters most in this release: the way errors cross the bridge changed, a
  library built before it still loads, and every error it raises then reaches
  Dart as a `TypeError`. **Who this reaches:** `rust/target/` is
  `.pubignore`d, so a consumer installing from pub.dev never takes this path;
  it affects work in this repository and anyone depending on it by path or git
  who has built the crate. A `rust/target/release/` built before this release
  carries no stamp and is refused, which is the intended answer: `make build`
  fixes it.

#### Documentation

- **`SECURITY.md` matches the coded errors** (`SECURITY.md`) — the
  certificate-validation example called a `senderCert.validate(...)` returning
  a `bool`, which this package does not have; it now uses
  `validateSenderCertificate`, which never returns `false` but throws, and the
  section says what `verificationFailure` does and does not tell you, and that
  an application must never let it change its configuration or make it fall
  back to unsealed sending. The identity-trust section now says to branch on
  `LibSignalErrorCode.untrustedIdentity` instead of looking for "untrusted
  identity" in the message, and that on a pre-key message the code reports a
  key someone presented, not one shown to be the contact's. The load-time
  section no longer says FRB's content-hash check pins the bridge's API
  signature: the check covers the bridged functions' names only, so
  `libsignal_frb` 6.4.0 passes `init()` under this release. The section now
  also says to replace a library pinned with `libraryPath` on every upgrade,
  with the crate version that release's build hook downloads.

- **`SECURITY.md` no longer says the tag ruleset stops a `write`
  collaborator** (`SECURITY.md`) — it said the `Protect release tags` ruleset
  restricts creating, moving and deleting tags to Admins and Maintainers, so
  that a plain `write` collaborator cannot mint a release tag. The ruleset
  leaves all three, unsigned, to the roles on its bypass list, and on
  2026-10-07 GitHub's GraphQL API named those roles `admin` and `write` on the
  live ruleset. What gates a release whoever pushed its tag is the approval of
  the `native-build` and `pub.dev` environments' required reviewers, which the
  section now names as the control that holds on every path. The repository
  has no collaborator but its admin, and the ruleset itself is unchanged.

- **The README says what a failure tells you, and the API docs name the
  codes** (`README.md`, `rust/src/api/sealed_sender.rs`,
  `lib/src/rust/api/sealed_sender.dart`,
  `lib/src/stores/identity_key_store.dart`) — a new *Error Handling* section
  shows how to branch on `code`, lists the codes a decrypt call can return
  before anything in the message is authenticated, says that
  `untrustedIdentity` is a claim rather than a proof and that codes change
  only in a major release, and names the failures that are not a
  `LibSignalException`: a store callback that throws, any other panic, a call
  after `dispose()`, and the checks made in Dart. The documentation of
  `validateSenderCertificate` now says that it never returns `false` and which
  failures are `verificationFailure`, as `SECURITY.md` section F does, and that
  of `IdentityKeyStore` names `LibSignalErrorCode.untrustedIdentity` instead
  of the error's old name.

- **The README says what a missing `web/pkg/` actually does** (`README.md`,
  `CLAUDE.md`, `Makefile`, `example/lib/main.dart`) — *Known Limitations* said
  that `RustLib.init()` then fails on a 404 for `pkg/libsignal_frb.js`. It
  never completes: flutter_rust_bridge 2.13.0 loads the module through a
  `<script>` tag and waits for its `load` event with no error path or
  timeout, so a missing module — a 404, or, under `flutter run`, the app's own
  page served in its place with a 200 — leaves the call pending with nothing
  reported to Dart. Measured with
  `make run-example-web`, the build hook disabled by its skip marker so that
  `web/pkg/` stayed empty, in headless Chrome: `init()` neither returned nor
  threw for 75 seconds, and the dev server answered the missing file with the
  app's own HTML page and a 200, which is why no 404 shows in the network
  tab. The example's error screen never appears in this case; its spinner
  runs on. The README and the comments now say that the call never completes,
  and the example's hint no longer names a missing `web/pkg/` as the usual
  cause of an error screen that case never reaches.

### For Contributors

#### Added

- **Tests pin the error type, the codes' wire numbers and every code**
  (`rust/src/api/error.rs`, `test/errors/lib_signal_exception_test.dart`,
  `test/test_helpers/error_matchers.dart`,
  `test/sealed_sender/usmc_and_multi_recipient_test.dart`) — a bridged
  function declared with another error type, such as `-> Result<T, String>`,
  still compiles, and Dart then gets that type.
  `generated_bindings_use_no_other_error_type` reads
  `rust/src/frb_generated.rs` and fails when any bridged function's error type,
  under any codec, is not `LibSignalException`. `codes_keep_their_wire_positions`
  checks the number each generated encoder and decoder writes for every code,
  so a code inserted, moved or appended fails it, as it fails the Dart test that
  lists `LibSignalErrorCode.values`. Every code except `internalError` is
  asserted with an exact matcher somewhere under `test/`, through the public
  API. `every_protocol_error_variant_has_its_code` holds one row per
  `SignalProtocolError` variant, checked against the list that also builds an
  exhaustive `match`: a variant libsignal adds does not compile until it is
  listed, and then fails the test until it has a row. The foreign-trust-root
  test in `usmc_and_multi_recipient_test.dart` issues its forged certificate
  for the key that seals it, so the trust-root check is what it reaches and
  `verificationFailure` what it expects; libsignal's own check that a
  certificate names the key the envelope was sealed with has a test of its
  own, a genuine certificate sealed with another key failing as
  `invalidMessage`. The test that a throwing store surfaces as `PanicException`
  runs on the Dart VM only.
- **A check between the release stages runs the suite against the released
  binary** (`CLAUDE.md`, `.claude/skills/release-package/SKILL.md`) — no
  workflow ever does: `publish.yml` and `test.yml`, its `workflow_run` after
  the native build included, build the library from source with `make build`,
  so a mismatch between the stage-1 binary and the Dart about to be published
  would first reach consumers. Both now describe checking `HEAD` out in a fresh
  sibling worktree, which has no `rust/target/`, and running `make get` and
  `make test` there, so that the build hook downloads that release's library
  for this host, checks its checksum and every test runs against it; the
  other platforms' libraries are not loaded. Measured both ways, against the
  released 6.4.0: from the tree just before this change (`c653698`, 927
  tests), 82 fail, every one with the `TypeError` an old binary gives the new
  error type; from `v7.4.1`, whose Dart matches that binary, all 895 pass.
- **CI type-checks the three iOS targets on every push and pull request**
  (`.github/workflows/test-reusable.yml`, `Makefile`, `CLAUDE.md`,
  `.github/rulesets/README.md`) — nothing that ran before a release tag
  compiled iOS, so the `libc` 0.2.190 break
  below was green on its pull request and on `main`, and only the tag's
  `build-ios` legs would have found it, with the crate version already spent.
  A `Type-check (iOS)` job now runs `make rust-check-ios` on macOS:
  `cargo check --locked` for `aarch64-apple-ios`, `aarch64-apple-ios-sim` and
  `x86_64-apple-ios`, the three the release builds. Measured both ways: with
  the lock from before the `libc` hold it fails on the first target with the
  same four `E0425`, and with the current one all three pass. It catches
  compile errors, not link errors, and it is not a required check, which the
  rulesets README now says; because `publish.yml` runs its tests through the
  same reusable workflow, a failure there also stops stage 2, as the Android
  jobs already do.

#### Changed

- **`thiserror` is no longer a direct dependency of the crate**
  (`rust/Cargo.toml`, `rust/Cargo.lock`) — nothing in `rust/src/` derives or
  names it. It still reaches the binary at the same 2.0.21 through
  `libsignal-core`, `libsignal-protocol`, `signal-crypto` and `spqr`, so the
  set of compiled crates is identical on the host and on wasm32, and
  `THIRD_PARTY_NOTICES.txt` does not move. The template keeps the line:
  projects generated from it do use `thiserror`.
- **`libc` is held at 0.2.189, the version 6.4.0 shipped** (`rust/Cargo.lock`,
  `THIRD_PARTY_NOTICES.txt`) — the libsignal v0.104.0 update took it to
  0.2.190, which puts `_dyld_image_count` and the `_dyld_get_image_*`
  functions behind `cfg(target_os = "macos")`. `backtrace` 0.3.76, which every
  native build compiles through `flutter_rust_bridge` and `allo-isolate`, calls
  them on every Apple target, so all three iOS builds failed with `error[E0425]`
  and a crate release tag would have produced no GitHub Release. No workflow
  that runs before a release tag compiles iOS, which is why the update pull
  request and `main` were green. Upstream tracks it as
  [rust-lang/libc#5601](https://github.com/rust-lang/libc/issues/5601), and
  0.2.190 was still its latest release on 2026-10-07. The binaries keep the
  `libc` that 6.4.0 shipped.
  ⚠ A full `cargo update` — `make rust-update`, which the libsignal update
  bot also runs — takes `libc` back to 0.2.190 until upstream releases a fix;
  the `Type-check (iOS)` job added above now fails on the pull request that
  does it, and `make rust-check-ios` runs the same check locally.
- **`make release` refuses a stage-1 release whose native sources moved since
  its tag** (`scripts/src/release.dart`, `scripts/release.dart`,
  `test/scripts/release_test.dart`, `CLAUDE.md`,
  `.claude/skills/release-package/SKILL.md`) — "built from this tree" was
  checked on two values, the codegen version and the libsignal pin, so a
  commit to `rust/src` between the two stages passed, as would a stage 2 run
  with stage 1 forgotten whenever the pin had not moved — and the package then
  went out against a binary built without that code. `rust/` (all but
  `rust/fuzz` and `rust/deny.toml`) and `lib/src/rust/` at the stage-1 tag
  are now compared with `HEAD` by git object, read through GitHub's contents
  API on one side and `git ls-tree` on the other: equal shas mean equal
  content, no tag has to exist locally, and `HEAD` need not be pushed. It
  fails closed when either side cannot be read. **Any commit touching those
  paths after stage 1 now needs a new crate**, a test-only change under
  `rust/src` and a docstring-only regeneration included, and
  `--skip-frb-check` skips both checks. Measured on the real tags:
  `libsignal_frb-6.4.0` against `v7.4.1` reports nothing, against `HEAD` it
  names `lib/src/rust`, `rust/Cargo.lock`, `rust/Cargo.toml` and `rust/src`,
  and both readers return the same objects for the same tag.
- **The Linux x86_64 library is built on a pinned `ubuntu-24.04`**
  (`.github/workflows/build-libsignal.yml`) — it was the one release build on
  `ubuntu-latest`, which moves to Ubuntu 26 from 2026-10-19
  ([runner-images#14748](https://github.com/actions/runner-images/issues/14748)),
  and the `.so` links against the runner's glibc: a newer one can raise the
  oldest glibc a consumer's Linux needs to load the library. arm64 was already
  pinned to `ubuntu-24.04-arm`, and 6.4.0's libraries need `GLIBC_2.34` on
  both architectures (measured with `llvm-objdump -T`), so the release keeps
  the environment 6.4.0 was built in and consumers see no change. The CI test
  leg for Linux x86_64 still runs on `ubuntu-latest`.

#### Fixed

- **The release recovery advice works with the release scripts**
  (`.claude/skills/release-frb-crate/SKILL.md`,
  `.claude/skills/release-package/SKILL.md`,
  `.github/workflows/build-libsignal.yml`) — both skills said to delete a
  failed release's tag, fix `main` and run the same version again, which the
  scripts refuse: past the fix the version bump is no longer `HEAD`, and the
  version is not greater than itself. They now tell a transient failure, which
  is retried on the same tag (re-run the failed jobs, or dispatch the native
  build on the tag, never on `main`, whose newer code would be published under
  the tag's version), from a code failure, which spends the version and needs
  the next patch. The build workflow's comments said to delete a release
  *and its tag* to rebuild it, which leaves nothing to dispatch on; they now
  say to keep the tag.
- **No instruction tags a release by hand without the checks `make release`
  makes, or misstates who may create a tag** (`Makefile`,
  `.github/workflows/publish.yml`,
  `.github/workflows/check-libsignal-updates.yml`,
  `.claude/skills/release-package/SKILL.md`,
  `.claude/skills/release-frb-crate/SKILL.md`, `CLAUDE.md`, `CONTRIBUTING.md`,
  `.github/rulesets/README.md`, `.claude/skills/security-review/SKILL.md`) —
  `make publish`'s help and `publish.yml`'s header told you to
  `git tag vX.Y.Z && git push`, an unsigned tag that skips every check
  `make release` makes, and the update bot's pull request listed stage 2 as
  steps to do by hand; all three now name `make release`. The release skill's
  manual fallback, for a release that cannot go through `make release`, still
  tags by hand, and now starts with what `make release` checks first: that
  the stage-1 release exists, and that `git diff --quiet` finds nothing
  between its tag and `HEAD` in the native sources. On the real tags that
  command agrees with the scripted check: nothing for `libsignal_frb-6.4.0`
  against `v7.4.1`, the same four paths against `HEAD`. The skill said tag
  creation is not gated; the `Protect release tags` ruleset gates it, to the
  roles on its bypass list, and every one of them bypasses its
  `required_signatures` rule (`always`), which `CLAUDE.md` said rejects an
  unsigned tag. The rulesets README called `actor_id` 4 on that list
  Maintain, which GitHub names `write` (the `SECURITY.md` entry above); the
  README now maps it as GitHub does and says what that allows, and both
  release skills, `CLAUDE.md` and `CONTRIBUTING.md` speak of the roles on the
  bypass list instead of naming them. The JSON is unchanged: which roles
  belong there is a policy decision. And the security-review skill's certificate example
  still called a `senderCert.validate(...)` this package does not have; it is
  now `SECURITY.md` section F's.
- **`rustContentHash` is described as what it is** (`CLAUDE.md`, `Makefile`,
  `hook/build.dart`, `test/hook/build_hook_test.dart`,
  `test/scripts/release_test.dart`, `scripts/src/release.dart`) — seven places
  in six files said it compares the FFI *surface*. flutter_rust_bridge 2.13.0 hashes the
  sorted names of the bridged functions and nothing else
  (`generate_content_hash`), so a change to argument, return or error types —
  this release's errors included — leaves it where it was.
- **The contributor docs teach the coded error type** (`CONTRIBUTING.md`,
  `.claude/skills/frb-patterns/SKILL.md`) — both still had a new bridged
  function return `Result<T, String>`, and the skill converted libsignal's
  errors with `e.to_string()`: the shape this release replaces, and one
  `generated_bindings_use_no_other_error_type` now fails. Their examples return
  `Result<T, LibSignalException>`, and the skill's *Error Handling* says how a
  libsignal error keeps its code (`From`, `.context()`), how one raised here
  names its own, and why there is no `From<String>`. The template keeps its
  wording, since its copy serves every generated project and each one picks its
  own error type, so the skill is now a standing divergence.
- **`make get` passes `ARGS` on** (`Makefile`, `CLAUDE.md`) — it ran
  `dart pub get` on the root package whatever it was given, so
  `make get ARGS="--directory=example_cli"` exited 0 having resolved the
  wrong package, and on a fresh checkout `make analyze ARGS="example_cli"`
  failed with `uri_does_not_exist` with no make target to fix it. Measured both
  ways: with `example_cli` unresolved, the analysis fails, and after the fixed
  `make get ARGS="--directory=example_cli"` it is clean; a plain `make get`
  behaves as before.

## Older releases

7.4.1 and everything before it are in
[CHANGELOG-ARCHIVE.md](https://github.com/djx-y-z/libsignal_dart/blob/main/CHANGELOG-ARCHIVE.md).

[Unreleased]: https://github.com/djx-y-z/libsignal_dart/compare/v8.0.1...HEAD
[8.0.1]: https://github.com/djx-y-z/libsignal_dart/compare/v8.0.0...v8.0.1
[8.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v7.4.1...v8.0.0
