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

## [7.4.1] - 2026-09-29

### For Users

#### ✨ Highlights

- **7.4.0 was tagged but never published** — pub.dev refused its upload
  because `CHANGELOG.md` had grown past its 256 KiB limit (281 788 bytes). This
  release carries exactly the same code, so everything listed under 7.4.0
  below — `KyberKeyPair.fromKeys()`, the store-callback zeroization, libsignal
  v0.103.1 — reaches pub.dev with 7.4.1
- **libsignal v0.103.1** — unchanged this release
- **libsignal_frb v6.4.0** — unchanged this release

#### Documentation

- **Releases 7.2.0 and older moved to `CHANGELOG-ARCHIVE.md`**
  (`CHANGELOG.md`, `CHANGELOG-ARCHIVE.md`, `.pubignore`) — pub.dev rejects a
  `CHANGELOG.md` larger than 262 144 bytes, and this file had reached 281 788;
  `dart pub publish --dry-run` does not check it, so the limit surfaced only
  as the 7.4.0 upload was refused. `CHANGELOG.md` keeps the latest releases
  (82 KB) and links to the archive by absolute GitHub URL, since the archive
  is not part of the published package. The moved sections are unchanged,
  compare links included.

## [7.4.0] - 2026-09-29

### For Users

#### ✨ Highlights

- **`KyberKeyPair.fromKeys()` rebuilds a Kyber key pair from a public and a
  secret key stored apart** — the way back from the halves' own `serialize()`
  to a `KyberPreKeyRecord`, which the API did not offer. It checks that the two
  belong together, which upstream does not, because a mismatched record would
  otherwise be accepted and fail only on a peer's first message
  ([#103](https://github.com/djx-y-z/libsignal_dart/issues/103))
- **Secrets a store hands to Rust are cleared even when a store throws** — the
  identity key pair, session, pre-key and sender-key records loaded through
  store callbacks are now zeroized on every exit, where a throwing store used
  to skip the wipe and some of them were never wiped at all
- **libsignal v0.103.1** — internal/dependency update, no public-API impact
- **libsignal_frb v6.4.0** — Rust FFI bindings

#### Added

- **`KyberKeyPair.fromKeys()` rebuilds a Kyber key pair from its two halves**
  ([#103](https://github.com/djx-y-z/libsignal_dart/issues/103))
  (`rust/src/api/kyber.rs`, `rust/Cargo.toml`, `README.md`) —
  `KyberPreKeyRecord.create` takes a `KyberKeyPair`, and the only ways to get
  one were `KyberKeyPair.generate()`, or `getKeyPair()` and `cloneKey()` on a
  record or pair already held. An application that stores the public and
  secret keys apart — each has its own `serialize()` — therefore had no way
  back from those bytes to a record through the API. The EC records never had
  this gap: `PreKeyRecord` and `SignedPreKeyRecord` take their public and
  private keys separately. Signal's own bindings share it — none of them builds
  a key pair from its two halves — so this is an addition on our side,
  performing the same join libsignal does when it reads a stored Kyber record
  back.

  There is still no serialized form of the pair itself, and that is deliberate:
  upstream defines none, and a format this package invented would be one it had
  to keep reading forever. The halves' own encodings are the format. A pre-key
  kept whole needs none of this — `KyberPreKeyRecord.serialize()` carries both
  halves together with the id, timestamp and signature.

  `fromKeys()` also checks that the halves belong together, which upstream does
  not: its key pair compares only the key types. The check encapsulates a
  shared secret to the public key, decapsulates it under the secret key and
  compares the two in constant time. That is the pair-wise consistency test
  FIPS 203 (§7.1) and FIPS 140-3 IG 10.3.A define for ML-KEM, applied to
  round-3 Kyber by analogy rather than by requirement — and only that step, not
  FIPS 203's full key-pair check. Nothing later would catch a mismatch: creating
  a record and reading it back do not check the pairing, and Kyber
  decapsulation does not fail under the wrong key — it returns a different
  secret. A mixed-up record would be accepted and published, and the mismatch
  would surface only when a peer's first message failed to decrypt. Observed
  rather than inferred: a record whose secret key is not the partner of the
  published public key makes that first message fail with a bare
  `invalid PreKey message: decryption failed`, naming no key, and
  `test/kyber/kyber_key_pair_test.dart` pins that it fails to decrypt, next to a
  record rebuilt through `fromKeys()` that succeeds. The test stores a foreign
  pair rather than mixed halves; to the recipient the two are the same case,
  since it reads only the record's secret key. It follows that every session
  started against a mixed-up last-resort key would fail until the key was
  rotated.

  Unlike `IdentityKeyPair.fromKeys`, it borrows its arguments instead of moving
  them, so both handles stay usable after the call, whether or not the check
  passes. The pair holds its own copy of the secret key: `dispose()` the
  `KyberSecretKey` you passed in once you are done with it. `subtle`, already in
  the dependency graph through libsignal, is now a direct dependency for the
  comparison. The README's key table gains a `KyberKeyPair` row.

#### Changed

- **libsignal v0.103.0 → v0.103.1 moves only its version constant here; the
  one change that reaches the binary is `rand` 0.10.2 → 0.10.3**
  (`rust/Cargo.toml`, `rust/Cargo.lock`, `THIRD_PARTY_NOTICES.txt`) — upstream's
  own notes name one item, "Swift: BackupJsonExporter is now available", and
  the five commits in the
  [range](https://github.com/signalapp/libsignal/compare/v0.103.0...v0.103.1)
  land in `swift/`, `java/`, `node/` and `rust/bridge/`, none of which is in
  this package's dependency graph. Four libsignal crates are: in the lockfile
  `libsignal-protocol`, `libsignal-core` and `signal-crypto` change only their
  source revision, and `libsignal-debug` only its version, 0.103.0 → 0.103.1.
  The one file touched under any of them is `rust/core/src/version.rs`, the
  version string. `spqr` stays at 1.6.0.

  `rand` 0.10.3 is a crates.io patch release, not part of libsignal, and it
  does reach the binary — through `hpke-rs-crypto` (under `signal-crypto`) and
  `libcrux-traits` (under the ML-KEM and HMAC code). Its source changes are
  confined to `distr/` and `seq/` (`Uniform`, `WeightedIndex`, `Bernoulli`,
  index sampling); both crates use only its RNG traits, which it did not
  touch. `make codegen` leaves `lib/src/rust/` unchanged, so the FFI surface
  did not move.

- **`thiserror` 2.0.20 → 2.0.21** (`rust/Cargo.lock`,
  `THIRD_PARTY_NOTICES.txt`) — Dependabot's bump (#104), inside the `"2.0"`
  range `rust/Cargo.toml` already declares. Nothing under `rust/src/` uses it;
  it reaches the binary through `libsignal-core` and `signal-crypto`, and the
  release changes only compile-time parsing there: `thiserror-impl` now
  tracks turbofish nesting (`::<…>`) inside `#[error(...)]` format arguments,
  so code that used no turbofish there expands exactly as before. Its declared
  floor rises to Rust 1.77, below this crate's 1.93.1.

#### Security

- **Secrets from store callbacks are cleared on every exit, including when a
  store throws** (`rust/src/api/session_cipher.rs`,
  `rust/src/api/group_session.rs`, `rust/src/api/session_builder.rs`,
  `rust/src/api/sealed_sender.rs`, `SECURITY.md`) — FRB declares every Dart
  store callback non-failable, so a store that throws — a locked SQLite
  database, say — panics the Rust worker, and the unwind skipped any
  `zeroize()` still ahead of it. In `session_cipher.rs` (all three paths) and
  `session_builder.rs` the identity key pair is fetched first and further
  store callbacks run after it (`getLocalRegistrationId`, `getIdentity`, the
  pre-key loads), so a throwing store left the serialized identity key pair in
  freed memory. In `group_session.rs` the sender-key record was the exposed
  one: encryption and distribution-message creation load it before calling
  `getIdentityKeyPair`. Some secrets were never cleared at all: the session
  record on the encrypt and Signal-message decrypt paths, and on the pre-key
  decrypt path the existing session plus the signed, one-time and Kyber
  pre-key records, each carrying a private key. In the sealed-sender pre-key
  path those three records were cleared only after a `?` that could skip it.

  Every secret a store callback returns is now held in `Zeroizing`, whose
  `Drop` runs on return, on error and on unwind alike — the shape
  `sealed_sender.rs`'s entry points already used — and is dropped as soon as
  the work is done, before the write-back callbacks, where the old `zeroize()`
  ran. The two group-session functions that call no other store callback
  before the work gain it for consistency and to cover a panic inside the work
  itself. Function bodies
  only: no signature changes, `make codegen` leaves `lib/src/rust/` untouched,
  and the FFI surface does not move. The exception still reaches Dart as
  before. This covers what the stores *hand in*; the records Rust produces for
  the write-back (the updated session and sender-key record) are handed to
  Dart as before and are not wrapped. `SECURITY.md` now says which callback
  results are cleared and on which exits.

#### Fixed

- **The example app reports why it failed to start instead of spinning
  forever** (`example/lib/main.dart`) — `_initLibSignal()` is fire-and-forget
  from `initState()` and caught nothing, so any `LibSignal.init()` failure left
  the initialized flag false and the progress indicator running, with the
  exception visible only in the console. The body now branches three ways and
  renders the error, the raw message included, plus a hint that names the
  usual web cause and `make run-example-web`.

  It is the same failure a consumer meets. On web `init()` throws when
  `web/pkg/` was never provisioned, and the most common way to reach that is
  documented under *Known Limitations*: `flutter run -d chrome` after a run for
  another platform reuses that run's `dart_build` stamp — the build directory
  key does not include the target platform — and skips the build hook outright.
  A spinner says none of that.

- **A local WASM build left over from an older crate version is no longer
  served silently** (`hook/build.dart`, `Makefile`) — the web path of the build
  hook prefers a local `rust/target/wasm32/` build over the released module,
  and it took that directory on the sole condition that the two files *exist*.
  It then recorded `local-dev` in `web/pkg/.wasm-version` rather than a
  version, so the staleness check that guards the download path — added in
  6.1.0 for exactly this failure — was unreachable on the local one. A wasm
  module built before a crate bump was therefore copied into `web/pkg/` and
  served, announced by nothing louder than `Using local WASM build from …`.

  Measured in this repository rather than reasoned about: after the 6.3.1
  release, `rust/target/wasm32/` still held a module built on 2026-09-08, when
  the crate was 6.3.0 and the vendored libsignal was v0.102.0. A web build
  would have run that module against a package whose native side is v0.103.0 —
  that is, without the two hardenings 7.3.1 is about.

  ⚠ **`rustContentHash` cannot catch this**, which is the reason the fix is a
  version stamp rather than a reuse of the existing check. That value compares
  the FFI *surface*, and the surface was byte-identical across 6.3.0 → 6.3.1 —
  precisely why that release was a patch. The one value already crossing the
  Dart-to-binary boundary is blind to this case by construction. Timestamps are
  no better: a checkout or a stash moves them in either direction without the
  content changing.

  `make build-web` now stamps the crate version into
  `rust/target/wasm32/.crate-version`, and the hook refuses a local build whose
  stamp is missing or disagrees with `rust/Cargo.toml`, naming the command that
  fixes it. A directory built before this release carries no stamp and is
  rejected, which is the intended answer rather than an accident.

  **Who this reaches:** `rust/target/` is `.pubignore`d and absent from the
  published archive, so a consumer installing from pub.dev never takes this
  path. It affects work in this repository and anyone depending on it by path
  or git who has run `make build-web`. It was also latent rather than active —
  `make run-example-web` depends on `build-web`, so the module is rebuilt
  before every run through it; the exposed routes are `flutter build web` and a
  hand-run `flutter run -d chrome`.

#### Documentation

- **Every store interface's example compiles again**
  (`lib/src/stores/pre_key_store.dart`, `signed_pre_key_store.dart`,
  `session_store.dart`, `kyber_pre_key_store.dart`) — each class doc showed
  `…Record.deserialize(data)`, but all four constructors take a named
  argument, so the example a store implementer starts from did not compile. It
  reads `deserialize(bytes: data)` now.

- **`KyberPreKeyStore` names its two kinds of key correctly**
  (`lib/src/stores/kyber_pre_key_store.dart`) — the class doc called the
  one-time Kyber pre-keys "last resort" and the reusable ones "signed": the
  wrong way round, and the wrong distinction, since the last-resort key is the
  one that is reused and both kinds are signed. The doc of
  `markKyberPreKeyUsed` always had it right; the class doc now agrees with it
  and points there.

- **SECURITY.md no longer says libsignal zeroizes keys** (`SECURITY.md`) —
  three places credited libsignal's Rust code with `zeroize` for sensitive
  data, and the plaintext section said "Keys ARE zeroized", all against the
  document's own §A. libsignal-core's `PrivateKey` is `Copy` and has no
  `Drop`, the Kyber secret key has no `ZeroizeOnDrop`, and neither
  libsignal-protocol nor libsignal-core calls `zeroize` in its own code — it
  appears only as a feature of the cipher crates underneath. What this package
  can promise is that it wipes its own copies of the serialized key material
  it receives, and the four places now say exactly that.

- **SECURITY.md §B's example calls methods that exist** (`SECURITY.md`) — it
  verified with `publicKey.verifySignature(...)`, which `PublicKey` never had
  (the method is `verify()`; `verifySignature` belongs to `SenderKeyMessage`),
  and its "AVOID" line compared two `Uint8List`s with `==`, which in Dart
  compares identity rather than content — false even for equal keys, so
  timing was not its problem. The section also credited every operation to
  libsignal-protocol, where `hkdfDerive` and `Aes256GcmSiv` run on the
  RustCrypto crates, and it now names the one comparison this package makes
  itself (`KyberKeyPair.fromKeys`, through `subtle`). Its pointer to
  `package:crypto` became concrete: `Digest(a) == Digest(b)` is the
  constant-time comparison that package offers.

- **The README's crypto table lists API that exists** (`README.md`) —
  `Hkdf.deriveSecrets` and `Fingerprint.compare` have been gone since the move
  to Flutter Rust Bridge; the table now names `hkdfDerive` and
  `fingerprintCompare`, both free functions.

### For Contributors

#### Changed

- **copier template adopted: v4.15.1 → v4.15.2** (`.copier-answers.yml`) —
  the adoption moved `_commit` and nothing else, because every change in the
  release was written here first: the three `refresh-notices.yml` fixes below
  (`GH_REPO`, the unused `APP_SLUG`, and the `--rawfile` payload) and the
  `claude-code-action` v1.0.236 pin. copier merged them as identical changes
  on both sides and reported no conflicts; the two workflow files are
  byte-identical to the template's.

- **`anthropics/claude-code-action` moves to v1.0.236**
  (`.github/workflows/ai-review.yml`, `.github/workflows/repair-build.yml`) —
  v1.0.228 → v1.0.236, made on `main` directly, with the template's two copies
  moved to the same SHA. Dependabot proposed v1.0.230 in #101 and, once `main`
  had that, rebuilt the pull request as v1.0.235; v1.0.236 was already out and
  differs from it by one more bundled-CLI bump, so the pin skips straight to
  it. The annotated tag dereferences to
  `8ce9314fa9a404564fa7e954cd84f25bcba2b829`, checked against the upstream ref
  rather than taken from a pull request body. Across the range the action
  itself changes only the bundled Claude Code, 2.1.275 → 2.1.284, and its
  Agent SDK; the rest is upstream's own CI. Both steps run only when the agent
  engine is `claude-code`, and this repository's `AGENT_ENGINE` is `opencode`,
  so nothing that runs here changes — the pin is kept current for the day the
  engine is switched.

- **copier template adopted: v4.15.0 → v4.15.1, plus the two fixes it
  needs to run** (`.copier-answers.yml`, `.github/workflows/refresh-notices.yml`) —
  the notices refresh pushed `THIRD_PARTY_NOTICES.txt` onto Dependabot's cargo
  branches as an ordinary, **unsigned** commit. `signing-commit.json` excludes
  `dependabot/**/*`, so the push was accepted, but `main`'s
  `required_signatures` is not excluded, so the pull request could then never
  be merged. #104 is that case exactly: Dependabot's commit is
  `verified: true`, the workflow's `1e251c6` is `unsigned`, and the pull
  request sits `BLOCKED` with every required context green. v4.15.1 writes the
  commit through GraphQL `createCommitOnBranch`, which signs it, and reads
  `verification.verified` back to fail loudly if it did not.

  ⚠ **As released, that step cannot run.** It passes `$GH_REPO` to the
  mutation and to the verification call under `set -euo pipefail`, and nothing
  sets it — not the step's `env:`, not `GITHUB_ENV`, not the runner — so it
  would stop on `GH_REPO: unbound variable` before creating any commit. The
  step's `env:` gains `GH_REPO: ${{ github.repository }}` here; the template
  gets the same bytes, so the next adoption merges it as an identical change
  on both sides. `make actionlint` was green on the broken file and cannot see
  this: shellcheck treats upper-case names as coming from the environment. The
  same step also drops `APP_SLUG`, which only fed the `git config` identity the
  GraphQL route no longer needs.

  ⚠ **The first live run found a second defect behind the first.** Dispatched
  for #104 (run `36544895160`), it got past `GH_REPO` and stopped on
  `/usr/bin/jq: Argument list too long`, exit 126: the step handed the whole
  base64-encoded inventory to `jq` as one `--arg`, and this repository's
  `THIRD_PARTY_NOTICES.txt` is 500 KB — 667 KB encoded — against the 128 KiB
  Linux allows a single argument. The encoding now goes to a file under
  `$RUNNER_TEMP` and reaches `jq` through `--rawfile`; built locally from the
  real inventory, the payload decodes back to it byte for byte. Nothing short
  of running it could have shown this either — it depends on the size of the
  file, not on the script.

- **copier template adopted: v4.14.1 → v4.15.0** (`.copier-answers.yml`,
  `.github/workflows/repair-build.yml`, `.github/workflows/ai-review.yml`,
  `.github/workflows/check-template-updates.yml`,
  `.github/workflows/build-libsignal.yml`,
  `.github/workflows/test-reusable.yml`, `.gitignore`, `CLAUDE.md`) — the CI
  agents change in two ways that matter here. The repair and review workflows
  now read `.github/agent-config/opencode.json` from the **default branch**
  rather than from the tree being checked out: the permission assertion that
  validates it is baked into the workflow, which always comes from the default
  branch, so the agent's permissions used to travel with the checkout while the
  assertion about them did not. It failed closed, and the class it blocked was
  exactly `update-template-*` — the branch carrying the template's new config
  while the workflow judging it is the old one, which is what every template
  release produces. And the template-update checker now closes the update pull
  requests it supersedes, gated on the branch shape, an older version, the
  `agent-repaired` label, a `repair-build:` commit trailer and any non-bot
  commit author; `dry_run` defaults to on for a manual run and off for a
  scheduled one.

  Both were verified against this repository's own runs rather than by reading.
  Run `35428400857` had stopped at `commands this workflow expects that are not
  allowed: ['make doc', 'make rust-doc']`, naming the workspace path it read;
  run `35582021377`, dispatched with the same `run_id` from a branch carrying
  the fix, reports `repair permissions resolve as intended: 15 commands,
  exactly the documented set` and goes on to run the model — a path that had
  never executed live before. The closing rule was replayed over all 63 bot
  pull requests here: it selects exactly the five superseded
  `update-template-*` ones, ignores all 57 of the other class, and is held back
  by both the label and a real human commit.

  ⚠ **The trailer it looks for is a commit-message trailer, not a pull-request
  body one**, and the difference was measured here: the update bot's body
  embeds the generated CHANGELOG entry, and a CHANGELOG entry quotes
  `repair-build: <sha> (agent)` verbatim while describing the feature, so a body
  search vetoes #99 — which was never repaired.

  The rest is smaller. `build-libsignal.yml` and `test-reusable.yml` get the
  corrected `setup-android` comment: both said upstream had no fixed release
  two lines above a pin at v4.0.4, when `android-actions/setup-android#537`
  closed on 2026-09-17 and v4.0.2 shipped six minutes later. The `packages:`
  input is unchanged — it names exactly the package those jobs need, which is
  the property whose absence made the original outage possible. `.gitignore`
  gains `__pycache__/` and `*.py[cod]`, latent until somebody runs one of the
  Python gates locally. `CLAUDE.md` gains the block explaining that
  `make build-web` stamps `rust/target/wasm32/.crate-version` and that the hook
  refuses a local build whose stamp is missing or disagrees — behaviour this
  repository already had, from `9f0c86c`, and did not document.

  **A new template question arrived and was answered empty.**
  `forbidden_features` names cargo features that must never be enabled in the
  shipped dependency graph, keyed by crate. Empty renders **no gate at all**
  rather than a gate with nothing to check, so the three files behind it are
  not created here and nothing in the build changes. Setting it is a separate
  decision that needs a measured answer — which feature on which crate, and
  why shipping it would be wrong — and there is no such finding for this
  package yet.

  copier merged all eight files with **no conflicts**, which on a file like
  `CLAUDE.md` is not by itself evidence, so the checks that catch a false-clean
  merge were run anyway: no heading in `CLAUDE.md` is duplicated that was not
  already duplicated at `HEAD` (`#### Added` and `#### Changed` appear twice in
  the changelog-format documentation, under both audiences, and did before),
  and every one of the eight was compared byte-for-byte against a fresh render
  of v4.15.0 made with this project's own answers. Five are identical to it.
  The two that differ are the standing divergences and differ by exactly the
  line counts they did before: all of `CLAUDE.md`'s project-specific content,
  and one comment in `test-reusable.yml` that names `libsignal` where the
  template generalises to "the native library" — a fourth instance of the same
  wording pattern the previous adoption recorded three of.

- **copier template adopted: v4.14.0 → v4.14.1** (`.copier-answers.yml`) — the
  adoption moved `_commit` and nothing else, and that is the finding rather
  than an absence of one: of the release's four commits, the two that reach a
  generated project were both written here first. The action pins
  (`anthropics/claude-code-action` v1.0.222 → v1.0.228,
  `android-actions/setup-android` v4.0.1 → v4.0.4) arrived as Dependabot's
  grouped bump `f58bbcc`, and the local-WASM version stamp is the `#### Fixed`
  entry above, `9f0c86c`. The other two commits — moving the template's *own*
  release workflow to `actions/checkout@v7`, and the release preparation —
  live at the template root rather than under `template/`, so they reach no
  generated project at all.

  Three files conflicted, `Makefile`, `hook/build.dart` and
  `test/hook/build_hook_test.dart`, and all three resolved to ours on wording
  alone: our comments name the vendored *crypto* and the concrete 6.3.0 →
  6.3.1 that motivated the stamp where the template generalises to "native
  code" and "a patch release", and our tests assert against the real crate
  versions where the template's skeleton uses `1.5.0` / `1.4.0`. The mechanical
  check that guards a keep-ours resolution — resolve every block to ours, then
  diff against `HEAD` — came back empty on all three, so nothing the template
  had merged cleanly outside the conflict brackets was discarded.

  One thing was checked by hand because no gate can report it.
  `.github/agent-prompts/changelog-scope.md` is `_skip_if_exists`, so a
  template change to it can never arrive: its absence from a change list is a
  dropped change rather than an identical one. It did not move in this range.

#### Fixed

- **The `security-review` skill's example calls methods that exist**
  (`.claude/skills/security-review/SKILL.md`) — it carried the same
  `publicKey.verifySignature(...)` and `Uint8List ==` example as SECURITY.md
  §B, corrected the same way, and gains one checklist line: a new Rust-side
  comparison of secret values goes through `subtle::ConstantTimeEq`, as
  `KyberKeyPair.fromKeys` does.

## [7.3.1] - 2026-09-20

### For Users

#### ✨ Highlights

- **libsignal v0.103.0** — two upstream hardenings reach the protocol this
  package exposes: a peer can no longer turn post-quantum ratcheting off by
  presenting an SPQR version this client does not support, and a repeated
  pre-key message that carries a different identity key is rejected instead of
  being accepted into the session that is already established
- **libsignal_frb v6.3.1** — Rust FFI bindings

#### Changed

- **libsignal moves to v0.103.0** (`rust/Cargo.toml`) — fourteen commits
  upstream ([compare](https://github.com/signalapp/libsignal/compare/v0.102.3...v0.103.0)).
  Upstream's own notes for the tag list five items, and the one that reaches
  this package is the first of them — the SPQR update, which is under
  **Security** below.

  The other four do not reach it. The WebAuthn registration flow, the
  `OneTimePasswordNotVerified` → `MfaNotVerified` rename, the two MFA
  verification APIs and key transparency over gRPC all land in `rust/net`,
  twenty of the range's seventy-two files, and `libsignal-net` appears nowhere
  in `rust/Cargo.lock` — not directly and not transitively. The `{webp,mp4}san`
  0.5.4 upgrade changes no file under `rust/media` at all; it is a
  `[workspace.dependencies]` bump, and `mp4san`, `webpsan` and
  `mediasan-common` are absent from the lockfile too. Thirty-two more files are
  the Swift, Java and Node bindings and nine are `rust/bridge`, the C FFI
  surface those bindings compile against, which this package does not use — it
  binds the pure-Rust crates directly. The rest are upstream's own
  `acknowledgments/`, its podspec, and the notes, manifest and lockfile its
  release commit touches.

  Of the four crates from that repository in this package's dependency graph,
  the complete file list touches two files. `rust/core/src/version.rs` is the
  version string. `rust/protocol/src/protocol.rs` drops a `log::warn!` that
  printed both MACs when a `SignalMessage` MAC check failed; the constant-time
  comparison itself is unchanged, and this package installs no `log`
  implementation, so those records already went nowhere here and nothing
  observable changes. No source file under `signal-crypto` is listed, and the
  file list does not join either change to a named commit. Upstream's workspace
  `rust-version` stays at 1.93.1, so the build floor does not move.
  `make codegen` produced no change under `lib/src/rust/`, so the FFI surface
  did not move — and, as with v0.102.3, that is not the same as "nothing
  reaches the surface".

  Asked at the lockfile rather than the file tree, the transitive half appears,
  and that is where this release's one user-visible change lives: `spqr` moves
  1.5.3 → 1.6.0 and drops `curve25519-dalek` and `displaydoc` from its runtime
  dependencies, keeping the former as a dev-dependency. Six registry crates
  move — `cc`, `cfg-if`, `find-msvc-tools`, `rustix`, `syn` and
  `unicode-ident` — and none is added or removed. `THIRD_PARTY_NOTICES.txt`
  records the moves that are not test-only.
- **libsignal moves to v0.102.3** (`rust/Cargo.toml`) — ten commits upstream
  ([compare](https://github.com/signalapp/libsignal/compare/v0.102.2...v0.102.3)).
  Upstream's own notes for the tag name only the four new `AuthKeysService`
  pre-key APIs, and the one change in this range that does reach this package is
  not among them — it is under **Security** below.

  Of the four crates from that repository in this package's dependency graph,
  the range touches two source files beyond the version string, and they come
  from **different** commits. `rust/protocol/src/session.rs`, with its test
  `rust/protocol/tests/session.rs`, is `08b7ba68`, the stricter pre-key
  validation. `rust/protocol/src/state/prekey.rs` is `2a569601`, one of the
  `AuthKeysService` commits, and all it does there is add `#[repr(transparent)]`
  to `PreKeyId(u32)` — a memory-layout attribute, which changes no behaviour, no
  serialization and nothing this package exposes.

  The `AuthKeysService` work itself lands in `rust/net/chat` and `rust/net/grpc`,
  crates outside this package's dependency graph, and its Swift, Java and Node
  halves land in the upstream bridge and language-binding directories, which this
  package does not use — it binds the pure-Rust crates directly.
  `rust/core/src/version.rs` changes only the version string, and no source file
  under `signal-crypto` is listed. Upstream's workspace `rust-version` stays at
  1.93.1, so the build floor does not move. `make codegen` produced no change
  under `lib/src/rust/`, so the FFI surface did not move — but this time that is
  not the same as "nothing reaches the surface", because the behaviour behind an
  unchanged signature did change.
- **libsignal moves to v0.102.2, and again nothing it changed is reachable from
  here** (`rust/Cargo.toml`) — nine commits upstream
  ([compare](https://github.com/signalapp/libsignal/compare/v0.102.1...v0.102.2)).
  Upstream's own notes for the tag name three of them: SVR production moving
  to 2026Q3, and two backup validations — the `sharedName` field on `Contact`
  together with `aci`, `nickname` and `note` on `ContactAttachment`, and the
  `sharedName` option in `LearnedProfileChatUpdate.previousName`. The first is
  in `rust/net` and the other two in `rust/message-backup`, and neither
  `libsignal-net` nor `libsignal-message-backup` appears in `rust/Cargo.lock`
  at all — not as a direct dependency and not transitively.

  The five the notes do not mention land in the same two places or in the
  bridge. Removing the `send_raw_grpc` endpoints, adding a per-wrapper
  `LOG_TAG` and dropping the unused UDP DNS stub resolver are `rust/net`; the
  Gaussian padding calculations are `rust/message-backup`, and also add a
  `rand_distr` entry to the upstream workspace, which this package does not
  resolve. The `export_name` syntax change is in `rust/bridge`, as are the
  bridge halves of the `send_raw_grpc` removal and the padding change — that is
  the C FFI surface the Swift, Java and Node bindings compile against, which
  this package does not use: it binds the pure-Rust crates directly. The ninth
  commit is upstream's own `Reset for version v0.102.2`.

  Four crates from that repository do reach the graph: `libsignal-protocol`,
  `libsignal-core` and `signal-crypto`, which this package names, and
  `libsignal-debug`, which arrives transitively. Between them the range changes
  exactly one file — `rust/core/src/version.rs`, the version string.
  Regenerating the bindings produced no change under `lib/src/rust/`, so these
  changes do not affect this library's public API. Upstream's workspace
  `rust-version` stays at 1.93.1, so the build floor does not move either.
- **libsignal moves to v0.102.1, and nothing it changed is reachable from here**
  (`rust/Cargo.toml`) — five commits upstream ([compare](https://github.com/signalapp/libsignal/compare/v0.102.0...v0.102.1)),
  and upstream's own release notes carry a single line: "Allow unknown chunks in
  webp sanitization". That relaxation is in `rust/media/src/sanitize/webp.rs`,
  and `libsignal-media` is not in this package's dependency graph. The other
  three land the same way and for the same reason: the `SignalType_` typedef
  rename is in `rust/bridge/shared/types`, the C FFI surface the Swift, Java and
  Node bindings compile against, which this package does not use — it binds the
  pure-Rust crates directly — and the two tinyvec commits drop a
  `>=1.11.0, <1.13.0` workspace cap and a dev-dependency in `rust/net/infra`,
  neither of which is a crate this package resolves.

  Four crates from that repository do reach the graph: `libsignal-protocol`,
  `libsignal-core` and `signal-crypto`, which this package names, and
  `libsignal-debug`, which arrives transitively. Between them the range changes
  exactly one file — `rust/core/src/version.rs`, the version string. So the
  weaker claim is the true one and the stronger one is not: they are not
  unchanged, but nothing they changed reaches the surface this package exposes.
  Regenerating the bindings produced no change under `lib/src/rust/`; the FFI
  surface did not move. Upstream's workspace `rust-version` stays at 1.93.1, so
  the build floor does not move either.

  Asked at the lockfile rather than the file tree, the answer holds:
  `rust/Cargo.lock` carries 226 packages before and after, with **none added and
  none removed**. Beside the four retagged libsignal crates, twenty registry
  versions move, and eleven of them put code in a shipped artifact — `aes`
  0.9.2 → 0.9.3 under `aes-gcm-siv`, `zerocopy` 0.8.56 → 0.8.57 under
  `libsignal-core`, `indexmap` 2.14.1 → 2.14.2 under `libsignal-protocol`,
  `hybrid-array` under `block-buffer`, the three `crossbeam` crates under
  `rayon-core`, and, in the WASM module only, `wasm-bindgen` 0.2.127 → 0.2.128
  with `js-sys`, `web-sys` and `wasm-bindgen-futures`. The remaining nine are
  proc-macro or test-only. `minicov` moves **backwards**, 0.3.9 → 0.3.8, which
  is not a resolver regression: `wasm-bindgen-test` 0.3.78 tightened its
  requirement from `^0.3.8` to `=0.3.8`, and it is a dev-dependency that reaches
  no artifact. `THIRD_PARTY_NOTICES.txt` records the seventeen moves that are
  not test-only

#### Security

- **A peer can no longer turn off post-quantum ratcheting by presenting an
  unsupported SPQR version** — upstream v0.103.0 moves `spqr`, the sparse
  post-quantum ratchet, from 1.5.3 to 1.6.0. It is not a direct dependency and
  no symbol in `lib/` or `rust/src/api/` names it, but it runs inside the
  Double Ratchet this package exposes: `rust/protocol/src/triple_ratchet.rs`
  mixes the key it returns into every message key, and
  `test/protocol/spqr_ratchet_progress_test.dart` exercises it through the
  ordinary encrypt/decrypt path.

  libsignal creates every session — both `initialize_alice_session` and
  `initialize_bob_session` — with `min_version: spqr::Version::V1`, commented
  "Require that all clients speak SPQR". Under 1.5.3 that floor was not
  consulted on the path that mattered. A message whose leading version byte was
  not a version the client recognised returned `Ok` with the state unchanged
  and **no key**, and a missing post-quantum key means the message keys are
  derived from the classical chain alone. A peer could therefore opt the
  session out of post-quantum ratcheting on its own, by presenting a version
  number from the future. 1.6.0 checks the floor first, for every message, and
  a version the client does not share is either answered with real chain-key
  material or refused outright — never ignored. A refusal surfaces here as
  `InvalidMessage` carrying "post-quantum ratchet error".

  **The wire format did not change**, which is worth stating because a change
  to this crate normally would. `spqr`'s encoder is byte-identical between the
  two tags — `version || varint(epoch) || varint(index) || type || chunk` — and
  the epoch cadence and chain parameters are untouched. What moved is the
  decoder: version, epoch and index are now parsed ahead of the
  version-specific body, so a message from a *higher* SPQR version can still be
  read far enough to return the epoch-0 chain key for its index, where 1.5.3
  could return nothing usable. Sessions between two clients on this release are
  unaffected, and so is compatibility with clients on the previous one.

  **What a caller may see:** a decrypt from a peer presenting an SPQR version
  this client does not support now either derives proper post-quantum material
  or throws, where it used to succeed with none mixed in. No signature changed
  and no caller has to change code.
- **A repeated pre-key message carrying a different identity key is now
  rejected** — upstream `08b7ba68`, reached from here through
  `messageDecryptPrekeyWithCallbacks` and `sealedSenderDecryptWithCallbacks`,
  both exported from `libsignal.dart`. When a pre-key message arrives for a
  session that is already established, libsignal used to read it as a replay and
  return early, accepting it into that session whatever identity key it carried;
  a mismatch surfaced later at the MAC check, if it surfaced at all. It now
  compares the message's identity key against the one stored for the session —
  a constant-time comparison, upstream notes, as long as the two keys are of the
  same type — and returns `InvalidMessage` with "remote identity key not
  consistent with previously-established session" straight away.

  **What a caller may see:** a decrypt that previously failed later, differently,
  or not at all can now throw at this point instead. No signature changed and no
  caller has to change code, so this is not breaking; but a caller that branches
  on error text rather than catching the exception should know the message is
  new. Upstream's release notes for v0.102.3 do not mention this change.

### For Contributors

#### Added

- **The repair agent can reach the branch it has to repair**
  (`.github/workflows/repair-build.yml`,
  `.github/agent-prompts/repair-build.md`,
  `.github/agent-config/opencode.json`) — `repair-build.yml` watched `main` and
  nothing else, and the failure this package actually gets is the one that can
  never appear there. When an `update-libsignal-*` pull request pins a version
  whose API has changed shape, the required checks fail, so it never merges, so
  `main` stays green and the workflow sees nothing. It has happened three times
  — `bc081c7` (v0.87.0, `IdentityKey` lost its comparison), `4a28ea8` (v0.93.1,
  two functions gained `local_address`) and `fc80c5b` (v0.94.0, `verify_mac` →
  `verify_mac_with_addresses`) — each fixed by hand.

  The workflow gains a second mode rather than a wider trigger: it takes the
  head of a red bot pull request as its base and lands the repair as a commit on
  that branch, signed, through `createCommitOnBranch`. Most of those never reach
  a model — 31 pull requests here have carried `codegen-failed` and 3 were
  genuine API changes, so the job runs `make codegen` first and asks a model only
  when the generator itself fails against the new pin.

  Two checks were added that a model cannot argue with, and the first closes a
  hole this repository has already fallen into. The generated files are
  **regenerated after the agent and refused if they move** — the one pull request
  this workflow ever opened (#67) made a red build green by hand-editing
  `lib/src/rust/frb_generated.dart`, which compiled, passed the tests, and was
  caught by the AI reviewer rather than by anything deterministic. The same run
  explains why: the repair job never installed `flutter_rust_bridge_codegen`, so
  `make codegen` exited 127 and hand-editing was the only move left. It installs
  it now. Second, whether this package's own Dart API moved is **measured** from
  the generated bindings rather than taken from the agent's account of it;
  replayed against the three commits above, the measurement separates the one
  that was not breaking from the two that were.

  That measurement is what the boundary rests on: a value available in scope is
  repaired silently, a value that exists only at the caller means the public API
  widens, which is breaking and not an agent's decision. There the whole change
  is prepared and the pull request is labelled `needs-decision` — the version
  number stays where it belongs. Two of the three historical cases land there,
  and structurally: `local_name`/`local_device_id` are parameters of our own FRB
  functions arriving from Dart, and no store callback supplies a local address.

#### Changed

- **copier template adopted: v4.12.0 → v4.14.0** (`.copier-answers.yml`,
  `Makefile`, `CLAUDE.md`, `CONTRIBUTING.md`,
  `.github/workflows/build-libsignal.yml`,
  `.github/workflows/test-reusable.yml`, `scripts/src/update_changelog.dart`,
  new `scripts/verify_release_artifacts.py` and
  `scripts/verify_library_loads.py`) — two releases, and v4.13.0 is only half
  of one: every commit in it was written in this repository first, so its
  adoption moved `_commit` and nothing else, landed as `0471f7a`, and was never
  written up. This entry covers both.

  Three gates arrive. `make rust-clippy-web` lints the wasm32 half of the crate
  and blocks on the Linux x86_64 leg — `make rust-clippy` runs under the host
  target, and a `cfg(target_arch = "wasm32")` body is a *different
  implementation* of the same function rather than the same code on another
  host, so the host pass reads none of its lines while its green reads as if it
  had. The other two first run at the next stage 1.
  `verify_release_artifacts.py` refuses a release archive that does not hold
  what its name says; it reads the libc in ELF `DT_NEEDED` and the platform in
  Mach-O `LC_BUILD_VERSION` rather than calling `file`, because a Linux and an
  Android arm64 `.so` share an ELF header and a macOS, an iOS and an
  iOS-simulator `.dylib` share a Mach-O cputype — exactly the pairs a
  copy-paste slip in the workflow's hand-written `tar` list produces. It runs as
  a job placed **before** `create-release`, so a wrong build is caught without
  spending a reviewer's approval on it, and again over the packed archives
  before the provenance attestation, since a signed attestation for a mispacked
  archive is a mispacked archive that is harder to argue with.
  `verify_library_loads.py` loads the library each build job just produced and
  looks up `frb_init_frb_dart_api_dl`, on the legs whose runner matches the
  target; that covers the one failure every other check here is blind to — a
  library that compiles, packs, checksums and attests, and then does not load.

  Both release gates were measured here before adoption rather than left to
  prove themselves during a release: run against the published
  `libsignal_frb-6.3.0` archives they report green on all twelve platforms, and
  the loader was additionally given a negative control — a Linux `.so` on
  macOS, which it refuses — so its green is known to mean something.

  `insertChangelogEntry` also stops filing a `#### Changed` it has to create
  *above* an existing `#### Added`. It anchors on the first `#### ` heading
  under `### For Users`, and only `#### Changed (Breaking)` was excluded from
  anchoring — but `#### Added` precedes it in the documented order too, and so
  silently took later entries above itself. The exclusion is now a named
  predicate, `precedesChanged`, and the order `CLAUDE.md` documents gains the
  two subsections it was missing, `#### Added` and `#### Documentation`.

  Two things the template offered were **not** taken. It rewrites the released
  `## [1.0.0]` section from `### Added` to `### For Users` / `#### Added`:
  released sections are immutable, and three further sections of that vintage
  carry the same old shape, so normalizing one of the four would have edited
  history in order to make this file *less* consistent. And it adds a paragraph
  describing the audience split to the changelog preamble — which this file
  does not have, which is why the paragraph merged into the middle of the
  history instead. `CLAUDE.md` already documents the split.

- **copier template adopted: v4.9.0 → v4.12.0** (`.copier-answers.yml`,
  `.claude/skills/frb-patterns/SKILL.md`, `.github/rulesets/README.md`, new
  `.github/workflows/refresh-notices.yml`) — three template releases in one
  pass, and taking them separately was not an option: v4.10.0 required the whole
  CI matrix in a generated project and, in doing so, made every cargo pull
  request unmergeable, while v4.11.0 is the repair.

  `refresh-notices.yml` regenerates `THIRD_PARTY_NOTICES.txt` on Dependabot's
  cargo pull requests. Dependabot edits `rust/Cargo.toml` and `rust/Cargo.lock`
  with no way to run `make third-party-notices` afterwards, so its pull requests
  always arrive carrying a stale inventory — cosmetic while nothing depended on
  it, a hard block once `verify-third-party-notices` sat inside a required
  context. The `.github/rulesets/README.md` paragraph records why the Dependabot
  branch exclusions cannot simply be narrowed: that workflow pushes an ordinary
  **unsigned** commit to those branches, which is legal only because
  `required_signatures` does not reach them. And `SKILL.md` gains a section
  saying that `rust/src/api/` is the directory codegen scans, so a helper that
  exists only to serve the bridge — a test double, a wrapper that records what
  an upstream call did — belongs at the crate root instead; what decides is
  whether the module is reachable from the `rust_input` root, not whether it
  sits in the folder.

  One file the template offers was deliberately **not** taken:
  `.github/rulesets/protect-main.json`. This repository's required-contexts list
  is its own — eleven contexts, with the ARM64 leg excluded as flaky — and
  adopting the template's copy would have rewritten the live ruleset. That is
  why the adoption is four files rather than five, and why the bot's own pull
  request for it was closed rather than merged.

#### Fixed

- **The Android CI legs stopped asking the SDK for a package Google deleted**
  (`.github/workflows/test-reusable.yml`,
  `.github/workflows/build-libsignal.yml`) — all three
  `test / Cross-compile (Android …)` jobs went red at once on 2026-09-15 with
  no change on this side, and because they are required contexts, `main` was
  red and nothing was mergeable.

  `android-actions/setup-android` takes a `packages:` input whose default is
  `tools platform-tools`. `tools` is the legacy SDK Tools package, obsoleted by
  `cmdline-tools` years ago and now absent from `repository2-3.xml`, Google's
  own index, while `platform-tools` is still in it. The action asks for it
  regardless, `sdkmanager` exits 1, and the action fails before the job reaches
  a step of its own — the `sdkmanager --install "ndk;…"` below it never ran,
  which is why the failure looked nothing like a build error. Upstream had no
  fixed release: v4.0.1 is the latest and `android-actions/setup-android#537`,
  opened the same day, is filed against exactly this. Passing
  `packages: platform-tools` drops the dead name and nothing else.

  Both call sites moved together, and that is the point rather than tidiness:
  `build-libsignal.yml` runs the same action, so the next `libsignal_frb-*` tag
  would have failed its Android matrix the same way — after the tag was pushed,
  which is the expensive moment to find out.

- **Three defects in the automated CHANGELOG entry, every one of them fixed in
  code rather than in the prompt** (`scripts/src/update_changelog.dart`,
  `test/scripts/update_changelog_test.dart`) — the v0.102.2 update pull request
  arrived with a doubled list marker, a false statement about upstream, and a
  second Highlights line contradicting the first. All three are decidable from
  the text or from one extra request, which is the same reasoning
  `noImpactPhrase` already carries.

  `insertChangelogEntry` writes the Highlights line as `'- $nativeHighlight'`,
  and the model returned one carrying its own marker, so the entry read
  `- - **libsignal v0.102.2**` — in GFM a nested list under an empty parent
  bullet. Neither side is at fault: rule 1 of the highlight rules gives that
  line without a marker, and four lines above it the current CHANGELOG is pasted
  under "match this house style exactly", where every Highlights line begins
  with one. `stripLeadingListMarker` normalises the answer and a third highlight
  rule states where the marker comes from. Worth recording how this shipped
  green — all five `insertChangelogEntry` tests fed an already-clean string, so
  the suite could not have caught it.

  The entry then opened "upstream has no published release notes". libsignal
  publishes every GitHub release with an empty body, which is all
  `_fetchReleaseNotes` read, so the prompt was handed a placeholder and the
  model reported that absence as a fact about the release — for a tag whose own
  `RELEASE_NOTES.md` named three changes. The fetch now falls back to that file,
  whose first line must name the tag: upstream overwrites it each release, so a
  tag whose release commit missed it would return the previous release's notes,
  wrong rather than missing. A seventh prompt rule closes the rest of the case —
  the sections above the prompt are its inputs, their state is a fact about the
  fetch and never about the release, and an entry must not narrate it.

  Third, Highlights lines accumulated: `[Unreleased]` named v0.102.1 and
  v0.102.2 at once. That line states which upstream version the section ships,
  one per release section, and since dependency bumps now accumulate on `main`
  between releases the second bump in a window meets the first one's line. The
  new line supersedes the old — but only when the old one is the prompt's own
  mandated default, now a shared constant read by both the rule and the check.
  A rewritten line is never touched: those run onto continuation lines, so a
  line match would strand them as a dangling paragraph. When one is left
  standing the section does name two versions, so that case warns instead of
  passing silently.

  That left one cause standing, and it was the one behind the other two faults
  in the same entry — the weak verdict where a checkable claim was available,
  and the Gaussian-padding commit filed under `rust/net` when it landed in
  `rust/message-backup` and `rust/bridge`. A commit subject names a change and
  not a place, and subject lines were all the prompt had. **The compare API's
  file list is now fed to it**, at no extra cost: `files` and `commits` arrive
  in the same payload, and the fetch was already discarding half of it.

  The list carries a header saying whether it is COMPLETE, and that is the part
  that had to be designed rather than the list. The entry rests on a negative
  claim — the crates we bind changed only this file — which is sound only from
  an exhaustive list, and the API caps `files` at 300 while saying so nowhere
  in the payload. So completeness is decided in code, where the counts are, and
  stated in the words the model reads: COMPLETE licenses reasoning from
  absence, TRUNCATED withdraws it. Replayed against the range that produced the
  bad entry, the header reads `COMPLETE … (71)` and the only line in the bound
  crates is `modified rust/core/src/version.rs` — the claim a human had to
  write by hand.

  Still open: the `rust/Cargo.lock` diff, which the prompt also never sees
  though `make rust-update` runs before the changelog step. Same family,
  smaller payoff.
- **The same automated entry then mis-attributed a file, and this one is fixed
  in the prompt rather than in code** (`scripts/src/update_changelog.dart`) —
  feeding the file list bought a real improvement and opened a new way to be
  wrong. The v0.102.3 entry read the list correctly and then guessed which
  commit had changed what.

  That range holds ten commits. `08b7ba68` ("be stricter for pre-key messages
  that change identity keys") touches `rust/protocol/src/session.rs`;
  `2a569601` ("Expose AuthKeysService.setOneTimeEcPreKeys") touches
  `rust/protocol/src/state/prekey.rs`. Both files sit in a bound crate, the list
  names both, and nothing in the material says which commit brought which. The
  entry paired the second file with the first subject, concluded the stricter
  validation reached serialization, and reported as fact something no commit
  did: that file's entire change is `#[repr(transparent)]` on `PreKeyId(u32)`, a
  memory-layout attribute.

  The compare payload is flat by construction — `commits[]` carries no files and
  `files[]` carries no commits — so the prompt now says exactly that and forbids
  attribution outright: name what the range changed, never which commit changed
  it, and where the reason matters, say the data does not carry it. Per-commit
  requests would turn attribution into data; they were considered and deferred,
  because one request per commit is the expensive half and earns nothing if
  stating the gap is enough. A cap on commit count was considered and rejected
  outright — it withdraws the attribution data exactly when a range is large,
  which is when attribution is hardest. The next update pull request measures
  whether the prompt rule suffices.

  Rule 4 gained a second precondition at the same time, for a contradiction in
  that same entry: it said the change reaches the exposed X3DH path and closed
  with "these changes do not affect this library's public API". Both cannot
  hold. `breakingContradictsNoImpact` stayed quiet because it keys on
  `**BREAKING:**`, which the entry never wrote. The phrase is now false by
  construction in two checkable cases — when a COMPLETE file list shows a bound
  crate's source changing, source meaning a file that is neither a version
  string nor a test, and when the only ground offered is an unchanged FFI
  surface, because an unchanged signature is not unchanged behaviour. v0.102.3 was precisely that: same signature, a
  call that can now throw where it used to return. This one stays in the prompt
  rather than joining the code checks for a reason worth recording — deciding it
  in code needs a crate-name-to-path mapping the script does not hold
  (`changelog-scope.md` names crates, not paths), and a check keyed on a line no
  existing scope file carries would pass silently for every project that has
  one.
- **The scope file was asserting as fact the one thing it should have asked to
  be checked** (`.github/agent-prompts/changelog-scope.md`) — the v0.103.0
  entry arrived claiming the update "can change its wire bytes and the number of
  messages in an epoch". It cannot: `spqr`'s encoder is byte-identical between
  1.5.3 and 1.6.0, and the entry missed the security hardening that was the
  release's one user-visible change.

  The model did not invent that sentence. This file carried it, unconditionally
  — "a change to it changes the bytes on the wire and the number of messages an
  epoch takes" — as a standing property of any `spqr` change, and the model
  restated it, hedged to "can". So this is the third distinct source of a bad
  entry in as many bumps, after the prompt and the flat file list, and the only
  one that lives in the project's own material rather than in the template's.

  What makes the premise unverifiable from the prompt's inputs is worth
  recording, because no enrichment of the libsignal compare would fix it:
  **`spqr` is a different repository.** A bump leaves exactly one trace in the
  material the prompt is given — a version number in a manifest — and its
  contents appear nowhere in that compare, per-commit file lists or not. The
  paragraph now says "can", names acceptance alongside wire bytes and epoch
  cadence, and tells the model to report the version move and then say the
  material does not carry what changed inside — the honest answer, where it
  used to hand down a conclusion.

  It first said something else, and the repository's own AI reviewer caught it:
  "read the `spqr` range itself (`gh api …/compare/<old>...<new>`)". The client
  that sends this prompt sends a plain completion with **no tools at all**, so
  that is an instruction the model cannot follow and can only appear to satisfy
  by inventing the answer — the very failure the paragraph was being rewritten
  to stop, reintroduced one level up, and contradicting the prompt rule added
  beside it. The command now lives in `CLAUDE.md`, addressed to whoever
  finishes the pull request, together with the reason the file list alone is
  not enough: on 1.5.3 → 1.6.0 `serialize.rs` appears in the diff and the
  serializer is byte-identical all the same.
- **The one warning that would have caught the stacked Highlights lines reached
  only the run log** (`scripts/src/update_changelog.dart`,
  `scripts/update_changelog.dart`,
  `.github/workflows/check-libsignal-updates.yml`,
  `test/scripts/update_changelog_test.dart`) — the v0.102.2 fix that stopped
  Highlights lines from stacking deliberately does **not** supersede a
  *rewritten* line, because those run onto continuation lines a line match
  would strand. It warns instead, and on v0.103.0 it warned exactly right:
  "the section now names two upstream versions — collapse them by hand before
  releasing". Nobody saw it. It is printed by the script, `CHANGELOG_OK` stays
  `true`, and the pull request renders a clean "AI-generated entry" line with
  no caveat anywhere.

  That is worse than cosmetic, because nothing downstream collapses them
  either: `make release` finalizes `[Unreleased]` by renaming the heading **in
  place**, so a section left naming two upstream versions is frozen into a
  released one, and released sections are immutable.

  The condition is now returned rather than only logged — `updateChangelog`
  hands back a `ChangelogUpdate` carrying it beside the model — and published
  through the `--ci-output` channel that already carried `ai_provider`. The
  pull request body gains a warning and a "Before Merge" action, the run gains
  an annotation, and the step summary gains a line. The key is written on
  **both** outcomes: one that appeared only when true could not be told apart
  from a script too old to emit it, and `false` is what lets a reader treat the
  silence as "checked". `ciOutputsFor` renders the block as a separate,
  testable function for the reason the `insertChangelogEntry` tests already
  demonstrated — the format is what breaks silently, and a test that exercises
  the predicate alone proves nothing about what reaches the file. One of its
  four cases is the trailing newline, since that file is appended to by several
  writers and an unterminated block takes the next one down with it.
- **The prompt never said how to read the one input it calls CRITICAL**
  (`scripts/src/update_changelog.dart`) — the scope section is pasted under
  "CRITICAL for classification" and rule 2 classifies every upstream change
  against it, but nothing told the model what kind of statement it was reading.
  A sentence there describing what a dependency's changes *do* is a statement
  about what such a change can REACH; handed over unqualified, in that
  position, it reads as a fact available to assert. That is the whole mechanism
  behind the v0.103.0 entry.

  Two paragraphs now travel with the block, in the idiom the file list beside
  it already uses — instructions attached to their data rather than filed in
  the rules list, so an edit to the rules cannot separate them. The first says
  the section states reachability and never a report about this release, and
  that a claim found there is the question to answer from the material, not the
  answer. The second states the limit that no enrichment of this pipeline can
  lift: **the compare covers ONE repository**, so a dependency living in
  another leaves a single trace in it — a version number in a manifest — and
  nothing about what changed inside. Where an entry would turn on that, it must
  say the material does not carry it rather than infer the change from the
  bump, from the dependency's name, or from what the scope section says such a
  change can reach.

## [7.3.0] - 2026-09-08

### For Users

#### ✨ Highlights

- **`IdentityKeyPair.sign()` signs with the identity key without copying it into
  the Dart heap** — the one route that existed read the `privateKey` getter and
  rebuilt a `PrivateKey` from those bytes, putting the long-term identity secret
  somewhere nothing can zeroize it. The getter still works, so nothing breaks;
  every call site in this package moved to the new method
- **libsignal v0.102.0** — unchanged this release
- **libsignal_frb v6.3.0** — Rust FFI bindings

#### Changed

- **`PrivateKey.agree()` documents what it does not do** (`rust/src/api/keys.rs`)
  — it is the raw X25519 primitive, and its docstring said only that the output
  is sensitive and should be zeroed. That is true and insufficient: the three
  ways this method is misused are not memory-hygiene mistakes.

  The result is not a key. X25519 returns the x-coordinate of a curve point, a
  field element rather than a uniformly distributed 32-byte string, so
  encrypting with it directly is wrong even though the bytes look random — it
  belongs in a KDF first, and `hkdfDerive` on this same surface takes it as
  `inputKeyMaterial`. A single agreement between two long-lived keys returns the
  same secret forever, so on its own it provides no forward secrecy; that comes
  from ratcheting over ephemeral keys, which is what `SessionBuilder` and
  `SessionCipher` already do and what a caller of this method has to build.
  And the method authenticates nothing: libsignal rejects the all-zero shared
  secret a low-order public key produces, in constant time and as a thrown
  error rather than 32 zero bytes, but checking that the peer's public key is
  the expected one stays the caller's job.

  The docstring now says so, and says plainly that ordinary Signal Protocol use
  never needs this method. No behaviour changed — `rustContentHash` is
  unmoved, which is the mechanical confirmation that the FFI surface did not.

- **`IdentityKeyPair.sign()` signs without copying the identity secret into the
  Dart heap** (`rust/src/api/keys.rs`, `README.md`) — signing a signed pre-key or
  a Kyber pre-key with the long-term identity key had exactly one route:
  `PrivateKey.deserialize(bytes: identity.privateKey.toList())`, then `.sign()`
  on the result. That is what the README documented and what every call site in
  this repository did. It materialises the long-term identity private key as a
  `Vec<u8>` handed across FFI, and from there nothing can reach it: no `zeroize`
  in Rust, no `dispose()` on the Dart side, only the garbage collector at a time
  of its choosing. `identityKeyPair.sign(message: ...)` does the same work with
  the secret never leaving Rust.

  It grants no capability that was not already reachable: the `privateKey`
  getter it replaces can sign the same arbitrary bytes today, so this narrows the
  surface a secret is exposed on rather than widening what the key can do.
  Signatures from it are not interchangeable with `signAlternateIdentity`, which
  signs a domain-separated message — a fixed 32-byte prefix and a label ahead of
  the other identity key — and a serialized public key cannot begin with that
  prefix, so the two uses overlap only if a caller deliberately builds it.

  Upstream libsignal's `IdentityKeyPair` has no general-purpose `sign`; this is a
  deliberate addition on our side, and the `privateKey` getter still works, so
  nothing that relied on the old route breaks. The getter's own documentation now
  points at this method.

- **The README names the Flutter build-system skip that leaves `web/pkg/`
  unprovisioned** (`README.md`) — the build hook copies the WASM module into the
  consuming app's `web/pkg/`, and `flutter run -d chrome` reaches the hook only
  while Flutter still considers its `dart_build` target out of date. That
  target's cache key omits the target platform: a debug `flutter run` keys its
  build directory on the engine revision, the entrypoint, the build mode and the
  output path alone, so a debug run for another platform leaves a stamp naming
  its own dependencies, the next run for Chrome finds every one of them
  unchanged, logs `Skipping target: dart_build`, and the hook is never invoked.
  In an app whose `web/pkg/` is not already provisioned that surfaces as
  `RustLib.init()` failing on a 404 for `pkg/libsignal_frb.js`, with nothing in
  the output naming the hook or the platform that poisoned the stamp.

  Nothing in this package can close it — the skip happens above `hooks_runner`,
  so no dependency the hook declares is ever read — so *Known Limitations*
  documents the escapes instead: one `flutter build web`, which is keyed to its
  own build directory and always reaches the hook; deleting
  `build/*/dart_build.stamp`; or `flutter clean`. Once `web/pkg/` holds the right
  files, `flutter run -d chrome` serves them.

- **The Android libraries are built by a pinned cargo-ndk, and their 16 KB
  alignment is measured on the bytes that get uploaded**
  (`.github/workflows/build-libsignal.yml`, `scripts/verify_android_alignment.py`,
  `Makefile`) — Google Play has required an app's bundled native libraries to be
  16 KB-aligned, for apps targeting Android 15 or later, since 1 November 2025.
  Nothing here would have noticed a regression: a misaligned `.so` fails no test
  in this repository, it makes the **consuming** app unpublishable, which is the
  worst place to find out and somebody else's release that it stops.

  The alignment is supplied by cargo-ndk's linker flags —
  `-Wl,-z,max-page-size=16384` and its `common-page-size` twin — and not by the
  NDK: r26-built and r28-built artefacts measure `p_align=0x4000` alike, and
  32-bit `armeabi-v7a` measures `0x1000` on both, correctly, the requirement
  being a 64-bit one. So the property belonged to a tool the release job
  installed with `cargo install cargo-ndk --locked` and no version, taking
  whatever was newest that day. It is pinned to `4.1.2` now, the version whose
  flags were read out of the binary, and the job verifies the result rather than
  trusting the pin: `make verify-android-alignment` reads ELF program headers
  directly — no `readelf`, no NDK — and fails closed on a non-ELF file, on a
  file with no `PT_LOAD` segments, and on finding nothing to check at all.

### For Contributors

#### Added

- **`main` requires the whole CI matrix, not just a codegen guard**
  (`.github/rulesets/protect-main.json`, `.github/rulesets/README.md`) — none of
  the four rulesets carried a `required_status_checks` rule, so a red CI run
  never blocked a merge. Eleven contexts are required now: `FRB bindings were
  regenerated` plus ten legs of the test matrix.

  Requiring the guard alone came first, and it closed the loop that guard was
  written for: it exists because replaying the AI reviewer over 47 merged pull
  requests put its recall on that one condition at 21%, and the two-line shell
  check that replaced it had reported ever since with nothing depending on it.
  Requiring the matrix as well was blocked on a mechanism rather than on a
  preference — see the `test.yml` entry under *Changed* for what had to move and
  why the two are inseparable.

  Two legs stay out of the ruleset while still running in the workflow.
  `test / Update Coverage Badge` is skipped on pull requests, so requiring it
  would assert nothing. `test / Test (Linux ARM64)` is out because of a flake —
  but the flake is not its property, and the runbook now says so on measured
  ground rather than on reputation. Across the 25 most recent `Tests` runs the
  signature `TimeoutException after 0:00:30` produced three isolated leg
  failures: `Windows x86_64` twice and `Linux ARM64` once, every other red run
  in that window being a genuine multi-job breakage. Three events over four legs
  cannot single out a platform, and "the slowest runner flakes" is not the
  answer either — the slowest leg by wall clock is `Linux x86_64` (248 s average
  against ARM64's 91 s) and it has never flaked. So the exclusion is chosen by
  what its absence costs — Linux stays required through
  `test / Test (Linux x86_64)`, while dropping Windows would leave that platform
  with no required coverage at all — and Windows stays required knowing it will
  occasionally fail on its own until the timeout is understood.

  Every context string was read off the head commit of a real pull request
  rather than off a push to `main`: the two triggers do not produce the same set
  of check runs — `Update Coverage Badge` reports `success` on one and `skipped`
  on the other — and it is the pull-request set that a merge gate is measured
  against. The runbook records that check, and records that applying an edited
  ruleset takes `make setup-repo-protections ARGS="--update"`, plain
  `setup-repo-protections` skipping one that already exists.

  Applied to `main` on 2026-09-07 and verified against the live API: the rule
  carries all eleven contexts, each with `integration_id` 15368 and
  `strict_required_status_checks_policy` still `false`; the Admin bypass and the
  other three rulesets are untouched; `rules/branches/main` reports the rule as
  effective, and a Dependabot branch still reports none. All four live rulesets
  match their committed JSON, and the `--update` PUT preserved
  `require_extra_approval_for_unattributed_changes`, a field GitHub stores as a
  default and the committed file does not carry — worth confirming rather than
  assuming, since a PUT sends the file and not the difference.

- **CI cross-compiles the three Android ABIs on every pull request**
  (`.github/workflows/test-reusable.yml`) — Android was cross-compiled in exactly
  one place, `build-libsignal.yml`, which runs on `workflow_dispatch` and on a
  `libsignal_frb-*` release tag. Every leg of the test matrix runs `make build`,
  which builds for the host. So an Android-only build failure was invisible on
  `main` under every green gate, and the workflow that would discover it is the
  one publishing binaries — at a moment when the tag has already been pushed and
  a crate version is already spent. All three ABIs rather than one, because a
  vendored-assembly failure can be architecture-specific while the same
  dependency carries assembly the other legs never reach. It builds and does not
  test: nothing in CI can execute an Android artefact without an emulator, and a
  compile-and-assemble failure is what this catches. The job reads
  `android_ndk_version` and the API level from the same answers
  `build-libsignal.yml` does, so the gate cannot run on a different toolchain
  than the release.

- **`make actionlint`, and a `Workflow Lint (actionlint)` job that runs it**
  (`.github/actionlint.yaml`, `Makefile`, `.github/workflows/test-reusable.yml`) —
  the workflows are the one part of this repository that nothing rehearses before
  merge: a job is only ever executed by pushing it, so a typo in an expression, a
  context that does not exist, or a `needs:` naming a renamed job all reach `main`
  and then fail on the very run that was supposed to gate them. actionlint reads
  them statically and hands every `run:` block to shellcheck, which is where most
  of what it finds lives — so the job asserts shellcheck is present rather than
  trusting the runner image, an absent one being a green gate that quietly
  stopped checking its most productive half. It is pinned by version and by
  checksum, because the step fetches an executable from a third-party release and
  runs it over the repository, and nothing bumps that pin automatically.
  Suppressions live in `.github/actionlint.yaml` rather than in flags, so a local
  run reports exactly what CI reports. Clean on this repository's workflows,
  divergent ones included, at the first run.

#### Changed

- **`test.yml` no longer filters pull requests by path, so every pull request
  runs the matrix** (`.github/workflows/test.yml`) — this is what let the ruleset
  above grow past one context, and it is not a preference. A required check is
  satisfied by a check run reporting on the pull request's head commit, and the
  two ways a job can fail to run are not equivalent: a job excluded by a
  job-level `if:` still reports, as `skipped`, and counts as satisfied, while a
  workflow excluded by a workflow-level `paths:` reports nothing at all — and no
  setting reads a missing check as passed. While `test.yml` filtered
  `pull_request` by path, requiring any `test / …` context would have left every
  documentation-only pull request waiting forever with nothing to fix.

  The filter stays on `push`, where it guards the cache scope rather than a
  gate: a pull-request run can read the base branch's cache scope but never the
  reverse. The cost of dropping it was measured before it was paid — of the
  fifteen most recently merged pull requests, fifteen already matched it, so
  what changes in practice is that the rare documentation-only pull request now
  runs the matrix too.

  `test.yml`'s header states that asymmetry forward rather than only recording
  the decision, because the tempting repair if the cost ever bites is the filter
  coming back, and the correct one is a job-level `if:` on the expensive legs.

- **`make verify-frb-pins` tells a fuzz crate with nothing to say from one it
  cannot read** (`scripts/src/frb_pins.dart`, `scripts/verify_frb_pins.dart`,
  `test/scripts/frb_pins_test.dart`) — the sixth source `2761886` added was
  required outright. That is right here, where `rust/fuzz/Cargo.toml` pins
  `flutter_rust_bridge` and cargo refuses to resolve the fuzz crate against the
  main one when the two drift, and wrong everywhere else: the copier template
  generates a fuzz crate that takes the main crate by path and names
  flutter_rust_bridge nowhere, so the same file carried over unchanged turns the
  gate red on the first run of every generated project. Measured in a render
  rather than reasoned about: dropped into one, the old file fails the manifest
  for holding no readable pin, and the new one reports it as declaring no such
  dependency.

  A manifest that does not declare the crate is absent now, the way bindings are
  absent until `make codegen` has run. One that declares it but writes the
  version in a form the reader does not accept is still a failure: collapsing
  those two is how a gate ends up reporting agreement it never checked. The
  predicate that separates them is anchored to the start of a line, so a
  commented-out dependency does not count as one and `flutter_rust_bridge_codegen`
  is not mistaken for it, and both directions are covered by tests that go red
  on the substring version somebody would otherwise simplify it to.

  Nothing about this repository's own check changes: all six sources still say
  2.13.0 and a fuzz crate left behind on an older pin still fails by name. The
  success line measures its own column instead of assuming eighteen characters,
  because two of the reasons a source can be absent are wider than that.

- **The pin's prose no longer counts files a particular checkout happens to
  have** (`CONTRIBUTING.md`, `Makefile`, `.github/dependabot.yml`) — six files
  can record the version and two of them are conditional, so "five files" and
  "the version has to move in four places at once" were each true of one
  project. The Dependabot comment now names `make verify-frb-pins` as the thing
  that enumerates them, which is the part that cannot go stale, instead of
  repeating a list beside it.

- **`make run-example-web` clears the stale `dart_build` stamp before it runs**
  (`Makefile`, `CLAUDE.md`) — the target wiped `example/web/pkg/` and trusted the
  build hook to refresh it, which the hook cannot do when Flutter never invokes
  it. `flutter run` shares one build directory, and so one `dart_build` stamp,
  between a debug run for macOS and a debug run for Chrome, because the target
  platform is not part of that directory's key; whichever ran first satisfies the
  other. The wipe then turned a stale `web/pkg/` into a missing one, so the
  example failed to start with a 404 for `pkg/libsignal_frb.js` rather than with
  the wrong WASM — the more confusing of the two failures, and the one that reads
  as a Rust or FRB bug. Deleting `example/build/*/dart_build.stamp` is correct by
  construction: a stamp that does not exist cannot be stale, and an unmatched glob
  under `rm -f` is a no-op, so a fresh tree is unaffected. Measured both ways
  before and after — with the stamp in place the hook does not run and
  `example/web/pkg/` stays missing; with it deleted the hook runs, and the dev
  server serves `pkg/libsignal_frb.js` and `pkg/libsignal_frb_bg.wasm` in full.
  The comment above the target no longer claims the hook "*should* refresh on its
  own", and `CLAUDE.md` carries the same warning.

- **The codegen guard regenerates the bindings instead of only reading a label**
  (`.github/workflows/codegen-guard.yml`) — the job's name promised more than it
  checked. It refused a pull request carrying `codegen-failed` and nothing else,
  which is right for the case it was written for and blind to the neighbouring
  one: a pull request that changes an existing signature is already caught,
  because `frb_generated.rs` stops compiling and `make build` goes red on four
  platforms — but one that *adds* a `pub fn`, or edits a docstring, compiles
  perfectly and simply lacks the function on the Dart side. That is the gap
  `bc0fdc9` fell through here, where a corrected Rust security note never reached
  the generated Dart. `make codegen` appeared in CI in exactly one place, the
  bot's own update workflow, and never as a gate on a human's pull request.

  The two rules are a disjunction — label present *or* regeneration moves
  something — which is worth stating because the file argues at length against
  the conjunction, and that argument still holds. Drift is read from
  `git status --porcelain`, not `git diff --exit-code`, because codegen can add a
  file and `git diff` is blind to an untracked path. The job name is untouched on
  purpose: `FRB bindings were regenerated` is a required status check in
  `protect-main.json`, matched as a string, so a rename or a second job would
  make the ruleset stop matching silently and leave every pull request waiting on
  a report nobody files. For the same reason the trigger still carries no
  `paths:` filter; the cost is avoided per step instead, with the regeneration
  half running only when the pull request touches something that can move the
  bindings.

- **Adopted copier template v4.8.0 → v4.9.0** (`.copier-answers.yml`) — much of
  the range is this repository's own work returning: the sixth pin source, the
  required status check and the `dart_build` stamp fix are the entries above,
  and they came back byte-identical, so `protect-main.json`, `frb_pins.dart`,
  `verify_frb_pins.dart` and `frb_pins_test.dart` were not touched at all. What
  actually arrived is the four items already listed plus two sweeps: every
  `$GITHUB_OUTPUT`, `$GITHUB_ENV`, `$GITHUB_PATH` and `$GITHUB_STEP_SUMMARY`
  redirection is quoted, in the composite actions as well as the workflows — the
  reason the new lint gate is green at full strength rather than green because
  its noisiest check was off — and `.github/rulesets/README.md` gains the
  `actionlint` and three `Cross-compile (Android …)` contexts, which the runbook
  had been due to grow by hand.

  Two hand-merges. `README.md` and `CONTRIBUTING.md` conflicted and resolved to
  ours in full, both misalignments rather than disagreements: copier paired the
  template's new *Known Limitations* text against an unrelated heading, and its
  rewritten pin section against the security checklist. Both additions are
  already here, and this repository's wording of the fuzz-crate paragraph is the
  accurate one — our fuzz crate does name `flutter_rust_bridge`, where the
  template describes a generated one that does not. `.github/rulesets/README.md`
  merged with no conflict marker and a duplicated section: the template's
  rewritten runbook was appended beside the existing one, leaving two
  `### Required status checks` and two `### Why Dependabot branches are excluded`
  with contradictory context lists. The template's copy is kept — it is the one
  carrying the new contexts — with `test / Test (Linux ARM64)` pruned from it and
  named as pruned, which is what its own caution about flaky legs asks each
  project to do.

  `android_ndk_version` deliberately stays at r26. The template moved its
  *default* to r28 because OpenSSL 3.6 emits Intel SM3 assembly that r26's Clang
  17 cannot assemble, reached through `openssl-src` by projects that vendor
  SQLCipher; `rust/Cargo.lock` here contains no `openssl-src`, `openssl-sys`,
  `rusqlite` or `libsqlite3-sys`, so the reason does not apply and an update
  keeps a recorded answer regardless. The new Android job reads that same answer,
  so gate and release stay on one toolchain either way.

#### Fixed

- **The rulesets runbook described a bypass actor that is not there**
  (`.github/rulesets/README.md`) — it said **Signing commit** "is bypassed only
  by the update GitHub App" while its own table two paragraphs above said "none
  by default", the committed JSON has an empty `bypass_actors`, and so does the
  live ruleset. The conclusion the sentence draws — that not even an admin may
  force-push — is a consequence of the empty array, not of an actor, and the
  file says as much about `delete-branches.json` in the next section.

## Older releases

7.2.0 and everything before it are in
[CHANGELOG-ARCHIVE.md](https://github.com/djx-y-z/libsignal_dart/blob/main/CHANGELOG-ARCHIVE.md).

[Unreleased]: https://github.com/djx-y-z/libsignal_dart/compare/v8.0.0...HEAD
[8.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v7.4.1...v8.0.0
[7.4.1]: https://github.com/djx-y-z/libsignal_dart/compare/v7.4.0...v7.4.1
[7.4.0]: https://github.com/djx-y-z/libsignal_dart/compare/v7.3.1...v7.4.0
[7.3.1]: https://github.com/djx-y-z/libsignal_dart/compare/v7.3.0...v7.3.1
[7.3.0]: https://github.com/djx-y-z/libsignal_dart/compare/v7.2.0...v7.3.0
