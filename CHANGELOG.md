## [7.0.2] - 2026-08-08

### For Users

#### ✨ Highlights

- **libsignal v0.100.0** — dependency update only: the single change reaching the crates this package binds removes a helper this library never called, and the FFI surface regenerates byte-for-byte identical
- **libsignal_frb v6.0.2** — Rust FFI bindings

#### Changed

- **libsignal native library → v0.100.0** ([compare](https://github.com/signalapp/libsignal/compare/v0.99.3...v0.100.0))
  - The range covers two upstream releases. **v0.99.4** — upstream's own summary is "SVRB: 2026Q1 to previous", "SGX: Enforce TCB number in evidence" and "Backups: Validate the new `blockedAtTimestamp` field on Contact and Group" — lands entirely in `rust/net`, `rust/attest` and `rust/message-backup`, alongside a `LogSafeDisplay` for `socks::Protocol` and the Java/Kotlin binding generators. None of that is exposed by this library, and in the three crates this package binds (`libsignal-protocol`, `signal-crypto`, `libsignal-core`) its only diff is the `VERSION` constant
  - **v0.100.0** is the minor bump, and the one release in range that touches a bound crate. Upstream summarises it as "SPQR: Remove requirePqRatio argument for sessions, instead requiring for all sessions". Concretely, `should_use_nonpq_session()` is deleted from `libsignal-protocol` along with its re-export and its test — the helper that decided, from a server-supplied ratio, which non-post-quantum sessions to keep and which to archive during the post-quantum ratchet rollout — and upstream's own `SessionRecord_HasUsableSenderChain` bridge drops the matching `requirePqRatio` argument, so it now always demands `NotStale | EstablishedWithPqxdh | Spqr`
  - **The removal does not reach this package.** It never called or exposed `should_use_nonpq_session`: choosing a migration ratio is an application's policy question rather than a protocol binding's, and `SessionRecord.hasUsableSenderChain()` here is this package's own FRB binding, which never carried the argument upstream has now dropped. The release build is clean and `make codegen` reproduces `lib/src/rust/` byte-for-byte, so the FFI surface is unchanged and the binding's signature is the same on both sides
  - Also in range but out of reach: `UnauthBackupsService.listBackupMedia`, a new typed API in the `rust/net` chat layer this package does not bind, and a zkgroup fix that stops invalid curve points being treated as candidate profile keys — `zkgroup` is not in this package's dependency graph at all
  - Upstream prepared a v0.99.5 that was never tagged, which is why two releases span three version numbers
  - Both upstream GitHub releases carry an **empty** body; the summaries quoted above come from upstream's in-repo `RELEASE_NOTES.md`, and the per-crate analysis is derived from the commit range
  - Transitively, the shipped binary picks up `libsignal-debug` 0.99.3 → 0.100.0, `zerocopy` 0.8.55 → 0.8.56, and `data-encoding` 2.11.0 → 2.11.1 with its `data-encoding-macro` 0.1.20 → 0.1.21 wrapper. `zerocopy-derive`, `data-encoding-macro-internal` and `delegate-attr` move as well but are proc-macros, and `aho-corasick` 1.1.4 → 1.1.5 and `regex-automata` 0.4.16 → 0.4.18 enter the graph only through `prost-build`, a build-dependency of `libsignal-protocol` and `spqr` — so none of those five reach the binary. `THIRD_PARTY_NOTICES.txt` is regenerated to match

## [7.0.1] - 2026-08-03

### For Users

#### ✨ Highlights

- **libsignal v0.99.3** — dependency update only: nothing in the libsignal crates this package links changed beyond added tests and version strings, and the FFI surface regenerates byte-for-byte identical
- **libsignal_frb v6.0.1** — Rust FFI bindings

#### Changed

- **libsignal native library → v0.99.3** ([compare](https://github.com/signalapp/libsignal/compare/v0.99.1...v0.99.3))
  - Upstream work across v0.99.2 and v0.99.3 targets the chat/backup transport, key transparency, the SVR2 enclaves and their attestation, a PNI-less zkgroup `AuthCredential` API, and the Node/Java/TypeScript bindings — none of which this library exposes
  - Of the crates from that repository which reach the binary — the three this package binds (`libsignal-protocol`, `signal-crypto`, `libsignal-core`) plus the transitive `libsignal-debug` — the only source change in either release is two added `#[test]` functions covering HPKE invalid inputs in `signal-crypto`; everything else is the `VERSION` constant. The FRB bindings regenerate byte-for-byte identical, so the FFI surface is unchanged
  - Neither upstream release published release notes, so this entry is derived from the commit range rather than from a changelog
  - Transitively, the shipped binary picks up `aes` 0.9.1 → 0.9.2 and `hybrid-array` 0.4.13 → 0.4.14 (the RustCrypto array crate `aes` is built on). `cc`, `clang-sys`, `displaydoc`, `either` and `toml_parser` also move, but reach this crate only as build-dependencies or through proc-macro subtrees, so none of them ship. `THIRD_PARTY_NOTICES.txt` is regenerated to match

- **Encryption of store contents at rest is documented** — every record a store persists serializes with its private key material included, and the library holds no key to encrypt it with: it is a pure Dart package with no platform-channel access, so it cannot reach Keychain, Android Keystore, DPAPI or libsecret, and on the web no key source exists that does not require a passphrase each session. A new `SECURITY.md` section gives the sealed-store pattern on the already-public `Aes256GcmSiv` + `hkdfDerive` — KEK installed once as an opaque handle, AAD bound to the slot being read, nonce rules and why GCM-SIV rather than GCM, a format version byte — plus a per-platform table of where the KEK comes from and an explicit statement that this protects against an attacker who reads your storage, not one executing code in your process

### For Contributors

#### Changed

- **`.fvmrc` no longer drifts on every `make codegen`** — `flutter_rust_bridge_codegen` shells out to `fvm install`, and `fvm install` rewrites `.fvmrc` and `.vscode/settings.json` whenever they are not already byte-identical to what it would emit. The committed files were not: fvm orders the keys `flutter, flavors, runPubGetOnSdkChanges, updateVscodeSettings, updateGitIgnore` and writes **no trailing newline**, and it rewrites `dart.flutterSdkPath` to the version-pinned `.fvm/versions/<v>`. So every codegen run left two modified files behind, and the nightly libsignal-update workflow — which runs codegen and then `create-pull-request` without `add-paths` — swept them into its PR commits. `.fvmrc` is now committed in fvm's own serialization with `updateVscodeSettings: false`, which makes `fvm install` a byte-level no-op on both files; verified by running `make codegen` and comparing checksums. fvm writes the file with Dart's `JsonEncoder.withIndent('  ')` + `writeAsStringSync`, which emits LF and no trailing newline on every platform, so `.fvmrc` is also marked `-text` in `.gitattributes` — otherwise a Windows checkout under the default `core.autocrlf=true` gets CRLF, never matches, and is silently rewritten on every install. `.vscode/settings.json` deliberately keeps `.fvm/flutter_sdk` rather than fvm 4's version-pinned path: the symlink is still created by fvm 4, so it works on fvm 2, 3 and 4 alike, while `.fvm/versions/3.38.4` breaks for anyone on fvm 2.x and needs editing on every Flutter bump. Leaving the file to fvm was the worse option in any case — where fvm has no privileged access (Windows without Developer Mode, where it also creates neither symlink) it writes an **absolute, machine-local** SDK path into this committed file. The one cost is a `[WARN] You are using VSCode, but fvm is not managing VSCode settings` line on each install; do not "fix" it by removing the setting

- **The pre-commit hook reports a missing toolchain as a missing toolchain** — any failure of step 1 was announced as `Formatting check failed. Run 'make format'`, so a hook run from an IDE or GUI git client — which inherits a minimal PATH and cannot find `fvm`, `make` or `cargo` — sent you looking at your code instead of your PATH. The hook now appends the usual install locations before the first check — appended rather than prepended so a tool deliberately placed earlier in PATH keeps winning, and covering both the Unix (`~/.pub-cache/bin`) and the Windows/Git-Bash (`%LOCALAPPDATA%\Pub\Cache\bin`) pub-cache layouts, honouring `PUB_CACHE` / `CARGO_HOME`, and adding only directories that exist. It then checks `make`, `fvm` and `cargo` are present up front, and distinguishes exit 127 from a genuine check failure so a broken environment is never reported as a code problem. Both the old and new hooks are `shellcheck` clean

- **`Discard FVM config changes` in `setup-fvm` is documented as a guard, not a fix** — a step in a composite action can only clean up after that action, while `fvm install` also runs later in the job from inside `make codegen`, so its position was never the defect. Comment only; the config change above is the actual fix

- **`make setup-repo-protections` now turns on automatic head-branch deletion** — the script applied rulesets and the `native-build` environment but never touched repo settings, so `delete_branch_on_merge` sat at GitHub's default of off and every merged branch stayed forever; 42 `update-libsignal-*` branches had accumulated since v0.86.10 (deleted, and each is still reachable through its pull request's `refs/pull/<n>/head`). `delete-branch: true` on `peter-evans/create-pull-request` does not cover this — it only removes branches the action itself closes as obsolete. The script now also sends `PATCH repos/<slug>` with `delete_branch_on_merge=true`, warning rather than failing when it cannot. Note that GitHub performs the deletion as whoever merged the pull request, so the `Delete branches` ruleset confines it to that ruleset's bypass actors (repository admins here); for anyone else it quietly does nothing, which leaves the branch exactly where the setting being off would have left it

- **A mistyped signing passphrase no longer aborts a release, and an interrupted one is resumed by re-running the same command** — `git` signs a commit or a tag by shelling out to `ssh-keygen -Y sign`, which reads the passphrase exactly once and calls `fatal()` on a failed load rather than re-prompting. One typo therefore killed the release wherever it happened, and the position that hurts is *between* the commit and the tag, because that state blocks its own recovery: the version bump is committed, no tag exists, and re-running trips the "must be greater than the current version" precondition. Both stages now route every signing and push step through `runInheritRetry`, which prints the failure and runs the step again, so the prompt simply comes back the way `ssh` and `sudo` behave — **Ctrl-C is the way out**, which works because `inheritStdio` delivers the interrupt to the whole foreground process group. The loop is uncapped (an attempt limit would reinstate the failure it exists to prevent), a non-interactive stdin throws on the first failure so CI behaviour is unchanged — tested via `stdin.echoMode`, deliberately not `hasTerminal`, which calls a run redirected from `/dev/null` interactive — and from the third consecutive failure it paces itself at two seconds so a step failing in milliseconds cannot scroll past faster than it can be read. `alreadyDone` is consulted after a failure so a step whose effect already landed reports success instead of being attempted twice, and `beforeRetry` re-stages the release files before each commit retry, because our own pre-commit hook runs `make rust-check`, whose `cargo check` rewrites `rust/Cargo.lock` when the crate version moved. Separately, a Ctrl-C or a closed terminal is now recognised: `isResumableRelease` requires *all* of a clean tree, the version file already reading exactly the requested version, and `HEAD`'s subject equal to the exact subject the release writes (held in one `commitSubject` variable passed both to `git commit -m` and to the predicate, so the two cannot drift apart), and a leftover tag is accepted only when it is this release's tag *and* points at `HEAD`. Interrupting *before* the commit is the one case nothing can report at the time, so the "working tree is not clean" error now uses `onlyTheseFilesDirty` to name the single `git restore` that discards the release's own edits — declining to suggest one for an untracked path or a rename, where the command would not work or would take something else with it. Covered by a new `test/scripts/release_common_test.dart` (13 cases over both predicates); the retry loop's own I/O is driven by a terminal by construction and was verified against a pty upstream instead

- **copier template adopted: v4.1.0 → v4.2.0** — three of the five commits in this range are the template's adoption of fixes made here first (the `.fvmrc` / `.vscode/settings.json` drift, the pre-commit hook's PATH handling, and `delete_branch_on_merge`), and all three came back byte-identical, so `copier update` left those files untouched. The template's fourth fix — that its `pre-commit` hook shipped mode 644 and therefore never ran in a generated project — never applied here: this repo's hook has been 755 since it was added. What actually lands is the release-script work above, plus two documentation carriers for a decision this repo already made: `.vscode/settings.json` gains the header explaining why it is committed and why `fvm install`'s "remove `updateVscodeSettings: false`" warning must not be acted on, and `CONTRIBUTING.md` gains an *Editor Setup (FVM)* section saying the same for contributors, including the note that Windows needs Developer Mode before the first `fvm install` for the `.fvm/flutter_sdk` symlink `dart.flutterSdkPath` points at. Adopting the release-script change now is deliberate: no release is in flight, so unlike the v3.0.2 adoption it cannot alter the behaviour of a run already under way

- **copier template adopted: v4.2.0 → v4.3.0** — the template now applies its own updates instead of only announcing them: `make update-template` (`scripts/update_template.dart`, `scripts/src/update_template.dart`, and a `test/scripts/update_template_test.dart` covering the unmerged-path parser and the CHANGELOG insertion) runs `copier update`, reports what it could not merge, and files the adoption entry; the scheduled workflow runs it and opens a pull request carrying the result, the way the libsignal update workflow already does. It reports two failure modes separately because both are quiet: conflicts leave both sides in the file and make the pull request a **draft** — nothing else catches them, since `format-check`, `rust-check` and `analyze` read only Dart and Rust while copier's conflicts land in Markdown — and `.copier-answers.yml` failing to move `_commit` fails the job *after* the pull request exists, because that state merges as an un-updated project and re-opens the same pull request forever. Copier is pinned (`copier==9.11.1`, `jinja2-strcase==0.0.2`) for the reason the actions are pinned by SHA: this runs unattended, and a copier release that changed how it merges would arrive as a conflict-shaped diff rather than a clean failure. The gates the pre-commit hook runs are executed and reported in the pull request body but never enforced — a template update that breaks a gate is precisely the one a human most needs to see

  Also fixed: **the `git restore` hint added in v4.2.0 never fired.** The release scripts read `git status --porcelain` through `git()`, which trims its output; the two status columns are positional, so an unstaged modification is `' M path'`, and trimming ate the leading space of the *first* line and shifted that path by one character. `onlyTheseFilesDirty` then matched nothing and rejected the whole status, so every interrupted release got the generic "working tree is not clean" instead — in exactly the case the hint was written for, because a release edits its files without staging them. Both scripts now read the status through a `gitStatus()` that strips only trailing newlines, and a test pins the two shapes against each other so a future trim cannot pass unnoticed. This is why the update was taken before the release rather than after it

  The fourth commit in the range releases the template repository itself and touches nothing under `template/`, so it does not reach here. `copier update` produced no conflicts and no `.rej` files, and `_commit` landed on v4.3.0 unaided; none of this repository's standing divergences (`fuzz.yml`, `SECURITY.md`, `CLAUDE.md`'s two-stage Release Flow, the rulesets' populated bypass actor, `scripts/src/update_changelog.dart`'s project-specific prompt) were in range — `CLAUDE.md` took a single new line in its command list

## [7.0.0] - 2026-07-30

### For Users

#### ✨ Highlights

- **Kyber pre-keys are marked used on every decryption path, with libsignal's full argument list** — **(breaking)** closes a gap where `SealedSenderCipher.decrypt` consumed a Kyber pre-key without ever telling the store, and widens `KyberPreKeyStore.markKyberPreKeyUsed` to the three arguments libsignal's own store trait receives, so last-resort anti-replay becomes implementable
- **Pre-key consumption follows libsignal instead of guessing at it** — a redelivered pre-key message no longer re-consumes the one-time keys libsignal deliberately left alone, and the session is now persisted *after* those writes, so a crash between the two cannot leave a one-time pre-key usable forever
- **Store durability, write ordering and rollback are a documented contract** — every store interface and cipher, plus a new `SECURITY.md` section, now state what your implementation has to guarantee. This corrects rather than extends the previous advice: a lock *inside* the store leaves `load → ratchet → store` unprotected, so two concurrent `encrypt` calls for one address derive the same message key
- **`THIRD_PARTY_NOTICES.txt` ships with the package** — the prebuilt native library is statically linked against its Rust dependency tree, and those licences require the notices to travel with a binary, including an application that embeds it. Signal's own AGPL-3.0-only crates are named there alongside the permissive majority
- **libsignal v0.99.1** — unchanged this release
- **libsignal_frb v6.0.0** — Rust FFI bindings

#### Changed (Breaking)

- **`KyberPreKeyStore.markKyberPreKeyUsed` now takes the signed pre-key ID and the sender's base key** — the signature changes from `markKyberPreKeyUsed(int kyberPreKeyId)` to `markKyberPreKeyUsed(int kyberPreKeyId, int signedPreKeyId, PublicKey baseKey)`, mirroring libsignal's `KyberPreKeyStore::mark_kyber_pre_key_used`. Previously only the Kyber ID reached Dart, so the last-resort check that trait documents ("check whether the same combination of pre-keys was used with the given base key before") was impossible for a consumer to implement — the data simply never arrived. **Action required:** update your `KyberPreKeyStore` implementation to the new signature. Retiring a *one-time* key still only needs `kyberPreKeyId`; for a *last-resort* key, record the `(kyberPreKeyId, signedPreKeyId, baseKey)` triple and treat a repeat as a replayed pre-key message. See `KyberPreKeyStore.markKyberPreKeyUsed` and limitation 5 in `SECURITY.md` for what a detected repeat can and cannot do

- **`SealedSenderDecryptResult.preKeyToRemove` removed** — only affects callers of the raw generated API (`sealedSenderDecryptWithCallbacks`); `SealedSenderCipher.decrypt` is unchanged for its users. Sealed-sender decryption now takes `removePreKey` and `markKyberPreKeyUsed` callbacks, which the bridge invokes itself in libsignal's order, rather than returning an ID for the caller to act on afterwards — matching how `SessionCipher.decrypt` has always worked. **Action required:** if you call the raw function, pass the two new callbacks and delete your post-call `removePreKey` handling

#### Changed

- **The package ships `THIRD_PARTY_NOTICES.txt`** — the prebuilt native library is statically linked against its Rust dependency tree, and those licences require their notices to travel with a binary distribution, including an application that embeds the library. Flutter's `LicenseRegistry` does not cover them: it aggregates `LICENSE` files of pub packages, and Rust crates are not pub packages. The file sits at the package root and is generated from the resolved dependency graph with no platform filtering at all, so the same commit yields the same file on any machine — build edges are included because that is how vendored native code reaches the binary — and CI verifies it stays in sync with `Cargo.lock`. It is not an inventory of permissive licences: Signal's own crates in that graph (`libsignal-protocol`, `libsignal-core`, `signal-crypto` and their siblings) are AGPL-3.0-only, and they are named alongside the MIT / Apache-2.0 / BSD / ISC majority, with the README's new *Third-party notices* section pointing at [LICENSE.libsignal](LICENSE.libsignal) for what that means when you redistribute a binary. Where a crate ships no licence file of its own, the canonical text of the licence it declares is supplied in its place, so the file delivers the licences rather than merely naming them. It is deliberately **not** declared under `flutter: assets:`, which would bundle it into every consuming application whether or not it is ever displayed; the README shows how to register it with `LicenseRegistry` for an app that wants it at runtime

#### Security

- **Store durability, write ordering and rollback are now a documented contract** — storage is delegated to the application, and libsignal derives message keys deterministically (the Double Ratchet has no per-message nonce guard), so a store write that is lost to a crash or rolled back by a restore makes the next send reuse a message key and IV. The contract is now stated where implementers read it: on every store interface (`SessionStore`, `IdentityKeyStore`, `PreKeyStore`, `SignedPreKeyStore`, `KyberPreKeyStore`, `SenderKeyStore`), on `SessionCipher` / `SessionBuilder` / `SealedSenderCipher` / `GroupCipher`, and in a new [`SECURITY.md` section](SECURITY.md#store-durability-write-ordering-and-rollback). No behaviour change — the library already awaited every store-write callback before returning a ciphertext or plaintext (verified against the Rust bridge for every entry point); what was missing was the requirement that *your* callback not complete until the write is durable
  - **Durable before release** — a store write must reach stable storage before the operation's output leaves the device or is acted upon, either inside the callback (`fsync`, SQLite `synchronous = FULL`) or via a transaction committed before sending. Deletes and pre-key consumption (`removePreKey`, `markKyberPreKeyUsed`) count as writes
  - **Serialize per address** — corrects the previous guidance in `SECURITY.md` §H, which suggested a lock *inside* the store: that leaves the `load → ratchet → store` window unprotected, so two concurrent `encrypt` calls for one address derive the same message key with no crash involved. The lock must span the whole cipher call
  - **Rollback** — at-rest encryption gives confidentiality, not rollback protection; documents the achievable mitigation (bind the store to a marker in non-backed-up storage and treat a restored copy as a session reset) plus the platform limits of `fsync` on Apple platforms and of IndexedDB durability on the web

- **`SealedSenderCipher.decrypt` now marks the Kyber pre-key it consumed** — it removed the one-time EC pre-key a pre-key message consumed but never called `markKyberPreKeyUsed` for the Kyber pre-key on that same path, so a store that retires marked one-time Kyber pre-keys kept serving one that sealed sender had already consumed. Sealed sender is a normal delivery path for a first message, so this was the ordinary case rather than a corner. Both decryption paths now issue the same four writes

- **Pre-key consumption now reports what libsignal actually did, and `storeSession` is written last** — the bridge inferred `removePreKey` / `markKyberPreKeyUsed` from the fields of the incoming message, while libsignal issues them only when the pre-key message really establishes a new session. A redelivered pre-key message matching an existing session therefore re-consumed keys libsignal had deliberately left alone. The bridge now observes the calls libsignal makes against the stores it is handed. That change requires the session to be persisted **after** the consumption writes (it previously went first): had the order stayed, a crash between the session write and `removePreKey` would let the redelivered message match the persisted session, consume nothing, and leave a one-time pre-key usable forever. The awaited-write table in `SECURITY.md` documents the new order

### For Contributors

#### Added

- **CI verifies the declared MSRV** — `rust-version = "1.88"` in `rust/Cargo.toml` is a promise to anyone building the native library from source, and nothing checked it: the first dependency or language feature to raise the real floor would have broken that build silently, with the failure landing on a contributor rather than here. A new `msrv` job reads the version out of the manifest — rather than repeating it, so the job cannot drift from the claim it checks — installs exactly that toolchain, installs protoc — `spqr`'s prost-based build script shells out to it, so without it the job would fail on tooling rather than on the MSRV it exists to check — and runs `make rust-check`. Verified locally against 1.88 before the job was added; the reusable `setup-rust` action gained a `toolchain` input (default `stable`) to make it possible

- **Reference durable store in `example_cli`** (repository only — `example_cli/` is not part of the published archive) — `lib/stores/durable_file_stores.dart` implements all six stores on an append-only journal that flushes before each write's future completes and replays on open, truncating a torn tail — which, without per-frame checksums, it cannot tell apart from a corrupt header, a limitation the file documents. It ships an `AddressLocks` helper for call-site serialization. `lib/demos/durable_store_demo.dart` proves the round trip: it establishes a session, exchanges messages, closes the stores, reopens them from disk and continues the same conversation. `DurableKyberPreKeyStore` demonstrates both halves of the Kyber contract: a one-time key is retired on its first mark (`loadKyberPreKey` stops serving it), while a last-resort key stays in service and every `(kyberPreKeyId, signedPreKeyId, baseKey)` agreement is journalled, with repeats surfaced through `replayedAgreements`. The demo's final step exercises that second half end to end — it rolls Bob's state back the way a restored backup would, replays the same ciphertext, and shows the identical agreement being marked twice

- **`test/protocol/kyber_pre_key_consumption_test.dart`** — pins the two behaviours that had no coverage: a second pre-key message arriving on the session an earlier one established consumes nothing further, and `SealedSenderCipher.decrypt` marks the Kyber pre-key with the same triple as `SessionCipher.decrypt`

#### Changed

- **`stores-implementation` and `security-review` skills, plus the `CONTRIBUTING.md` review checklist, corrected** — they recommended a lock *inside* the store, which does not cover `load → ratchet → store`, and are now aligned with the durability/serialization contract. Both transaction examples also note that the store's writes must be routed through the ambient transaction (`sqflite` deadlocks if the `db` handle is used inside `db.transaction(...)`)

- **GitHub Actions bumped to their Node 24 majors** — the first grouped Dependabot run moves `actions/checkout` 4 → 7, `actions/upload-artifact` 4 → 7, `actions/download-artifact` 4 → 8, `actions/cache` 4 → 6, `actions/create-github-app-token` 2 → 3, `android-actions/setup-android` 3.2.2 → 4.0.1 and `schneegans/dynamic-badges-action` 1.7.0 → 1.9.0, converging on the pins the copier template now carries. This is catching up to the runner rather than optional drift: CI was already warning that "actions/cache@v4, actions/checkout@v4" target the deprecated Node 20 and "are being forced to run on Node.js 24". Every input these workflows pass still exists on the new majors, and both SHA-pinned actions were verified against their upstream tag refs. The two behaviour changes that do land: `download-artifact` now *fails* a run on a digest mismatch instead of only warning, and `setup-android` dropped its SDK cache (slower Android legs, same output). No workflow logic changed

- **Dependabot branches excluded from the `Signing commit` and `Delete branches` rulesets** — both target `~ALL` branches, so `non_fast_forward` stopped Dependabot from force-pushing a rebase onto a moved `main` and `deletion` stopped it from cleaning up a merged branch: a grouped update PR could never refresh itself once `main` had moved. `refs/heads/dependabot/**/*` is now in each ruleset's `ref_name.exclude` — the trailing `/*` is load-bearing, since a bare `**` does not cross a `/` and so would miss the multi-segment branch names Dependabot actually creates. `main` is unaffected (it is not a Dependabot branch) and keeps `required_signatures` from the same ruleset. Scoped with `exclude` rather than a bypass actor, which on a `~ALL` ruleset would have exempted that actor on `main` too

- **copier template adopted: v3.0.3 → v4.1.0** — the major's single contract change is that every project generate and commit `THIRD_PARTY_NOTICES.txt` before its next CI run, because `test-reusable.yml` now verifies it; that file and its generator arrive here for the first time (see *For Users* above). Also landing: `make rust-test` and a CI step that runs the crate's own unit tests; `make third-party-notices` / `make verify-third-party-notices`, with `make rust-update` regenerating the inventory so the lockfile and the notices cannot drift apart; the fuzz workflow reads its targets from the `[[bin]]` entries of `rust/fuzz/Cargo.toml` and fans them out one job per target (`fail-fast: false`, per-target crash artefacts) instead of looping over a hardcoded list in a single job that stopped at the first crash — the discovery step was run against `rust/fuzz/Cargo.toml` and yields exactly the six existing targets; `validateUpstreamTag` names which input it rejected, since an API `tag_name`, a `--version` argument and the pin recorded in `rust/Cargo.toml` fail for different reasons; `insertChangelogEntry` matches `#### Changed` exactly, where a prefix match previously also filed a native-library bump under `#### Changed (Breaking)`; the build hook declares a local native build as a dependency, so `make clean` no longer leaves `dart test` pointed at a cached asset that is gone; and `copyright_year` becomes a stored answer, recorded as 2025 — the year of first publication — though for an AGPL-3.0 project it does not reach the rendered `LICENSE`, which the template only stamps for MIT and BSD.
  Three deviations are deliberate. The AI changelog prompt stays this project's own: the template now carries a generic version, while the one here enumerates the crates this wrapper binds and the upstream areas it does not expose, which is what keeps an upstream networking, keytrans or zkgroup change from being announced as a feature of this package. The `freezed_annotation` / `freezed` / `build_runner` dependencies are not adopted — they exist so that a *freshly generated* project's first codegen succeeds against an unknown API surface, whereas this FRB surface has no data-carrying enums, and `freezed_annotation` sits in `dependencies`, so every consumer would download a package nothing here imports. And `ffigen` stays at `^20.1.1` instead of returning to the template's `^20.0.0`.
  The follow-up minor, v4.1.0, landed net-zero: its whole content is this project's own notice-inventory and MSRV work (the two fixes below, plus the reproducibility pass) carried back upstream, so `copier update` had nothing left to apply beyond recording the version

- **The `Signing commit` ruleset no longer bypasses the update GitHub App** — `bypass_actors` is now empty, matching the template. The app's commits are created through the API and are therefore signed by GitHub, so `required_signatures` is satisfied without an exemption, and on a `~ALL` ruleset a bypass actor is exempted everywhere, `main` included — the same reasoning the Dependabot entry above applies. `refs/heads/update-*` is still *not* excluded from the ruleset: the template's policy is to widen `exclude` only on an observed failure, and a failure here is visible rather than silent, since the bot comments on the pull request it could not refresh

#### Fixed

- **The notice inventory no longer depends on the machine that generated it** — `cargo tree --target <triple>` filters *normal* dependencies by that triple but resolves *build*-dependencies for the **host**, so the inventory recorded the build graph of whoever ran the generator rather than of the released targets. Here that is `prost-build` → `tempfile` → `rustix`, whose backend is host-gated: `errno` on a macOS host, `linux-raw-sys` on a Linux one. One crate swapped for the other with the crate count unchanged, so the file generated locally was rejected by the CI check on its first run — correct where it was written, wrong everywhere else, and the check could only report "the contents differ". Nor is the problem confined to build edges: proc-macro subtrees are host-compiled too, which is how `winapi` — reached through `ansi_term` inside a proc-macro crate — stays invisible everywhere except a Windows host. No per-target query escapes this, so the crate set is now taken from `cargo tree --target all`, the only query cargo offers that applies no platform filtering at all; the per-target sweep is kept because it is the one thing that fails when a declared release target stops resolving. Over-attribution is the deliberate trade: the extra entries are build tooling and platform-gated crates that a given build never links — `winapi` here reaches the graph only through a host-compiled proc-macro — but a notice file that lists them on every machine is worth more than a narrower one that changes with the machine, since the byte-exact CI check is only viable if the output is reproducible. Accordingly the inventory grows from 206 to 241 crates, the additions being platform-gated crates and build tooling that were always in the graph but invisible from a macOS host (`linux-raw-sys`, `windows-sys`, `winapi`, `bindgen`, `clang-sys`, …). Cross-checked against `cargo-about`: it now reports no crate this inventory omits. `--check` now also prints the first differing line and the lines unique to each side, since its failure is normally read from a CI log where bisecting a 450 KB file by hand is the only alternative

## [6.1.1] - 2026-07-25

### For Users

#### ✨ Highlights

- **libsignal v0.99.1** — internal/dependency update, no public-API impact
- **libsignal_frb v5.1.2** — Rust FFI bindings

#### Changed

- **libsignal native library → v0.99.1** ([compare](https://github.com/signalapp/libsignal/compare/v0.97.4...v0.99.1))
  - Upstream user-facing changes target the chat/backup/registration services and logging — none of which this library exposes
  - The crates we bind (`libsignal-protocol`, `signal-crypto`, `libsignal-core`) saw internal refactors to track the updated RustCrypto / curve25519-dalek / spqr dependencies, with no change to behaviour or the FFI surface (FRB bindings regenerate byte-for-byte identical)

#### Security

- **Upstream libcrux advisories resolved** — v0.99.1 pulls in `libcrux-sha3` 0.0.10 and `libcrux-secrets` 0.0.6, which fix RUSTSEC-2026-0207, RUSTSEC-2026-0208 (incremental/AVX2 SHAKE) and RUSTSEC-2026-0212 (aarch64 const-time swap). The interim `cargo-audit` / `cargo-deny` suppressions for these three have been removed

## [6.1.0] - 2026-07-21

### For Users

#### ✨ Highlights

- **Build provenance attestation (Sigstore, SLSA Build L2)** — every native-release archive is now cryptographically attested to this repository's tag-triggered build, closing the previously documented authenticity gap (verify with `gh attestation verify`)
- **Web: stale-WASM-after-upgrade fixed** — the web build hook now refreshes `web/pkg/` on a version change instead of serving the previous version's WASM, which could crash Dart-store-callback paths (`processPreKeyBundle`, `SessionCipher`, sealed sender, group messaging) after an upgrade
- **Smaller package & explicit minimum OS versions** — the vestigial platform-plugin scaffolding is removed (smaller published archive) and the prebuilt binaries are now built against the documented macOS 10.15 / Android API 24 minimums
- **libsignal v0.97.4** — internal/dependency update, no public-API impact
- **libsignal_frb v5.1.1** — Rust FFI bindings

#### Changed

- **Platform-plugin scaffolding removed from the published package** — the vestigial `ios/`, `macos/`, `android/`, `linux/`, `windows/` directories (podspecs, Gradle project, CMakeLists, plugin stubs) are gone. The package has never declared a `flutter: plugin:` section, so flutter_tools never consumed them; native delivery is (and remains) via the `hook/build.dart` build hook. No consumer action required — the published archive just gets smaller
- **Explicit minimum OS versions for the prebuilt binaries** — CI now builds the macOS dylibs with `MACOSX_DEPLOYMENT_TARGET: '10.15'` (previously rustc's per-target default, 10.12 for x86_64) and links the Android `.so`s against API level 24 via cargo-ndk `--platform 24` (previously cargo-ndk's default, 21), matching the documented platform-support table
- **libsignal v0.97.4 update** — bump the bound native library ([compare](https://github.com/signalapp/libsignal/compare/v0.97.3...v0.97.4))
  - Upstream changes are limited to `AuthAccountsService` (registration-lock set/clear, discoverable-by-phone-number, registration-recovery-password), `UnauthBackupsService.copyMedia`/`copyBackupMedia`, SVR2 node APIs, and language-binding / bridge tooling (node/java/swift/ts) — none of which this library exposes
  - The only change to the crates we bind (`libsignal-protocol`, `signal-crypto`, `libsignal-core`) is the `libsignal-core` version string (`rust/core/src/version.rs`); `make codegen` produces no binding diff
  - Note: These changes do not affect this library's public API
- **libsignal v0.97.3 update** — bump the bound native library ([compare](https://github.com/signalapp/libsignal/compare/v0.97.2...v0.97.3))
  - Upstream changes are limited to `AuthUsernamesService.deleteUsernameHash()`/`deleteUsernameLink()` (username services), reclassifying an established chat connection's transport errors as retryable (`.ioError`, Swift binding), and increasing the key-transparency clock-skew tolerance interval — none of which this library exposes
  - The crates we bind (`libsignal-protocol`, `signal-crypto`, `libsignal-core`) are unchanged apart from version strings; `make codegen` produces no binding diff
  - Note: These changes do not affect this library's public API

#### Security

- **Build provenance attestation (Sigstore, SLSA Build L2)** — every native-release archive is now attested with GitHub Artifact Attestations: CI signs a provenance statement proving the archive was built by this repository's tag-triggered `build-libsignal.yml` from a specific commit, closing the previously documented authenticity gap (the SHA256 checksums file ships in the same release as the archives). Verify with `gh attestation verify <archive> --repo djx-y-z/libsignal_dart`; a Sigstore bundle (`libsignal_frb-<version>.sigstore.jsonl`) is attached to each release for fully offline verification. See SECURITY.md → Authenticity (the build hook itself still verifies SHA256 only — attestation verification is manual)

#### Fixed

- **Stale web WASM after a package upgrade** — the web build hook (`hook/build.dart`) now records the provisioned crate version in `web/pkg/.wasm-version` and re-downloads when it changes, instead of skipping whenever the two WASM files merely exist. Previously, upgrading the package kept the prior version's WASM in the consuming app's `web/pkg/` (it survives `flutter clean`), so on web any FRB entry that calls Dart store callbacks — `SessionBuilder.processPreKeyBundle`, `SessionCipher`, `SealedSenderCipher`, group messaging — panicked with an argument-count mismatch (`called Option::unwrap() on a None value`) once the wire signature had changed between versions. The download cache is now version-keyed and `rust/Cargo.toml` is a declared web-build dependency, both mirroring the native path (which was unaffected)
- **Build hook download/cache resilience** — the hook (`hook/build.dart`) is more robust against partial/transient failures: a download-cache entry is only reused after a `.download-complete` marker proves the extraction finished (an interrupted `tar` no longer leaves a truncated library that is reused forever), a locally built `rust/target/` library is used only when it matches the target OS **and** architecture (previously a host build could be bundled for a cross-target, e.g. a macOS dylib into an iOS app), the web path no longer fetches checksums when a warm cache can serve the files offline, and both the checksums fetch and the binary download now retry on transient HTTP 5xx/429 instead of failing the build on a single blip

### For Contributors

#### Added

- **`make release-frb` + `release-frb-crate` skill** — one-command native-crate release (stage 1): bumps `rust/Cargo.toml`, stamps the CHANGELOG `libsignal_frb` Highlights line, and creates a signed commit + `libsignal_frb-<version>` tag, pushing to trigger the native build. The commit/tag/push inherit the terminal, so the signing passphrase is entered interactively during the command. Pairs with `release-package` (stage 2)
- **`make release` + updated `release-package` skill** — one-command Dart package release (stage 2) symmetric to `make release-frb`: verifies the stage-1 native binary exists on GitHub Releases, bumps `pubspec.yaml`, finalizes the CHANGELOG (`[Unreleased]` → dated version + a fresh `[Unreleased]` + the bottom compare-link refs), validates with a publish dry-run, then signs a commit + `vX.Y.Z` tag and pushes to trigger the pub.dev publish. The two release commands share git/terminal helpers in `scripts/src/release_common.dart`
- **Repository-protection tooling** — the branch and release-tag rulesets now live in-repo as committed JSON (`.github/rulesets/*.json`, the source of truth), and `make setup-repo-protections` applies them to GitHub via `gh` (idempotent by ruleset name) and configures the `native-build` environment. A new **Protect release tags** ruleset restricts tag creation (all tags) to Admins/Maintainers — covering the release-triggering `libsignal_frb-*` / `v*` and any other — and the native-crate publish (`build-libsignal.yml`) now runs in the required-reviewer `native-build` environment — gating tag-push and `workflow_dispatch` alike, mirroring the `pub.dev` environment that gates pub.dev publishing
- **Dependabot for GitHub Actions** — `.github/dependabot.yml`: weekly grouped update PRs (Monday 06:00 UTC, `chore(deps)` prefix) bump the pinned actions — both the commit SHA and its `# vX.Y.Z` comment — across the workflows and the composite actions (a `directories` glob covers `/.github/actions/*`, since `/` only scans `.github/workflows/`). `dtolnay/rust-toolchain` is ignored: it has no versioned releases (master-SHA pin, toolchain selected via input) and stays manually bumped

#### Changed

- **Accept unremediable upstream libcrux crypto advisories in cargo-deny / cargo-audit** — three RustSec advisories published 2026-07-17 (`RUSTSEC-2026-0207` / `-0208`, incorrect / panicking SHAKE in `libcrux-sha3` 0.0.8; `RUSTSEC-2026-0212`, incorrect aarch64 constant-time swap in `libcrux-secrets` 0.0.5) live in libsignal's git-pinned ML-KEM stack and are not fixable from this repo — the fix requires a libsignal release that bumps `libcrux-ml-kem` (v0.97.4 still ships the old libcrux). Added to `rust/deny.toml` `[advisories].ignore` and the `rust-audit` `--ignore` flags as a tracked interim suppression so the `cargo-deny` / `cargo-audit` CI jobs pass — to be removed once a fixed libsignal release lands
- **Decoupled the `libsignal_frb` native release from libsignal dependency updates** — automated update PRs no longer bump the crate version or build binaries; dependency updates accumulate on `main` (tested from source in CI), and the native build is now triggered by pushing a `libsignal_frb-<version>` tag instead of by pushing to `main`. The crate-version bump is now a deliberate release decision (`make release-frb`). See CLAUDE.md → Release Flow
- **AI changelog generator classifies upstream changes against the bound-crate surface** — the prompt now states which crates/APIs this wrapper actually binds, so out-of-scope upstream changes (net / chat / keytrans / username services / zkgroup / …) are framed as "none of which this library exposes", and it links to a version `compare` instead of the (often incomplete) release notes
- **CI enforces deployment-target consistency** — `test-reusable.yml` now runs `make check-targets` (Linux leg) so the build fails if the iOS / macOS / Android minimum deployment targets drift out of sync across the CI build env vars, the example Xcode projects and the README platform table. Previously the check existed (`make check-targets`) but was never run automatically
- **Deployment-target sources consolidated** — `.copier-answers.yml` remains the single source of truth; with the platform scaffolding removed, `make check-targets` and `scripts/get_android_min_sdk.dart` no longer read the podspecs/`build.gradle` but verify the CI workflow (`IPHONEOS_DEPLOYMENT_TARGET`, `MACOSX_DEPLOYMENT_TARGET`, cargo-ndk `--platform`) instead
- **Upstream tag names validated before reaching the shell** — `check_updates.dart` / `check_template_updates.dart` reject a release `tag_name` that is not a plain semver-ish tag before it lands in `GITHUB_OUTPUT`, and the update workflows pass step outputs/inputs into `run:` blocks via `env:` instead of inline `${{ }}` interpolation — closing a shell-injection path from upstream release names (backport of the liboqs audit)
- **Least-privilege `GITHUB_TOKEN` everywhere** — `publish.yml` and `build-libsignal.yml` now default to `contents: read` with job-level opt-ups (`id-token: write` on the pub.dev publish job, `contents: write` on the release jobs); the two update-checker workflows drop `contents/pull-requests: write` entirely (all writes go through the App token)
- **Third-party actions pinned to commit SHAs** — `dart-lang/setup-dart`, `peter-evans/create-pull-request`, `android-actions/setup-android`, `ilammy/msvc-dev-cmd`, `schneegans/dynamic-badges-action`, `Swatinem/rust-cache`, `dtolnay/rust-toolchain` (toolchain now passed via the `toolchain` input since the ref no longer selects it)
- **`setup-make` verifies gnumake.exe by SHA256** — release assets are mutable, so the size check alone did not lock the Windows make binary; a hardcoded SHA256 (updated together with the version) now does
- **Pre-release hardening pass (audit fixes)** — a review of this cycle's changes fixed, among others: `make release-frb` now syncs and stages `rust/Cargo.lock` alongside `rust/Cargo.toml` (the pre-commit `cargo check` no longer leaves a dirty tree that blocked stage 2, and the signed tag no longer carries a stale lock); `Swatinem/rust-cache` is repinned from the floating `v2` tag object to the real `v2.9.1` commit (would have broken every Rust job when upstream re-tagged `v2`); the pub.dev release notes are written via `--notes-file` instead of an inline heredoc (a literal `EOF` line in the changelog can no longer break out into the shell); `build-libsignal.yml` no longer delete-then-recreates a release (fail-loud, no silent clobber) and the release-existence probe fails closed on API errors; the `fuzz.yml` dispatch `duration` input is validated and passed via `env:`; `make check-targets` fails closed when a checked file/pattern disappears; and `--date` in `make release` is validated. Docs corrected across README/CLAUDE/CONTRIBUTING/SECURITY/rulesets (build-hook fallback, `AI_MODELS_TOKEN`, two-stage publishing, `.skip_*_hook` semantics, stale Cargokit/loading-order references)
- **Adopt copier template v3.0.0** — most of this template release (the two-stage release flow, repository rulesets, Dependabot, and the CI deployment-target check) was already backported into this repo, so the update reduced to a documentation and tooling sync: `CONTRIBUTING.md` gains the "Releasing (two stages)" and "Repository rulesets & tag protection" sections, and the `Makefile` `.PHONY` list is reordered to match the template (no behavior change)

## [6.0.0] - 2026-07-14

### For Users

#### ✨ Highlights

- **Identity-trust enforcement (breaking)** — a remote identity key that differs from the stored one is now rejected with `UntrustedIdentity` on every session operation (MITM / safety-number-change detection), instead of being silently accepted
- **Hardened supply chain & binary** — the native-binary download is now fail-closed (aborts if it can't be verified), and the wrapper crate is built with integer-overflow checks
- **App store additional permission** — the license now allows AGPL-compliant apps to ship through app stores with AGPL-incompatible terms (e.g. the Apple App Store); see `LICENSE.appstore`
- **libsignal v0.97.2** — internal/dependency update, no public-API impact
- **libsignal_frb v5.0.0 (internal Rust FFI crate)** — breaking (major): adds a required `get_identity` callback

#### Changed (Breaking)

- **Identity-trust is now enforced on every session operation**, matching upstream libsignal's `is_trusted_identity` semantics. `SessionBuilder.processPreKeyBundle`, `SessionCipher.encrypt`/`decrypt` (both pre-key and regular Whisper messages), and `SealedSenderCipher.encrypt`/`decrypt` now consult your `IdentityKeyStore.getIdentity` and reject a remote identity key that differs from the stored one with an `UntrustedIdentity` error. Previously a substituted identity (e.g. from a malicious key-distribution server) was accepted without error. First contact is still trusted-on-first-use.
  - **Action required:** catch `UntrustedIdentity` (its message contains `untrusted identity`) and treat it as a safety-number change — verify with the user, then save the new identity (or clear the old one) in your store and archive the old session for that address before retrying. Requires your `IdentityKeyStore.getIdentity` to be implemented correctly.

#### Changed

- Update libsignal native library to v0.97.2 ([compare](https://github.com/signalapp/libsignal/compare/v0.96.4...v0.97.2))
  - Upstream changes between v0.96.4 and v0.97.2 are limited to net/registration, chat/backups gRPC, bridge/codegen tooling, and CI / language-binding (node/swift/java) updates — none of which this library exposes
  - The only diffs in the crates we bind are cosmetic: a test-only import in `kem.rs`, an internal `TryFrom` refactor in `state/bundle.rs` (`and_then(…map…)` → `.zip(…)`, behavior identical), and the `libsignal-core` version string
  - Note: These changes do not affect this library's public API
- **App store additional permission (AGPL §7)** — the package license now carries an explicit app-store exception (the Feeel/wger wording, see `LICENSE.appstore`): GPL/AGPL-compliant applications may distribute this package in object-code form through app stores whose terms are incompatible with the AGPL (such as the Apple App Store), provided their source stays available under the AGPL through an unrestricted channel. The permission covers only this repository's code; the status of an equivalent permission for the bundled upstream `libsignal` is tracked in [signalapp/libsignal#684](https://github.com/signalapp/libsignal/issues/684). Requested in [#44](https://github.com/djx-y-z/libsignal_dart/issues/44)

#### Security

- **Fail-closed native library verification** — the build hook (`hook/build.dart`) now aborts the build if the SHA256 checksums for a downloaded binary cannot be fetched or the archive has no entry, instead of silently proceeding unverified. An escape hatch (`LIBSIGNAL_ALLOW_UNVERIFIED_DOWNLOAD=1`) remains for releases with no checksums file
- **Hardened crate build** — the wrapper's release profile enables `overflow-checks`, so an integer overflow in the wrapper is a deterministic (catchable) panic rather than silent wraparound (the audited crypto dependencies are left untouched)
- **Secret-lifetime & zeroing caveats documented** — `SECURITY.md` now spells out that opaque secret handles (`PrivateKey`, `KyberSecretKey`, `SessionRecord`, …) stay resident in native memory until a non-deterministic GC finalizer runs, so security-critical code should call `dispose()` to bound that window (noting the extractable key types are `Copy`/plain-boxed and thus not zeroized on drop — `dispose()` shortens the exposure window, it does not wipe), and that Rust's `zeroize` covers Rust memory only: secret bytes that cross the FFI boundary into a Dart `Uint8List` live on the un-zeroed GC heap where `SecureBytes`/`zeroize()` are best-effort. `PrivateKey.cloneKey()` / `KyberSecretKey.cloneKey()` now carry a `# Security` doc note that each copy is an independent secret

#### Fixed

- **Device ID truncation** — the `ProtocolAddress` and `PreKeyBundle` constructors no longer truncate the `u32` device ID to `u8` before validating (e.g. `257` is no longer accepted as device `1`); out-of-range IDs are rejected as documented (1–127)
- **HKDF output bound** — `hkdfDerive` now rejects an output length above the RFC 5869 maximum (`255 × 32 = 8160` bytes) before allocating, instead of attempting an oversized allocation
- **In-memory identity-store equality** — `InMemoryIdentityKeyStore` now compares identity keys by value (`equals()`) rather than by object reference, so a re-presented key is correctly seen as unchanged (matters for production stores copied from this reference implementation)
- **Native-library download cache key** — the build hook (`hook/build.dart`) now keys its download cache by crate version and the full platform variant (e.g. `ios-device-arm64` vs `ios-simulator-arm64`) rather than only OS + architecture. On Apple-silicon hosts iOS device and simulator builds shared a key, so whichever built first poisoned the cache for the other and `dyld` rejected the bundled library at runtime (`incompatible platform: have 'iOS-simulator', need 'iOS'`); a version bump could also serve a stale cached binary

### For Contributors

#### Added

- **Fuzzing harness** — `cargo-fuzz` targets (`rust/fuzz/`) covering every byte-parsing entry point (keys, messages, records, sealed-sender certificates, crypto primitives, pre-key decryption), a seed-corpus generator, and a `Fuzz` CI workflow (per-PR smoke run + weekly deep run). See `make fuzz-list` / `make fuzz`
- **Dependency policy** — `cargo-deny` (`rust/deny.toml`, `make rust-deny`, CI `deny` job) enforcing RustSec advisories, an AGPL-compatible license allow-list, and a source allow-list restricted to crates.io and the official Signal repositories
- **Rust linting (Clippy)** — `cargo clippy --all-targets -- -D warnings` now runs in CI (the reusable test workflow, on the Linux x86_64 leg) and locally via `make rust-clippy`; the hand-written wrapper is lint-clean, with the FRB-inherent lints (many-callback store signatures, complex tuple returns) annotated with justified site-local `#[allow]`s

#### Changed

- **CI least-privilege** — the reusable test workflow now declares `permissions: contents: read`
- **Rust lint** — hand-written Rust is compiled with `unsafe_code = "deny"` (only the FRB-generated bridge is exempt)
- **Copier template adopted (v2.5.1)** — `flutter_rust_bridge_codegen` is now pinned via `make setup-frb-codegen` (kept in sync with the `flutter_rust_bridge` dependency, `2.12.0`); the libsignal-update workflow installs the codegen binary (fixing a codegen step that failed with exit 127) and skips regenerating an update PR that already exists; `check_updates.dart` bumps the wrapper crate version mirroring the upstream SemVer delta, `update_changelog.dart` classifies update severity via AI, and the `update-libsignal` skill now analyzes the full upstream diff

## [5.0.9] - 2026-06-27

### For Users

#### ✨ Highlights

- **libsignal v0.96.4** — internal improvements and updates
- **libsignal_frb v4.0.9** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.96.4 ([compare](https://github.com/signalapp/libsignal/compare/v0.96.3...v0.96.4))
  - Upstream changes are limited to net/registration and chat gRPC helpers, server-side SVR enclave rotation (2026Q2), FFI bridge tooling, and new typed `reserveUsernameHash()` / donation-permit client APIs — none of which this library exposes
  - The `libsignal-protocol` and `signal-crypto` crates are unchanged; `libsignal-core` only bumps its internal version string
  - Note: These changes do not affect this library's public API

## [5.0.8] - 2026-06-24

### For Users

#### ✨ Highlights

- **libsignal v0.96.3** — internal improvements and updates
- **libsignal_frb v4.0.8** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.96.3 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.96.3))
  - Upstream changes are limited to an internal ML-KEM parameter key type fix plus net/node/gRPC/server-side updates, none of which this library exposes
  - Note: These changes do not affect this library's public API

## [5.0.7] - 2026-06-20

### For Users

#### ✨ Highlights

- **libsignal v0.96.2** — internal improvements and updates
- **libsignal_frb v4.0.7** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.96.2 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.96.2))
  - Upstream changes are limited to zkgroup donation credentials (`DonationPermit`), which this library does not expose
  - Note: These changes do not affect this library's public API

## [5.0.6] - 2026-06-19

### For Users

#### ✨ Highlights

- **libsignal v0.96.1** — internal improvements and updates
- **libsignal_frb v4.0.6** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.96.1 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.96.1))
  - Internal improvements and updates
  - Note: These changes do not affect this library's public API

## [5.0.5] - 2026-06-12

### For Users

#### ✨ Highlights

- **libsignal v0.96.0** — internal improvements and updates
- **libsignal_frb v4.0.5** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.96.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.96.0))
  - Internal improvements and updates
  - Note: These changes do not affect this library's public API

## [5.0.4] - 2026-06-10

### For Users

#### ✨ Highlights

- **libsignal v0.95.0** — internal improvements and updates
- **libsignal_frb v4.0.4** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.95.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.95.0))
  - Internal improvements and updates
  - Note: These changes do not affect this library's public API

## [5.0.3] - 2026-06-04

### For Users

#### ✨ Highlights

- **libsignal v0.94.4** — internal improvements and updates
- **libsignal_frb v4.0.3** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.94.4 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.94.4))
  - Internal improvements and updates
  - Note: These changes do not affect this library's public API

## [5.0.2] - 2026-05-31

### For Users

#### ✨ Highlights

- **libsignal v0.94.3** — internal improvements and updates
- **libsignal_frb v4.0.2** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.94.3 ([compare](https://github.com/signalapp/libsignal/compare/v0.94.1...v0.94.3))
  - Binding/tooling improvements (JNI, Node, Swift type converters), backup validator and reflector routing updates
  - Note: No changes to the libsignal-protocol crate — does not affect this library's public API

#### Documentation

- Document `flutter build web --wasm` (dart2wasm) limitation in README — Rust returns fail with `Type 'JSValue' is not a subtype of type 'List<dynamic>'` under dart2wasm. Upstream limitation in `flutter_rust_bridge` ([#2575](https://github.com/fzyzcjy/flutter_rust_bridge/issues/2575)), affects every FRB-based Dart package. Standard `flutter build web` (dart2js) target continues to work.

## [5.0.1] - 2026-05-19

### For Users

#### ✨ Highlights

- **libsignal v0.94.1** — internal improvements and updates
- **libsignal_frb v4.0.1** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.94.1 ([compare](https://github.com/signalapp/libsignal/compare/v0.94.0...v0.94.1))
  - Networking improvements: gRPC/H2 transport additions, reflector proxy support
  - Key Transparency: added account data reset, additional logging around monitor versions
  - Note: No changes to libsignal-protocol crate — does not affect this library's public API

## [5.0.0] - 2026-05-12

### For Users

#### ✨ Highlights

- **libsignal v0.94.0** — extends sender/recipient address binding to `SignalMessage.verifyMac()`
- **libsignal_frb v4.0.0** — Rust FFI bindings updated with new sender/recipient address parameters on `verifyMac` (breaking)

#### Changed

- Update libsignal native library to v0.94.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.94.0))
  - **Breaking:** `SignalMessage.verifyMac()` now requires `senderAddressName`, `senderAddressDeviceId`, `recipientAddressName`, and `recipientAddressDeviceId` parameters
  - Upstream made the previous `SignalMessage::verify_mac` method private and exposed `verify_mac_with_addresses` as the public replacement, extending the misdirection protection (started in v0.91.0) to message MAC verification

## [4.0.1] - 2026-05-06

### For Users

#### ✨ Highlights

- **libsignal v0.93.2** — internal improvements and updates
- **libsignal_frb v3.0.1** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.93.2 ([compare](https://github.com/signalapp/libsignal/compare/v0.93.1...v0.93.2))
  - Networking improvements: H2 GOAWAY (graceful shutdown) handling for WebSockets
  - Updated `hickory-proto` DNS dependency to 0.26.1
  - Updated CDSI production enclave and added new SVR enclaves (server-side)
  - Note: No changes to libsignal-protocol crate — does not affect this library's public API

## [4.0.0] - 2026-05-01

### For Users

#### ✨ Highlights

- **libsignal v0.93.1** — extends sender/recipient address binding to remaining session APIs
- **libsignal_frb v3.0.0** — Rust FFI bindings updated with new `localAddress` parameter (breaking)

#### Changed

- Update libsignal native library to v0.93.1 ([v0.93.0](https://github.com/signalapp/libsignal/releases/tag/v0.93.0), [v0.93.1](https://github.com/signalapp/libsignal/releases/tag/v0.93.1))
  - **Breaking:** `SessionBuilder` constructor now requires `localAddress` parameter
  - **Breaking:** `processPrekeyBundleWithCallbacks` now requires `localName` and `localDeviceId` parameters
  - **Breaking:** `messageDecryptSignalWithCallbacks` now requires `localName` and `localDeviceId` parameters
  - `process_prekey_bundle` and `message_decrypt_signal` now bind sender/recipient addresses, completing the misdirection protection introduced in v0.91.0

## [3.0.3] - 2026-04-20

### For Users

#### ✨ Highlights

- **libsignal v0.92.2** — internal refactors and dependency updates
- **libsignal_frb v2.0.2** — Rust FFI bindings (libsignal upstream bump)

#### Changed

- Update libsignal native library to v0.92.2 ([compare](https://github.com/signalapp/libsignal/compare/v0.92.1...v0.92.2))
  - Internal refactor of 1:1 messaging code
  - Key Transparency (keytrans) improvements: persist latest distinguished tree head, validate search responses
  - Upgraded `rand` crate and `rustls-webpki`
  - Note: These changes do not affect this library's public API

## [3.0.2] - 2026-04-12

### For Users

#### ✨ Highlights

- **libsignal v0.92.1** — SPQR v1 enforcement and dependency updates
- **libsignal_frb v2.0.1** — updated native dependencies

#### Changed

- Update libsignal native library to v0.92.1 ([v0.92.0](https://github.com/signalapp/libsignal/releases/tag/v0.92.0), [v0.92.1](https://github.com/signalapp/libsignal/releases/tag/v0.92.1))
  - Force use of SPQR v1 for all newly initiated sessions (v0.92.0) — fallback to non-PQR sessions is no longer allowed
  - Expose `getUploadForm()` for backup uploads (v0.92.1)
  - Note: These changes do not affect this library's public API

## [3.0.1] - 2026-04-03

#### Fixed

- Fix README examples for `SessionCipher` and `SealedSenderCipher` to match new API (added `localAddress` and all required stores)
- Fix incorrect class name `SealedSessionCipher` → `SealedSenderCipher` in README
- Fix incorrect method name `decryptPreKeySignalMessage` → `decryptPreKeyMessage` in README

## [3.0.0] - 2026-04-03

### For Users

#### ✨ Highlights

- **libsignal v0.91.0** — message encryption now includes sender/recipient addresses in MAC for misdirection protection
- **libsignal_frb v2.0.0** — Rust FFI bindings updated with new `localAddress` parameter (breaking)

#### Changed

- Update libsignal native library to v0.91.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.91.0))
  - **Breaking:** `SessionCipher` and `SealedSenderCipher` constructors now require `localAddress` parameter
  - **Breaking:** `messageEncryptWithCallbacks` and `messageDecryptPrekeyWithCallbacks` now require `localName` and `localDeviceId` parameters
  - **Breaking:** `sealedSenderDecryptWithCallbacks` now requires `localName` and `localDeviceId` parameters
  - 1:1 message encryption and decryption now includes sender/recipient addresses in the message MAC to prevent message misdirection attacks
  - Backward compatible with messages from older clients that don't include addresses

## [2.9.0] - 2026-03-29

### For Users

#### ✨ Highlights

- **libsignal v0.90.0** — `CiphertextMessage` now implements `Clone`
- **libsignal_frb v1.5.0** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.90.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.90.0))
  - `CiphertextMessage` enum now derives `Clone` (previously only `Debug`)
  - Networking improvements: authenticated WebSocket message sending, key transparency API simplification
  - Note: These changes do not affect this library's public API
- Update Flutter Rust Bridge to v2.12.0 ([fix](https://github.com/fzyzcjy/flutter_rust_bridge/pull/3010))
  - Fixes web build compatibility with wasm-bindgen >=0.2.109
  - Removed version pins for wasm-bindgen, js-sys, and web-sys

## [2.8.2] - 2026-03-25

### For Users

#### ✨ Highlights

- **libsignal v0.89.2** — dependency updates and networking improvements
- **libsignal_frb v1.4.5** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.89.2 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.89.2))
  - Updated libcrux and SPQR (post-quantum) dependencies
  - Updated rustls-webpki and tokio-util dependencies
  - Networking improvements: service-level backoff, request cancellation
  - Note: No changes to `libsignal-protocol` crate API — this library's public API is unaffected

## [2.8.1] - 2026-03-20

### For Users

#### ✨ Highlights

- **libsignal v0.89.1** — patch release with dependency updates
- **libsignal_frb v1.4.4** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.89.1 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.89.1))
  - Patch release with internal dependency updates
  - No public API changes

## [2.8.0] - 2026-03-18

### For Users

#### ✨ Highlights

- **libsignal v0.89.0** — internal improvements and updates
- **libsignal_frb v1.4.3** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.89.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.89.0))
  - Internal improvements to the FFI bridge and callback mechanisms
  - Enhanced backup/export functionalities
  - Updates to keytrans handling
  - Note: These changes do not affect this library's public API

## [2.7.2] - 2026-03-15

### For Users

#### ✨ Highlights

- **libsignal v0.88.3** — internal improvements and updates
- **libsignal_frb v1.4.2** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.88.3 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.88.3))
  - Internal changes: FFI bridge callback improvements, backup/export refactoring, keytrans updates
  - Note: These changes do not affect this library's public API

## [2.7.1] - 2026-03-07

### For Users

#### ✨ Highlights

- **libsignal v0.88.1** — internal bridge refactoring
- **libsignal_frb v1.4.1** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.88.1 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.88.1))
  - Internal refactoring: further improvements to SenderKeyStore bridge implementations
  - Note: These changes do not affect this library's public API

## [2.7.0] - 2026-03-03

### For Users

#### ✨ Highlights

- **libsignal v0.88.0** — internal bridge refactoring, no protocol changes
- **libsignal_frb v1.4.0** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.88.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.88.0))
  - Internal refactoring: consolidated SenderKeyStore bridge implementations
  - No changes to `libsignal-protocol` crate API — this library's public API is unaffected

## [2.6.0] - 2026-02-27

### For Users

#### ✨ Highlights

- **libsignal v0.87.5** — updated post-quantum cryptography dependencies
- **libsignal_frb v1.3.0** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.87.5 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.87.5))
  - Updated SPQR (SparsePostQuantumRatchet) to v1.5.0
  - Updated hpke-rs to v0.6.0 and libcrux-ml-kem to v0.0.7
  - Added `zeroize` support for HPKE Rng in signal-crypto
  - Note: These changes do not affect this library's public API

## [2.5.0] - 2026-02-21

### For Users

#### ✨ Highlights

- **libsignal v0.87.4** — updated BoringSSL and internal improvements
- **libsignal_frb v1.2.0** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.87.4 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.87.4))
  - Updated `boring` dependency to v5.0.1 (bundled BoringSSL update)
  - Added RemoteConfig for accountExists gRPC
  - keytrans: removed search-with-version fallback from `monitor_and_search`
  - Note: These changes do not affect this library's public API

## [2.4.0] - 2026-02-18

### For Users

#### ✨ Highlights

- **libsignal v0.87.2** — security hardening for Diffie-Hellman key agreements
- **libsignal_frb v1.1.0** — Rust FFI bindings

#### Security

- Update libsignal native library to v0.87.2 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.87.2))
  - Added validation of X25519 Diffie-Hellman shared secrets — rejects all-zero outputs per [RFC 7748 §6.1](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1), preventing potential use of predictable shared secrets from malicious low-order public keys
  - Enabled overflow checks for release builds
  - Updated BoringSSL to signalapp/boring v4.21.1
  - Note: No changes to this library's public API

### For Contributors

#### Changed

- Adopt copier template v2.3.2 → v2.4.0
  - Added Rust dependency caching (`Swatinem/rust-cache@v2`) in CI setup-rust action — dramatically speeds up Windows builds (~10 min OpenSSL compile cached)
  - Added Strawberry Perl configuration for Windows CI to fix OpenSSL build (MSYS2 Perl from Git Bash is incompatible)
  - Added `IPHONEOS_DEPLOYMENT_TARGET` env var for iOS CI builds — fixes linker errors when vendored C code is compiled with newer Xcode
  - Added `make check-targets` command and `scripts/check_deployment_targets.dart` for checking deployment target consistency (iOS/macOS/Android) across all project files
  - Added "Setting up Coverage Badge" and "Setting up pub.dev Publishing" sections to CONTRIBUTING.md
  - Replaced `dart run scripts/` with `dart scripts/` in Makefile commands, removing `.skip_libsignal_hook` workaround (scripts only use `dart:` imports, so `dart run` build hooks are unnecessary)
  - Fixed WASM build hook: local builds now take priority over cached/downloaded files, avoiding stale content hash mismatches

## [2.3.1] - 2026-02-11

### For Users

#### Changed

- Remove `flutter` SDK constraint from `environment` — pub.dev now displays both Dart and Flutter SDK badges ([#14](https://github.com/djx-y-z/libsignal_dart/pull/14), thanks [@ahnaineh](https://github.com/ahnaineh))

### For Contributors

#### Changed

- Adopt copier template v2.2.0 → v2.3.2
  - Publishing checklist now uses annotated tags (`git tag -a`) instead of lightweight tags
  - Added `git push origin main` step before pushing tag in publishing checklist
  - Replaced "Claude Commands" section with "Claude Skills" section in CLAUDE.md
  - Removed redundant `prepare-release` and `update-template` Claude commands (functionality covered by Claude skills)
  - Updated platform support table in README: SDK 24+, iOS 13.0+, macOS 10.15+, WASM label
  - Improved `frb-patterns` Claude skill with additional patterns:
    - Added anti-pattern example to Constructor-Style API Pattern section
    - Added Transparent Struct Pattern section
    - Added Bridging Sync Traits to Async Callbacks section with `block_on` example
    - Added Adapter Pattern documentation for bridging DartFn callbacks to upstream traits
    - Added `block_on` panics troubleshooting entry
    - Added "When to regenerate" checklist to Regenerating Bindings section
    - Added No Threading on WASM warning

#### Fixed

- Restore 100% test coverage by adding `coverage:ignore` markers to untestable platform-specific code in `platform_io.dart`
  - AOT mode library loading path (unreachable during `dart test` which runs in JIT mode)
  - `openLibraryFromPath()` function (only called with custom `libraryPath`, already ignored at call site)

## [2.3.0] - 2026-02-07

### For Users

#### ✨ Highlights

- **libsignal v0.87.1** — latest upstream native library
- **libsignal_frb v1.0.3** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.87.1 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.87.1))
  - `CallLinkRootKey` now allows variable sizing; call link epochs removed from backup
  - Test infrastructure improvements (reusable session fuzz test support)
  - Note: These changes do not affect this library's API
- Update `libsignal_frb` (Rust crate) to v1.0.3

#### Security

- Updated `bytes` dependency to v1.11.1 to address [RUSTSEC-2026-0009](https://rustsec.org/advisories/RUSTSEC-2026-0009)

### For Contributors

#### Changed

- Adopt copier template (`copier-dart-frb-wrapper`) v2.0.1 for project structure
  - Standardized scripts naming: `check_new_upstream_version.dart`, `check_exists_frb_release.dart`
  - Unified common utilities in `scripts/src/common.dart`
  - Renamed workflow: `build-libsignal-frb.yml` → `build-libsignal.yml`
  - Configurable `version_tag_prefix` for upstream version tag handling
  - Improved version normalization in `check_updates.dart` — supports configurable tag prefix instead of hardcoded `v` stripping
- Renamed `make update` → `make rust-update` to avoid ambiguity
- Refactored build hook (`hook/build.dart`)
  - Added SHA256 checksum verification for WASM downloads (supply chain security)
  - Smarter app root detection: verifies pubspec depends on this package before copying WASM files
  - WASM file caching with shared output directory (avoids redundant downloads)
  - Incremental file copy: only copies if source is newer than destination
  - Added `_crateName` constant to eliminate hardcoded `libsignal_frb` strings
  - Added `rust/Cargo.toml` as dependency for cache invalidation on local builds
  - Improved error messages with actionable guidance throughout
- Replaced copier template placeholders with dynamic values from helper scripts
  - `{{ android_min_sdk }}` → reads from `android/build.gradle` at build time
  - `{{ crate_name }}` → uses `_crateName` constant
  - `fvm install` → `fvm use` with version from `.fvmrc`
- Updated example app platform configs to use template-standard naming
  - Renamed `libsignal_example` → `example` in web, Windows, macOS, Linux, iOS configs
- Renamed Claude skill `ffi-patterns` → `frb-patterns` to match current FRB architecture
- Improved CI workflows with better step status tracking
  - Each step now reports `success=true/false` for clearer PR status
  - PR body shows inline status for each updated file
- Removed unused `GITHUB_TOKEN` from `check_updates.dart` (not needed for public GitHub API)
- Fully automated libsignal update workflow (`check-libsignal-updates.yml`)
  - Now automatically runs `cargo update` to update Cargo.lock
  - Now automatically regenerates FRB bindings via `make codegen`
  - Now automatically updates CHANGELOG.md using AI (requires `AI_MODELS_TOKEN` secret with `models:read` permission)
  - All steps are non-blocking: PR is created even if some steps fail
  - PR description shows status of each step (success/failure)
  - Labels added for failed steps (`cargo-toml-failed`, `cargo-lock-failed`, `codegen-failed`, `changelog-needed`)

#### Fixed

- Fix `workflow_run` trigger in `test.yml` — referenced wrong workflow name (`"Build libsignal Native Libraries"` → `"Build libsignal FRB Libraries"`), causing tests to never auto-trigger after build completion
- Fix env var name in `build-libsignal.yml` check-release step (`GH_TOKEN` → `GITHUB_TOKEN`) — Dart script reads `GITHUB_TOKEN`, not `GH_TOKEN`
- Fix outdated script filenames in `scripts/README.md` (`check_new_libsignal_version.dart` → `check_new_upstream_version.dart`, `check_exists_libsignal_frb_release.dart` → `check_exists_frb_release.dart`)
- Fix incorrect env var reference in `CLAUDE.md` inline comment (`GITHUB_TOKEN` → `AI_MODELS_TOKEN`)
- Upgrade `flutter_lints` in example app from `^5.0.0` to `^6.0.0`
- Fix `.pubignore` — include Rust source files in published package (only exclude `rust/target/` build artifacts, not entire `rust/` directory); add trailing newline

#### Removed

- Removed legacy scripts with project-specific naming
  - `scripts/check_new_libsignal_version.dart` → `scripts/check_new_upstream_version.dart`
  - `scripts/check_exists_libsignal_frb_release.dart` → `scripts/check_exists_frb_release.dart`
  - `scripts/src/check_new_libsignal_version.dart` → `scripts/src/check_updates.dart`
- Removed unused `scripts/combine_artifacts.dart`

#### Added

- `make check-template-updates` command to check for new copier template versions
- `check-template-updates.yml` workflow — daily CI check for template updates with automated notification PR
- `update-template` Claude skill — step-by-step guide for applying template updates
  - Documents `--defaults` flag for non-interactive `copier update` (required for Claude Code)
  - Documents manual `_commit` update in `.copier-answers.yml` when copier fails to update it (conflicts or no file changes)
- `make rust-update` command to update `rust/Cargo.lock` via `cargo update`
- `make update-changelog` command to update CHANGELOG.md using GitHub Models AI
- AI-powered changelog generation script (`scripts/update_changelog.dart`)
  - Fetches libsignal release notes from GitHub API
  - Uses GitHub Models (gpt-4o-mini) to generate appropriate changelog entry
  - Includes real examples from project's CHANGELOG in AI prompt for consistent formatting
  - Automatically inserts entry in correct CHANGELOG.md location
- Helper scripts for dynamic build configuration
  - `scripts/get_android_min_sdk.dart` — reads `minSdk` from `android/build.gradle`
  - `scripts/get_flutter_version.dart` — reads Flutter version from `.fvmrc`
- Analyzer exclusions for `hook/**`, `scripts/**`, `example/**`, `example_cli/**` (separate packages, not part of main analysis)

## [2.2.1] - 2026-02-03

### For Users

#### Fixed

- Fix native library loading for pure Dart CLI applications
  - **JIT mode** (`dart run`): loads from `.dart_tool/lib/`
  - **AOT mode** (`dart build cli`): loads from `bundle/lib/` relative to executable
  - Enables standalone executables to be distributed and run from any location

#### Security

- Remove CWD-based library search to prevent library hijacking attacks
  - Previously searched `rust/target/release/` in current working directory
  - Attacker could place malicious library in CWD to hijack application
  - Now only searches trusted paths: build hook locations and executable-relative paths

## [2.2.0] - 2026-02-03

### For Users

#### ✨ Highlights

- **libsignal v0.87.0** — latest upstream Signal Protocol library
- **libsignal_frb v1.0.2** — Rust FFI bindings

#### Changed

- Update libsignal native library to v0.87.0 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.87.0))
  - **Breaking change in upstream**: `PublicKey` ordered comparison (Ord trait) has been removed
  - New: `accountExists()` API exposed to client libraries
  - New: gRPC support for username hash lookup
  - Note: Our `PublicKey.compare()` method continues to work — now compares by serialized bytes
- Update `libsignal_frb` (Rust crate) to v1.0.2
  - Adapted `PublicKey.compare()` to use byte comparison after upstream Ord removal

#### Fixed

- Fix native library loading for pure Dart CLI applications using `dart run`
  - `DynamicLibrary.open()` doesn't resolve native asset IDs in JIT mode
  - Now reads `.dart_tool/native_assets.yaml` to get the actual library path
  - Enables `example_cli` and other CLI apps to work with published package

#### Security

- Updated `bytes` dependency to v1.11.1 to fix integer overflow vulnerability ([RUSTSEC-2026-0007](https://rustsec.org/advisories/RUSTSEC-2026-0007))

### For Contributors

#### Added

- `make update` command to update `rust/Cargo.lock` via `cargo update`
- `make update-changelog` command to update CHANGELOG.md using GitHub Models AI
- AI-powered changelog generation script (`scripts/update_changelog.dart`)
  - Fetches libsignal release notes from GitHub API
  - Uses GitHub Models (gpt-4o-mini) to generate appropriate changelog entry
  - Includes real examples from project's CHANGELOG in AI prompt for consistent formatting
  - Automatically inserts entry in correct CHANGELOG.md location

#### Changed

- Fully automated libsignal update workflow (`check-libsignal-updates.yml`)
  - Now automatically runs `cargo update` to update Cargo.lock
  - Now automatically regenerates FRB bindings via `make codegen`
  - Now automatically updates CHANGELOG.md using AI (requires `AI_MODELS_TOKEN` secret with `models:read` permission)
  - All steps are non-blocking: PR is created even if some steps fail
  - PR description shows status of each step (success/failure)
  - Labels added for failed steps (`cargo-toml-failed`, `cargo-lock-failed`, `codegen-failed`, `changelog-needed`)
  - Added checklist items for `rust/Cargo.toml` version bump and `make rust-check`
- Updated `update_changelog.dart` script to generate two Highlights entries (libsignal + libsignal_frb)
- Updated Claude skill `.claude/skills/update-libsignal/SKILL.md` with "Review Automated PR" section

## [2.1.1] - 2026-01-30

### For Users

#### Changed

- Update libsignal native library to v0.86.16 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.86.16))
  - chat: Make gRPC failures directly convertible to RequestError
  - Make E164Info and AciInfo constructors public
  - Note: These changes do not affect this library's API

## [2.1.0] - 2026-01-29

### For Users

#### ✨ Highlights

- **libsignal v0.86.15** — latest upstream Signal Protocol library

#### Added

- `SecureBytes` class for wrapping sensitive byte data with automatic zeroing on disposal
- `SecureUint8List` extension with `zeroize()` method for manual zeroing of `Uint8List`

#### Changed

- Update libsignal native library to v0.86.15 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.86.15))
  - SVR2: Updated production enclave
  - SVRB: Added new production enclave to `current` set
  - New `accountExists()` typed API
  - Backup: Support for key transparency fields
  - Note: These changes are server-side infrastructure updates, no API changes affect this library

#### Security

- Rust-side zeroing of sensitive input bytes in all `deserialize()` methods (keys, prekeys, sessions)
- Added security documentation comments to methods returning sensitive data (serialize, agree, decrypt)
- Added zeroing best practices to SECURITY.md (Section J)
- Regenerated FRB bindings to include security documentation in Dart API

### For Contributors

#### Changed

- Remove unused `source_files` from iOS podspec
  - Native assets packages don't need CocoaPods to compile Swift code
  - Libraries are loaded via `hook/build.dart`, not CocoaPods
  - See [Flutter docs](https://docs.flutter.dev/platform-integration/bind-native-code)

#### Fixed

- Fix Windows CI: download `make` and `protoc` from GitHub Releases instead of Chocolatey (CDN unreliable)

## [2.0.0] - 2026-01-24

### For Users

#### ⚠️ Breaking Changes

- **Platform requirements**: Minimum iOS raised to 13.0, macOS to 10.15
- **Architecture**: Migrated from C FFI to Flutter Rust Bridge (FRB)
  - No more `dispose()` calls needed — memory managed automatically by Rust
  - Store operations now use DartFn callbacks for async Dart-to-Rust communication

- **API Changes**:
  - `ProtocolAddress('name', 1)` → `ProtocolAddress(name: 'name', deviceId: 1)`
  - `privateKey.serialize().bytes` → `privateKey.serialize()` (returns `Uint8List` directly)
  - `publicKey.verify(message, signature)` → `publicKey.verify(message: message, signature: signature)`
  - `Fingerprint.create(...)` → `Fingerprint(iterations: ..., version: ..., ...)`
  - `Aes256GcmSiv(key)` → `Aes256GcmSiv(key: key)`
  - `cipher.encrypt/decrypt` now requires `associatedData` parameter
  - `GroupSession` class replaced with callback-based functions

#### ✨ Highlights

- **Web platform support (WASM)** — run Signal Protocol in browsers
- **Flutter Rust Bridge architecture** — cleaner API, automatic memory management
- **libsignal v0.86.14** — latest upstream Signal Protocol library
- **Modern platform support** — iOS 13.0+, macOS 10.15+ (Catalina)

#### Security

- Add low-order point validation for public keys in `PreKeyBundle` and `Fingerprint`
  - Reject non-canonical Curve25519 points that could be used in small subgroup attacks

#### Added

- **Web platform support (WASM)** — first-class browser support via wasm-pack
- Native assets build hooks (`hook/build.dart`) for automatic library download
- Precompiled binaries via GitHub Releases — no Rust required for end users
- SHA256 checksum verification for precompiled binaries

#### Changed

- Update libsignal native library to v0.86.14 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.86.14))
  - MSRV bumped to Rust 1.88
- Improve error message for unexpected ciphertext message types (now shows actual type)

#### Removed

- `SecureBytes`, `SerializationValidator`, `LibSignalException` classes
- Manual Dart wrapper classes (replaced by FRB-generated code)

### For Contributors

#### Added

- `make rust-audit` — Rust dependency vulnerability scanning
- `make setup-rust-tools` — installs cargo-audit, flutter_rust_bridge_codegen
- `make setup-protoc` — cross-platform protoc installation
- `make setup-web` — installs wasm-pack for web builds
- `make setup-android` — installs cargo-ndk for Android builds
- Rust security audit job in CI (runs `cargo-audit` on every test run)
- Plaintext handling documentation in SECURITY.md
- CI workflow for building precompiled binaries (`build-libsignal-frb.yml`)

#### Changed

- Update `.claude/skills/` documentation for FRB architecture
- Restructure `make setup` to install all required tools

#### Removed

- Old C FFI code (`lib/src/bindings/`, `rust/src/ffi/`)
- Pre-built native libraries (`bin/`, `macos/Libraries/`, `ios/Libraries/`, etc.)
- `headers/signal_ffi.h`

## [1.1.2] - 2026-01-19

### Changed

- Update libsignal native library to v0.86.12 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.86.12))
  - H2 support for unauthenticated chat (new remote config option)
  - Updated libcrux-ml-kem and spqr dependencies

## [1.1.1] - 2026-01-13

### Added

- `.claude/skills/` folder now included in repository and published package

### Changed

- Update libsignal native library to v0.86.11 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.86.11))
  - Fixes TLS proxy connectivity issue with certain TLS certificates
- Update FFI bindings to match new libsignal API:
  - KyberPreKeyStore callbacks now include `destroy` callback
  - Callback function names updated to longer namespaced format
  - Parameter types updated (`SignalConstPointer*` to `SignalMutPointer*` where applicable)

## [1.1.0] - 2026-01-08

### Added

- Add `make setup-build` command to install native build dependencies (Rust, protoc)
- Add `make setup-fvm` command (renamed from previous `make setup`)
- Restructure `make setup` to run full setup (FVM + build dependencies)
- Add "Skip Build Hook Pattern" documentation to CLAUDE.md
- Add multi-platform testing: Linux x86_64, Linux ARM64, macOS ARM64, Windows x86_64
- Add reusable test workflow (`test-reusable.yml`) to eliminate code duplication between `test.yml` and `publish.yml`

### Changed

- Replace `softprops/action-gh-release` with official `gh` CLI in CI workflows
- Update GitHub Actions to latest versions:
  - `actions/create-github-app-token` v1 → v2
  - `peter-evans/create-pull-request` v7 → v8
  - `ilammy/msvc-dev-cmd` v1 → v1.13.0
- Tests now run in parallel on all 4 platforms
- Extract test logic into reusable workflow for better maintainability
- Update libsignal native library to v0.86.10 ([release notes](https://github.com/signalapp/libsignal/releases/tag/v0.86.10))
- Simplify `check-libsignal-updates.yml` workflow:
  - Remove AI analysis (GitHub Models) - now only updates `native_version` in pubspec.yaml
  - Remove automatic FFI bindings regeneration (now manual step after merge)
  - Add clear instructions in PR body for manual steps after build completes
- Simplify `check_updates.dart` script:
  - Remove `--ai`, `--no-ai`, `--bump`, `--no-changelog` options
  - No longer updates package version or CHANGELOG.md automatically
- Remove `scripts/src/ai_analysis.dart` (no longer needed)
- Use GitHub App token instead of `GITHUB_TOKEN` in workflows:
  - `check-libsignal-updates.yml`: PR creation
  - `build-libsignal.yml`: release version checks
- Skip tests for bot PRs in `test.yml` (native libraries not yet built for version updates)
- Discard FVM config changes in CI to prevent unwanted `.fvmrc` and `.vscode/settings.json` modifications in PRs
- Extract Rust setup into reusable `.github/actions/setup-rust` action

### Fixed

- Fix duplicate "v" prefix in native library release notes (`vv0.86.10` → `v0.86.10`)
- Remove redundant "Usage" section from native library release description
- Fix ARM64 group messaging crash caused by `SignalUuid` 16-byte struct-by-value FFI limitation ([dart-lang/sdk#36730](https://github.com/dart-lang/sdk/issues/36730))
  - Pass `SignalUuid` as two `Int64` values matching ARM64 AAPCS64 register layout
  - Affects `signal_sender_key_distribution_message_create` and `signal_group_encrypt_message`
- Fix Windows native library build in CI
  - Create shell wrapper for `fvm` in `setup-fvm` action (Git Bash cannot execute `.bat` files)
  - Use PowerShell for build step to ensure MSVC `link.exe` is used instead of Git's `/usr/bin/link`
- Fix `make regen` CI failure when `cbindgen` is not pre-installed
- Fix `make regen` CI failure due to missing `protoc` (required by libsignal's spqr dependency)
- Add `protoc` to build prerequisites documentation (README.md, CLAUDE.md)

## [1.0.1] - 2026-01-02

### Added

- Added `make doc` command for local API documentation generation
- Added "Implementation Status" section to README.md with overview of wrapped native functionality
- Added pre-commit git hook for format check and static analysis (configured via `make setup`)
- Added `workflow_dispatch` trigger to test workflow (allows manual test runs from GitHub Actions)

### Changed

- Improved test coverage to 98.4%
- Added `// coverage:ignore` comments to genuinely untestable code (FFI callbacks, finalizers, defensive null checks)
- Removed unused `extractOwnedBuffer` function from `FfiHelpers`
- Refactored CI update workflow: moved AI analysis from bash to Dart script
- Simplified `check-libsignal-updates.yml` workflow (~530 → ~220 lines)
- Added `--ai`, `--no-ai`, `--ci` flags to `check_updates.dart` script
- Script now writes directly to `GITHUB_OUTPUT` in CI mode (no jq parsing needed)
- `build-libsignal.yml` workflow now skips build if release already exists (prevents unnecessary rebuilds when only package version changes)

### Fixed

- Fixed `publish.yml` workflow: use Flutter SDK (via FVM) instead of Dart SDK for publishing Flutter packages
- Added `workflow_dispatch` with dry-run option to publish workflow
- Added duplicate version check (validates against pub.dev API before publishing)
- Added `publish-dry-run` validation step before actual publishing
- Aligned publish workflow structure with liboqs_dart for consistency
- Fixed version parsing in `build-libsignal.yml` workflow (use Dart script instead of grep for reliable parsing)
- Fixed unresolved dartdoc references in `LibSignalException`, `GroupSession`, and `InMemoryIdentityKeyStore`
- Fixed `.pubignore` to include `CONTRIBUTING.md` in published package
- Fixed `.pubignore` to exclude generated `doc/` directory
- Fixed LICENSE file format for proper pub.dev recognition (added full AGPL-3.0 text with SPDX identifier)

## [1.0.0] - 2025-12-31

### Added

- Pre-built native libraries for all platforms (iOS, Android, macOS, Linux, Windows)
- **Signal Protocol**: Double Ratchet algorithm for forward secrecy and break-in recovery
- **X3DH**: Extended Triple Diffie-Hellman for asynchronous key agreement
- **Key Management**: Curve25519 key pairs (`PrivateKey`, `PublicKey`, `IdentityKeyPair`)
- **Pre-keys**: `PreKeyRecord`, `SignedPreKeyRecord`, `PreKeyBundle` for session establishment
- **Post-quantum**: Kyber key pairs (`KyberKeyPair`, `KyberPreKeyRecord`) for quantum resistance
- **Sessions**: `SessionRecord`, `ProtocolAddress` for session management
- **Messages**: `SignalMessage`, `PreKeySignalMessage` for encrypted communication
- **Sealed Sender**: Anonymous message sending (`ServerCertificate`, `SenderCertificate`)
- **Group Messaging**: SenderKey distribution (`GroupSession`, `SenderKeyRecord`, `SenderKeyDistributionMessage`)
- **Cryptographic utilities**: AES-256-GCM-SIV (`Aes256GcmSiv`), HKDF (`Hkdf`), identity fingerprints (`Fingerprint`)
- **Storage interfaces**: `SessionStore`, `IdentityKeyStore`, `PreKeyStore`, `SignedPreKeyStore`, `KyberPreKeyStore`, `SenderKeyStore`
- In-memory store implementations for testing and prototyping
- Automatic native library download via build hooks
- SHA256 verification for native library integrity
- `LibSignal.init()` for optional library pre-initialization
- Comprehensive exception handling with `SignalException`
- GitHub Actions CI/CD pipeline for automated testing and publishing
- Automated upstream version tracking with AI-powered changelog generation
- Cross-platform build scripts for native library compilation
- Example Flutter application and CLI example demonstrating all features

### Security

- Based on libsignal v0.86.11 from Signal Foundation
- Secret keys are handled securely with proper memory management
- Cryptographic operations use constant-time implementations where applicable

[Unreleased]: https://github.com/djx-y-z/libsignal_dart/compare/v7.0.2...HEAD
[7.0.2]: https://github.com/djx-y-z/libsignal_dart/compare/v7.0.1...v7.0.2
[7.0.1]: https://github.com/djx-y-z/libsignal_dart/compare/v7.0.0...v7.0.1
[7.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v6.1.1...v7.0.0
[6.1.1]: https://github.com/djx-y-z/libsignal_dart/compare/v6.1.0...v6.1.1
[6.1.0]: https://github.com/djx-y-z/libsignal_dart/compare/v6.0.0...v6.1.0
[6.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.9...v6.0.0
[5.0.9]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.8...v5.0.9
[5.0.8]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.7...v5.0.8
[5.0.7]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.6...v5.0.7
[5.0.6]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.5...v5.0.6
[5.0.5]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.4...v5.0.5
[5.0.4]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.3...v5.0.4
[5.0.3]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.2...v5.0.3
[5.0.2]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.1...v5.0.2
[5.0.1]: https://github.com/djx-y-z/libsignal_dart/compare/v5.0.0...v5.0.1
[5.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v4.0.1...v5.0.0
[4.0.1]: https://github.com/djx-y-z/libsignal_dart/compare/v4.0.0...v4.0.1
[4.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v3.0.3...v4.0.0
[3.0.3]: https://github.com/djx-y-z/libsignal_dart/compare/v3.0.2...v3.0.3
[3.0.2]: https://github.com/djx-y-z/libsignal_dart/compare/v3.0.1...v3.0.2
[3.0.1]: https://github.com/djx-y-z/libsignal_dart/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.9.0...v3.0.0
[2.9.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.8.2...v2.9.0
[2.8.2]: https://github.com/djx-y-z/libsignal_dart/compare/v2.8.1...v2.8.2
[2.8.1]: https://github.com/djx-y-z/libsignal_dart/compare/v2.8.0...v2.8.1
[2.8.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.7.2...v2.8.0
[2.7.2]: https://github.com/djx-y-z/libsignal_dart/compare/v2.7.1...v2.7.2
[2.7.1]: https://github.com/djx-y-z/libsignal_dart/compare/v2.7.0...v2.7.1
[2.7.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.3.1...v2.4.0
[2.3.1]: https://github.com/djx-y-z/libsignal_dart/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/djx-y-z/libsignal_dart/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/djx-y-z/libsignal_dart/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/djx-y-z/libsignal_dart/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/djx-y-z/libsignal_dart/compare/v1.1.2...v2.0.0
[1.1.2]: https://github.com/djx-y-z/libsignal_dart/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/djx-y-z/libsignal_dart/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/djx-y-z/libsignal_dart/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/djx-y-z/libsignal_dart/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/djx-y-z/libsignal_dart/releases/tag/v1.0.0
