# What this package binds and exposes

This file is pasted into the prompt that writes the CHANGELOG entry for an
upstream dependency bump (`make update-changelog`, and the automatic update pull
request). It is the list that entry is classified against: an upstream change
that cannot be tied to something named here gets no bullet of its own, and
giving it one turns somebody else's release notes into a list of features this
package does not have. That is the single most common way this step goes wrong.
The opposite mistake is the quieter one: a change inside a crate we bind,
dismissed because its name is not here, when an item that is here runs through
it. The map under the two bullets below is what lets the entry tie such a change
to that item.

**This file is yours, not the template's.** The template writes it once and never
overwrites it (`_skip_if_exists`), so `copier update` will not touch your edits
and there is no conflict to resolve later.

Three labels here are load-bearing, because the prompt quotes them: the
heading `## Not bound or exposed`, and the two bullet labels `Crates bound:` and
`Exposed surface:`. Keep all three verbatim — rewriting a bullet into prose
leaves the prompt's rule 2 pointing at nothing. Everything else is yours. And
prefer concrete names over categories: a model can check "does this change touch
`SignedPreKeyRecord`" and cannot check "does this change touch key management".

## Crates bound and surface exposed

This wrapper builds ONLY these upstream crates and exposes ONLY the Signal
Protocol primitives on top of them:

- Crates bound: `libsignal-protocol` and `libsignal-core`, and two more from
  the same repository that they pull in: `signal-crypto`, through
  `libsignal-protocol`, and `libsignal-debug`, through `libsignal-core`
- Exposed surface: identity, pre-, signed pre- and Kyber keys (`PrivateKey`,
  `PublicKey`, `IdentityKeyPair`, `KyberKeyPair`, `PreKeyRecord`,
  `SignedPreKeyRecord`, `KyberPreKeyRecord`, `PreKeyBundle`), with signing,
  verification and key agreement; session establishment from a bundle
  (`processPreKeyBundle`, X3DH with Kyber); Double Ratchet encrypt and decrypt
  (`SessionCipher`) and the session record (`SessionRecord`, its
  `hasUsableSenderChain` included); group messaging (SenderKey); sealed sender
  v1 and v2, with sender and server certificates; safety numbers
  (`Fingerprint`: `displayString`, `scannableEncoding`, `fingerprintCompare`);
  the messages, parsed and serialized (`SignalMessage`, `PreKeySignalMessage`,
  `SenderKeyMessage`, `SenderKeyDistributionMessage`, `PlaintextContent`,
  `DecryptionErrorMessage`, `UnidentifiedSenderMessageContent`);
  `ProtocolAddress`; and the `LibSignalErrorCode` every failed call carries,
  mapped from libsignal's error variants.

That list names what a caller calls. The calls run through far more of those
crates than it names, so a changed body in any of these files can reach this
package's users although no name above matches it. Whether one did is what its
patch shows — the same result for every input, or a different one:

- `libsignal-protocol`: `fingerprint.rs` is `Fingerprint`; the session code
  (`session.rs`, `session_management.rs` and its directory, `tahini.rs`,
  `state/session.rs`, `consts.rs`) is `SessionRecord` and every session
  operation; `double_ratchet.rs`, `triple_ratchet.rs`, `ratchet.rs` and its
  directory, `pqxdh.rs`, `handshake.rs` and `kem.rs` with its directory are
  establishment, encrypt and decrypt; `sealed_sender.rs` is sealed sender;
  `group_cipher.rs` and `sender_keys.rs` are group messaging; `crypto.rs`
  (HMAC-SHA256, AES-CTR) is under the ratchet's chain keys, group messaging and
  sealed sender; `protocol.rs` is the messages; `state/` holds the records;
  `identity_key.rs` is `IdentityKeyPair`; `proto.rs` and `proto/` are the bytes
  every parse and `serialize` reads and writes; `storage.rs` and its directory
  are the store callbacks; `error.rs` holds the variants `LibSignalErrorCode`
  maps.
- `signal-crypto`: its AES-256-CBC (`aes_cbc.rs`) is what `triple_ratchet.rs`
  and `group_cipher.rs` call to encrypt and decrypt the body of every Double
  Ratchet and every SenderKey message.
- `libsignal-core`: `curve.rs` and `curve/` are the keys, signatures and key
  agreement; `address.rs` is `ProtocolAddress`.

A file missing from this map is not thereby out of reach: the map was written
against v0.106, and upstream adds and renames files. The one file known to be
out of reach is `libsignal-protocol`'s `incremental_mac.rs`, which this package
does not bind.

One thing reaches this package's users without being named anywhere in that
list, so it needs saying explicitly: the sparse post-quantum ratchet (`spqr`,
its own repository, pulled in transitively by `libsignal-protocol`) runs
*inside* the Double Ratchet that is exposed. No symbol in `lib/` or
`rust/src/api/` mentions it, and it is not a direct dependency — but a change to
it can reach the bytes on the wire, the number of messages an epoch takes, and
whether a message is accepted at all, and
`test/protocol/spqr_ratchet_progress_test.dart` exercises it through the
ordinary encrypt/decrypt path. So an upstream change to the ratchet's
post-quantum machinery **is** user-visible here even though it satisfies neither
of the two conditions in rule 2. Treat it as in scope and say what moved.

⚠️ **"Can" is the whole word there, and this paragraph used to say "does".**
That wording cost an entry: the v0.103.0 bump (`spqr` 1.5.3 → 1.6.0) was
written up as changing the wire bytes and the epoch cadence because this file
asserted it as a standing fact, when the encoder was byte-identical across the
two tags and the real change was a security hardening — a peer could no longer
turn post-quantum ratcheting off by presenting a version the client does not
recognise. The model hedged the claim it was handed; the premise was still
wrong. **`spqr` is a different repository, so a version bump here is the only
trace it leaves in the libsignal compare the prompt is given — its contents are
never in that material.** So treat the bump as in scope and report it as the
version move it is, and make no claim about what changed inside it — not even
that the material does not say: a reader of the CHANGELOG has no material. Do
not infer the change from the bump, from the dependency's name, or from this
paragraph.

⚠️ And nothing here may tell the model to go and fetch that range. This file is
pasted into a prompt whose client sends a plain completion with **no tools at
all**, so an instruction to run a command is one it cannot follow and can only
appear to satisfy by inventing the answer — the same failure, one level up.
Reading the range by hand is the job of whoever finishes the pull request;
CLAUDE.md carries the command.

## Not bound or exposed

Treat any change here as INVISIBLE to this package's users, and never present it
as a feature or change of this package:

- networking / chat / websocket transport (`libsignal-net`)
- key transparency (keytrans)
- username services (e.g. `AuthUsernamesService`)
- zkgroup, profile keys, credentials
- SVR / secure value recovery, registration, CDSI, backups
- language bindings for Swift / Java / Node, and CLI / bridge / codegen / CI
  tooling
