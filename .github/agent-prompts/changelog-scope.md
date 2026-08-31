# What this package binds and exposes

This file is pasted into the prompt that writes the CHANGELOG entry for an
upstream dependency bump (`make update-changelog`, and the automatic update pull
request). It is the list that entry is classified against: an upstream change
that cannot be tied to something named here is invisible to this package's
users, and saying otherwise turns somebody else's release notes into a list of
features this package does not have. That is the single most common way this
step goes wrong.

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

- Crates bound: `libsignal-protocol`, `libsignal-core`, `signal-crypto`
- Exposed surface: identity / pre / signed-pre / Kyber keys, X3DH session
  establishment, Double Ratchet encrypt/decrypt, sealed sender, group messaging
  (SenderKey), and serialization of the above.

One thing reaches this package's users without being named anywhere in that
list, so it needs saying explicitly: the sparse post-quantum ratchet (`spqr`,
its own repository, pulled in transitively by `libsignal-protocol`) runs
*inside* the Double Ratchet that is exposed. No symbol in `lib/` or
`rust/src/api/` mentions it, and it is not a direct dependency — but a change to
it changes the bytes on the wire and the number of messages an epoch takes, and
`test/protocol/spqr_ratchet_progress_test.dart` exercises it through the
ordinary encrypt/decrypt path. So an upstream change to the ratchet's
post-quantum machinery **is** user-visible here even though it satisfies neither
of the two conditions in rule 2. Treat it as in scope and say what moved.

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
