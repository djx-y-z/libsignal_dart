//! Differential tests: the session bridge against libsignal's own API.
//!
//! The bridge does not call libsignal with the application's stores. Each
//! entry point loads what it needs through Dart callbacks into fresh in-memory
//! stores, calls libsignal, then reads the result back and replays the writes
//! to Dart. Every one of those steps assumes something about what libsignal
//! does inside the call — which session is current afterwards, which writes it
//! makes and when — and those are exactly what an upstream release can change
//! without changing a signature. libsignal v0.106.0 did: an archived session
//! stopped being made current again, and the bridge, which read the identity
//! to save off the current session, turned every message on an archived
//! session into `sessionNotFound`. The compiler had nothing to say, and no test
//! here produced that state.
//!
//! So this compares the bridge with libsignal itself, step by step. Each
//! operation runs twice from the same state: through the bridge's FRB entry
//! point, against stores standing in for the Dart ones, and through
//! libsignal's own function, against its reference in-memory stores. What
//! each returned, what it wrote and what the state looks like afterwards must
//! agree. libsignal's behaviour is the specification, so a release that
//! changes it moves the expectation along with it; only a bridge that no
//! longer follows fails.
//!
//! Lockstep, not two worlds side by side: the bridge draws its own randomness,
//! so two worlds would hold different keys, and libsignal settles a
//! simultaneous initiation by comparing session ids, so they could pick
//! different winners and drift apart for reasons that are not bugs. Here both
//! runs of a step start from one snapshot, so every decision that depends on
//! state is made on the same inputs, and what the bridge produced — its state
//! and its ciphertexts — carries on to the next step.
//!
//! Covered: session establishment from a bundle, encryption and decryption of
//! plain and sealed-sender messages, and four things an application does
//! between them — archiving a session, forgetting the identity it stored for
//! a peer, trusting a peer's new identity after that peer reinstalled, and
//! running out of one-time pre-keys. The application's steps change the
//! state both runs start from, so they need no libsignal counterpart:
//! libsignal is judged on what it does with the state they leave.
//!
//! That includes libsignal's last-resort Kyber replay check. The reference
//! store refuses a (Kyber pre-key, signed pre-key, base key) agreement it has
//! seen, and the Dart stores here remember theirs the same way and answer the
//! bridge's `mark_kyber_pre_key_used` with it; each step's reference store is
//! seeded with what the party's Dart store has seen.
//!
//! Deliberately not compared:
//! - The bytes of session records and ciphertexts, which depend on fresh
//!   randomness. Their observable properties are compared instead.
//! - Write order. The bridge stores the session last on purpose (see
//!   `message_decrypt_prekey_with_callbacks`); only the end state counts.
//!   `test/protocol/write_order_test.dart` pins the order instead.
//!
//! Run with `make rust-test`. Deliberately outside `api/`, which FRB codegen
//! scans.

use crate::api::bundle::PreKeyBundle as BridgeBundle;
use crate::api::error::{LibSignalErrorCode, LibSignalException};
use crate::api::sealed_sender::{
    sealed_sender_decrypt_with_callbacks, sealed_sender_encrypt_with_callbacks,
};
use crate::api::session::SessionRecord as BridgeSessionRecord;
use crate::api::session_builder::process_prekey_bundle_with_callbacks;
use crate::api::session_cipher::{
    message_decrypt_prekey_with_callbacks, message_decrypt_signal_with_callbacks,
    message_encrypt_with_callbacks,
};
use async_trait::async_trait;
use flutter_rust_bridge::DartFnFuture;
use futures::executor::block_on;
use libsignal_protocol::{
    self as up, GenericSignedPreKey as _, IdentityKeyStore, KyberPreKeyStore, PreKeyStore,
    SessionStore as _, SignedPreKeyStore as _,
};
use rand::rngs::{OsRng, StdRng};
use rand::{Rng as _, SeedableRng as _, TryRngCore as _};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{SystemTime, UNIX_EPOCH};

const ALICE: usize = 0;
const BOB: usize = 1;
const DEVICE: u32 = 1;
const SIGNED_PRE_KEY_ID: u32 = 1;

// ---------------------------------------------------------------------------
// Running the bridge
// ---------------------------------------------------------------------------

/// Drives a bridge entry point to completion.
///
/// Not `futures::executor::block_on`: the bridge calls that itself around
/// libsignal's store traits, and nesting two of them panics. Every callback
/// here resolves at once, so the future never waits and a no-op waker is
/// enough; the bound turns a future that never completes into a failure
/// rather than a hang.
fn run<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("a bridge future did not complete although every callback is ready");
}

fn ready<T: Send + 'static>(value: T) -> DartFnFuture<T> {
    Box::pin(std::future::ready(value))
}

fn code(error: up::SignalProtocolError) -> LibSignalErrorCode {
    LibSignalException::from(error).code
}

fn address(name: &str) -> up::ProtocolAddress {
    up::ProtocolAddress::new(name.to_owned(), up::DeviceId::new(DEVICE as u8).unwrap())
}

/// The writes that consume a pre-key or record trust: the ones a lost or
/// extra write would turn into a security bug rather than a stale cache.
#[derive(Clone, Debug, Default, PartialEq)]
struct Writes {
    identities_saved: Vec<Vec<u8>>,
    pre_keys_removed: Vec<u32>,
    kyber_marked: Vec<(u32, u32, Vec<u8>)>,
}

/// What a Dart application's stores hold for one party.
#[derive(Clone, Default)]
struct DartStores {
    sessions: BTreeMap<String, Vec<u8>>,
    identities: BTreeMap<String, Vec<u8>>,
    pre_keys: BTreeMap<u32, Vec<u8>>,
    signed_pre_keys: BTreeMap<u32, Vec<u8>>,
    kyber_pre_keys: BTreeMap<u32, Vec<u8>>,
    /// Every (Kyber pre-key, signed pre-key, base key) agreement marked used,
    /// which a store needs to refuse a replayed one.
    kyber_agreements_seen: BTreeSet<(u32, u32, Vec<u8>)>,
    /// What the current operation wrote; cleared before each one.
    writes: Writes,
}

type Shared = Arc<Mutex<DartStores>>;

// The callbacks, one constructor each, in the shape FRB hands them to Rust.

fn load_session(s: &Shared) -> impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static {
    let s = s.clone();
    move |name, _| ready(s.lock().unwrap().sessions.get(&name).cloned())
}

fn store_session(s: &Shared) -> impl Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static {
    let s = s.clone();
    move |name, _, record| {
        s.lock().unwrap().sessions.insert(name, record);
        ready(())
    }
}

fn save_identity(s: &Shared) -> impl Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static {
    let s = s.clone();
    move |name, _, key| {
        let mut s = s.lock().unwrap();
        s.writes.identities_saved.push(key.clone());
        s.identities.insert(name, key);
        ready(())
    }
}

fn get_identity(s: &Shared) -> impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static {
    let s = s.clone();
    move |name, _| ready(s.lock().unwrap().identities.get(&name).cloned())
}

fn load_signed_pre_key(s: &Shared) -> impl Fn(u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static {
    let s = s.clone();
    move |id| ready(s.lock().unwrap().signed_pre_keys.get(&id).cloned())
}

fn load_pre_key(s: &Shared) -> impl Fn(u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static {
    let s = s.clone();
    move |id| ready(s.lock().unwrap().pre_keys.get(&id).cloned())
}

fn remove_pre_key(s: &Shared) -> impl Fn(u32) -> DartFnFuture<()> + Send + Sync + 'static {
    let s = s.clone();
    move |id| {
        let mut s = s.lock().unwrap();
        s.writes.pre_keys_removed.push(id);
        s.pre_keys.remove(&id);
        ready(())
    }
}

fn load_kyber_pre_key(s: &Shared) -> impl Fn(u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static {
    let s = s.clone();
    move |id| ready(s.lock().unwrap().kyber_pre_keys.get(&id).cloned())
}

/// Records the call and keeps the key, as libsignal's reference store does: it
/// treats every Kyber pre-key as a last-resort one, and refuses an agreement
/// it has seen.
fn mark_kyber_pre_key_used(s: &Shared) -> impl Fn(u32, u32, Vec<u8>) -> DartFnFuture<bool> + Send + Sync + 'static {
    let s = s.clone();
    move |kyber, signed, base_key| {
        let mut s = s.lock().unwrap();
        s.writes.kyber_marked.push((kyber, signed, base_key.clone()));
        ready(s.kyber_agreements_seen.insert((kyber, signed, base_key)))
    }
}

// ---------------------------------------------------------------------------
// libsignal's reference stores, with the same writes recorded
// ---------------------------------------------------------------------------

/// A reference store whose consuming and trusting writes are recorded.
///
/// Written here rather than taken from `crate::recording_stores`, so the
/// reference side shares no code with the bridge it is judging.
struct Recorded<S> {
    inner: S,
    writes: Writes,
}

impl<S> Recorded<S> {
    fn new(inner: S) -> Self {
        Self { inner, writes: Writes::default() }
    }
}

type StoreResult<T> = Result<T, up::SignalProtocolError>;

#[async_trait(?Send)]
impl IdentityKeyStore for Recorded<up::InMemIdentityKeyStore> {
    async fn get_identity_key_pair(&self) -> StoreResult<up::IdentityKeyPair> {
        self.inner.get_identity_key_pair().await
    }

    async fn get_local_registration_id(&self) -> StoreResult<u32> {
        self.inner.get_local_registration_id().await
    }

    async fn save_identity(
        &mut self,
        address: &up::ProtocolAddress,
        identity: &up::IdentityKey,
    ) -> StoreResult<up::IdentityChange> {
        self.writes.identities_saved.push(identity.serialize().to_vec());
        self.inner.save_identity(address, identity).await
    }

    async fn is_trusted_identity(
        &self,
        address: &up::ProtocolAddress,
        identity: &up::IdentityKey,
        direction: up::Direction,
    ) -> StoreResult<bool> {
        self.inner.is_trusted_identity(address, identity, direction).await
    }

    async fn get_identity(&self, address: &up::ProtocolAddress) -> StoreResult<Option<up::IdentityKey>> {
        self.inner.get_identity(address).await
    }
}

#[async_trait(?Send)]
impl PreKeyStore for Recorded<up::InMemPreKeyStore> {
    async fn get_pre_key(&self, id: up::PreKeyId) -> StoreResult<up::PreKeyRecord> {
        self.inner.get_pre_key(id).await
    }

    async fn save_pre_key(&mut self, id: up::PreKeyId, record: &up::PreKeyRecord) -> StoreResult<()> {
        self.inner.save_pre_key(id, record).await
    }

    async fn remove_pre_key(&mut self, id: up::PreKeyId) -> StoreResult<()> {
        self.writes.pre_keys_removed.push(id.into());
        self.inner.remove_pre_key(id).await
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for Recorded<up::InMemKyberPreKeyStore> {
    async fn get_kyber_pre_key(&self, id: up::KyberPreKeyId) -> StoreResult<up::KyberPreKeyRecord> {
        self.inner.get_kyber_pre_key(id).await
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: up::KyberPreKeyId,
        record: &up::KyberPreKeyRecord,
    ) -> StoreResult<()> {
        self.inner.save_kyber_pre_key(id, record).await
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        id: up::KyberPreKeyId,
        signed: up::SignedPreKeyId,
        base_key: &up::PublicKey,
    ) -> StoreResult<()> {
        self.writes
            .kyber_marked
            .push((id.into(), signed.into(), base_key.serialize().to_vec()));
        self.inner.mark_kyber_pre_key_used(id, signed, base_key).await
    }
}

/// libsignal's reference stores, holding what one party's Dart stores hold.
struct Reference {
    sessions: up::InMemSessionStore,
    identities: Recorded<up::InMemIdentityKeyStore>,
    pre_keys: Recorded<up::InMemPreKeyStore>,
    signed_pre_keys: up::InMemSignedPreKeyStore,
    kyber_pre_keys: Recorded<up::InMemKyberPreKeyStore>,
}

impl Reference {
    fn of(party: &Party, stores: &DartStores) -> Self {
        let mut reference = Reference {
            sessions: up::InMemSessionStore::new(),
            identities: Recorded::new(up::InMemIdentityKeyStore::new(
                party.identity,
                party.registration_id,
            )),
            pre_keys: Recorded::new(up::InMemPreKeyStore::new()),
            signed_pre_keys: up::InMemSignedPreKeyStore::new(),
            kyber_pre_keys: Recorded::new(up::InMemKyberPreKeyStore::new()),
        };
        block_on(async {
            for (name, bytes) in &stores.sessions {
                let record = up::SessionRecord::deserialize(bytes).unwrap();
                reference.sessions.store_session(&address(name), &record).await.unwrap();
            }
            // Through the inner store: the seeding is not a write to compare.
            for (name, bytes) in &stores.identities {
                let key = up::IdentityKey::new(up::PublicKey::deserialize(bytes).unwrap());
                reference.identities.inner.save_identity(&address(name), &key).await.unwrap();
            }
            for (id, bytes) in &stores.pre_keys {
                let record = up::PreKeyRecord::deserialize(bytes).unwrap();
                reference.pre_keys.inner.save_pre_key((*id).into(), &record).await.unwrap();
            }
            for (id, bytes) in &stores.signed_pre_keys {
                let record = up::SignedPreKeyRecord::deserialize(bytes).unwrap();
                reference.signed_pre_keys.save_signed_pre_key((*id).into(), &record).await.unwrap();
            }
            for (id, bytes) in &stores.kyber_pre_keys {
                let record = up::KyberPreKeyRecord::deserialize(bytes).unwrap();
                reference.kyber_pre_keys.inner.save_kyber_pre_key((*id).into(), &record).await.unwrap();
            }
            for (kyber, signed, base_key) in &stores.kyber_agreements_seen {
                let base_key = up::PublicKey::deserialize(base_key).unwrap();
                reference
                    .kyber_pre_keys
                    .inner
                    .mark_kyber_pre_key_used((*kyber).into(), (*signed).into(), &base_key)
                    .await
                    .unwrap();
            }
        });
        reference
    }

    fn writes(&self) -> Writes {
        Writes {
            identities_saved: self.identities.writes.identities_saved.clone(),
            pre_keys_removed: self.pre_keys.writes.pre_keys_removed.clone(),
            kyber_marked: self.kyber_pre_keys.writes.kyber_marked.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// The parties
// ---------------------------------------------------------------------------

struct Party {
    name: String,
    registration_id: u32,
    identity: up::IdentityKeyPair,
    signed_pre_key: up::KeyPair,
    signed_pre_key_signature: Vec<u8>,
    stores: Shared,
    next_pre_key_id: u32,
    /// Whether its bundles still carry a one-time pre-key; see
    /// [Op::RunOutOfOneTimePreKeys].
    one_time_pre_keys_left: bool,
}

impl Party {
    fn new(name: &str, registration_id: u32) -> Self {
        let mut rng = OsRng.unwrap_err();
        let identity = up::IdentityKeyPair::generate(&mut rng);
        let signed_pre_key = up::KeyPair::generate(&mut rng);
        let signed_pre_key_signature = identity
            .private_key()
            .calculate_signature(&signed_pre_key.public_key.serialize(), &mut rng)
            .unwrap()
            .to_vec();
        let record = up::SignedPreKeyRecord::new(
            SIGNED_PRE_KEY_ID.into(),
            up::Timestamp::from_epoch_millis(0),
            &signed_pre_key,
            &signed_pre_key_signature,
        );
        let mut stores = DartStores::default();
        stores.signed_pre_keys.insert(SIGNED_PRE_KEY_ID, record.serialize().unwrap());
        Party {
            name: name.to_owned(),
            registration_id,
            identity,
            signed_pre_key,
            signed_pre_key_signature,
            stores: Arc::new(Mutex::new(stores)),
            next_pre_key_id: 100,
            one_time_pre_keys_left: true,
        }
    }

    fn identity_key(&self) -> Vec<u8> {
        self.identity.identity_key().serialize().to_vec()
    }

    /// Publishes a bundle with a fresh one-time pre-key and a fresh Kyber
    /// pre-key, both stored before it is handed out, as a client that
    /// replenishes the server does. Once the party has run out of one-time
    /// pre-keys the bundle carries none.
    fn publish_bundle(&mut self) -> (BridgeBundle, up::PreKeyBundle) {
        let mut rng = OsRng.unwrap_err();
        let id = self.next_pre_key_id;
        self.next_pre_key_id += 1;
        let one_time = self.one_time_pre_keys_left.then(|| up::KeyPair::generate(&mut rng));
        let kyber = up::kem::KeyPair::generate(up::kem::KeyType::Kyber1024, &mut rng);
        let kyber_signature = self
            .identity
            .private_key()
            .calculate_signature(&kyber.public_key.serialize(), &mut rng)
            .unwrap()
            .to_vec();
        {
            let mut s = self.stores.lock().unwrap();
            if let Some(one_time) = &one_time {
                s.pre_keys
                    .insert(id, up::PreKeyRecord::new(id.into(), one_time).serialize().unwrap());
            }
            let kyber_record = up::KyberPreKeyRecord::new(
                id.into(),
                up::Timestamp::from_epoch_millis(0),
                &kyber,
                &kyber_signature,
            );
            s.kyber_pre_keys.insert(id, kyber_record.serialize().unwrap());
        }
        let bridge = BridgeBundle::new(
            self.registration_id,
            DEVICE,
            one_time.is_some().then_some(id),
            one_time.as_ref().map(|key| key.public_key.serialize().to_vec()),
            SIGNED_PRE_KEY_ID,
            self.signed_pre_key.public_key.serialize().to_vec(),
            self.signed_pre_key_signature.clone(),
            self.identity_key(),
            id,
            kyber.public_key.serialize().to_vec(),
            kyber_signature.clone(),
        )
        .unwrap();
        let reference = up::PreKeyBundle::new(
            self.registration_id,
            up::DeviceId::new(DEVICE as u8).unwrap(),
            one_time.map(|key| (id.into(), key.public_key)),
            SIGNED_PRE_KEY_ID.into(),
            self.signed_pre_key.public_key,
            self.signed_pre_key_signature.clone(),
            id.into(),
            kyber.public_key.clone(),
            kyber_signature,
            *self.identity.identity_key(),
        )
        .unwrap();
        (bridge, reference)
    }
}

/// The server's half of sealed sender: a trust root, the server certificate it
/// signs, and the key that signs each party's sender certificate.
struct Trust {
    root: up::KeyPair,
    server: up::ServerCertificate,
    server_key: up::KeyPair,
}

impl Trust {
    fn new() -> Self {
        let mut rng = OsRng.unwrap_err();
        let root = up::KeyPair::generate(&mut rng);
        let server_key = up::KeyPair::generate(&mut rng);
        let server =
            up::ServerCertificate::new(1, server_key.public_key, &root.private_key, &mut rng).unwrap();
        Trust { root, server, server_key }
    }

    /// A day's sender certificate for the party's current identity, which a
    /// reinstall replaces.
    fn certificate(&self, party: &Party) -> up::SenderCertificate {
        up::SenderCertificate::new(
            party.name.clone(),
            None,
            *party.identity.public_key(),
            up::DeviceId::new(DEVICE as u8).unwrap(),
            up::Timestamp::from_epoch_millis(now_millis() + 86_400_000),
            self.server.clone(),
            &self.server_key.private_key,
            &mut OsRng.unwrap_err(),
        )
        .unwrap()
    }
}

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

// ---------------------------------------------------------------------------
// What is compared
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum Outcome {
    Done,
    Encrypted { pre_key_message: bool },
    /// A sealed-sender message, whose inner type the envelope hides.
    Sealed,
    Decrypted(Vec<u8>),
    Failed(LibSignalErrorCode),
}

/// What can be observed of a session record without reading its bytes.
#[derive(Debug, PartialEq)]
struct SessionView {
    usable_sender_chain: Result<bool, LibSignalErrorCode>,
    archived_sessions: usize,
    version: Result<u32, LibSignalErrorCode>,
    local_registration_id: Result<u32, LibSignalErrorCode>,
    remote_registration_id: Result<u32, LibSignalErrorCode>,
    remote_identity: Result<Option<Vec<u8>>, LibSignalErrorCode>,
    /// The current session's id, its base key. Left out after a fetch, which
    /// draws a fresh one on each side.
    current_session: Option<Result<Vec<u8>, LibSignalErrorCode>>,
}

impl SessionView {
    fn of(record: &up::SessionRecord, with_session_id: bool) -> Self {
        SessionView {
            usable_sender_chain: record
                .has_usable_sender_chain(SystemTime::now(), up::SessionUsabilityRequirements::empty())
                .map_err(code),
            archived_sessions: record.archived_session_count(),
            version: record.session_version().map_err(code),
            local_registration_id: record.local_registration_id().map_err(code),
            remote_registration_id: record.remote_registration_id().map_err(code),
            remote_identity: record.remote_identity_key_bytes().map_err(code),
            current_session: with_session_id
                .then(|| record.alice_base_key().map(<[u8]>::to_vec).map_err(code)),
        }
    }
}

/// One party's state as it concerns its peer.
#[derive(Debug, PartialEq)]
struct PartyView {
    session_with_peer: Option<SessionView>,
    identity_of_peer: Option<Vec<u8>>,
    pre_keys: Vec<u32>,
}

// ---------------------------------------------------------------------------
// A conversation
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Op {
    /// `.0` fetches `.1`'s bundle and starts a session with it.
    Fetch(usize, usize),
    /// `.0` encrypts a new message to `.1`; it is in flight until delivered.
    Send(usize, usize),
    /// The `.2`-th message `.0` sent to `.1` arrives, again if it already did.
    Deliver(usize, usize, usize),
    /// `.0` archives its current session with `.1`, as an application does on
    /// a session reset. The bridge's own `SessionRecord` does it.
    Archive(usize, usize),
    /// `.0` seals a new message to `.1` with sealed sender; it is in flight
    /// until delivered.
    SealedSend(usize, usize),
    /// `.0`'s application deletes the identity it stored for `.1`, as one that
    /// lost or cleared its trust store does.
    Forget(usize, usize),
    /// `.0` reinstalls: a new identity, new keys, nothing stored. What it sent
    /// is still in flight, and so is what was sent to it.
    Reinstall(usize),
    /// `.0`'s application trusts `.1`'s current identity in place of the one
    /// it stored — the user accepted a changed safety number.
    Retrust(usize, usize),
    /// `.0` has no one-time pre-keys left, so its bundles from now on carry
    /// only the signed pre-key and a Kyber pre-key — which is also what a
    /// server can choose to hand out.
    RunOutOfOneTimePreKeys(usize),
}

#[derive(Clone)]
struct InFlight {
    pre_key_message: bool,
    sealed: bool,
    bytes: Vec<u8>,
    plaintext: Vec<u8>,
    delivered: bool,
}

struct Conversation {
    label: String,
    parties: [Party; 2],
    trust: Trust,
    sent: BTreeMap<(usize, usize), Vec<InFlight>>,
    script: Vec<String>,
    reached: Reached,
}

impl Conversation {
    fn new(label: &str) -> Self {
        Conversation {
            label: label.to_owned(),
            parties: [Party::new("alice", 1111), Party::new("bob", 2222)],
            trust: Trust::new(),
            sent: BTreeMap::new(),
            script: Vec::new(),
            reached: Reached::default(),
        }
    }

    fn sent(&self, from: usize, to: usize) -> &[InFlight] {
        self.sent.get(&(from, to)).map_or(&[], Vec::as_slice)
    }

    /// Fetch, a message, and an answer on the same session: both sides then
    /// hold it as their current, acknowledged session.
    fn establish(&mut self, initiator: usize, responder: usize) {
        self.apply(Op::Fetch(initiator, responder));
        self.apply(Op::Send(initiator, responder));
        self.deliver_last(initiator, responder);
        self.apply(Op::Send(responder, initiator));
        self.deliver_last(responder, initiator);
    }

    fn deliver_last(&mut self, from: usize, to: usize) {
        let last = self.sent(from, to).len().checked_sub(1).expect("nothing was sent");
        self.apply(Op::Deliver(from, to, last));
    }

    fn apply(&mut self, op: Op) {
        self.script.push(format!("{op:?}"));
        match op {
            Op::Fetch(from, to) => {
                let (bridge_bundle, reference_bundle) = self.parties[to].publish_bundle();
                let (snapshot, mut reference) = self.begin(from);
                let (p, peer) = (&self.parties[from], &self.parties[to]);
                let bridge = run(process_prekey_bundle_with_callbacks(
                    peer.name.clone(),
                    DEVICE,
                    p.name.clone(),
                    DEVICE,
                    &bridge_bundle,
                    load_session(&p.stores),
                    store_session(&p.stores),
                    identity_key_pair(p),
                    registration_id(p),
                    save_identity(&p.stores),
                    get_identity(&p.stores),
                ));
                let upstream = block_on(up::process_prekey_bundle(
                    &address(&peer.name),
                    &address(&p.name),
                    &mut reference.sessions,
                    &mut reference.identities,
                    &reference_bundle,
                    SystemTime::now(),
                    &mut OsRng.unwrap_err(),
                ));
                self.compare(
                    from,
                    to,
                    bridge.map_or_else(|e| Outcome::Failed(e.code), |()| Outcome::Done),
                    upstream.map_or_else(|e| Outcome::Failed(code(e)), |()| Outcome::Done),
                    &snapshot,
                    &reference,
                    false,
                );
            }
            Op::Send(from, to) => {
                let plaintext = format!("message {} from {}", self.script.len(), self.parties[from].name);
                let plaintext = plaintext.into_bytes();
                let (snapshot, mut reference) = self.begin(from);
                let (p, peer) = (&self.parties[from], &self.parties[to]);
                let bridge = run(message_encrypt_with_callbacks(
                    peer.name.clone(),
                    DEVICE,
                    p.name.clone(),
                    DEVICE,
                    plaintext.clone(),
                    load_session(&p.stores),
                    store_session(&p.stores),
                    identity_key_pair(p),
                    registration_id(p),
                    save_identity(&p.stores),
                    get_identity(&p.stores),
                ));
                let upstream = block_on(up::message_encrypt(
                    &plaintext,
                    &address(&peer.name),
                    &address(&p.name),
                    &mut reference.sessions,
                    &mut reference.identities,
                    SystemTime::now(),
                    &mut OsRng.unwrap_err(),
                ));
                self.compare(
                    from,
                    to,
                    match &bridge {
                        Ok(result) => Outcome::Encrypted { pre_key_message: result.message_type == 3 },
                        Err(e) => Outcome::Failed(e.code),
                    },
                    match upstream {
                        Ok(message) => Outcome::Encrypted {
                            pre_key_message: message.message_type() == up::CiphertextMessageType::PreKey,
                        },
                        Err(e) => Outcome::Failed(code(e)),
                    },
                    &snapshot,
                    &reference,
                    true,
                );
                if let Ok(result) = bridge {
                    self.sent.entry((from, to)).or_default().push(InFlight {
                        pre_key_message: result.message_type == 3,
                        sealed: false,
                        bytes: result.ciphertext,
                        plaintext,
                        delivered: false,
                    });
                }
            }
            Op::SealedSend(from, to) => {
                let plaintext =
                    format!("sealed message {} from {}", self.script.len(), self.parties[from].name);
                let plaintext = plaintext.into_bytes();
                let (snapshot, mut reference) = self.begin(from);
                let (p, peer) = (&self.parties[from], &self.parties[to]);
                let certificate = self.trust.certificate(p);
                let bridge = run(sealed_sender_encrypt_with_callbacks(
                    peer.name.clone(),
                    DEVICE,
                    plaintext.clone(),
                    certificate.serialized().unwrap().to_vec(),
                    load_session(&p.stores),
                    store_session(&p.stores),
                    identity_key_pair(p),
                    registration_id(p),
                    save_identity(&p.stores),
                    get_identity(&p.stores),
                ));
                let upstream = block_on(up::sealed_sender_encrypt(
                    &address(&peer.name),
                    &certificate,
                    &plaintext,
                    &mut reference.sessions,
                    &mut reference.identities,
                    SystemTime::now(),
                    &mut OsRng.unwrap_err(),
                ));
                self.compare(
                    from,
                    to,
                    match &bridge {
                        Ok(_) => Outcome::Sealed,
                        Err(e) => Outcome::Failed(e.code),
                    },
                    upstream.map_or_else(|e| Outcome::Failed(code(e)), |_| Outcome::Sealed),
                    &snapshot,
                    &reference,
                    true,
                );
                if let Ok(result) = bridge {
                    self.sent.entry((from, to)).or_default().push(InFlight {
                        pre_key_message: false,
                        sealed: true,
                        bytes: result.ciphertext,
                        plaintext,
                        delivered: false,
                    });
                }
            }
            Op::Deliver(from, to, index) => {
                let message = self.sent(from, to)[index].clone();
                let (snapshot, mut reference) = self.begin(to);
                let (p, peer) = (&self.parties[to], &self.parties[from]);
                let bridge = if message.sealed {
                    run(sealed_sender_decrypt_with_callbacks(
                        message.bytes.clone(),
                        self.trust.root.public_key.serialize().to_vec(),
                        now_millis(),
                        p.name.clone(),
                        DEVICE,
                        load_session(&p.stores),
                        store_session(&p.stores),
                        identity_key_pair(p),
                        registration_id(p),
                        save_identity(&p.stores),
                        load_signed_pre_key(&p.stores),
                        load_pre_key(&p.stores),
                        remove_pre_key(&p.stores),
                        load_kyber_pre_key(&p.stores),
                        mark_kyber_pre_key_used(&p.stores),
                        get_identity(&p.stores),
                    ))
                    .map(|result| result.plaintext)
                } else if message.pre_key_message {
                    run(message_decrypt_prekey_with_callbacks(
                        peer.name.clone(),
                        DEVICE,
                        p.name.clone(),
                        DEVICE,
                        message.bytes.clone(),
                        load_session(&p.stores),
                        store_session(&p.stores),
                        identity_key_pair(p),
                        registration_id(p),
                        save_identity(&p.stores),
                        load_signed_pre_key(&p.stores),
                        load_pre_key(&p.stores),
                        remove_pre_key(&p.stores),
                        load_kyber_pre_key(&p.stores),
                        mark_kyber_pre_key_used(&p.stores),
                        get_identity(&p.stores),
                    ))
                } else {
                    run(message_decrypt_signal_with_callbacks(
                        peer.name.clone(),
                        DEVICE,
                        p.name.clone(),
                        DEVICE,
                        message.bytes.clone(),
                        load_session(&p.stores),
                        store_session(&p.stores),
                        identity_key_pair(p),
                        registration_id(p),
                        save_identity(&p.stores),
                        get_identity(&p.stores),
                    ))
                };
                let upstream = if message.sealed {
                    block_on(up::sealed_sender_decrypt(
                        &message.bytes,
                        &self.trust.root.public_key,
                        up::Timestamp::from_epoch_millis(now_millis()),
                        None,
                        p.name.clone(),
                        up::DeviceId::new(DEVICE as u8).unwrap(),
                        &mut reference.identities,
                        &mut reference.sessions,
                        &mut reference.pre_keys,
                        &reference.signed_pre_keys,
                        &mut reference.kyber_pre_keys,
                    ))
                    .map(|result| result.message)
                } else {
                    let ciphertext = if message.pre_key_message {
                        up::CiphertextMessage::PreKeySignalMessage(
                            up::PreKeySignalMessage::try_from(&message.bytes[..]).unwrap(),
                        )
                    } else {
                        up::CiphertextMessage::SignalMessage(
                            up::SignalMessage::try_from(&message.bytes[..]).unwrap(),
                        )
                    };
                    block_on(up::message_decrypt(
                        &ciphertext,
                        &address(&peer.name),
                        &address(&p.name),
                        &mut reference.sessions,
                        &mut reference.identities,
                        &mut reference.pre_keys,
                        &reference.signed_pre_keys,
                        &mut reference.kyber_pre_keys,
                        &mut OsRng.unwrap_err(),
                    ))
                };
                if let Ok(plaintext) = &upstream {
                    assert_eq!(plaintext, &message.plaintext, "[{}] upstream decrypted another message", self.label);
                }
                if message.sealed && upstream.is_ok() {
                    self.reached.sealed_decrypted += 1;
                }
                self.compare(
                    to,
                    from,
                    bridge.map_or_else(|e| Outcome::Failed(e.code), Outcome::Decrypted),
                    upstream.map_or_else(|e| Outcome::Failed(code(e)), Outcome::Decrypted),
                    &snapshot,
                    &reference,
                    true,
                );
                self.sent.get_mut(&(from, to)).unwrap()[index].delivered = true;
            }
            Op::Archive(who, peer) => {
                let mut s = self.parties[who].stores.lock().unwrap();
                let name = self.parties[peer].name.clone();
                if let Some(bytes) = s.sessions.get(&name) {
                    let mut record = BridgeSessionRecord::deserialize(bytes.clone()).unwrap();
                    record.archive_current_state().unwrap();
                    s.sessions.insert(name, record.serialize().unwrap());
                }
            }
            Op::Forget(who, peer) => {
                let name = self.parties[peer].name.clone();
                self.parties[who].stores.lock().unwrap().identities.remove(&name);
            }
            Op::Reinstall(who) => {
                let (name, registration_id) =
                    (self.parties[who].name.clone(), self.parties[who].registration_id + 1);
                self.parties[who] = Party::new(&name, registration_id);
            }
            Op::Retrust(who, peer) => {
                let (name, key) = (self.parties[peer].name.clone(), self.parties[peer].identity_key());
                self.parties[who].stores.lock().unwrap().identities.insert(name, key);
            }
            Op::RunOutOfOneTimePreKeys(who) => self.parties[who].one_time_pre_keys_left = false,
        }
    }

    /// Clears the party's write log, snapshots its stores, and builds
    /// libsignal's reference stores from the snapshot.
    fn begin(&self, party: usize) -> (DartStores, Reference) {
        let snapshot = {
            let mut s = self.parties[party].stores.lock().unwrap();
            s.writes = Writes::default();
            s.clone()
        };
        let reference = Reference::of(&self.parties[party], &snapshot);
        (snapshot, reference)
    }

    /// Compares one step's two runs: the outcome, the consuming and trusting
    /// writes, and the state they leave. [session_id] says whether the current
    /// session's id is comparable, which it is not after a fetch: each side
    /// draws a fresh one.
    #[allow(clippy::too_many_arguments)]
    fn compare(
        &mut self,
        party: usize,
        peer: usize,
        bridge: Outcome,
        upstream: Outcome,
        snapshot: &DartStores,
        reference: &Reference,
        session_id: bool,
    ) {
        let context = || {
            format!(
                "[{}] at step {} ({}); the script so far:\n  {}",
                self.label,
                self.script.len(),
                self.script.last().unwrap(),
                self.script.join(", ")
            )
        };
        assert_eq!(bridge, upstream, "the outcome differs from libsignal's {}", context());

        let (p, peer) = (&self.parties[party], &self.parties[peer]);
        let bridge_writes = p.stores.lock().unwrap().writes.clone();
        let upstream_writes = reference.writes();
        assert_eq!(bridge_writes, upstream_writes, "the writes differ from libsignal's {}", context());

        let bridge_view = {
            let s = p.stores.lock().unwrap();
            PartyView {
                session_with_peer: s.sessions.get(&peer.name).map(|bytes| {
                    SessionView::of(&up::SessionRecord::deserialize(bytes).unwrap(), session_id)
                }),
                identity_of_peer: s.identities.get(&peer.name).cloned(),
                pre_keys: s.pre_keys.keys().copied().collect(),
            }
        };
        let upstream_view = PartyView {
            session_with_peer: block_on(reference.sessions.load_session(&address(&peer.name)))
                .unwrap()
                .map(|record| SessionView::of(&record, session_id)),
            identity_of_peer: block_on(reference.identities.get_identity(&address(&peer.name)))
                .unwrap()
                .map(|key| key.serialize().to_vec()),
            pre_keys: snapshot
                .pre_keys
                .keys()
                .copied()
                .filter(|id| !upstream_writes.pre_keys_removed.contains(id))
                .collect(),
        };
        assert_eq!(bridge_view, upstream_view, "the state differs from libsignal's {}", context());

        // An encryption that stored the identity again after the application
        // had forgotten it: the write the bridge used to drop.
        if matches!(bridge, Outcome::Encrypted { .. } | Outcome::Sealed)
            && !snapshot.identities.contains_key(&peer.name)
            && !bridge_writes.identities_saved.is_empty()
        {
            self.reached.identity_restored_on_encrypt += 1;
        }
        match &bridge {
            Outcome::Decrypted(_) => {
                self.reached.decrypted += 1;
                if bridge_view
                    .session_with_peer
                    .as_ref()
                    .is_some_and(|view| view.remote_registration_id.is_err())
                {
                    self.reached.decrypted_leaving_no_current_session += 1;
                }
            }
            Outcome::Failed(code) => *self.reached.failures.entry(format!("{code:?}")).or_default() += 1,
            _ => {}
        }
    }
}

/// What a script reached, so the random one can show it still reaches the
/// states it exists for.
#[derive(Default)]
struct Reached {
    decrypted: usize,
    /// Decrypted, and the record came out with no current session: the state
    /// v0.106.0 introduced, after an application's archive or libsignal's own.
    decrypted_leaving_no_current_session: usize,
    sealed_decrypted: usize,
    identity_restored_on_encrypt: usize,
    failures: BTreeMap<String, usize>,
}

fn identity_key_pair(p: &Party) -> impl Fn() -> DartFnFuture<Vec<u8>> + Send + Sync + 'static {
    let bytes = p.identity.serialize().to_vec();
    move || ready(bytes.clone())
}

fn registration_id(p: &Party) -> impl Fn() -> DartFnFuture<u32> + Send + Sync + 'static {
    let id = p.registration_id;
    move || ready(id)
}

// ---------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------

/// The first #125 failure: the recipient archived the session, the sender did
/// not know and kept using it.
#[test]
fn a_message_on_a_session_the_recipient_archived() {
    let mut c = Conversation::new("archived by the recipient");
    c.establish(ALICE, BOB);
    c.apply(Op::Archive(BOB, ALICE));
    c.apply(Op::Send(ALICE, BOB));
    c.deliver_last(ALICE, BOB);
    c.apply(Op::Send(BOB, ALICE));
    c.apply(Op::Fetch(BOB, ALICE));
    c.apply(Op::Send(BOB, ALICE));
    c.deliver_last(BOB, ALICE);
}

/// The second: Bob starts a second session that never reaches Alice, who keeps
/// sending on the first, until libsignal archives Bob's current session to
/// break the back-and-forth.
#[test]
fn a_conversation_that_keeps_switching_sessions() {
    let mut c = Conversation::new("switching sessions");
    c.establish(ALICE, BOB);
    c.apply(Op::Fetch(BOB, ALICE));
    for _ in 0..10 {
        c.apply(Op::Send(BOB, ALICE));
        c.apply(Op::Send(ALICE, BOB));
        c.deliver_last(ALICE, BOB);
    }
    c.apply(Op::Fetch(BOB, ALICE));
    c.apply(Op::Send(BOB, ALICE));
    c.deliver_last(BOB, ALICE);
    c.apply(Op::Send(ALICE, BOB));
    c.deliver_last(ALICE, BOB);
}

/// Both sides start a session at once; libsignal's tiebreak decides which one
/// each side keeps current.
#[test]
fn both_sides_start_a_session_at_once() {
    let mut c = Conversation::new("simultaneous initiation");
    c.apply(Op::Fetch(ALICE, BOB));
    c.apply(Op::Fetch(BOB, ALICE));
    c.apply(Op::Send(ALICE, BOB));
    c.apply(Op::Send(BOB, ALICE));
    c.deliver_last(ALICE, BOB);
    c.deliver_last(BOB, ALICE);
    for _ in 0..3 {
        c.apply(Op::Send(ALICE, BOB));
        c.deliver_last(ALICE, BOB);
        c.apply(Op::Send(BOB, ALICE));
        c.deliver_last(BOB, ALICE);
    }
}

/// A pre-key message delivered twice, and messages out of order.
#[test]
fn redelivery_and_reordering() {
    let mut c = Conversation::new("redelivery and reordering");
    c.apply(Op::Fetch(ALICE, BOB));
    for _ in 0..4 {
        c.apply(Op::Send(ALICE, BOB));
    }
    c.apply(Op::Deliver(ALICE, BOB, 2));
    c.apply(Op::Deliver(ALICE, BOB, 2));
    c.apply(Op::Deliver(ALICE, BOB, 0));
    c.apply(Op::Deliver(ALICE, BOB, 3));
    c.apply(Op::Send(BOB, ALICE));
    c.deliver_last(BOB, ALICE);
    c.apply(Op::Deliver(ALICE, BOB, 1));
    c.apply(Op::Deliver(ALICE, BOB, 1));
}

/// The identity the application forgot is stored again by the next message
/// out, plain or sealed: libsignal saves the identity it has just checked.
#[test]
fn an_identity_the_application_forgot_is_stored_again_on_encrypt() {
    let mut c = Conversation::new("forgotten identity");
    c.establish(ALICE, BOB);
    c.apply(Op::Forget(ALICE, BOB));
    c.apply(Op::Send(ALICE, BOB));
    c.deliver_last(ALICE, BOB);
    c.apply(Op::Forget(ALICE, BOB));
    c.apply(Op::SealedSend(ALICE, BOB));
    c.deliver_last(ALICE, BOB);
    assert_eq!(c.reached.identity_restored_on_encrypt, 2, "an encryption did not store the identity again");
}

/// Bob reinstalls: his new identity is refused by Alice, from his messages and
/// from his bundle alike, until her application trusts it.
#[test]
fn a_peer_that_reinstalls_is_refused_until_trusted_again() {
    let mut c = Conversation::new("reinstall");
    c.establish(ALICE, BOB);
    c.apply(Op::Reinstall(BOB));
    c.apply(Op::Send(ALICE, BOB));
    c.deliver_last(ALICE, BOB);
    c.apply(Op::Fetch(BOB, ALICE));
    c.apply(Op::Send(BOB, ALICE));
    c.deliver_last(BOB, ALICE);
    c.apply(Op::Fetch(ALICE, BOB));
    assert_eq!(
        c.reached.failures.get("UntrustedIdentity").copied(),
        Some(2),
        "the new identity was not refused from both the message and the bundle"
    );
    c.apply(Op::Retrust(ALICE, BOB));
    c.deliver_last(BOB, ALICE);
    c.apply(Op::Send(ALICE, BOB));
    c.deliver_last(ALICE, BOB);
    c.apply(Op::SealedSend(BOB, ALICE));
    c.deliver_last(BOB, ALICE);
    c.apply(Op::Fetch(ALICE, BOB));
    c.apply(Op::Send(ALICE, BOB));
    c.deliver_last(ALICE, BOB);
}

/// Sealed sender both ways: a pre-key message inside the envelope, delivery out
/// of order and twice, and a message on a session the recipient archived.
#[test]
fn sealed_sender_messages() {
    let mut c = Conversation::new("sealed sender");
    c.apply(Op::Fetch(ALICE, BOB));
    c.apply(Op::SealedSend(ALICE, BOB));
    c.apply(Op::SealedSend(ALICE, BOB));
    c.deliver_last(ALICE, BOB);
    c.apply(Op::Deliver(ALICE, BOB, 0));
    c.apply(Op::Deliver(ALICE, BOB, 0));
    c.apply(Op::SealedSend(BOB, ALICE));
    c.deliver_last(BOB, ALICE);
    c.apply(Op::Archive(BOB, ALICE));
    c.apply(Op::SealedSend(ALICE, BOB));
    c.deliver_last(ALICE, BOB);
    c.apply(Op::SealedSend(BOB, ALICE));
    assert!(c.reached.sealed_decrypted >= 4, "too few sealed messages decrypted");
}

/// The replay a last-resort Kyber key is exposed to. Bob has no one-time
/// pre-keys left, so Alice's first messages carry none, and once their session
/// has left Bob's record — three newer archived sessions push it out since
/// v0.106.0 — each would build that session all over again. libsignal's
/// reference store refuses the repeated agreement before anything is written,
/// and the bridge has to as well, plain and sealed.
#[test]
fn a_replayed_pre_key_message_without_a_one_time_pre_key() {
    let mut c = Conversation::new("replayed last-resort agreement");
    c.apply(Op::RunOutOfOneTimePreKeys(BOB));
    c.apply(Op::Fetch(ALICE, BOB));
    // Two pre-key messages on Alice's new session, one of them sealed.
    c.apply(Op::Send(ALICE, BOB));
    c.apply(Op::SealedSend(ALICE, BOB));
    c.apply(Op::Deliver(ALICE, BOB, 0));
    c.apply(Op::Deliver(ALICE, BOB, 1));
    for _ in 0..4 {
        c.apply(Op::Fetch(BOB, ALICE));
    }
    c.apply(Op::Deliver(ALICE, BOB, 0));
    c.apply(Op::Deliver(ALICE, BOB, 1));
    assert_eq!(
        c.reached.failures.get("InvalidMessage").copied(),
        Some(2),
        "the replayed agreements were not both refused"
    );
}

/// Random scripts: messages plain and sealed, delivered in order, out of order,
/// twice or never; sessions archived and started over by either side; an
/// identity forgotten, a party reinstalling, its new identity trusted again.
#[test]
fn seeded_random_conversations() {
    const SEEDS: u64 = 40;
    const STEPS: usize = 60;
    let mut reached = Reached::default();
    for seed in 0..SEEDS {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut c = Conversation::new(&format!("seed {seed}"));
        for _ in 0..STEPS {
            let from = rng.random_range(0..2);
            let to = 1 - from;
            let undelivered: Vec<usize> = (0..c.sent(from, to).len())
                .filter(|&i| !c.sent(from, to)[i].delivered)
                .collect();
            // Whether `from` holds an identity for `to` that is no longer
            // `to`'s: what a reinstall leaves until it is trusted again.
            let stale = c.parties[from]
                .stores
                .lock()
                .unwrap()
                .identities
                .get(&c.parties[to].name)
                .is_some_and(|key| *key != c.parties[to].identity_key());
            let op = match rng.random_range(0..106) {
                0..10 => Op::Fetch(from, to),
                10..14 => Op::Archive(from, to),
                14..40 => Op::Send(from, to),
                40..50 => Op::SealedSend(from, to),
                // In order, which is the usual case.
                50..80 if !undelivered.is_empty() => Op::Deliver(from, to, undelivered[0]),
                // Out of order, or never: the oldest is skipped.
                80..92 if !undelivered.is_empty() => {
                    Op::Deliver(from, to, undelivered[rng.random_range(0..undelivered.len())])
                }
                // Again.
                92..100 if !c.sent(from, to).is_empty() => {
                    Op::Deliver(from, to, rng.random_range(0..c.sent(from, to).len()))
                }
                100..102 => Op::Forget(from, to),
                102 => Op::Reinstall(from),
                103..106 if stale => Op::Retrust(from, to),
                _ => Op::Send(from, to),
            };
            c.apply(op);
        }
        reached.decrypted += c.reached.decrypted;
        reached.decrypted_leaving_no_current_session += c.reached.decrypted_leaving_no_current_session;
        reached.sealed_decrypted += c.reached.sealed_decrypted;
        reached.identity_restored_on_encrypt += c.reached.identity_restored_on_encrypt;
        for (failure, n) in c.reached.failures {
            *reached.failures.entry(failure).or_default() += n;
        }
    }
    let summary = format!(
        "decrypted {}, of which {} left no current session and {} were sealed; identities stored \
         again on encrypt {}; failures {:?}",
        reached.decrypted,
        reached.decrypted_leaving_no_current_session,
        reached.sealed_decrypted,
        reached.identity_restored_on_encrypt,
        reached.failures
    );
    eprintln!("{summary}");

    // Floors at about half of what these seeds reach (measured run to run within
    // ±2, the keys being fresh each time). A script that stops reaching a state
    // compares nothing there and still passes, so falling below one is a
    // failure: re-tune the weights above.
    let failures = |code: &str| reached.failures.get(code).copied().unwrap_or(0);
    assert!(reached.decrypted >= 250, "too few messages decrypted: {summary}");
    assert!(
        reached.decrypted_leaving_no_current_session >= 24,
        "too few decryptions left a record with no current session: {summary}"
    );
    assert!(reached.sealed_decrypted >= 50, "too few sealed messages decrypted: {summary}");
    assert!(
        reached.identity_restored_on_encrypt >= 8,
        "too few encryptions stored a forgotten identity again: {summary}"
    );
    assert!(failures("DuplicatedMessage") >= 38, "too few redeliveries: {summary}");
    assert!(failures("InvalidMessage") >= 13, "too few undecryptable messages: {summary}");
    assert!(failures("UntrustedIdentity") >= 10, "too few refused identities: {summary}");
}
