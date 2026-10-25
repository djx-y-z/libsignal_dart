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
//! Deliberately not compared:
//! - The bytes of session records and ciphertexts, which depend on fresh
//!   randomness. Their observable properties are compared instead.
//! - `save_identity` on encrypt. libsignal saves the identity it has just
//!   checked, and the bridge's encrypt entry point has no callback for it.
//!   With the identity already stored that write changes nothing; it would
//!   matter only for an address whose identity the application deleted, and
//!   no script here deletes one.
//! - Write order. The bridge stores the session last on purpose (see
//!   `message_decrypt_prekey_with_callbacks`); only the end state counts.
//! - libsignal's last-resort Kyber replay check. The reference store refuses a
//!   repeated (Kyber pre-key, signed pre-key, base key) agreement, which a
//!   Dart callback cannot do (SECURITY.md, Known Limitations, item 5). Every
//!   bundle here carries a one-time pre-key, so a replayed agreement fails on
//!   the consumed pre-key first, on both sides, and never reaches that check.
//!
//! Not covered yet: the sealed-sender entry points, and a change of identity.
//! Sealed sender decrypts through the same libsignal functions with a
//! write-back of its own, which `test/protocol/archived_session_test.dart`
//! pins for now. An identity change needs an application step, re-trusting
//! the new key, that has no libsignal counterpart to compare against.
//!
//! Run with `make rust-test`. Deliberately outside `api/`, which FRB codegen
//! scans.

use crate::api::bundle::PreKeyBundle as BridgeBundle;
use crate::api::error::{LibSignalErrorCode, LibSignalException};
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
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::SystemTime;

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
/// treats every Kyber pre-key as a last-resort one.
fn mark_kyber_pre_key_used(s: &Shared) -> impl Fn(u32, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static {
    let s = s.clone();
    move |kyber, signed, base_key| {
        s.lock().unwrap().writes.kyber_marked.push((kyber, signed, base_key));
        ready(())
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
        }
    }

    fn identity_key(&self) -> Vec<u8> {
        self.identity.identity_key().serialize().to_vec()
    }

    /// Publishes a bundle with a fresh one-time pre-key and a fresh Kyber
    /// pre-key, both stored before it is handed out, as a client that
    /// replenishes the server does.
    fn publish_bundle(&mut self) -> (BridgeBundle, up::PreKeyBundle) {
        let mut rng = OsRng.unwrap_err();
        let id = self.next_pre_key_id;
        self.next_pre_key_id += 1;
        let one_time = up::KeyPair::generate(&mut rng);
        let kyber = up::kem::KeyPair::generate(up::kem::KeyType::Kyber1024, &mut rng);
        let kyber_signature = self
            .identity
            .private_key()
            .calculate_signature(&kyber.public_key.serialize(), &mut rng)
            .unwrap()
            .to_vec();
        {
            let mut s = self.stores.lock().unwrap();
            s.pre_keys
                .insert(id, up::PreKeyRecord::new(id.into(), &one_time).serialize().unwrap());
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
            Some(id),
            Some(one_time.public_key.serialize().to_vec()),
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
            Some((id.into(), one_time.public_key)),
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

// ---------------------------------------------------------------------------
// What is compared
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum Outcome {
    Done,
    Encrypted { pre_key_message: bool },
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
}

#[derive(Clone)]
struct InFlight {
    pre_key_message: bool,
    bytes: Vec<u8>,
    plaintext: Vec<u8>,
    delivered: bool,
}

struct Conversation {
    label: String,
    parties: [Party; 2],
    sent: BTreeMap<(usize, usize), Vec<InFlight>>,
    script: Vec<String>,
    reached: Reached,
}

impl Conversation {
    fn new(label: &str) -> Self {
        Conversation {
            label: label.to_owned(),
            parties: [Party::new("alice", 1111), Party::new("bob", 2222)],
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
                    Compare { session_id: false, identity_writes: true },
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
                    Compare { session_id: true, identity_writes: false },
                );
                if let Ok(result) = bridge {
                    self.sent.entry((from, to)).or_default().push(InFlight {
                        pre_key_message: result.message_type == 3,
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
                let bridge = if message.pre_key_message {
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
                let ciphertext = if message.pre_key_message {
                    up::CiphertextMessage::PreKeySignalMessage(
                        up::PreKeySignalMessage::try_from(&message.bytes[..]).unwrap(),
                    )
                } else {
                    up::CiphertextMessage::SignalMessage(
                        up::SignalMessage::try_from(&message.bytes[..]).unwrap(),
                    )
                };
                let upstream = block_on(up::message_decrypt(
                    &ciphertext,
                    &address(&peer.name),
                    &address(&p.name),
                    &mut reference.sessions,
                    &mut reference.identities,
                    &mut reference.pre_keys,
                    &reference.signed_pre_keys,
                    &mut reference.kyber_pre_keys,
                    &mut OsRng.unwrap_err(),
                ));
                if let Ok(plaintext) = &upstream {
                    assert_eq!(plaintext, &message.plaintext, "[{}] upstream decrypted another message", self.label);
                }
                self.compare(
                    to,
                    from,
                    bridge.map_or_else(|e| Outcome::Failed(e.code), Outcome::Decrypted),
                    upstream.map_or_else(|e| Outcome::Failed(code(e)), Outcome::Decrypted),
                    &snapshot,
                    &reference,
                    Compare { session_id: true, identity_writes: true },
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

    #[allow(clippy::too_many_arguments)]
    fn compare(
        &mut self,
        party: usize,
        peer: usize,
        bridge: Outcome,
        upstream: Outcome,
        snapshot: &DartStores,
        reference: &Reference,
        compare: Compare,
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
        let mut bridge_writes = p.stores.lock().unwrap().writes.clone();
        let mut upstream_writes = reference.writes();
        if !compare.identity_writes {
            bridge_writes.identities_saved.clear();
            upstream_writes.identities_saved.clear();
        }
        assert_eq!(bridge_writes, upstream_writes, "the writes differ from libsignal's {}", context());

        let bridge_view = {
            let s = p.stores.lock().unwrap();
            PartyView {
                session_with_peer: s.sessions.get(&peer.name).map(|bytes| {
                    SessionView::of(&up::SessionRecord::deserialize(bytes).unwrap(), compare.session_id)
                }),
                identity_of_peer: s.identities.get(&peer.name).cloned(),
                pre_keys: s.pre_keys.keys().copied().collect(),
            }
        };
        let upstream_view = PartyView {
            session_with_peer: block_on(reference.sessions.load_session(&address(&peer.name)))
                .unwrap()
                .map(|record| SessionView::of(&record, compare.session_id)),
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

#[derive(Clone, Copy)]
struct Compare {
    session_id: bool,
    identity_writes: bool,
}

/// What a script reached, so the random one can show it still reaches the
/// states it exists for.
#[derive(Default)]
struct Reached {
    decrypted: usize,
    /// Decrypted, and the record came out with no current session: the state
    /// v0.106.0 introduced, after an application's archive or libsignal's own.
    decrypted_leaving_no_current_session: usize,
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

/// Random scripts: messages delivered in order, out of order, twice or never;
/// sessions archived and started over by either side.
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
            let op = match rng.random_range(0..100) {
                0..10 => Op::Fetch(from, to),
                10..14 => Op::Archive(from, to),
                14..50 => Op::Send(from, to),
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
                _ => Op::Send(from, to),
            };
            c.apply(op);
        }
        reached.decrypted += c.reached.decrypted;
        reached.decrypted_leaving_no_current_session += c.reached.decrypted_leaving_no_current_session;
        for (failure, n) in c.reached.failures {
            *reached.failures.entry(failure).or_default() += n;
        }
    }
    let summary = format!(
        "decrypted {}, of which {} left no current session; failures {:?}",
        reached.decrypted, reached.decrypted_leaving_no_current_session, reached.failures
    );
    eprintln!("{summary}");

    // Floors at about half of what these seeds reach (measured run to run within
    // ±2, the keys being fresh each time). A script that stops reaching a state
    // compares nothing there and still passes, so falling below one is a
    // failure: re-tune the weights above.
    let failures = |code: &str| reached.failures.get(code).copied().unwrap_or(0);
    assert!(reached.decrypted >= 300, "too few messages decrypted: {summary}");
    assert!(
        reached.decrypted_leaving_no_current_session >= 30,
        "too few decryptions left a record with no current session: {summary}"
    );
    assert!(failures("DuplicatedMessage") >= 45, "too few redeliveries: {summary}");
    assert!(failures("InvalidMessage") >= 5, "too few undecryptable messages: {summary}");
}
