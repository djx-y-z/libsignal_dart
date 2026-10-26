//! Per-call stores that record what libsignal actually wrote.
//!
//! The high-level ciphers hand libsignal a set of fresh in-memory stores and
//! then replay the resulting writes to the Dart stores. Deriving those writes
//! from the *message* fields, or from the session record afterwards,
//! over-reports, because libsignal decides which writes happen:
//!
//! - It consumes the pre-key bundle only when the pre-key message really
//!   establishes a new session. `message_decrypt_prekey` first looks for a
//!   session with the message's base key, and when one exists — the
//!   redelivery case, where the first delivery consumed the keys — it
//!   decrypts against that session and calls neither `mark_kyber_pre_key_used`
//!   nor `remove_pre_key`.
//! - It saves the remote identity only for a message that decrypts on the
//!   current session or establishes a new one. Since libsignal v0.106.0 a
//!   message that decrypts on an archived session saves nothing, so a delayed
//!   message cannot roll the stored identity back. That session also stays
//!   archived, so the record may have no current session left to read an
//!   identity from.
//! - On the way out it saves the identity it has just checked, on every
//!   message: `message_encrypt`, and `sealed_sender_encrypt` through it. With
//!   the identity already stored that changes nothing; for an address whose
//!   identity the application deleted it stores the key again.
//!
//! These wrappers observe the real calls instead of guessing. For Kyber they
//! also capture the full argument triple: `mark_kyber_pre_key_used` is handed
//! the signed EC pre-key ID and the sender's base key alongside the Kyber ID,
//! and those are exactly what a store needs for the last-resort anti-replay
//! check that the upstream trait documents. libsignal treats that call as a
//! gate — a store that has seen the agreement fails it, and the decryption
//! with it, before anything is written — and the per-call store here cannot
//! refuse anything, so the cipher entry points put the same question to the
//! Dart store before their first write-back and fail with [`reused_base_key`]
//! when it answers that it has.

use async_trait::async_trait;
use libsignal_protocol::{
    CiphertextMessageType, Direction, IdentityChange, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, InMemIdentityKeyStore, InMemKyberPreKeyStore, InMemPreKeyStore,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore,
    ProtocolAddress, PublicKey, SignalProtocolError, SignedPreKeyId,
};

type Result<T> = std::result::Result<T, SignalProtocolError>;

/// The error libsignal's reference store refuses a repeated agreement with,
/// which `message_decrypt_prekey` passes on unchanged. The bridge returns the
/// same when the Dart store answers `mark_kyber_pre_key_used` with `false`.
pub(crate) fn reused_base_key() -> SignalProtocolError {
    SignalProtocolError::InvalidMessage(CiphertextMessageType::PreKey, "reused base key".to_owned())
}

/// The arguments of the `mark_kyber_pre_key_used` call libsignal made.
pub(crate) struct KyberPreKeyUsed {
    /// The Kyber pre-key that was consumed.
    pub kyber_pre_key_id: u32,
    /// The signed EC pre-key it was consumed together with.
    pub signed_pre_key_id: u32,
    /// The sender's serialized base key for this PQXDH agreement.
    pub base_key: Vec<u8>,
}

/// [`PreKeyStore`] that records the one-time pre-key libsignal removed.
pub(crate) struct RecordingPreKeyStore {
    inner: InMemPreKeyStore,
    removed: Option<u32>,
}

impl RecordingPreKeyStore {
    pub(crate) fn new() -> Self {
        Self {
            inner: InMemPreKeyStore::new(),
            removed: None,
        }
    }

    /// The pre-key ID libsignal removed, if it consumed one.
    pub(crate) fn take_removed(&mut self) -> Option<u32> {
        self.removed.take()
    }
}

#[async_trait(?Send)]
impl PreKeyStore for RecordingPreKeyStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord> {
        self.inner.get_pre_key(prekey_id).await
    }

    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        self.inner.save_pre_key(prekey_id, record).await
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<()> {
        self.removed = Some(prekey_id.into());
        self.inner.remove_pre_key(prekey_id).await
    }
}

/// [`KyberPreKeyStore`] that records the `mark_kyber_pre_key_used` call.
pub(crate) struct RecordingKyberPreKeyStore {
    inner: InMemKyberPreKeyStore,
    used: Option<KyberPreKeyUsed>,
}

impl RecordingKyberPreKeyStore {
    pub(crate) fn new() -> Self {
        Self {
            inner: InMemKyberPreKeyStore::new(),
            used: None,
        }
    }

    /// The recorded call, if libsignal consumed a Kyber pre-key.
    pub(crate) fn take_used(&mut self) -> Option<KyberPreKeyUsed> {
        self.used.take()
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for RecordingKyberPreKeyStore {
    async fn get_kyber_pre_key(&self, kyber_prekey_id: KyberPreKeyId) -> Result<KyberPreKeyRecord> {
        self.inner.get_kyber_pre_key(kyber_prekey_id).await
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<()> {
        self.inner.save_kyber_pre_key(kyber_prekey_id, record).await
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<()> {
        self.used = Some(KyberPreKeyUsed {
            kyber_pre_key_id: kyber_prekey_id.into(),
            signed_pre_key_id: ec_prekey_id.into(),
            base_key: base_key.serialize().to_vec(),
        });
        // Delegating keeps the reference anti-replay bookkeeping in place. It
        // cannot fire here — the store is fresh for every call — but the Dart
        // store this call is forwarded to is not, and its answer is what
        // refuses a replay; see `reused_base_key`.
        self.inner
            .mark_kyber_pre_key_used(kyber_prekey_id, ec_prekey_id, base_key)
            .await
    }
}

/// [`IdentityKeyStore`] that records the identity libsignal saved.
///
/// Wrap the store only once the bridge has seeded it (`preseed_identity`): the
/// seeding goes through `save_identity` too, and it is not a write libsignal
/// made.
pub(crate) struct RecordingIdentityKeyStore {
    inner: InMemIdentityKeyStore,
    saved: Option<Vec<u8>>,
}

impl RecordingIdentityKeyStore {
    pub(crate) fn new(inner: InMemIdentityKeyStore) -> Self {
        Self { inner, saved: None }
    }

    /// The serialized identity key libsignal saved, if it saved one. It saves
    /// only for the address it was handed, which is the one written back to.
    pub(crate) fn take_saved(&mut self) -> Option<Vec<u8>> {
        self.saved.take()
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for RecordingIdentityKeyStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        self.inner.get_identity_key_pair().await
    }

    async fn get_local_registration_id(&self) -> Result<u32> {
        self.inner.get_local_registration_id().await
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange> {
        self.saved = Some(identity.serialize().to_vec());
        self.inner.save_identity(address, identity).await
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool> {
        self.inner
            .is_trusted_identity(address, identity, direction)
            .await
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        self.inner.get_identity(address).await
    }
}
