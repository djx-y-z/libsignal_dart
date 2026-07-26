//! Per-call stores that record what libsignal actually consumed.
//!
//! The high-level ciphers hand libsignal a set of fresh in-memory stores and
//! then replay the resulting writes to the Dart stores. Deriving those writes
//! from the *message* fields over-reports: libsignal consumes the pre-key
//! bundle only when the pre-key message really establishes a new session.
//! `session_management::message_decrypt_prekey` gates both
//! `mark_kyber_pre_key_used` and `remove_pre_key` behind a `PreKeysUsed`, and
//! `session::process_prekey_impl` returns `None` for it as soon as
//! `promote_matching_session` matched an already-established session — the
//! redelivery case, where the keys were consumed by the first delivery.
//!
//! These wrappers observe the real calls instead of guessing. For Kyber they
//! also capture the full argument triple: `mark_kyber_pre_key_used` is handed
//! the signed EC pre-key ID and the sender's base key alongside the Kyber ID,
//! and those are exactly what a store needs for the last-resort anti-replay
//! check that the upstream trait documents.

use async_trait::async_trait;
use libsignal_protocol::{
    InMemKyberPreKeyStore, InMemPreKeyStore, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyId, PreKeyRecord, PreKeyStore, PublicKey, SignalProtocolError, SignedPreKeyId,
};

type Result<T> = std::result::Result<T, SignalProtocolError>;

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
        // store this call is forwarded to is not, which is the whole point of
        // handing it the triple.
        self.inner
            .mark_kyber_pre_key_used(kyber_prekey_id, ec_prekey_id, base_key)
            .await
    }
}
