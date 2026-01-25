//! Session record API using libsignal-protocol.

use libsignal_protocol::{SessionRecord as NativeSessionRecord, SessionUsabilityRequirements};
use std::time::{Duration, UNIX_EPOCH};
use zeroize::Zeroize;

use super::keys::PublicKey;

/// A session record containing the state of a Signal Protocol session.
pub struct SessionRecord {
    inner: NativeSessionRecord,
}

impl SessionRecord {
    /// Create from native libsignal SessionRecord.
    pub(crate) fn from_native(record: NativeSessionRecord) -> Self {
        Self { inner: record }
    }

    /// Get the inner native record (for use by other modules).
    pub(crate) fn native(&self) -> &NativeSessionRecord {
        &self.inner
    }

    /// Get a mutable reference to the inner native record.
    pub(crate) fn native_mut(&mut self) -> &mut NativeSessionRecord {
        &mut self.inner
    }

    /// Deserialize a session record from bytes.
    ///
    /// # Security
    /// The input bytes are securely zeroized after deserialization.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(mut bytes: Vec<u8>) -> Result<SessionRecord, String> {
        let result = NativeSessionRecord::deserialize(&bytes).map_err(|e| e.to_string());
        bytes.zeroize(); // SECURITY: Zeroize input bytes
        Ok(SessionRecord { inner: result? })
    }

    /// Serialize this session record to bytes.
    ///
    /// # Security
    /// The returned bytes contain sensitive session state (including ratchet keys).
    /// The caller is responsible for securely zeroing these bytes when done.
    /// Consider using `SecureBytes.wrap()` on the Dart side to ensure automatic zeroing.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        self.inner.serialize().map_err(|e| e.to_string())
    }

    /// Archive the current session state.
    #[flutter_rust_bridge::frb(sync)]
    pub fn archive_current_state(&mut self) -> Result<(), String> {
        self.inner
            .archive_current_state()
            .map_err(|e| e.to_string())
    }

    /// Check if this session has a usable sender chain.
    #[flutter_rust_bridge::frb(sync)]
    pub fn has_usable_sender_chain(&self, now_millis: u64) -> Result<bool, String> {
        let now = UNIX_EPOCH + Duration::from_millis(now_millis);
        self.inner
            .has_usable_sender_chain(now, SessionUsabilityRequirements::empty())
            .map_err(|e| e.to_string())
    }

    /// Check if the current ratchet key matches the given public key.
    #[flutter_rust_bridge::frb(sync)]
    pub fn current_ratchet_key_matches(&self, key: &PublicKey) -> Result<bool, String> {
        self.inner
            .current_ratchet_key_matches(key.native())
            .map_err(|e| e.to_string())
    }

    /// Get the local registration ID.
    #[flutter_rust_bridge::frb(sync)]
    pub fn local_registration_id(&self) -> Result<u32, String> {
        self.inner
            .local_registration_id()
            .map_err(|e| e.to_string())
    }

    /// Get the remote registration ID.
    #[flutter_rust_bridge::frb(sync)]
    pub fn remote_registration_id(&self) -> Result<u32, String> {
        self.inner
            .remote_registration_id()
            .map_err(|e| e.to_string())
    }

    /// Create a copy of this session record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_record(&self) -> Result<SessionRecord, String> {
        Ok(SessionRecord {
            inner: self.inner.clone(),
        })
    }
}
