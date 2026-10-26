//! Session record API using libsignal-protocol.

use crate::api::error::LibSignalException;
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
    pub fn deserialize(mut bytes: Vec<u8>) -> Result<SessionRecord, LibSignalException> {
        let result = NativeSessionRecord::deserialize(&bytes).map_err(LibSignalException::from);
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
    pub fn serialize(&self) -> Result<Vec<u8>, LibSignalException> {
        self.inner.serialize().map_err(LibSignalException::from)
    }

    /// Archive the current session state.
    ///
    /// The archived session still decrypts what the peer sends on it, but
    /// libsignal never makes it current again: until a new session is
    /// established with `SessionBuilder.processPreKeyBundle`, encrypting to
    /// this address throws `LibSignalErrorCode.sessionNotFound`. libsignal also
    /// archives the current session itself when a conversation keeps switching
    /// back and forth between two sessions, with the same result. A record
    /// keeps at most 3 archived sessions, and archiving drops the oldest beyond
    /// that.
    #[flutter_rust_bridge::frb(sync)]
    pub fn archive_current_state(&mut self) -> Result<(), LibSignalException> {
        self.inner
            .archive_current_state()
            .map_err(LibSignalException::from)
    }

    /// Whether the current session can be sent on at `now_millis`, by the
    /// requirements Signal's own clients apply.
    ///
    /// The session must have a sender chain, and it must be:
    /// - not stale: started by the peer, answered by the peer, or less than
    ///   30 days old — an unanswered session older than that is one libsignal
    ///   itself no longer encrypts on;
    /// - established with PQXDH rather than X3DH;
    /// - using the post-quantum ratchet, SPQR.
    ///
    /// These are libsignal's `NotStale`, `EstablishedWithPqxdh` and `Spqr`, the
    /// set its Java, Swift and Node bindings ask for. libsignal warns that the
    /// last one also accepts an unanswered session whose pre-key message
    /// carries SPQR, which an answer without SPQR turns from usable to unusable
    /// where the client accepts that downgrade. This libsignal does not: the
    /// sessions it creates require SPQR, so such an answer fails to decrypt
    /// instead. A `false` is the point at which a Signal client archives the
    /// session and builds a new one with `SessionBuilder.processPreKeyBundle`.
    #[flutter_rust_bridge::frb(sync)]
    pub fn has_usable_sender_chain(&self, now_millis: u64) -> Result<bool, LibSignalException> {
        let now = UNIX_EPOCH + Duration::from_millis(now_millis);
        self.inner
            .has_usable_sender_chain(
                now,
                SessionUsabilityRequirements::NotStale
                    | SessionUsabilityRequirements::EstablishedWithPqxdh
                    | SessionUsabilityRequirements::Spqr,
            )
            .map_err(LibSignalException::from)
    }

    /// Check if the current ratchet key matches the given public key.
    #[flutter_rust_bridge::frb(sync)]
    pub fn current_ratchet_key_matches(&self, key: &PublicKey) -> Result<bool, LibSignalException> {
        self.inner
            .current_ratchet_key_matches(key.native())
            .map_err(LibSignalException::from)
    }

    /// Get the local registration ID.
    ///
    /// Read from the current session, so it throws
    /// `LibSignalErrorCode.sessionNotFound` on a record that has none — see
    /// `archiveCurrentState`.
    #[flutter_rust_bridge::frb(sync)]
    pub fn local_registration_id(&self) -> Result<u32, LibSignalException> {
        self.inner
            .local_registration_id()
            .map_err(LibSignalException::from)
    }

    /// Get the remote registration ID.
    ///
    /// Read from the current session, so it throws
    /// `LibSignalErrorCode.sessionNotFound` on a record that has none — see
    /// `archiveCurrentState`.
    #[flutter_rust_bridge::frb(sync)]
    pub fn remote_registration_id(&self) -> Result<u32, LibSignalException> {
        self.inner
            .remote_registration_id()
            .map_err(LibSignalException::from)
    }

    /// Create a copy of this session record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_record(&self) -> Result<SessionRecord, LibSignalException> {
        Ok(SessionRecord {
            inner: self.inner.clone(),
        })
    }
}
