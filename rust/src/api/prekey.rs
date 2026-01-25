//! PreKey record API using libsignal-protocol.

use libsignal_protocol::{KeyPair, PreKeyId, PreKeyRecord as NativePreKeyRecord};
use zeroize::Zeroize;

use super::keys::{PrivateKey, PublicKey};

/// A pre-key record containing a key pair and ID.
pub struct PreKeyRecord {
    inner: NativePreKeyRecord,
}

impl PreKeyRecord {
    /// Create from native libsignal PreKeyRecord.
    pub(crate) fn from_native(record: NativePreKeyRecord) -> Self {
        Self { inner: record }
    }

    /// Get the inner native record (for use by other modules).
    pub(crate) fn native(&self) -> &NativePreKeyRecord {
        &self.inner
    }

    /// Create a new pre-key record.
    ///
    /// # Arguments
    /// * `id` - The pre-key identifier
    /// * `public_key` - The public key
    /// * `private_key` - The private key
    #[flutter_rust_bridge::frb(sync)]
    pub fn new(
        id: u32,
        public_key: &PublicKey,
        private_key: &PrivateKey,
    ) -> Result<PreKeyRecord, String> {
        let prekey_id = PreKeyId::from(id);
        let key_pair = KeyPair::new(*public_key.native(), *private_key.native());
        let native = NativePreKeyRecord::new(prekey_id, &key_pair);
        Ok(PreKeyRecord { inner: native })
    }

    /// Deserialize a pre-key record from bytes.
    ///
    /// # Security
    /// The input bytes are securely zeroized after deserialization.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(mut bytes: Vec<u8>) -> Result<PreKeyRecord, String> {
        let result = NativePreKeyRecord::deserialize(&bytes).map_err(|e| e.to_string());
        bytes.zeroize(); // SECURITY: Zeroize input bytes
        Ok(PreKeyRecord { inner: result? })
    }

    /// Serialize this pre-key record to bytes.
    ///
    /// # Security
    /// The returned bytes contain sensitive key material (including the private key).
    /// The caller is responsible for securely zeroing these bytes when done.
    /// Consider using `SecureBytes.wrap()` on the Dart side to ensure automatic zeroing.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        self.inner.serialize().map_err(|e| e.to_string())
    }

    /// Get the pre-key ID.
    #[flutter_rust_bridge::frb(sync)]
    pub fn id(&self) -> Result<u32, String> {
        let id = self.inner.id().map_err(|e| e.to_string())?;
        Ok(id.into())
    }

    /// Get the public key.
    #[flutter_rust_bridge::frb(sync)]
    pub fn public_key(&self) -> Result<Vec<u8>, String> {
        let key = self.inner.public_key().map_err(|e| e.to_string())?;
        Ok(key.serialize().into_vec())
    }

    /// Get the private key.
    ///
    /// # Security
    /// The returned bytes contain sensitive private key material.
    /// The caller is responsible for securely zeroing these bytes when done.
    /// Consider using `SecureBytes.wrap()` on the Dart side to ensure automatic zeroing.
    #[flutter_rust_bridge::frb(sync)]
    pub fn private_key(&self) -> Result<Vec<u8>, String> {
        let key = self.inner.private_key().map_err(|e| e.to_string())?;
        Ok(key.serialize())
    }
}
