//! Signed pre-key record API using libsignal-protocol.

use libsignal_protocol::{
    GenericSignedPreKey, KeyPair, SignedPreKeyId, SignedPreKeyRecord as NativeSignedPreKeyRecord,
    Timestamp,
};
use zeroize::Zeroize;

use super::keys::{PrivateKey, PublicKey};

/// A signed pre-key record containing a key pair, ID, timestamp, and signature.
pub struct SignedPreKeyRecord {
    inner: NativeSignedPreKeyRecord,
}

impl SignedPreKeyRecord {
    /// Create from native libsignal SignedPreKeyRecord.
    pub(crate) fn from_native(record: NativeSignedPreKeyRecord) -> Self {
        Self { inner: record }
    }

    /// Get the inner native record (for use by other modules).
    pub(crate) fn native(&self) -> &NativeSignedPreKeyRecord {
        &self.inner
    }

    /// Create a new signed pre-key record.
    ///
    /// # Arguments
    /// * `id` - The signed pre-key identifier
    /// * `timestamp` - The timestamp when this key was generated (milliseconds since epoch)
    /// * `public_key` - The public key
    /// * `private_key` - The private key
    /// * `signature` - The signature of the public key by the identity key
    #[flutter_rust_bridge::frb(sync)]
    pub fn new(
        id: u32,
        timestamp: u64,
        public_key: &PublicKey,
        private_key: &PrivateKey,
        signature: Vec<u8>,
    ) -> Result<SignedPreKeyRecord, String> {
        let signed_prekey_id = SignedPreKeyId::from(id);
        let ts = Timestamp::from_epoch_millis(timestamp);
        let key_pair = KeyPair::new(*public_key.native(), *private_key.native());
        let native = NativeSignedPreKeyRecord::new(signed_prekey_id, ts, &key_pair, &signature);
        Ok(SignedPreKeyRecord { inner: native })
    }

    /// Deserialize a signed pre-key record from bytes.
    ///
    /// # Security
    /// The input bytes are securely zeroized after deserialization.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(mut bytes: Vec<u8>) -> Result<SignedPreKeyRecord, String> {
        let result =
            NativeSignedPreKeyRecord::deserialize(&bytes).map_err(|e| e.to_string());
        bytes.zeroize(); // SECURITY: Zeroize input bytes
        Ok(SignedPreKeyRecord { inner: result? })
    }

    /// Serialize this signed pre-key record to bytes.
    ///
    /// # Security
    /// The returned bytes contain sensitive key material (including the private key).
    /// The caller is responsible for securely zeroing these bytes when done.
    /// Consider using `SecureBytes.wrap()` on the Dart side to ensure automatic zeroing.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        self.inner.serialize().map_err(|e| e.to_string())
    }

    /// Get the signed pre-key ID.
    #[flutter_rust_bridge::frb(sync)]
    pub fn id(&self) -> Result<u32, String> {
        let id = self.inner.id().map_err(|e| e.to_string())?;
        Ok(id.into())
    }

    /// Get the timestamp when this key was generated.
    #[flutter_rust_bridge::frb(sync)]
    pub fn timestamp(&self) -> Result<u64, String> {
        let ts = self.inner.timestamp().map_err(|e| e.to_string())?;
        Ok(ts.epoch_millis())
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

    /// Get the signature.
    #[flutter_rust_bridge::frb(sync)]
    pub fn signature(&self) -> Result<Vec<u8>, String> {
        self.inner.signature().map_err(|e| e.to_string())
    }
}
