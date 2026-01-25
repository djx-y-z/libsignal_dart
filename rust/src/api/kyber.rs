//! Kyber post-quantum key types API using libsignal-protocol.

use libsignal_protocol::{
    GenericSignedPreKey, KyberPreKeyId, KyberPreKeyRecord as NativeKyberPreKeyRecord, Timestamp,
    kem::{KeyType, KeyPair as NativeKeyPair, PublicKey as NativePublicKey, SecretKey as NativeSecretKey},
};
use rand::{TryRngCore as _, rngs::OsRng};
use zeroize::Zeroize;

/// A Kyber public key for post-quantum key encapsulation.
pub struct KyberPublicKey {
    inner: NativePublicKey,
}

impl KyberPublicKey {
    /// Create from native libsignal KyberPublicKey.
    pub(crate) fn from_native(key: NativePublicKey) -> Self {
        Self { inner: key }
    }

    /// Get the inner native key (for use by other modules).
    pub(crate) fn native(&self) -> &NativePublicKey {
        &self.inner
    }

    /// Deserialize a Kyber public key from bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(bytes: Vec<u8>) -> Result<KyberPublicKey, String> {
        let native = NativePublicKey::deserialize(&bytes).map_err(|e| e.to_string())?;
        Ok(KyberPublicKey { inner: native })
    }

    /// Serialize this Kyber public key to bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.serialize().into_vec())
    }

    /// Check if this Kyber public key equals another.
    #[flutter_rust_bridge::frb(sync)]
    pub fn equals(&self, other: &KyberPublicKey) -> Result<bool, String> {
        Ok(self.inner == other.inner)
    }

    /// Clone this Kyber public key.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_key(&self) -> Result<KyberPublicKey, String> {
        Ok(KyberPublicKey {
            inner: self.inner.clone(),
        })
    }
}

/// A Kyber secret key for post-quantum key encapsulation.
pub struct KyberSecretKey {
    inner: NativeSecretKey,
}

impl KyberSecretKey {
    /// Create from native libsignal KyberSecretKey.
    pub(crate) fn from_native(key: NativeSecretKey) -> Self {
        Self { inner: key }
    }

    /// Get the inner native key (for use by other modules).
    pub(crate) fn native(&self) -> &NativeSecretKey {
        &self.inner
    }

    /// Deserialize a Kyber secret key from bytes.
    ///
    /// # Security
    /// The input bytes are securely zeroized after deserialization.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(mut bytes: Vec<u8>) -> Result<KyberSecretKey, String> {
        let result = NativeSecretKey::deserialize(&bytes).map_err(|e| e.to_string());
        bytes.zeroize(); // SECURITY: Zeroize input bytes
        Ok(KyberSecretKey { inner: result? })
    }

    /// Serialize this Kyber secret key to bytes.
    ///
    /// # Security
    /// The returned bytes contain sensitive secret key material.
    /// The caller is responsible for securely zeroing these bytes when done.
    /// Consider using `SecureBytes.wrap()` on the Dart side to ensure automatic zeroing.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.serialize().into_vec())
    }

    /// Clone this Kyber secret key.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_key(&self) -> Result<KyberSecretKey, String> {
        Ok(KyberSecretKey {
            inner: self.inner.clone(),
        })
    }
}

/// A Kyber key pair (public and secret key).
pub struct KyberKeyPair {
    inner: NativeKeyPair,
}

impl KyberKeyPair {
    /// Create from native libsignal KyberKeyPair.
    pub(crate) fn from_native(pair: NativeKeyPair) -> Self {
        Self { inner: pair }
    }

    /// Get the inner native key pair (for use by other modules).
    pub(crate) fn native(&self) -> &NativeKeyPair {
        &self.inner
    }

    /// Generate a new random Kyber key pair.
    #[flutter_rust_bridge::frb(sync)]
    pub fn generate() -> Result<KyberKeyPair, String> {
        // Default to Kyber1024 for post-quantum security
        let native = NativeKeyPair::generate(KeyType::Kyber1024, &mut OsRng.unwrap_err());
        Ok(KyberKeyPair { inner: native })
    }

    /// Get the public key from this key pair.
    #[flutter_rust_bridge::frb(sync)]
    pub fn get_public_key(&self) -> Result<KyberPublicKey, String> {
        Ok(KyberPublicKey {
            inner: self.inner.public_key.clone(),
        })
    }

    /// Get the secret key from this key pair.
    ///
    /// # Security
    /// The returned key contains sensitive secret key material. When serialized,
    /// the caller is responsible for securely zeroing those bytes when done.
    /// Consider using `SecureBytes.wrap()` on the Dart side after serialization.
    #[flutter_rust_bridge::frb(sync)]
    pub fn get_secret_key(&self) -> Result<KyberSecretKey, String> {
        Ok(KyberSecretKey {
            inner: self.inner.secret_key.clone(),
        })
    }

    /// Clone this Kyber key pair.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_key(&self) -> Result<KyberKeyPair, String> {
        Ok(KyberKeyPair {
            inner: self.inner.clone(),
        })
    }
}

/// A Kyber pre-key record for post-quantum Signal Protocol.
pub struct KyberPreKeyRecord {
    inner: NativeKyberPreKeyRecord,
}

impl KyberPreKeyRecord {
    /// Create from native libsignal KyberPreKeyRecord.
    pub(crate) fn from_native(record: NativeKyberPreKeyRecord) -> Self {
        Self { inner: record }
    }

    /// Get the inner native record (for use by other modules).
    pub(crate) fn native(&self) -> &NativeKyberPreKeyRecord {
        &self.inner
    }

    /// Create a new Kyber pre-key record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn create(
        id: u32,
        timestamp: u64,
        key_pair: &KyberKeyPair,
        signature: Vec<u8>,
    ) -> Result<KyberPreKeyRecord, String> {
        let kyber_id = KyberPreKeyId::from(id);
        let ts = Timestamp::from_epoch_millis(timestamp);
        let native =
            NativeKyberPreKeyRecord::new(kyber_id, ts, &key_pair.inner, &signature);
        Ok(KyberPreKeyRecord { inner: native })
    }

    /// Deserialize a Kyber pre-key record from bytes.
    ///
    /// # Security
    /// The input bytes are securely zeroized after deserialization.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(mut bytes: Vec<u8>) -> Result<KyberPreKeyRecord, String> {
        let result =
            NativeKyberPreKeyRecord::deserialize(&bytes).map_err(|e| e.to_string());
        bytes.zeroize(); // SECURITY: Zeroize input bytes
        Ok(KyberPreKeyRecord { inner: result? })
    }

    /// Serialize this Kyber pre-key record to bytes.
    ///
    /// # Security
    /// The returned bytes contain sensitive key material (including the secret key).
    /// The caller is responsible for securely zeroing these bytes when done.
    /// Consider using `SecureBytes.wrap()` on the Dart side to ensure automatic zeroing.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        self.inner.serialize().map_err(|e| e.to_string())
    }

    /// Get the ID of this Kyber pre-key record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn id(&self) -> Result<u32, String> {
        let id = self.inner.id().map_err(|e| e.to_string())?;
        Ok(id.into())
    }

    /// Get the timestamp of this Kyber pre-key record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn timestamp(&self) -> Result<u64, String> {
        let ts = self.inner.timestamp().map_err(|e| e.to_string())?;
        Ok(ts.epoch_millis())
    }

    /// Get the signature of this Kyber pre-key record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn signature(&self) -> Result<Vec<u8>, String> {
        self.inner.signature().map_err(|e| e.to_string())
    }

    /// Get the public key from this Kyber pre-key record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn get_public_key(&self) -> Result<KyberPublicKey, String> {
        let native = self.inner.public_key().map_err(|e| e.to_string())?;
        Ok(KyberPublicKey::from_native(native))
    }

    /// Get the secret key from this Kyber pre-key record.
    ///
    /// # Security
    /// The returned key contains sensitive secret key material. When serialized,
    /// the caller is responsible for securely zeroing those bytes when done.
    /// Consider using `SecureBytes.wrap()` on the Dart side after serialization.
    #[flutter_rust_bridge::frb(sync)]
    pub fn get_secret_key(&self) -> Result<KyberSecretKey, String> {
        let native = self.inner.secret_key().map_err(|e| e.to_string())?;
        Ok(KyberSecretKey::from_native(native))
    }

    /// Get the key pair from this Kyber pre-key record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn get_key_pair(&self) -> Result<KyberKeyPair, String> {
        let native = self.inner.key_pair().map_err(|e| e.to_string())?;
        Ok(KyberKeyPair::from_native(native))
    }

    /// Clone this Kyber pre-key record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_record(&self) -> Result<KyberPreKeyRecord, String> {
        Ok(KyberPreKeyRecord {
            inner: self.inner.clone(),
        })
    }
}
