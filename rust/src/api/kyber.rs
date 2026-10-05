//! Kyber post-quantum key types API using libsignal-protocol.

use crate::api::error::{LibSignalErrorCode, LibSignalException};
use libsignal_protocol::{
    GenericSignedPreKey, KyberPreKeyId, KyberPreKeyRecord as NativeKyberPreKeyRecord, Timestamp,
    kem::{KeyType, KeyPair as NativeKeyPair, PublicKey as NativePublicKey, SecretKey as NativeSecretKey},
};
use rand::{TryRngCore as _, rngs::OsRng};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, Zeroizing};

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
    pub fn deserialize(bytes: Vec<u8>) -> Result<KyberPublicKey, LibSignalException> {
        let native = NativePublicKey::deserialize(&bytes).map_err(LibSignalException::from)?;
        Ok(KyberPublicKey { inner: native })
    }

    /// Serialize this Kyber public key to bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, LibSignalException> {
        Ok(self.inner.serialize().into_vec())
    }

    /// Check if this Kyber public key equals another.
    #[flutter_rust_bridge::frb(sync)]
    pub fn equals(&self, other: &KyberPublicKey) -> Result<bool, LibSignalException> {
        Ok(self.inner == other.inner)
    }

    /// Clone this Kyber public key.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_key(&self) -> Result<KyberPublicKey, LibSignalException> {
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
    pub fn deserialize(mut bytes: Vec<u8>) -> Result<KyberSecretKey, LibSignalException> {
        let result = NativeSecretKey::deserialize(&bytes).map_err(LibSignalException::from);
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
    pub fn serialize(&self) -> Result<Vec<u8>, LibSignalException> {
        Ok(self.inner.serialize().into_vec())
    }

    /// Clone this Kyber secret key.
    ///
    /// # Security
    /// This duplicates sensitive secret key material into a second independent
    /// object. Each copy holds the secret in native memory until it is dropped,
    /// so every copy must be handled with the same care as the original.
    /// In security-critical applications, call `dispose()` on the Dart side of
    /// each copy as soon as it is no longer needed rather than waiting for the
    /// garbage collector, and avoid making copies you do not need.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_key(&self) -> Result<KyberSecretKey, LibSignalException> {
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
    pub fn generate() -> Result<KyberKeyPair, LibSignalException> {
        // Default to Kyber1024 for post-quantum security
        let native = NativeKeyPair::generate(KeyType::Kyber1024, &mut OsRng.unwrap_err());
        Ok(KyberKeyPair { inner: native })
    }

    /// Create a Kyber key pair from its two halves.
    ///
    /// For keys stored apart: each half has its own serialized form,
    /// `KyberPublicKey.serialize()` and `KyberSecretKey.serialize()`, while the
    /// pair has none — upstream libsignal defines no encoding for it. Deserialize
    /// both halves and join them here to get the key pair
    /// `KyberPreKeyRecord.create` takes. A Kyber pre-key kept whole needs none of
    /// this: `KyberPreKeyRecord.serialize()` carries both halves together with
    /// the id, timestamp and signature.
    ///
    /// The halves are checked to belong together: a shared secret encapsulated
    /// to `publicKey` has to decapsulate to the same value under `secretKey`.
    /// That is stricter than upstream libsignal, which compares only the key
    /// types, and nothing later would catch a mismatch. Creating a record and
    /// reading it back do not check the pairing, and decapsulating under the
    /// wrong secret key does not fail — it yields a different shared secret. A
    /// record built from mismatched halves would be accepted and published, and
    /// the mismatch would surface only when a peer's first message failed to
    /// decrypt, with nothing pointing back to this call.
    ///
    /// # Errors
    /// Fails if the two keys are for different KEM types, or are not halves of
    /// the same key pair.
    ///
    /// # Security
    /// Unlike `IdentityKeyPair.fromKeys`, this consumes neither argument: the
    /// pair holds its own copy of the secret key, and the `KyberSecretKey` passed
    /// in stays valid. Call `dispose()` on it as soon as it is no longer needed
    /// rather than waiting for the garbage collector — as with `cloneKey()`, each
    /// copy keeps the secret in native memory until it is dropped, and dropping
    /// does not wipe it.
    #[flutter_rust_bridge::frb(sync)]
    pub fn from_keys(
        public_key: &KyberPublicKey,
        secret_key: &KyberSecretKey,
    ) -> Result<KyberKeyPair, LibSignalException> {
        let (public_key, secret_key) = (&public_key.inner, &secret_key.inner);
        // Checked first so a mismatch fails with an error naming both types;
        // `decapsulate` below would refuse it too, with `WrongKEMKeyType`. The
        // pair is built as a struct literal, so `NativeKeyPair::new`, which
        // asserts on this condition, is never reached.
        if public_key.key_type() != secret_key.key_type() {
            return Err(LibSignalException::new(
                LibSignalErrorCode::InvalidKey,
                format!(
                    "Kyber key type mismatch: public key is {:?}, secret key is {:?}",
                    public_key.key_type(),
                    secret_key.key_type()
                ),
            ));
        }

        // SECURITY: `Zeroizing` wipes the two copies of the shared secret this
        // function holds, on every return path; the copies inside the upstream
        // KEM calls are out of its reach. The comparison is constant-time, as
        // pair-wise consistency tests conventionally are, even though whether
        // the secrets match is exactly what this call reports.
        let (sent, ciphertext) = public_key
            .encapsulate(&mut OsRng.unwrap_err())
            .map_err(LibSignalException::from)?;
        let sent = Zeroizing::new(sent);
        let received = Zeroizing::new(
            secret_key
                .decapsulate(&ciphertext)
                .map_err(LibSignalException::from)?,
        );
        if !bool::from(sent[..].ct_eq(&received[..])) {
            return Err(LibSignalException::new(
                LibSignalErrorCode::InvalidKey,
                "Kyber public key and secret key are not halves of the same key pair",
            ));
        }

        Ok(KyberKeyPair {
            inner: NativeKeyPair {
                public_key: public_key.clone(),
                secret_key: secret_key.clone(),
            },
        })
    }

    /// Get the public key from this key pair.
    #[flutter_rust_bridge::frb(sync)]
    pub fn get_public_key(&self) -> Result<KyberPublicKey, LibSignalException> {
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
    pub fn get_secret_key(&self) -> Result<KyberSecretKey, LibSignalException> {
        Ok(KyberSecretKey {
            inner: self.inner.secret_key.clone(),
        })
    }

    /// Clone this Kyber key pair.
    ///
    /// # Security
    /// This duplicates the pair's sensitive secret key material into a second
    /// independent object. Each copy holds the secret in native memory until it
    /// is dropped, so every copy must be handled with the same care as the
    /// original. In security-critical applications, call `dispose()` on the Dart
    /// side of each copy as soon as it is no longer needed rather than waiting
    /// for the garbage collector, and avoid making copies you do not need.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_key(&self) -> Result<KyberKeyPair, LibSignalException> {
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
    ) -> Result<KyberPreKeyRecord, LibSignalException> {
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
    pub fn deserialize(mut bytes: Vec<u8>) -> Result<KyberPreKeyRecord, LibSignalException> {
        let result =
            NativeKyberPreKeyRecord::deserialize(&bytes).map_err(LibSignalException::from);
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
    pub fn serialize(&self) -> Result<Vec<u8>, LibSignalException> {
        self.inner.serialize().map_err(LibSignalException::from)
    }

    /// Get the ID of this Kyber pre-key record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn id(&self) -> Result<u32, LibSignalException> {
        let id = self.inner.id().map_err(LibSignalException::from)?;
        Ok(id.into())
    }

    /// Get the timestamp of this Kyber pre-key record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn timestamp(&self) -> Result<u64, LibSignalException> {
        let ts = self.inner.timestamp().map_err(LibSignalException::from)?;
        Ok(ts.epoch_millis())
    }

    /// Get the signature of this Kyber pre-key record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn signature(&self) -> Result<Vec<u8>, LibSignalException> {
        self.inner.signature().map_err(LibSignalException::from)
    }

    /// Get the public key from this Kyber pre-key record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn get_public_key(&self) -> Result<KyberPublicKey, LibSignalException> {
        let native = self.inner.public_key().map_err(LibSignalException::from)?;
        Ok(KyberPublicKey::from_native(native))
    }

    /// Get the secret key from this Kyber pre-key record.
    ///
    /// # Security
    /// The returned key contains sensitive secret key material. When serialized,
    /// the caller is responsible for securely zeroing those bytes when done.
    /// Consider using `SecureBytes.wrap()` on the Dart side after serialization.
    #[flutter_rust_bridge::frb(sync)]
    pub fn get_secret_key(&self) -> Result<KyberSecretKey, LibSignalException> {
        let native = self.inner.secret_key().map_err(LibSignalException::from)?;
        Ok(KyberSecretKey::from_native(native))
    }

    /// Get the key pair from this Kyber pre-key record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn get_key_pair(&self) -> Result<KyberKeyPair, LibSignalException> {
        let native = self.inner.key_pair().map_err(LibSignalException::from)?;
        Ok(KyberKeyPair::from_native(native))
    }

    /// Clone this Kyber pre-key record.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_record(&self) -> Result<KyberPreKeyRecord, LibSignalException> {
        Ok(KyberPreKeyRecord {
            inner: self.inner.clone(),
        })
    }
}
