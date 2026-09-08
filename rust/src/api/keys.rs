//! Key management API using libsignal-protocol.

use libsignal_protocol::{
    IdentityKey, IdentityKeyPair as NativeIdentityKeyPair, KeyPair,
    PrivateKey as NativePrivateKey, PublicKey as NativePublicKey,
};
use rand::{TryRngCore as _, rngs::OsRng};
use zeroize::Zeroize;

/// A private key for X25519/Ed25519 operations.
pub struct PrivateKey {
    inner: NativePrivateKey,
}

impl PrivateKey {
    /// Create from native libsignal PrivateKey.
    pub(crate) fn from_native(key: NativePrivateKey) -> Self {
        Self { inner: key }
    }

    /// Get the inner native key (for use by other modules).
    pub(crate) fn native(&self) -> &NativePrivateKey {
        &self.inner
    }

    /// Generate a new random private key.
    #[flutter_rust_bridge::frb(sync)]
    pub fn generate() -> Result<PrivateKey, String> {
        let key_pair = KeyPair::generate(&mut OsRng.unwrap_err());
        Ok(PrivateKey {
            inner: key_pair.private_key,
        })
    }

    /// Deserialize a private key from bytes.
    ///
    /// # Security
    /// The input bytes are securely zeroized after deserialization.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(mut bytes: Vec<u8>) -> Result<PrivateKey, String> {
        let result = NativePrivateKey::deserialize(&bytes).map_err(|e| e.to_string());
        bytes.zeroize(); // SECURITY: Zeroize input bytes
        Ok(PrivateKey { inner: result? })
    }

    /// Serialize this private key to bytes.
    ///
    /// # Security
    /// The returned bytes contain sensitive key material. The caller is responsible
    /// for securely zeroing these bytes when done. Consider using `SecureBytes.wrap()`
    /// on the Dart side to ensure automatic zeroing.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.serialize())
    }

    /// Get the public key corresponding to this private key.
    #[flutter_rust_bridge::frb(sync)]
    pub fn get_public_key(&self) -> Result<PublicKey, String> {
        let native_pub = self.inner.public_key().map_err(|e| e.to_string())?;
        Ok(PublicKey { inner: native_pub })
    }

    /// Sign a message with this private key.
    #[flutter_rust_bridge::frb(sync)]
    pub fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, String> {
        let signature = self
            .inner
            .calculate_signature(&message, &mut OsRng.unwrap_err())
            .map_err(|e| e.to_string())?;
        Ok(signature.into_vec())
    }

    /// Perform X25519 key agreement with a public key.
    ///
    /// This is the raw Diffie-Hellman primitive and nothing more: 32 bytes out,
    /// no derivation, no ratchet, no replay protection. Ordinary Signal
    /// Protocol use never needs it — `SessionBuilder` and `SessionCipher`
    /// perform every agreement the protocol calls for, together with the
    /// derivation and ratcheting that make those agreements safe. Reach for
    /// this only when building a protocol this package does not implement.
    ///
    /// # Security
    /// The returned shared secret is highly sensitive cryptographic material.
    /// The caller is responsible for securely zeroing these bytes when done.
    /// Consider using `SecureBytes.wrap()` on the Dart side to ensure automatic zeroing.
    ///
    /// **The result is not a key.** X25519 returns the x-coordinate of a curve
    /// point, which is a field element rather than a uniformly distributed
    /// 32-byte string, so using it directly to encrypt is a mistake even though
    /// the bytes look random. Put it through a KDF first and use that output —
    /// `hkdfDerive` on this same surface takes it as `inputKeyMaterial`.
    ///
    /// One agreement between two long-lived keys yields the same secret every
    /// time it is computed, so on its own this offers no forward secrecy: a
    /// private key compromised later opens everything ever derived from it.
    /// Forward secrecy comes from ratcheting over ephemeral keys, which is what
    /// the session API does and what a caller of this method must build.
    ///
    /// An all-zero shared secret — what a low-order public key produces — is
    /// rejected in constant time and surfaces as a thrown error rather than as
    /// 32 zero bytes. That check catches the degenerate result only; validating
    /// that the peer's public key is the one expected remains the caller's job,
    /// and this method authenticates nothing.
    #[flutter_rust_bridge::frb(sync)]
    pub fn agree(&self, public_key: &PublicKey) -> Result<Vec<u8>, String> {
        let shared = self
            .inner
            .calculate_agreement(&public_key.inner)
            .map_err(|e| e.to_string())?;
        Ok(shared.into_vec())
    }

    /// Create a copy of this private key.
    ///
    /// # Security
    /// This duplicates sensitive secret key material into a second independent
    /// object. Each copy holds the secret in native memory until it is dropped,
    /// so every copy must be handled with the same care as the original.
    /// In security-critical applications, call `dispose()` on the Dart side of
    /// each copy as soon as it is no longer needed rather than waiting for the
    /// garbage collector, and avoid making copies you do not need.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_key(&self) -> Result<PrivateKey, String> {
        // PrivateKey is Copy, so we can just copy it
        Ok(PrivateKey { inner: self.inner })
    }
}

/// A public key for X25519/Ed25519 operations.
pub struct PublicKey {
    inner: NativePublicKey,
}

impl PublicKey {
    /// Create from native libsignal PublicKey.
    pub(crate) fn from_native(key: NativePublicKey) -> Self {
        Self { inner: key }
    }

    /// Get the inner native key (for use by other modules).
    pub(crate) fn native(&self) -> &NativePublicKey {
        &self.inner
    }

    /// Deserialize a public key from bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(bytes: Vec<u8>) -> Result<PublicKey, String> {
        let native = NativePublicKey::deserialize(&bytes).map_err(|e| e.to_string())?;

        // Check for low-order points (required for security)
        if !native.is_canonical() {
            return Err("Low-order point".to_string());
        }

        Ok(PublicKey { inner: native })
    }

    /// Serialize this public key to bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.serialize().into_vec())
    }

    /// Verify a signature on a message.
    #[flutter_rust_bridge::frb(sync)]
    pub fn verify(&self, message: Vec<u8>, signature: Vec<u8>) -> Result<bool, String> {
        Ok(self.inner.verify_signature(&message, &signature))
    }

    /// Compare this public key with another.
    ///
    /// Comparison is performed lexicographically on the serialized bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn compare(&self, other: &PublicKey) -> Result<i32, String> {
        use std::cmp::Ordering;
        let self_bytes = self.inner.serialize();
        let other_bytes = other.inner.serialize();
        Ok(match self_bytes.cmp(&other_bytes) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        })
    }

    /// Check if this public key equals another.
    #[flutter_rust_bridge::frb(sync)]
    pub fn equals(&self, other: &PublicKey) -> Result<bool, String> {
        Ok(self.inner == other.inner)
    }

    /// Get the raw public key bytes without the type prefix.
    #[flutter_rust_bridge::frb(sync)]
    pub fn get_public_key_bytes(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.public_key_bytes().to_vec())
    }

    /// Create a copy of this public key.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_key(&self) -> Result<PublicKey, String> {
        // PublicKey is Copy, so we can just copy it
        Ok(PublicKey { inner: self.inner })
    }
}

/// An identity key pair (public and private key for identity).
pub struct IdentityKeyPair {
    inner: NativeIdentityKeyPair,
}

impl IdentityKeyPair {
    /// Create from native libsignal IdentityKeyPair.
    pub(crate) fn from_native(pair: NativeIdentityKeyPair) -> Self {
        Self { inner: pair }
    }

    /// Get the inner native identity key pair (for use by other modules).
    pub(crate) fn native(&self) -> &NativeIdentityKeyPair {
        &self.inner
    }

    /// Generate a new identity key pair.
    #[flutter_rust_bridge::frb(sync)]
    pub fn generate() -> Result<IdentityKeyPair, String> {
        let native = NativeIdentityKeyPair::generate(&mut OsRng.unwrap_err());
        Ok(IdentityKeyPair { inner: native })
    }

    /// Create an identity key pair from existing keys.
    #[flutter_rust_bridge::frb(sync)]
    pub fn from_keys(private_key: PrivateKey, public_key: PublicKey) -> IdentityKeyPair {
        let identity_key = IdentityKey::new(public_key.inner);
        let native = NativeIdentityKeyPair::new(identity_key, private_key.inner);
        IdentityKeyPair { inner: native }
    }

    /// Deserialize an identity key pair from bytes.
    ///
    /// # Security
    /// The input bytes are securely zeroized after deserialization.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(mut bytes: Vec<u8>) -> Result<IdentityKeyPair, String> {
        let result = NativeIdentityKeyPair::try_from(&bytes[..]).map_err(|e| e.to_string());
        bytes.zeroize(); // SECURITY: Zeroize input bytes
        Ok(IdentityKeyPair { inner: result? })
    }

    /// Serialize this identity key pair.
    ///
    /// # Security
    /// The returned bytes contain sensitive key material (including the private key).
    /// The caller is responsible for securely zeroing these bytes when done.
    /// Consider using `SecureBytes.wrap()` on the Dart side to ensure automatic zeroing.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.serialize().into_vec())
    }

    /// Get the public key as serialized bytes.
    #[flutter_rust_bridge::frb(sync, getter)]
    pub fn public_key(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.public_key().serialize().into_vec())
    }

    /// Get the private key as serialized bytes.
    ///
    /// # Security
    /// The returned bytes contain sensitive private key material.
    /// The caller is responsible for securely zeroing these bytes when done.
    /// Consider using `SecureBytes.wrap()` on the Dart side to ensure automatic zeroing.
    ///
    /// If all you need is a signature by the identity key — signing a signed
    /// pre-key or a Kyber pre-key, say — call `identityKeyPair.sign` instead.
    /// It does the same work without copying the long-term secret out of Rust.
    #[flutter_rust_bridge::frb(sync, getter)]
    pub fn private_key(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.private_key().serialize())
    }

    /// Sign a message with this identity key pair's private key.
    ///
    /// This is how a signed pre-key or a Kyber pre-key gets its identity-key
    /// signature, which is what X3DH requires of a published pre-key bundle.
    ///
    /// # Security
    /// Prefer this over reading the `privateKey` getter and rebuilding a
    /// `PrivateKey` from those bytes. The getter copies the long-term identity
    /// secret into the Dart heap, where nothing can zeroize it and it survives
    /// until the garbage collector happens to reclaim it; this method keeps the
    /// secret in Rust for the whole operation.
    ///
    /// It grants no capability the pair did not already have — signing
    /// arbitrary bytes with the identity key is reachable through that same
    /// `privateKey` getter today. It removes a copy of the secret, nothing else.
    ///
    /// Signatures made here are not interchangeable with those from
    /// `signAlternateIdentity`, which signs a domain-separated message rather
    /// than the bytes it is given: a fixed 32-byte prefix and a label precede
    /// the other identity key. A serialized public key cannot begin with that
    /// prefix, so the two uses of the identity key overlap only if a caller
    /// deliberately builds the prefix and passes it as `message`.
    #[flutter_rust_bridge::frb(sync)]
    pub fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, String> {
        let signature = self
            .inner
            .private_key()
            .calculate_signature(&message, &mut OsRng.unwrap_err())
            .map_err(|e| e.to_string())?;
        Ok(signature.into_vec())
    }

    /// Sign an alternate identity key.
    ///
    /// This is used in the multi-device protocol to link devices.
    #[flutter_rust_bridge::frb(sync)]
    pub fn sign_alternate_identity(&self, other_identity: &PublicKey) -> Result<Vec<u8>, String> {
        let other_identity_key = IdentityKey::new(other_identity.inner);
        let signature = self
            .inner
            .sign_alternate_identity(&other_identity_key, &mut OsRng.unwrap_err())
            .map_err(|e| e.to_string())?;
        Ok(signature.into_vec())
    }
}

/// Sign an alternate identity key using separate keys.
///
/// This is a standalone version that doesn't require an IdentityKeyPair.
#[flutter_rust_bridge::frb(sync)]
pub fn identity_keypair_sign_alternate_identity_raw(
    public_key: &PublicKey,
    private_key: &PrivateKey,
    other_identity: &PublicKey,
) -> Result<Vec<u8>, String> {
    let identity_key = IdentityKey::new(public_key.inner);
    let pair = NativeIdentityKeyPair::new(identity_key, private_key.inner);
    let other_identity_key = IdentityKey::new(other_identity.inner);
    let signature = pair
        .sign_alternate_identity(&other_identity_key, &mut OsRng.unwrap_err())
        .map_err(|e| e.to_string())?;
    Ok(signature.into_vec())
}

/// Serialize an identity key pair from separate keys.
///
/// This is a standalone version that doesn't require an IdentityKeyPair.
#[flutter_rust_bridge::frb(sync)]
pub fn identity_keypair_serialize_raw(
    public_key: &PublicKey,
    private_key: &PrivateKey,
) -> Result<Vec<u8>, String> {
    let identity_key = IdentityKey::new(public_key.inner);
    let pair = NativeIdentityKeyPair::new(identity_key, private_key.inner);
    Ok(pair.serialize().into_vec())
}
