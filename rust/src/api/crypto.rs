//! Cryptographic primitives API using libsignal-protocol and standard crypto crates.

use aes_gcm_siv::aead::{Aead, KeyInit, Nonce};
use aes_gcm_siv::Aes256GcmSiv as CipherAes256GcmSiv;
use hkdf::Hkdf;
use libsignal_protocol::{
    Fingerprint as NativeFingerprint, IdentityKey, PublicKey as NativePublicKey,
};
use sha2::Sha256;
use zeroize::Zeroize;

/// Derive keys using HKDF (HMAC-based Key Derivation Function).
///
/// # Arguments
/// * `output_length` - The length of the output key material in bytes
/// * `input_key_material` - The input key material (IKM)
/// * `salt` - Optional salt value (can be empty)
/// * `info` - Optional context/application-specific info (can be empty)
///
/// # Returns
/// The derived key material of the specified length
///
/// # Security
/// Input key material and salt are securely zeroized after use, even on error.
/// The `info` parameter is not zeroized as it's application context (RFC 5869), not a secret.
///
/// Note: The HKDF implementation may create internal copies of key material that cannot
/// be zeroized by this function. However, these copies are stack-allocated and short-lived,
/// being cleared when the `Hkdf` instance goes out of scope.
#[flutter_rust_bridge::frb(sync)]
pub fn hkdf_derive(
    output_length: u32,
    mut input_key_material: Vec<u8>,
    mut salt: Vec<u8>,
    info: Vec<u8>,
) -> Result<Vec<u8>, String> {
    // RFC 5869: HKDF-SHA256 output is limited to 255 * HashLen (8160 bytes).
    // Validate before allocating so an invalid length cannot trigger a huge allocation.
    const MAX_OUTPUT_LENGTH: u32 = 255 * 32;
    if output_length > MAX_OUTPUT_LENGTH {
        input_key_material.zeroize();
        salt.zeroize();
        return Err(format!(
            "HKDF output length {} exceeds maximum {}",
            output_length, MAX_OUTPUT_LENGTH
        ));
    }

    let salt_ref = if salt.is_empty() { None } else { Some(&salt[..]) };
    let hk = Hkdf::<Sha256>::new(salt_ref, &input_key_material);
    let mut output = vec![0u8; output_length as usize];

    let result = hk.expand(&info, &mut output)
        .map_err(|e| format!("HKDF expansion failed: {}", e));

    // SECURITY: Always zeroize regardless of success/failure
    input_key_material.zeroize();
    salt.zeroize();

    result?;
    Ok(output)
}

/// AES-256-GCM-SIV authenticated encryption cipher.
pub struct Aes256GcmSiv {
    cipher: CipherAes256GcmSiv,
}

impl Aes256GcmSiv {
    /// Create a new AES-256-GCM-SIV cipher with the given key.
    ///
    /// # Arguments
    /// * `key` - The 32-byte encryption key
    ///
    /// # Security
    /// The key is securely zeroized after cipher creation, even on error.
    #[flutter_rust_bridge::frb(sync)]
    pub fn new(mut key: Vec<u8>) -> Result<Aes256GcmSiv, String> {
        if key.len() != 32 {
            key.zeroize(); // SECURITY: Zeroize even on error
            return Err(format!("Key must be 32 bytes, got {} bytes", key.len()));
        }

        let key_arr: &[u8; 32] = match key.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                key.zeroize(); // SECURITY: Zeroize on conversion error
                return Err("Failed to convert key".to_string());
            }
        };
        let cipher = CipherAes256GcmSiv::new(key_arr.into());

        // SECURITY: Zeroize key after cipher creation
        key.zeroize();

        Ok(Aes256GcmSiv { cipher })
    }

    /// Encrypt plaintext with the given nonce and associated data.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    /// * `nonce` - 12-byte nonce (must be unique for each encryption)
    /// * `associated_data` - Additional authenticated data (not encrypted)
    #[flutter_rust_bridge::frb(sync)]
    pub fn encrypt(
        &self,
        plaintext: Vec<u8>,
        nonce: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        if nonce.len() != 12 {
            return Err(format!("Nonce must be 12 bytes, got {} bytes", nonce.len()));
        }

        // `Array::from_slice` is deprecated in aead 0.6 in favour of `TryFrom`.
        // The length is already checked above, so this conversion cannot fail;
        // it is still handled rather than unwrapped so a future change to that
        // check cannot turn into a panic across the FFI boundary.
        let nonce_arr = Nonce::<CipherAes256GcmSiv>::try_from(&nonce[..])
            .map_err(|_| format!("Nonce must be 12 bytes, got {} bytes", nonce.len()))?;

        self.cipher
            .encrypt(
                &nonce_arr,
                aes_gcm_siv::aead::Payload {
                    msg: &plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|e| format!("Encryption failed: {}", e))
    }

    /// Decrypt ciphertext with the given nonce and associated data.
    ///
    /// # Arguments
    /// * `ciphertext` - The data to decrypt
    /// * `nonce` - 12-byte nonce (same as used for encryption)
    /// * `associated_data` - Additional authenticated data (same as used for encryption)
    ///
    /// # Security
    /// The returned plaintext may contain sensitive data. The caller is responsible
    /// for securely handling and zeroing the plaintext when done. This is intentional:
    /// the application knows the sensitivity of its data better than this library.
    /// Consider using `SecureBytes.wrap()` on the Dart side if the plaintext is sensitive.
    #[flutter_rust_bridge::frb(sync)]
    pub fn decrypt(
        &self,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        if nonce.len() != 12 {
            return Err(format!("Nonce must be 12 bytes, got {} bytes", nonce.len()));
        }

        // See `encrypt` above for why this is a checked conversion.
        let nonce_arr = Nonce::<CipherAes256GcmSiv>::try_from(&nonce[..])
            .map_err(|_| format!("Nonce must be 12 bytes, got {} bytes", nonce.len()))?;

        self.cipher
            .decrypt(
                &nonce_arr,
                aes_gcm_siv::aead::Payload {
                    msg: &ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|e| format!("Decryption failed: {}", e))
    }
}

/// Identity fingerprint for verifying identity keys.
pub struct Fingerprint {
    inner: NativeFingerprint,
}

impl Fingerprint {
    /// Create a new fingerprint for comparing identity keys.
    ///
    /// # Arguments
    /// * `iterations` - Number of iterations for fingerprint generation
    /// * `version` - Fingerprint protocol version
    /// * `local_identifier` - Local identity (e.g., phone number bytes)
    /// * `local_public_key` - Local identity public key bytes
    /// * `remote_identifier` - Remote identity (e.g., phone number bytes)
    /// * `remote_public_key` - Remote identity public key bytes
    #[flutter_rust_bridge::frb(sync)]
    pub fn new(
        iterations: u32,
        version: u32,
        local_identifier: Vec<u8>,
        local_public_key: Vec<u8>,
        remote_identifier: Vec<u8>,
        remote_public_key: Vec<u8>,
    ) -> Result<Fingerprint, String> {
        let local_pub = NativePublicKey::deserialize(&local_public_key).map_err(|e| e.to_string())?;
        if !local_pub.is_canonical() {
            return Err("Local public key is a low-order point".to_string());
        }
        let remote_pub = NativePublicKey::deserialize(&remote_public_key).map_err(|e| e.to_string())?;
        if !remote_pub.is_canonical() {
            return Err("Remote public key is a low-order point".to_string());
        }
        let local_identity = IdentityKey::new(local_pub);
        let remote_identity = IdentityKey::new(remote_pub);

        let native = NativeFingerprint::new(
            version,
            iterations,
            &local_identifier,
            &local_identity,
            &remote_identifier,
            &remote_identity,
        )
        .map_err(|e| format!("Fingerprint creation failed: {}", e))?;

        Ok(Fingerprint { inner: native })
    }

    /// Get the display string representation of this fingerprint.
    ///
    /// Returns a 60-digit numeric string formatted as 12 groups of 5 digits.
    #[flutter_rust_bridge::frb(sync)]
    pub fn display_string(&self) -> Result<String, String> {
        self.inner
            .display_string()
            .map_err(|e| format!("Failed to get display string: {}", e))
    }

    /// Get the scannable encoding of this fingerprint.
    ///
    /// Returns bytes suitable for encoding in a QR code.
    #[flutter_rust_bridge::frb(sync)]
    pub fn scannable_encoding(&self) -> Result<Vec<u8>, String> {
        self.inner
            .scannable
            .serialize()
            .map_err(|e| format!("Failed to serialize scannable fingerprint: {}", e))
    }

    /// Create a copy of this fingerprint.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_fingerprint(&self) -> Result<Fingerprint, String> {
        Ok(Fingerprint {
            inner: self.inner.clone(),
        })
    }
}

/// Compare two scannable fingerprint encodings.
///
/// # Arguments
/// * `fingerprint1` - First scannable encoding
/// * `fingerprint2` - Second scannable encoding
///
/// # Returns
/// True if the fingerprints match, false otherwise.
#[flutter_rust_bridge::frb(sync)]
pub fn fingerprint_compare(fingerprint1: Vec<u8>, fingerprint2: Vec<u8>) -> Result<bool, String> {
    let scannable1 = libsignal_protocol::ScannableFingerprint::deserialize(&fingerprint1)
        .map_err(|e| format!("Failed to deserialize fingerprint1: {}", e))?;
    scannable1
        .compare(&fingerprint2)
        .map_err(|e| format!("Failed to compare fingerprints: {}", e))
}
