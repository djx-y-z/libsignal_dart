//! Sealed Sender API for anonymous Signal Protocol messaging.
//!
//! Sealed Sender allows sending messages without revealing the sender's
//! identity to the server. Only the recipient can decrypt and learn who
//! sent the message.
//!
//! # Security
//!
//! All sensitive cryptographic data is explicitly zeroed after use via the `zeroize` crate.

use flutter_rust_bridge::DartFnFuture;
use futures::executor::block_on;
use libsignal_protocol::{
    IdentityKeyPair, InMemIdentityKeyStore, InMemSessionStore, InMemPreKeyStore,
    InMemSignedPreKeyStore, InMemKyberPreKeyStore, ProtocolAddress, PublicKey,
    SenderCertificate, SessionStore as SessionStoreTrait,
    PreKeyStore, SignedPreKeyStore, KyberPreKeyStore,
    PreKeyId, SignedPreKeyId, KyberPreKeyId,
    PreKeyRecord, GenericSignedPreKey, SignedPreKeyRecord, KyberPreKeyRecord,
    SignalProtocolError, CiphertextMessageType,
};
use rand::{TryRngCore as _, rngs::OsRng};
use zeroize::Zeroize;

// ============================================================================
// CERTIFICATE FUNCTIONS (sync, no callbacks needed)
// ============================================================================

/// Validate a sender certificate.
///
/// Returns true if valid, throws an error if invalid or expired.
#[flutter_rust_bridge::frb(sync)]
pub fn validate_sender_certificate(
    certificate: Vec<u8>,
    trust_root: Vec<u8>,
    timestamp: u64,
) -> Result<bool, String> {
    let cert = SenderCertificate::deserialize(&certificate).map_err(|e| e.to_string())?;
    let root = PublicKey::deserialize(&trust_root).map_err(|e| e.to_string())?;
    let ts = libsignal_protocol::Timestamp::from_epoch_millis(timestamp);

    let is_valid = cert.validate(&root, ts).map_err(|e| e.to_string())?;
    if !is_valid {
        return Err("Sender certificate validation failed".to_string());
    }
    Ok(true)
}

/// Get the sender name from a sender certificate.
#[flutter_rust_bridge::frb(sync)]
pub fn sender_certificate_get_sender_name(certificate: Vec<u8>) -> Result<String, String> {
    let cert = SenderCertificate::deserialize(&certificate).map_err(|e| e.to_string())?;
    Ok(cert.sender_uuid().map_err(|e| e.to_string())?.to_string())
}

/// Get the sender device ID from a sender certificate.
#[flutter_rust_bridge::frb(sync)]
pub fn sender_certificate_get_sender_device_id(certificate: Vec<u8>) -> Result<u32, String> {
    let cert = SenderCertificate::deserialize(&certificate).map_err(|e| e.to_string())?;
    Ok(cert.sender_device_id().map_err(|e| e.to_string())?.into())
}

/// Get the sender public key from a sender certificate.
#[flutter_rust_bridge::frb(sync)]
pub fn sender_certificate_get_key(certificate: Vec<u8>) -> Result<Vec<u8>, String> {
    let cert = SenderCertificate::deserialize(&certificate).map_err(|e| e.to_string())?;
    Ok(cert.key().map_err(|e| e.to_string())?.serialize().into_vec())
}

/// Get the expiration timestamp from a sender certificate.
#[flutter_rust_bridge::frb(sync)]
pub fn sender_certificate_get_expiration(certificate: Vec<u8>) -> Result<u64, String> {
    let cert = SenderCertificate::deserialize(&certificate).map_err(|e| e.to_string())?;
    Ok(cert.expiration().map_err(|e| e.to_string())?.epoch_millis())
}

// ============================================================================
// TEST CERTIFICATE CREATION (for testing sealed sender)
// ============================================================================

/// Create a server certificate for testing.
///
/// # Parameters
/// - `key_id` - A unique identifier for this server certificate
/// - `server_public_key` - The server's public key to be certified
/// - `trust_root_private_key` - The trust root's private key for signing
///
/// # Returns
/// The serialized server certificate.
#[flutter_rust_bridge::frb(sync)]
pub fn create_server_certificate(
    key_id: u32,
    server_public_key: Vec<u8>,
    trust_root_private_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let server_key = PublicKey::deserialize(&server_public_key).map_err(|e| e.to_string())?;
    let trust_root = libsignal_protocol::PrivateKey::deserialize(&trust_root_private_key)
        .map_err(|e| e.to_string())?;

    let cert = libsignal_protocol::ServerCertificate::new(
        key_id,
        server_key,
        &trust_root,
        &mut OsRng.unwrap_err(),
    ).map_err(|e| e.to_string())?;

    cert.serialized().map_err(|e| e.to_string()).map(|b| b.to_vec())
}

/// Create a sender certificate for testing.
///
/// # Parameters
/// - `sender_uuid` - The sender's UUID (e.g., "abc-123")
/// - `sender_device_id` - The sender's device ID
/// - `sender_identity_key` - The sender's identity public key
/// - `expiration` - Certificate expiration timestamp (milliseconds since epoch)
/// - `server_certificate` - The server certificate (serialized)
/// - `server_private_key` - The server's private key for signing
///
/// # Returns
/// The serialized sender certificate.
#[flutter_rust_bridge::frb(sync)]
pub fn create_sender_certificate(
    sender_uuid: String,
    sender_device_id: u32,
    sender_identity_key: Vec<u8>,
    expiration: u64,
    server_certificate: Vec<u8>,
    server_private_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let identity_key = PublicKey::deserialize(&sender_identity_key).map_err(|e| e.to_string())?;
    let server_cert = libsignal_protocol::ServerCertificate::deserialize(&server_certificate)
        .map_err(|e| e.to_string())?;
    let server_key = libsignal_protocol::PrivateKey::deserialize(&server_private_key)
        .map_err(|e| e.to_string())?;

    let device_id = libsignal_protocol::DeviceId::try_from(sender_device_id)
        .map_err(|_| "Invalid device ID")?;
    let exp_ts = libsignal_protocol::Timestamp::from_epoch_millis(expiration);

    let cert = SenderCertificate::new(
        sender_uuid,
        None, // e164 not needed for testing
        identity_key,
        device_id,
        exp_ts,
        server_cert,
        &server_key,
        &mut OsRng.unwrap_err(),
    ).map_err(|e| e.to_string())?;

    cert.serialized().map_err(|e| e.to_string()).map(|b| b.to_vec())
}

// ============================================================================
// SEALED SENDER ENCRYPT with DartFn callbacks
// ============================================================================

/// Result of sealed sender encryption.
pub struct SealedSenderEncryptResult {
    /// The sealed sender ciphertext.
    pub ciphertext: Vec<u8>,
    /// The updated session record.
    pub session_record: Vec<u8>,
}

/// Encrypt a message using Sealed Sender (anonymous delivery).
///
/// # Callbacks
/// - `load_session(name, device_id)` - Load existing session (required)
/// - `store_session(name, device_id, bytes)` - Store the updated session
/// - `get_identity_key_pair()` - Get our identity key pair
/// - `get_local_registration_id()` - Get our registration ID
///
/// # Parameters
/// - `recipient_name` - Recipient's user identifier
/// - `recipient_device_id` - Recipient's device ID
/// - `plaintext` - The message to encrypt
/// - `sender_certificate` - Our sender certificate (serialized)
// FRB entry point: carries the SessionStore + IdentityKeyStore callbacks, so
// the argument count mirrors the Signal store interface, not a refactor smell.
#[allow(clippy::too_many_arguments)]
pub async fn sealed_sender_encrypt_with_callbacks(
    recipient_name: String,
    recipient_device_id: u32,
    plaintext: Vec<u8>,
    sender_certificate: Vec<u8>,
    // SessionStore callbacks
    load_session: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    store_session: impl Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
    // IdentityKeyStore callbacks
    get_identity_key_pair: impl Fn() -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
    get_local_registration_id: impl Fn() -> DartFnFuture<u32> + Send + Sync + 'static,
    get_identity: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
) -> Result<SealedSenderEncryptResult, String> {
    // Step 1: Load data via callbacks
    let mut session_bytes = load_session(recipient_name.clone(), recipient_device_id).await
        .ok_or("No session found - cannot encrypt without established session")?;
    let mut identity_key_pair_bytes = get_identity_key_pair().await;
    let local_registration_id = get_local_registration_id().await;
    // Previously-trusted identity for this recipient (None on first contact).
    let known_recipient_identity = get_identity(recipient_name.clone(), recipient_device_id).await;

    // Step 2: Perform encryption
    let result = sealed_sender_encrypt_inner(
        &recipient_name,
        recipient_device_id,
        &plaintext,
        &sender_certificate,
        &session_bytes,
        &identity_key_pair_bytes,
        local_registration_id,
        &known_recipient_identity,
    );

    // SECURITY: Zeroize sensitive data
    session_bytes.zeroize();
    identity_key_pair_bytes.zeroize();

    let (ciphertext, updated_session_bytes) = result?;

    // Step 3: Store updated session
    store_session(recipient_name, recipient_device_id, updated_session_bytes.clone()).await;

    Ok(SealedSenderEncryptResult {
        ciphertext,
        session_record: updated_session_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
fn sealed_sender_encrypt_inner(
    recipient_name: &str,
    recipient_device_id: u32,
    plaintext: &[u8],
    sender_certificate: &[u8],
    session_bytes: &[u8],
    identity_key_pair_bytes: &[u8],
    local_registration_id: u32,
    known_recipient_identity: &Option<Vec<u8>>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Parse sender certificate
    let cert = SenderCertificate::deserialize(sender_certificate)
        .map_err(|e| e.to_string())?;

    // Parse identity
    let our_identity = IdentityKeyPair::try_from(identity_key_pair_bytes)
        .map_err(|e| e.to_string())?;

    // Parse session
    let session = libsignal_protocol::SessionRecord::deserialize(session_bytes)
        .map_err(|e| e.to_string())?;

    let recipient_address = ProtocolAddress::new(
        recipient_name.to_string(),
        recipient_device_id.try_into().map_err(|_| "Invalid device ID")?,
    );

    // Create in-memory stores
    let mut session_store = InMemSessionStore::new();
    let mut identity_store = InMemIdentityKeyStore::new(our_identity, local_registration_id);

    // SECURITY: enforce identity-trust for the recipient (see preseed_identity).
    // sealed_sender_encrypt goes through libsignal's message_encrypt, which
    // consults is_trusted_identity(Sending), so a stored identity that differs
    // from the session's yields UntrustedIdentity.
    super::preseed_identity(&mut identity_store, &recipient_address, known_recipient_identity)?;

    // Populate session store
    block_on(async {
        session_store.store_session(&recipient_address, &session).await
    }).map_err(|e| e.to_string())?;

    // Perform sealed sender encryption
    let ciphertext = block_on(async {
        libsignal_protocol::sealed_sender_encrypt(
            &recipient_address,
            &cert,
            plaintext,
            &mut session_store,
            &mut identity_store,
            crate::current_time(),
            &mut OsRng.unwrap_err(),
        ).await
    }).map_err(|e| e.to_string())?;

    // Get updated session
    let updated_session = block_on(async {
        SessionStoreTrait::load_session(&session_store, &recipient_address).await
    }).map_err(|e| e.to_string())?
        .ok_or("Session not found after encryption")?;

    let session_bytes = updated_session.serialize().map_err(|e| e.to_string())?;

    Ok((ciphertext, session_bytes))
}

// ============================================================================
// SEALED SENDER DECRYPT with DartFn callbacks
// ============================================================================

/// Result of sealed sender decryption.
pub struct SealedSenderDecryptResult {
    /// The decrypted plaintext.
    pub plaintext: Vec<u8>,
    /// The sender's name (UUID).
    pub sender_name: String,
    /// The sender's device ID.
    pub sender_device_id: u32,
    /// The sender's identity key (for verification).
    pub sender_identity_key: Vec<u8>,
    /// The updated or new session record.
    pub session_record: Vec<u8>,
    /// Pre-key ID to remove (if a one-time pre-key was used).
    pub pre_key_to_remove: Option<u32>,
}

/// Decrypt a Sealed Sender message.
///
/// # Callbacks
/// SessionStore:
/// - `load_session(name, device_id)` - Load existing session
/// - `store_session(name, device_id, bytes)` - Store session
///
/// IdentityKeyStore:
/// - `get_identity_key_pair()` - Get our identity key pair
/// - `get_local_registration_id()` - Get our registration ID
/// - `save_identity(name, device_id, identity_bytes)` - Save sender's identity
///
/// PreKeyStores:
/// - `load_signed_pre_key(id)` - Load signed pre-key
/// - `load_pre_key(id)` - Load one-time pre-key
/// - `load_kyber_pre_key(id)` - Load Kyber pre-key
///
/// # Parameters
/// - `ciphertext` - The sealed sender ciphertext
/// - `trust_root` - Server's trust root public key
/// - `timestamp` - Current timestamp for certificate validation
/// - `local_name` - Our user identifier (UUID)
/// - `local_device_id` - Our device ID
#[allow(clippy::too_many_arguments)]
pub async fn sealed_sender_decrypt_with_callbacks(
    ciphertext: Vec<u8>,
    trust_root: Vec<u8>,
    timestamp: u64,
    local_name: String,
    local_device_id: u32,
    // SessionStore callbacks
    load_session: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    store_session: impl Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
    // IdentityKeyStore callbacks
    get_identity_key_pair: impl Fn() -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
    get_local_registration_id: impl Fn() -> DartFnFuture<u32> + Send + Sync + 'static,
    save_identity: impl Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
    // PreKeyStore callbacks
    load_signed_pre_key: impl Fn(u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    load_pre_key: impl Fn(u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    load_kyber_pre_key: impl Fn(u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    get_identity: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
) -> Result<SealedSenderDecryptResult, String> {
    // Step 1: Load identity data
    let mut identity_key_pair_bytes = get_identity_key_pair().await;
    let local_registration_id = get_local_registration_id().await;

    // Step 2: Decrypt to get sender info (we need this to load the right session)
    let result = sealed_sender_decrypt_inner(
        &ciphertext,
        &trust_root,
        timestamp,
        &local_name,
        local_device_id,
        &identity_key_pair_bytes,
        local_registration_id,
        &load_session,
        &load_signed_pre_key,
        &load_pre_key,
        &load_kyber_pre_key,
        &get_identity,
    ).await;

    // SECURITY: Zeroize identity key bytes
    identity_key_pair_bytes.zeroize();

    let (plaintext, sender_name, sender_device_id, sender_identity_key, session_bytes, pre_key_to_remove) = result?;

    // Step 3: Store results
    store_session(sender_name.clone(), sender_device_id, session_bytes.clone()).await;
    save_identity(sender_name.clone(), sender_device_id, sender_identity_key.clone()).await;

    Ok(SealedSenderDecryptResult {
        plaintext,
        sender_name,
        sender_device_id,
        sender_identity_key,
        session_record: session_bytes,
        pre_key_to_remove,
    })
}

#[allow(clippy::too_many_arguments)]
async fn sealed_sender_decrypt_inner<
    LoadSessionFn,
    LoadSignedPreKeyFn,
    LoadPreKeyFn,
    LoadKyberPreKeyFn,
    GetIdentityFn,
>(
    ciphertext: &[u8],
    trust_root: &[u8],
    timestamp: u64,
    local_name: &str,
    local_device_id: u32,
    identity_key_pair_bytes: &[u8],
    local_registration_id: u32,
    load_session: &LoadSessionFn,
    load_signed_pre_key: &LoadSignedPreKeyFn,
    load_pre_key: &LoadPreKeyFn,
    load_kyber_pre_key: &LoadKyberPreKeyFn,
    get_identity: &GetIdentityFn,
) -> Result<(Vec<u8>, String, u32, Vec<u8>, Vec<u8>, Option<u32>), String>
where
    LoadSessionFn: Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync,
    LoadSignedPreKeyFn: Fn(u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync,
    LoadPreKeyFn: Fn(u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync,
    LoadKyberPreKeyFn: Fn(u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync,
    GetIdentityFn: Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync,
{
    // Parse trust root
    let root = PublicKey::deserialize(trust_root).map_err(|e| e.to_string())?;
    let ts = libsignal_protocol::Timestamp::from_epoch_millis(timestamp);

    // Parse our identity
    let our_identity = IdentityKeyPair::try_from(identity_key_pair_bytes)
        .map_err(|e| e.to_string())?;

    // Create in-memory stores
    let mut session_store = InMemSessionStore::new();
    let mut identity_store = InMemIdentityKeyStore::new(our_identity, local_registration_id);
    let mut prekey_store = InMemPreKeyStore::new();
    let mut signed_prekey_store = InMemSignedPreKeyStore::new();
    let mut kyber_prekey_store = InMemKyberPreKeyStore::new();

    // Use sealed_sender_decrypt_to_usmc to get the message content info
    let usmc = block_on(async {
        libsignal_protocol::sealed_sender_decrypt_to_usmc(
            ciphertext,
            &identity_store,
        ).await
    }).map_err(|e| e.to_string())?;

    // Get sender info from the USMC
    let sender_cert = usmc.sender().map_err(|e| e.to_string())?;

    // Validate sender certificate against trust root
    if !sender_cert.validate(&root, ts).map_err(|e| e.to_string())? {
        return Err("Sender certificate validation failed".to_string());
    }

    let sender_name = sender_cert.sender_uuid().map_err(|e| e.to_string())?.to_string();
    let sender_device_id: u32 = sender_cert.sender_device_id().map_err(|e| e.to_string())?.into();
    let sender_identity_key = sender_cert.key().map_err(|e| e.to_string())?.serialize().to_vec();

    let sender_address = ProtocolAddress::new(
        sender_name.clone(),
        sender_device_id.try_into().map_err(|_| "Invalid sender device ID")?,
    );

    // SECURITY: enforce identity-trust against the previously-trusted identity
    // for this cert-derived sender before establishing/advancing the session
    // (see preseed_identity). Matters for the pre-key branch below, where
    // libsignal's is_trusted_identity is consulted.
    let known_sender_identity = get_identity(sender_name.clone(), sender_device_id).await;
    super::preseed_identity(&mut identity_store, &sender_address, &known_sender_identity)?;

    // Load existing session if we have one
    if let Some(session_bytes) = load_session(sender_name.clone(), sender_device_id).await {
        let existing = libsignal_protocol::SessionRecord::deserialize(&session_bytes)
            .map_err(|e| format!("Failed to deserialize existing session: {}", e))?;
        block_on(async {
            session_store.store_session(&sender_address, &existing).await
        }).map_err(|e| format!("Failed to store existing session: {}", e))?;
    }

    // Get message type and content from USMC
    let msg_type = usmc.msg_type()
        .map_err(|e| format!("Failed to get message type from USMC: {}", e))?;
    let message_bytes = usmc.contents()
        .map_err(|e| format!("Failed to get contents from USMC: {}", e))?;

    let local_address = ProtocolAddress::new(
        local_name.to_string(),
        local_device_id.try_into().map_err(|_| "Invalid local device ID")?,
    );

    let mut pre_key_to_remove: Option<u32> = None;

    let plaintext = if msg_type == CiphertextMessageType::PreKey {
        // Parse as pre-key message to get key IDs
        let prekey_message = libsignal_protocol::PreKeySignalMessage::try_from(message_bytes)
            .map_err(|e| e.to_string())?;

        let signed_pre_key_id: u32 = prekey_message.signed_pre_key_id().into();
        let pre_key_id: Option<u32> = prekey_message.pre_key_id().map(|id| id.into());
        let kyber_pre_key_id: Option<u32> = prekey_message.kyber_pre_key_id().map(|id| id.into());

        // Load pre-keys
        let mut signed_pre_key_bytes = load_signed_pre_key(signed_pre_key_id)
            .await
            .ok_or_else(|| format!("Signed pre-key {} not found", signed_pre_key_id))?;
        let signed_prekey_record = SignedPreKeyRecord::deserialize(&signed_pre_key_bytes)
            .map_err(|e: SignalProtocolError| e.to_string())?;
        block_on(async {
            signed_prekey_store.save_signed_pre_key(SignedPreKeyId::from(signed_pre_key_id), &signed_prekey_record).await
        }).map_err(|e| e.to_string())?;
        signed_pre_key_bytes.zeroize();

        if let Some(id) = pre_key_id
            && let Some(mut bytes) = load_pre_key(id).await
        {
            let prekey_record = PreKeyRecord::deserialize(&bytes)
                .map_err(|e| e.to_string())?;
            block_on(async {
                prekey_store.save_pre_key(PreKeyId::from(id), &prekey_record).await
            }).map_err(|e| e.to_string())?;
            bytes.zeroize();
            pre_key_to_remove = Some(id);
        }

        if let Some(id) = kyber_pre_key_id
            && let Some(mut bytes) = load_kyber_pre_key(id).await
        {
            let kyber_prekey_record = KyberPreKeyRecord::deserialize(&bytes)
                .map_err(|e: SignalProtocolError| e.to_string())?;
            block_on(async {
                kyber_prekey_store.save_kyber_pre_key(KyberPreKeyId::from(id), &kyber_prekey_record).await
            }).map_err(|e| e.to_string())?;
            bytes.zeroize();
        }

        // Decrypt pre-key message
        block_on(async {
            libsignal_protocol::message_decrypt_prekey(
                &prekey_message,
                &sender_address,
                &local_address,
                &mut session_store,
                &mut identity_store,
                &mut prekey_store,
                &signed_prekey_store,
                &mut kyber_prekey_store,
                &mut OsRng.unwrap_err(),
            ).await
        }).map_err(|e| e.to_string())?
    } else if msg_type == CiphertextMessageType::Whisper {
        // Regular signal message
        let signal_message = libsignal_protocol::SignalMessage::try_from(message_bytes)
            .map_err(|e| e.to_string())?;

        block_on(async {
            libsignal_protocol::message_decrypt_signal(
                &signal_message,
                &sender_address,
                &local_address,
                &mut session_store,
                &mut identity_store,
                &mut OsRng.unwrap_err(),
            ).await
        }).map_err(|e| e.to_string())?
    } else {
        return Err(format!("Unsupported message type: {:?}", msg_type));
    };

    // Get updated session
    let updated_session = block_on(async {
        SessionStoreTrait::load_session(&session_store, &sender_address).await
    }).map_err(|e| e.to_string())?
        .ok_or("Session not found after decryption")?;

    let session_bytes = updated_session.serialize().map_err(|e| e.to_string())?;

    Ok((plaintext, sender_name, sender_device_id, sender_identity_key, session_bytes, pre_key_to_remove))
}
