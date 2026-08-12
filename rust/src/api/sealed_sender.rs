//! Sealed Sender API for anonymous Signal Protocol messaging.
//!
//! Sealed Sender allows sending messages without revealing the sender's
//! identity to the server. Only the recipient can decrypt and learn who
//! sent the message.
//!
//! # Security
//!
//! All sensitive cryptographic data is explicitly zeroed after use via the `zeroize` crate.

use crate::recording_stores::{KyberPreKeyUsed, RecordingKyberPreKeyStore, RecordingPreKeyStore};
use flutter_rust_bridge::DartFnFuture;
use futures::executor::block_on;
use libsignal_protocol::{
    IdentityKey, IdentityKeyPair, InMemIdentityKeyStore, InMemSessionStore,
    InMemSignedPreKeyStore, ProtocolAddress, PublicKey,
    SenderCertificate, SessionStore as SessionStoreTrait,
    PreKeyStore, SignedPreKeyStore, KyberPreKeyStore,
    PreKeyId, SignedPreKeyId, KyberPreKeyId,
    PreKeyRecord, GenericSignedPreKey, SignedPreKeyRecord, KyberPreKeyRecord,
    SignalProtocolError, CiphertextMessageType,
    UnidentifiedSenderMessageContent as NativeUnidentifiedSenderMessageContent,
};
use rand::{TryRngCore as _, rngs::OsRng};
use zeroize::{Zeroize, Zeroizing};

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
    // SECURITY: `Zeroizing` rather than a manual `zeroize()` after the call.
    // A Dart store callback that throws panics the worker thread (FRB declares
    // these callbacks non-failable), and a manual zeroize placed after the work
    // is skipped by that unwind. `Drop` is not.
    let session_bytes = Zeroizing::new(
        load_session(recipient_name.clone(), recipient_device_id)
            .await
            .ok_or("No session found - cannot encrypt without established session")?,
    );
    let identity_key_pair_bytes = Zeroizing::new(get_identity_key_pair().await);
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
}

/// Everything the inner decryption produced, for the wrapper to write back.
///
/// The two consumption fields report what libsignal *actually* did, as observed
/// by the recording stores — see [`crate::recording_stores`].
struct SealedSenderDecryptOutcome {
    plaintext: Vec<u8>,
    sender_name: String,
    sender_device_id: u32,
    sender_identity_key: Vec<u8>,
    session_record: Vec<u8>,
    pre_key_to_remove: Option<u32>,
    kyber_pre_key_used: Option<KyberPreKeyUsed>,
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
/// - `remove_pre_key(id)` - Remove a used one-time pre-key
/// - `load_kyber_pre_key(id)` - Load Kyber pre-key
/// - `mark_kyber_pre_key_used(kyber_id, signed_pre_key_id, base_key)` - Mark a
///   Kyber pre-key as used. Same three arguments as on the `SessionCipher`
///   path, mirroring libsignal's `KyberPreKeyStore::mark_kyber_pre_key_used`.
///
/// # Write ordering
/// Identical to `message_decrypt_prekey_with_callbacks`: `save_identity`,
/// `mark_kyber_pre_key_used`, `remove_pre_key`, then `store_session` last, so a
/// crash cannot persist the session while leaving the consumed pre-keys usable.
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
    remove_pre_key: impl Fn(u32) -> DartFnFuture<()> + Send + Sync + 'static,
    load_kyber_pre_key: impl Fn(u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    mark_kyber_pre_key_used: impl Fn(u32, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
    get_identity: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
) -> Result<SealedSenderDecryptResult, String> {
    // Step 1: Load identity data. `Zeroizing` so an unwind out of a throwing
    // store callback cannot leave the private identity key in freed memory.
    let identity_key_pair_bytes = Zeroizing::new(get_identity_key_pair().await);
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

    let outcome = result?;

    // Step 3: Store results, in libsignal's order — `store_session` last, so a
    // crash cannot leave a persisted session next to unconsumed pre-keys.
    save_identity(
        outcome.sender_name.clone(),
        outcome.sender_device_id,
        outcome.sender_identity_key.clone(),
    )
    .await;

    if let Some(used) = outcome.kyber_pre_key_used {
        mark_kyber_pre_key_used(
            used.kyber_pre_key_id,
            used.signed_pre_key_id,
            used.base_key,
        )
        .await;
    }

    if let Some(pk_id) = outcome.pre_key_to_remove {
        remove_pre_key(pk_id).await;
    }

    store_session(
        outcome.sender_name.clone(),
        outcome.sender_device_id,
        outcome.session_record.clone(),
    )
    .await;

    Ok(SealedSenderDecryptResult {
        plaintext: outcome.plaintext,
        sender_name: outcome.sender_name,
        sender_device_id: outcome.sender_device_id,
        sender_identity_key: outcome.sender_identity_key,
        session_record: outcome.session_record,
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
) -> Result<SealedSenderDecryptOutcome, String>
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
    let mut signed_prekey_store = InMemSignedPreKeyStore::new();
    // Recording variants: they report what libsignal consumed rather than what
    // the message referenced. See `crate::recording_stores`.
    let mut prekey_store = RecordingPreKeyStore::new();
    let mut kyber_prekey_store = RecordingKyberPreKeyStore::new();

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

    // SECURITY: upstream's `sealed_sender_decrypt` refuses a message whose
    // certificate names this very device, before it touches any store. This
    // wrapper rebuilds `sealed_sender_decrypt` out of its parts rather than
    // calling it, so the check has to be restated here. Upstream also matches
    // on the sender's E.164; this binding has no local E.164 to compare, so the
    // service id is the whole test.
    if sender_name == local_name && sender_device_id == local_device_id {
        return Err(SignalProtocolError::SealedSenderSelfSend.to_string());
    }

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

    // Load existing session if we have one.
    // SECURITY: a serialized SessionRecord carries root, chain and message
    // keys. `Zeroizing` rather than a manual `zeroize()` at the end, so the
    // bytes are cleared on the `?` paths below and on an unwind too.
    if let Some(session_bytes) = load_session(sender_name.clone(), sender_device_id).await {
        let session_bytes = Zeroizing::new(session_bytes);
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

    Ok(SealedSenderDecryptOutcome {
        plaintext,
        sender_name,
        sender_device_id,
        sender_identity_key,
        session_record: session_bytes,
        // What libsignal actually consumed, straight from the stores it used.
        // The Whisper branch touches neither, so both stay `None` there.
        pre_key_to_remove: prekey_store.take_removed(),
        kyber_pre_key_used: kyber_prekey_store.take_used(),
    })
}

// ============================================================================
// UNIDENTIFIED SENDER MESSAGE CONTENT (USMC)
// ============================================================================

/// The inner, still-sealed payload of a sealed sender message.
///
/// `SealedSenderCipher.encrypt` builds one of these implicitly with a default content
/// hint and no group id. Constructing it yourself is what lets you set those:
/// the **content hint** tells a recipient whether a message it cannot decrypt
/// is worth requesting a resend of, and the **group id** lets it attribute the
/// failure to a group without decrypting.
///
/// Content hint values (`content_hint`), matching libsignal:
/// `0` default, `1` resendable, `2` implicit. Any other value is passed through
/// unchanged.
///
/// # Security
/// Parsing a USMC out of a sealed sender message authenticates it — that is
/// what `sealedSenderDecryptToUsmc` does. Building one locally, or
/// deserializing raw USMC bytes with [UnidentifiedSenderMessageContent.deserialize],
/// does not: the sender certificate it carries is only meaningful once it has
/// been validated against a trusted server certificate.
pub struct UnidentifiedSenderMessageContent {
    inner: NativeUnidentifiedSenderMessageContent,
}

impl UnidentifiedSenderMessageContent {
    /// Build a new USMC.
    ///
    /// - `message_type` is a `CiphertextMessageType` value (2 = signal,
    ///   3 = pre-key, 7 = sender key, 8 = plaintext content)
    /// - `sender_certificate` is the serialized certificate for the sender
    /// - `contents` is the already-encrypted message to wrap
    /// - `group_id` is optional. An empty list is omitted from the serialized
    ///   form, so it survives on this object but reads back as absent after a
    ///   round trip — pass `null` if you mean absent.
    #[flutter_rust_bridge::frb(sync)]
    pub fn new(
        message_type: u8,
        sender_certificate: Vec<u8>,
        contents: Vec<u8>,
        content_hint: u32,
        group_id: Option<Vec<u8>>,
    ) -> Result<UnidentifiedSenderMessageContent, String> {
        let msg_type = CiphertextMessageType::try_from(message_type)
            .map_err(|_| format!("Invalid message type: {}", message_type))?;
        let cert = SenderCertificate::deserialize(&sender_certificate).map_err(|e| e.to_string())?;
        let native = NativeUnidentifiedSenderMessageContent::new(
            msg_type,
            cert,
            contents,
            libsignal_protocol::ContentHint::from(content_hint),
            group_id,
        )
        .map_err(|e: SignalProtocolError| e.to_string())?;
        Ok(UnidentifiedSenderMessageContent { inner: native })
    }

    /// Deserialize a USMC from its serialized form.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(data: Vec<u8>) -> Result<UnidentifiedSenderMessageContent, String> {
        let native = NativeUnidentifiedSenderMessageContent::deserialize(&data)
            .map_err(|e: SignalProtocolError| e.to_string())?;
        Ok(UnidentifiedSenderMessageContent { inner: native })
    }

    /// Serialize the USMC.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        self.inner
            .serialized()
            .map(<[u8]>::to_vec)
            .map_err(|e: SignalProtocolError| e.to_string())
    }

    /// Get the wrapped message's `CiphertextMessageType` value.
    #[flutter_rust_bridge::frb(sync)]
    pub fn message_type(&self) -> Result<u8, String> {
        self.inner
            .msg_type()
            .map(|t| t as u8)
            .map_err(|e: SignalProtocolError| e.to_string())
    }

    /// Get the sender's certificate (serialized).
    #[flutter_rust_bridge::frb(sync)]
    pub fn sender_certificate(&self) -> Result<Vec<u8>, String> {
        let cert = self
            .inner
            .sender()
            .map_err(|e: SignalProtocolError| e.to_string())?;
        cert.serialized()
            .map(<[u8]>::to_vec)
            .map_err(|e: SignalProtocolError| e.to_string())
    }

    /// Get the wrapped (still encrypted) message.
    #[flutter_rust_bridge::frb(sync)]
    pub fn contents(&self) -> Result<Vec<u8>, String> {
        self.inner
            .contents()
            .map(<[u8]>::to_vec)
            .map_err(|e: SignalProtocolError| e.to_string())
    }

    /// Get the content hint.
    #[flutter_rust_bridge::frb(sync)]
    pub fn content_hint(&self) -> Result<u32, String> {
        self.inner
            .content_hint()
            .map(libsignal_protocol::ContentHint::to_u32)
            .map_err(|e: SignalProtocolError| e.to_string())
    }

    /// Get the group id, if the sender set one.
    #[flutter_rust_bridge::frb(sync)]
    pub fn group_id(&self) -> Result<Option<Vec<u8>>, String> {
        self.inner
            .group_id()
            .map(|g| g.map(<[u8]>::to_vec))
            .map_err(|e: SignalProtocolError| e.to_string())
    }
}

/// Seal an already-built USMC for one recipient.
///
/// Unlike `SealedSenderCipher.encrypt` this does no Double Ratchet work — `contents`
/// is whatever you already encrypted — so no session is loaded or stored. It
/// only needs your identity key pair and the recipient's trusted identity.
pub async fn sealed_sender_encrypt_from_usmc_with_callbacks(
    recipient_name: String,
    recipient_device_id: u32,
    usmc: Vec<u8>,
    get_identity_key_pair: impl Fn() -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
    get_local_registration_id: impl Fn() -> DartFnFuture<u32> + Send + Sync + 'static,
    get_identity: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
) -> Result<Vec<u8>, String> {
    // `Zeroizing`: `get_identity` below is a store call that can throw, and a
    // throwing Dart callback unwinds the worker thread past any manual cleanup.
    let identity_key_pair_bytes = Zeroizing::new(get_identity_key_pair().await);
    let local_registration_id = get_local_registration_id().await;
    let recipient_identity = get_identity(recipient_name.clone(), recipient_device_id).await;

    sealed_sender_encrypt_from_usmc_inner(
        &recipient_name,
        recipient_device_id,
        &usmc,
        &identity_key_pair_bytes,
        local_registration_id,
        &recipient_identity,
    )
}

fn sealed_sender_encrypt_from_usmc_inner(
    recipient_name: &str,
    recipient_device_id: u32,
    usmc: &[u8],
    identity_key_pair_bytes: &[u8],
    local_registration_id: u32,
    recipient_identity: &Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let content = NativeUnidentifiedSenderMessageContent::deserialize(usmc)
        .map_err(|e: SignalProtocolError| e.to_string())?;
    let our_identity =
        IdentityKeyPair::try_from(identity_key_pair_bytes).map_err(|e| e.to_string())?;
    let recipient_address = ProtocolAddress::new(
        recipient_name.to_string(),
        recipient_device_id
            .try_into()
            .map_err(|_| "Invalid device ID")?,
    );

    let mut identity_store = InMemIdentityKeyStore::new(our_identity, local_registration_id);
    // This path looks the recipient's identity up directly rather than going
    // through message_encrypt, so without seeding there is nothing to find and
    // libsignal returns SessionNotFound.
    super::preseed_identity(&mut identity_store, &recipient_address, recipient_identity)?;

    block_on(async {
        libsignal_protocol::sealed_sender_encrypt_from_usmc(
            &recipient_address,
            &content,
            &identity_store,
            &mut OsRng.unwrap_err(),
        )
        .await
    })
    .map_err(|e| e.to_string())
}

/// Unseal a sealed sender message down to its USMC without decrypting the
/// message inside it.
///
/// Use it when you need the content hint or group id of a message you cannot
/// decrypt — that is exactly the case a resend request is for.
///
/// # Security
/// Three gates run before the envelope is returned — the same three, in the
/// same order, that `sealedSenderDecryptWithCallbacks` puts in front of its
/// plaintext:
///
/// 1. the sender certificate is validated against `trust_root`;
/// 2. a certificate naming `local_name`/`local_device_id` is refused as a
///    self-send, so your own message reflected back at you cannot be unsealed
///    and attributed to you; and
/// 3. the identity the certificate carries is checked against `get_identity`
///    for that sender, so a *changed* identity key is rejected with the same
///    `untrusted identity` error the decrypt path raises.
///
/// Gate 1 alone is not enough. It proves a server vouched for the certificate,
/// not that the certificate names the peer you have been talking to: a peer
/// that re-registers gets a valid certificate carrying a *new* identity key,
/// which is precisely a safety-number change. Without gate 3 this function
/// would hand that back silently while `SealedSenderCipher.decrypt` refuses it,
/// and a caller acting on `senderCertificate()` or `groupId()` — deciding who
/// to send a resend request to, and for which group — would never see the
/// change.
///
/// One difference from the decrypt path is worth knowing, because it is not a
/// weakening: gate 3 compares the **certificate's** identity key, while the
/// decrypt path lets libsignal compare the key bound into the *session* (or
/// carried by the inner `PreKeySignalMessage`). Upstream never checks that
/// those two agree. Comparing the certificate's key is the right test for a
/// function that hands the certificate back, and it is the stricter of the two
/// — a certificate carrying a key you have not stored is refused here even when
/// the session it wraps would still decrypt.
///
/// **Gate 1 is a deliberate divergence from upstream's factoring.** libsignal
/// splits the two: `sealed_sender_decrypt_to_usmc` performs no validation and
/// `sealed_sender_decrypt` layers it on. This binding merges them, so there is
/// no unchecked variant. The cost is real — a message whose certificate has
/// expired (clock skew, or long-queued delivery) can no longer be unsealed to
/// read its content hint at all — but `SealedSenderCipher.decrypt` already
/// behaves that way, and an unchecked reader is too sharp an edge to expose:
/// libsignal's own
/// `sealed_sender_decrypt_to_usmc` only binds the certificate to whoever sealed
/// the blob, and sealing requires nothing but the recipient's *public* identity
/// key. Without the trust-root check anyone could mint a certificate naming any
/// sender and any group, and a caller reading `senderCertificate()` or
/// `groupId()` off the result would attribute the message — and aim its resend
/// request — wherever the attacker chose.
#[allow(clippy::too_many_arguments)]
pub async fn sealed_sender_decrypt_to_usmc_with_callbacks(
    ciphertext: Vec<u8>,
    trust_root: Vec<u8>,
    timestamp: u64,
    local_name: String,
    local_device_id: u32,
    get_identity_key_pair: impl Fn() -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
    get_local_registration_id: impl Fn() -> DartFnFuture<u32> + Send + Sync + 'static,
    get_identity: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
) -> Result<Vec<u8>, String> {
    // `Zeroizing`: `get_identity` inside is a store call that can throw, and a
    // throwing Dart callback unwinds the worker thread past any manual cleanup.
    let identity_key_pair_bytes = Zeroizing::new(get_identity_key_pair().await);
    let local_registration_id = get_local_registration_id().await;

    sealed_sender_decrypt_to_usmc_inner(
        &ciphertext,
        &trust_root,
        timestamp,
        &local_name,
        local_device_id,
        &identity_key_pair_bytes,
        local_registration_id,
        &get_identity,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn sealed_sender_decrypt_to_usmc_inner<GetIdentityFn>(
    ciphertext: &[u8],
    trust_root: &[u8],
    timestamp: u64,
    local_name: &str,
    local_device_id: u32,
    identity_key_pair_bytes: &[u8],
    local_registration_id: u32,
    get_identity: &GetIdentityFn,
) -> Result<Vec<u8>, String>
where
    GetIdentityFn: Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync,
{
    let our_identity =
        IdentityKeyPair::try_from(identity_key_pair_bytes).map_err(|e| e.to_string())?;
    let root = PublicKey::deserialize(trust_root).map_err(|e| e.to_string())?;
    let ts = libsignal_protocol::Timestamp::from_epoch_millis(timestamp);
    let identity_store = InMemIdentityKeyStore::new(our_identity, local_registration_id);

    // SECURITY: the steps below are ordered, and the order is load-bearing.
    //   1. unseal        — proves whoever sealed this holds the certificate's key
    //   2. validate      — proves a server the caller trusts signed the certificate
    //   3. read sender   — safe only once the certificate is validated
    //   4. self-send     — refuse our own message reflected back at us
    //   5. get_identity  — only now is the sender name safe to look up
    //   6. compare       — safety-number check
    // Do not hoist step 5 above step 2: the sender_uuid of an *unvalidated*
    // certificate is attacker-chosen, so looking a store up by it would turn
    // this callback into an attacker-directed probe of the caller's store.
    // Steps 1-2 and 4-6 are the same gates, in the same order, that
    // `sealed_sender_decrypt_with_callbacks` puts in front of its plaintext.

    // 1.
    let content = block_on(async {
        libsignal_protocol::sealed_sender_decrypt_to_usmc(ciphertext, &identity_store).await
    })
    .map_err(|e| e.to_string())?;

    // 2. Upstream's decrypt_to_usmc stops at "whoever sealed this holds the
    // certificate's key" — the server signature is only checked one level up,
    // in sealed_sender_decrypt. Do it here so the unchecked certificate never
    // reaches Dart.
    let sender_cert = content.sender().map_err(|e: SignalProtocolError| e.to_string())?;
    if !sender_cert
        .validate(&root, ts)
        .map_err(|e: SignalProtocolError| e.to_string())?
    {
        return Err("Sender certificate validation failed".to_string());
    }

    // 3.
    let sender_name = sender_cert
        .sender_uuid()
        .map_err(|e: SignalProtocolError| e.to_string())?
        .to_string();
    let sender_device_id = sender_cert
        .sender_device_id()
        .map_err(|e: SignalProtocolError| e.to_string())?;
    let cert_identity = IdentityKey::new(
        sender_cert
            .key()
            .map_err(|e: SignalProtocolError| e.to_string())?,
    );

    // 4. Upstream's `sealed_sender_decrypt` refuses a message whose certificate
    // names this very device; without it a server that reflects your own
    // message back has you unseal it and report yourself as the sender, and a
    // caller acting on that would aim a resend request at itself. Upstream also
    // matches on the sender's E.164; this binding has no local E.164 to compare,
    // so the service id is the whole test — same as the decrypt path here.
    if sender_name == local_name && u32::from(sender_device_id) == local_device_id {
        return Err(SignalProtocolError::SealedSenderSelfSend.to_string());
    }

    // 5.
    let known_sender_identity = get_identity(sender_name.clone(), sender_device_id.into()).await;

    // 6. Same rule as libsignal's `is_trusted_identity`: no stored identity is
    // first use and is accepted; a stored one must match. Note every failure
    // here is an error — a malformed stored key must never degrade into a
    // skipped check.
    if let Some(bytes) = known_sender_identity {
        let stored = IdentityKey::new(PublicKey::deserialize(&bytes).map_err(|e| e.to_string())?);
        if stored != cert_identity {
            let address = ProtocolAddress::new(sender_name, sender_device_id);
            return Err(SignalProtocolError::UntrustedIdentity(address).to_string());
        }
    }

    content
        .serialized()
        .map(<[u8]>::to_vec)
        .map_err(|e: SignalProtocolError| e.to_string())
}

// ============================================================================
// SEALED SENDER v2 MULTI-RECIPIENT
// ============================================================================

/// One destination of a multi-recipient sealed sender message.
pub struct MultiRecipientDestination {
    /// The recipient's address name (service id string).
    pub name: String,
    /// The recipient's device ID.
    pub device_id: u32,
    /// The serialized `SessionRecord` for that address.
    ///
    /// libsignal reads exactly one thing out of it — `remote_registration_id()`,
    /// a 14-bit number — so these bytes carry root, chain and message keys for
    /// an integer's worth of information. They cannot be narrowed:
    /// `sealed_sender_multi_recipient_encrypt` takes `&SessionRecord`, and
    /// libsignal exposes no way to build one from a registration id. Passing the
    /// record as an FRB opaque handle instead was tried and rejected — it makes
    /// this whole struct opaque, leaving Dart no way to construct a destination.
    /// The bytes are zeroized on every exit from the call — return, error and
    /// panic alike; zero them on the Dart side too (`SecureBytes.wrap`).
    pub session_record: Vec<u8>,
}

/// Encrypt one USMC for many recipients at once (Sealed Sender v2).
///
/// The result is a single *SentMessage* blob addressed to the server, which
/// fans it out into a per-recipient *ReceivedMessage* — see
/// [sealedSenderV2ParseSentMessage]. Sessions are read but never advanced,
/// so nothing needs storing afterwards.
///
/// `excluded_recipients` are service id strings included in the message's
/// recipient list without a payload, which is how Signal tells a server about
/// recipients it deliberately skipped.
///
/// Two constraints Sealed Sender v2 imposes that the single-recipient path does
/// not:
/// - every destination's **address name must be a service id** — a bare UUID or
///   `PNI:<uuid>` — because that is how recipients are addressed on the wire
/// - every destination session's **registration id must fit in 14 bits**
///   (0..=16383); larger values are rejected as invalid
pub async fn sealed_sender_multi_recipient_encrypt_with_callbacks(
    destinations: Vec<MultiRecipientDestination>,
    excluded_recipients: Vec<String>,
    usmc: Vec<u8>,
    get_identity_key_pair: impl Fn() -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
    get_local_registration_id: impl Fn() -> DartFnFuture<u32> + Send + Sync + 'static,
    get_identity: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
) -> Result<Vec<u8>, String> {
    // SECURITY: session records carry root, chain and message keys. They arrive
    // as plain `Vec<u8>` from Dart rather than through a store callback, so this
    // is the only place that can clear them — and the `get_identity` loop below
    // is a store call that can throw, which panics the worker thread and unwinds
    // past any cleanup written after the work. Hence a guard whose `Drop` does
    // it, not a `zeroize()` at the end.
    let destinations = ZeroizingDestinations(destinations);
    let identity_key_pair_bytes = Zeroizing::new(get_identity_key_pair().await);
    let local_registration_id = get_local_registration_id().await;

    // libsignal needs the recipient's identity key, so each destination is
    // seeded from the caller's store; an account it knows nothing about is
    // refused rather than trusted on first use. Note the check is per *account*,
    // not per device: upstream groups contiguous destinations sharing an address
    // name and looks the identity up once for the group, which is correct
    // because SSv2's per-recipient key material is per-account.
    let mut destination_identities = Vec::with_capacity(destinations.0.len());
    for destination in &destinations.0 {
        destination_identities
            .push(get_identity(destination.name.clone(), destination.device_id).await);
    }

    sealed_sender_multi_recipient_encrypt_inner(
        &destinations.0,
        &destination_identities,
        &excluded_recipients,
        &usmc,
        &identity_key_pair_bytes,
        local_registration_id,
    )
}

/// Clears every destination's `session_record` when it goes out of scope.
///
/// `MultiRecipientDestination` is marshalled by FRB, so its `session_record`
/// field cannot simply become a `Zeroizing<Vec<u8>>` — FRB would have to
/// marshal that type. This guard gets the same `Drop` guarantee without
/// touching the wire struct.
#[flutter_rust_bridge::frb(ignore)]
struct ZeroizingDestinations(Vec<MultiRecipientDestination>);

impl Drop for ZeroizingDestinations {
    fn drop(&mut self) {
        for destination in &mut self.0 {
            destination.session_record.zeroize();
        }
    }
}

fn sealed_sender_multi_recipient_encrypt_inner(
    destinations: &[MultiRecipientDestination],
    destination_identities: &[Option<Vec<u8>>],
    excluded_recipients: &[String],
    usmc: &[u8],
    identity_key_pair_bytes: &[u8],
    local_registration_id: u32,
) -> Result<Vec<u8>, String> {
    if destinations.is_empty() {
        return Err("At least one destination is required".to_string());
    }

    let content = NativeUnidentifiedSenderMessageContent::deserialize(usmc)
        .map_err(|e: SignalProtocolError| e.to_string())?;
    let our_identity =
        IdentityKeyPair::try_from(identity_key_pair_bytes).map_err(|e| e.to_string())?;

    let addresses = destinations
        .iter()
        .map(|d| {
            Ok(ProtocolAddress::new(
                d.name.clone(),
                d.device_id
                    .try_into()
                    .map_err(|_| format!("Invalid device ID for {}", d.name))?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let sessions = destinations
        .iter()
        .map(|d| {
            libsignal_protocol::SessionRecord::deserialize(&d.session_record)
                .map_err(|e: SignalProtocolError| e.to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let excluded = excluded_recipients
        .iter()
        .map(|s| {
            libsignal_protocol::ServiceId::parse_from_service_id_string(s)
                .ok_or_else(|| format!("Invalid excluded recipient service id: {}", s))
        })
        .collect::<Result<Vec<_>, String>>()?;

    let address_refs: Vec<&ProtocolAddress> = addresses.iter().collect();
    let session_refs: Vec<&libsignal_protocol::SessionRecord> = sessions.iter().collect();

    let mut identity_store = InMemIdentityKeyStore::new(our_identity, local_registration_id);
    for (address, identity) in addresses.iter().zip(destination_identities) {
        super::preseed_identity(&mut identity_store, address, identity)?;
    }

    block_on(async {
        libsignal_protocol::sealed_sender_multi_recipient_encrypt(
            &address_refs,
            &session_refs,
            excluded,
            &content,
            &identity_store,
            &mut OsRng.unwrap_err(),
        )
        .await
    })
    .map_err(|e| e.to_string())
}

/// One device of one recipient in a parsed multi-recipient message.
pub struct SealedSenderV2Device {
    /// The recipient's device ID.
    pub device_id: u32,
    /// The registration ID that device had when the message was built.
    pub registration_id: u32,
}

/// One recipient of a parsed multi-recipient message.
pub struct SealedSenderV2Recipient {
    /// The recipient's service id string (a bare UUID, or `PNI:<uuid>`).
    pub service_id: String,
    /// The recipient's devices. Empty for an excluded recipient.
    pub devices: Vec<SealedSenderV2Device>,
    /// Start offset, in the parsed message, of this recipient's key material.
    ///
    /// Equal to [SealedSenderV2Recipient.keyMaterialEnd] for an excluded
    /// recipient, which has none.
    pub key_material_start: u32,
    /// End offset (exclusive), in the parsed message, of this recipient's key
    /// material.
    pub key_material_end: u32,
}

/// A parsed multi-recipient (Sealed Sender v2) SentMessage.
///
/// Carries offsets rather than bytes — see
/// [sealedSenderV2ParseSentMessage]. `SealedSenderV2SentMessage.receivedMessageFor`
/// assembles one recipient's message from them.
pub struct SealedSenderV2SentMessage {
    /// The version byte at the head of the *SentMessage*.
    pub version: u32,
    /// The version byte a per-recipient *ReceivedMessage* starts with.
    ///
    /// Not the same as [SealedSenderV2SentMessage.version]: the ReceivedMessage
    /// format has not changed since the first v2 revision, so a `0x23`
    /// SentMessage still fans out into `0x22` ReceivedMessages. Read from
    /// libsignal rather than hardcoded. `0` when there is nothing to fan out
    /// (every recipient excluded).
    pub received_message_version: u32,
    /// Offset, in the parsed message, of the bytes every recipient shares.
    /// The shared run extends to the end of the message.
    pub shared_bytes_offset: u32,
    /// Length of the message these offsets were read from.
    ///
    /// Every offset above indexes a buffer of exactly this size.
    /// `SealedSenderV2SentMessage.receivedMessageFor` refuses any other buffer,
    /// which is the only mismatch it can detect cheaply — a *different* buffer
    /// of the same length is indistinguishable from the right one.
    pub parsed_length: u32,
    /// The recipients, in the order they first appear in the message.
    pub recipients: Vec<SealedSenderV2Recipient>,
}

/// Parse a multi-recipient SentMessage so it can be fanned out.
///
/// This is the server-side half of
/// [sealedSenderMultiRecipientEncryptWithCallbacks]: it reads the envelope of
/// one SentMessage so each recipient's message can be split out of it. It reads
/// only the envelope — nothing here is decrypted or authenticated.
///
/// # Why offsets and not bytes
/// A recipient's message is `[version][their key material][shared bytes]`, and
/// the shared run is nearly the whole message. Returning it per recipient would
/// copy that run once each, so an `N`-byte input could produce roughly
/// `N²/272` bytes of output — a 570 KB message measured at 1 GB. So this
/// returns *offsets into `data`*, which is `O(recipients)` regardless of body
/// size, and `SealedSenderV2SentMessage.receivedMessageFor` builds one message
/// at a time from them. That is also how libsignal expects a fan-out server to
/// work: `range_for_recipient_key_material` and `offset_of_shared_bytes` exist
/// for exactly this.
///
/// All offsets index into the `data` you pass here, so hold on to it.
pub async fn sealed_sender_v2_parse_sent_message(
    data: Vec<u8>,
) -> Result<SealedSenderV2SentMessage, String> {
    // The offsets below are u32 for the FFI boundary; refuse anything that
    // could not be addressed by one rather than silently truncating.
    if data.len() > u32::MAX as usize {
        return Err(format!(
            "Message too large to address with 32-bit offsets: {} bytes",
            data.len()
        ));
    }

    let parsed = libsignal_protocol::SealedSenderV2SentMessage::parse(&data)
        .map_err(|e: SignalProtocolError| e.to_string())?;

    // Read the ReceivedMessage version byte off libsignal instead of repeating
    // its constant, which is private. Any recipient that has a message carries
    // it; if none does there is nothing to fan out and the value is unused.
    let received_message_version = parsed
        .recipients
        .values()
        .find(|recipient| !recipient.devices.is_empty())
        .and_then(|recipient| {
            // `parts` is bound so the borrow below outlives the `as_ref()`.
            let parts = parsed.received_message_parts_for_recipient(recipient);
            parts.as_ref().first().and_then(|part| part.first()).copied()
        })
        .unwrap_or(0);

    let recipients = parsed
        .recipients
        .iter()
        .map(|(service_id, recipient)| {
            // 0..0 for an excluded recipient, which has no key material.
            let range = parsed.range_for_recipient_key_material(recipient);
            SealedSenderV2Recipient {
                service_id: service_id.service_id_string(),
                devices: recipient
                    .devices
                    .iter()
                    .map(|(device_id, registration_id)| SealedSenderV2Device {
                        device_id: u32::from(*device_id),
                        registration_id: u32::from(*registration_id),
                    })
                    .collect(),
                key_material_start: range.start as u32,
                key_material_end: range.end as u32,
            }
        })
        .collect();

    Ok(SealedSenderV2SentMessage {
        version: parsed.version as u32,
        received_message_version: u32::from(received_message_version),
        shared_bytes_offset: parsed.offset_of_shared_bytes() as u32,
        // Safe to narrow: the guard at the top of this function refused
        // anything that does not fit in a u32.
        parsed_length: data.len() as u32,
        recipients,
    })
}
