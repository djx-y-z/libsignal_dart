//! Session cipher API for encrypting and decrypting Signal Protocol messages.
//!
//! This module provides message encryption and decryption functions using
//! DartFn callbacks for store operations.

use crate::recording_stores::{KyberPreKeyUsed, RecordingKyberPreKeyStore, RecordingPreKeyStore};
use flutter_rust_bridge::DartFnFuture;
use futures::executor::block_on;
use libsignal_protocol::{
    CiphertextMessageType, GenericSignedPreKey, IdentityKeyPair, InMemIdentityKeyStore,
    InMemSessionStore, InMemSignedPreKeyStore, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyId, PreKeyRecord, PreKeySignalMessage, PreKeyStore, ProtocolAddress,
    SessionRecord as NativeSessionRecord, SessionStore, SignalMessage, SignalProtocolError,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use rand::{rngs::OsRng, TryRngCore as _};
use zeroize::Zeroize;

/// Result of encrypting a message.
pub struct EncryptResult {
    /// The ciphertext type (1 = Signal message, 3 = Pre-key message).
    pub message_type: u8,
    /// The encrypted message bytes.
    pub ciphertext: Vec<u8>,
}

/// Everything a pre-key decryption produced, for the async wrapper to write back.
///
/// The two consumption fields are what libsignal *actually* did, as observed by
/// [`RecordingPreKeyStore`] / [`RecordingKyberPreKeyStore`] — not what the
/// message happened to reference. A redelivered pre-key message that matches an
/// already-established session consumes nothing, and this reports nothing.
struct PreKeyDecryptOutcome {
    plaintext: Vec<u8>,
    updated_session: Vec<u8>,
    remote_identity_key: Vec<u8>,
    pre_key_to_remove: Option<u32>,
    kyber_pre_key_used: Option<KyberPreKeyUsed>,
}

/// Pre-key IDs extracted from a pre-key message.
pub struct PreKeyMessageIds {
    /// The one-time pre-key ID (if present).
    pub pre_key_id: Option<u32>,
    /// The signed pre-key ID.
    pub signed_pre_key_id: u32,
    /// The Kyber pre-key ID (if present).
    pub kyber_pre_key_id: Option<u32>,
}

/// Extract pre-key IDs from a serialized pre-key message.
#[flutter_rust_bridge::frb(sync)]
pub fn extract_prekey_message_ids(message: Vec<u8>) -> Result<PreKeyMessageIds, String> {
    let msg = PreKeySignalMessage::try_from(&message[..]).map_err(|e| e.to_string())?;

    Ok(PreKeyMessageIds {
        pre_key_id: msg.pre_key_id().map(|id| id.into()),
        signed_pre_key_id: msg.signed_pre_key_id().into(),
        kyber_pre_key_id: msg.kyber_pre_key_id().map(|id| id.into()),
    })
}

// ============================================================================
// ENCRYPT with DartFn callbacks
// ============================================================================

/// Encrypt a message using an established session with DartFn callbacks.
///
/// # Callbacks
/// - `load_session(name, device_id)` - Load the session record
/// - `store_session(name, device_id, record)` - Store the updated session record
/// - `get_identity_key_pair()` - Get our serialized identity key pair
/// - `get_local_registration_id()` - Get our registration ID
///
/// # Parameters
/// - `local_name` - Our user identifier (UUID)
/// - `local_device_id` - Our device ID
// FRB entry point: carries the SessionStore + IdentityKeyStore callbacks, so
// the argument count mirrors the Signal store interface, not a refactor smell.
#[allow(clippy::too_many_arguments)]
pub async fn message_encrypt_with_callbacks(
    remote_name: String,
    remote_device_id: u32,
    local_name: String,
    local_device_id: u32,
    plaintext: Vec<u8>,
    load_session: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    store_session: impl Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
    get_identity_key_pair: impl Fn() -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
    get_local_registration_id: impl Fn() -> DartFnFuture<u32> + Send + Sync + 'static,
    get_identity: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
) -> Result<EncryptResult, String> {
    // Step 1: Load data via callbacks
    let session_bytes = load_session(remote_name.clone(), remote_device_id)
        .await
        .ok_or_else(|| {
            format!(
                "No session for {}:{}",
                remote_name.clone(),
                remote_device_id
            )
        })?;
    let mut identity_key_pair_bytes = get_identity_key_pair().await;
    let local_registration_id = get_local_registration_id().await;
    // Previously-trusted identity for this recipient (None on first contact).
    let known_remote_identity = get_identity(remote_name.clone(), remote_device_id).await;

    // Step 2: Encrypt
    let result = message_encrypt_inner(
        &remote_name,
        remote_device_id,
        &local_name,
        local_device_id,
        &plaintext,
        &session_bytes,
        &identity_key_pair_bytes,
        local_registration_id,
        &known_remote_identity,
    );

    // SECURITY: Zeroize sensitive data
    identity_key_pair_bytes.zeroize();

    let (encrypt_result, updated_session) = result?;

    // Step 3: Store updated session via callback
    store_session(remote_name, remote_device_id, updated_session).await;

    Ok(encrypt_result)
}

#[allow(clippy::too_many_arguments)]
fn message_encrypt_inner(
    remote_name: &str,
    remote_device_id: u32,
    local_name: &str,
    local_device_id: u32,
    plaintext: &[u8],
    session_bytes: &[u8],
    identity_key_pair_bytes: &[u8],
    local_registration_id: u32,
    known_remote_identity: &Option<Vec<u8>>,
) -> Result<(EncryptResult, Vec<u8>), String> {
    // Parse our identity
    let our_identity =
        IdentityKeyPair::try_from(identity_key_pair_bytes).map_err(|e| e.to_string())?;

    // Parse session
    let session = NativeSessionRecord::deserialize(session_bytes).map_err(|e| e.to_string())?;

    // Create protocol addresses
    let remote_address = ProtocolAddress::new(
        remote_name.to_string(),
        remote_device_id
            .try_into()
            .map_err(|_| "Invalid remote device ID")?,
    );
    let local_address = ProtocolAddress::new(
        local_name.to_string(),
        local_device_id
            .try_into()
            .map_err(|_| "Invalid local device ID")?,
    );

    // Create in-memory stores
    let mut session_store = InMemSessionStore::new();
    let mut identity_store = InMemIdentityKeyStore::new(our_identity, local_registration_id);

    // SECURITY: enforce identity-trust for the recipient (see preseed_identity).
    // libsignal's message_encrypt consults is_trusted_identity(Sending), so a
    // stored identity that differs from the session's yields UntrustedIdentity.
    super::preseed_identity(&mut identity_store, &remote_address, known_remote_identity)?;

    // Populate session store
    block_on(async { session_store.store_session(&remote_address, &session).await })
        .map_err(|e| e.to_string())?;

    // Encrypt using the library's function
    let ciphertext = block_on(async {
        libsignal_protocol::message_encrypt(
            plaintext,
            &remote_address,
            &local_address,
            &mut session_store,
            &mut identity_store,
            crate::current_time(),
            &mut OsRng.unwrap_err(),
        )
        .await
    })
    .map_err(|e| e.to_string())?;

    // Get the updated session
    let updated_session = block_on(async { session_store.load_session(&remote_address).await })
        .map_err(|e| e.to_string())?
        .ok_or("Session not found after encryption")?;

    // Serialize results
    let msg_type = match ciphertext.message_type() {
        CiphertextMessageType::Whisper => 1,
        CiphertextMessageType::PreKey => 3,
        other => return Err(format!(
            "Unexpected message type {:?}, expected Whisper (1) or PreKey (3)", other
        )),
    };

    let updated_session_bytes = updated_session.serialize().map_err(|e| e.to_string())?;

    Ok((
        EncryptResult {
            message_type: msg_type,
            ciphertext: ciphertext.serialize().to_vec(),
        },
        updated_session_bytes,
    ))
}

// ============================================================================
// DECRYPT SIGNAL MESSAGE with DartFn callbacks
// ============================================================================

/// Decrypt a Signal message (not a pre-key message) with DartFn callbacks.
///
/// # Callbacks
/// - `load_session(name, device_id)` - Load the session record
/// - `store_session(name, device_id, record)` - Store the updated session record
/// - `get_identity_key_pair()` - Get our serialized identity key pair
/// - `get_local_registration_id()` - Get our registration ID
/// - `save_identity(name, device_id, identity_key)` - Save the remote identity key
///
/// # Parameters
/// - `local_name` - Our user identifier (UUID)
/// - `local_device_id` - Our device ID
// FRB entry point: carries the SessionStore + IdentityKeyStore callbacks, so
// the argument count mirrors the Signal store interface, not a refactor smell.
#[allow(clippy::too_many_arguments)]
pub async fn message_decrypt_signal_with_callbacks(
    remote_name: String,
    remote_device_id: u32,
    local_name: String,
    local_device_id: u32,
    ciphertext: Vec<u8>,
    load_session: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    store_session: impl Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
    get_identity_key_pair: impl Fn() -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
    get_local_registration_id: impl Fn() -> DartFnFuture<u32> + Send + Sync + 'static,
    save_identity: impl Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
    get_identity: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
) -> Result<Vec<u8>, String> {
    // Step 1: Load data via callbacks
    let session_bytes = load_session(remote_name.clone(), remote_device_id)
        .await
        .ok_or_else(|| {
            format!(
                "No session for {}:{}",
                remote_name.clone(),
                remote_device_id
            )
        })?;
    let mut identity_key_pair_bytes = get_identity_key_pair().await;
    let local_registration_id = get_local_registration_id().await;
    // Previously-trusted identity for this sender (None on first contact).
    let known_remote_identity = get_identity(remote_name.clone(), remote_device_id).await;

    // Step 2: Decrypt
    let result = message_decrypt_signal_inner(
        &remote_name,
        remote_device_id,
        &local_name,
        local_device_id,
        &ciphertext,
        &session_bytes,
        &identity_key_pair_bytes,
        local_registration_id,
        &known_remote_identity,
    );

    // SECURITY: Zeroize sensitive data
    identity_key_pair_bytes.zeroize();

    let (plaintext, updated_session, remote_identity_key) = result?;

    // Step 3: Store results via callbacks
    store_session(remote_name.clone(), remote_device_id, updated_session).await;
    save_identity(remote_name, remote_device_id, remote_identity_key).await;

    Ok(plaintext)
}

// too_many_arguments: mirrors the store-callback surface above. type_complexity:
// the returned tuple bundles the serialized outputs handed back to the async
// wrapper (plaintext + updated session + identity to save).
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn message_decrypt_signal_inner(
    remote_name: &str,
    remote_device_id: u32,
    local_name: &str,
    local_device_id: u32,
    ciphertext: &[u8],
    session_bytes: &[u8],
    identity_key_pair_bytes: &[u8],
    local_registration_id: u32,
    known_remote_identity: &Option<Vec<u8>>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    // Parse the message
    let message = SignalMessage::try_from(ciphertext).map_err(|e| e.to_string())?;

    // Parse our identity
    let our_identity =
        IdentityKeyPair::try_from(identity_key_pair_bytes).map_err(|e| e.to_string())?;

    // Parse session
    let session = NativeSessionRecord::deserialize(session_bytes).map_err(|e| e.to_string())?;

    // Create protocol addresses
    let remote_address = ProtocolAddress::new(
        remote_name.to_string(),
        remote_device_id
            .try_into()
            .map_err(|_| "Invalid remote device ID")?,
    );
    let local_address = ProtocolAddress::new(
        local_name.to_string(),
        local_device_id
            .try_into()
            .map_err(|_| "Invalid local device ID")?,
    );

    // Create in-memory stores
    let mut session_store = InMemSessionStore::new();
    let mut identity_store = InMemIdentityKeyStore::new(our_identity, local_registration_id);

    // SECURITY: enforce identity-trust for the sender (see preseed_identity).
    // libsignal's message_decrypt_signal consults is_trusted_identity(Receiving),
    // so a stored identity that differs from the session's yields UntrustedIdentity.
    super::preseed_identity(&mut identity_store, &remote_address, known_remote_identity)?;

    // Populate session store
    block_on(async { session_store.store_session(&remote_address, &session).await })
        .map_err(|e| e.to_string())?;

    // Decrypt using the library's function
    let plaintext = block_on(async {
        libsignal_protocol::message_decrypt_signal(
            &message,
            &remote_address,
            &local_address,
            &mut session_store,
            &mut identity_store,
            &mut OsRng.unwrap_err(),
        )
        .await
    })
    .map_err(|e| e.to_string())?;

    // Get the updated session
    let updated_session = block_on(async { session_store.load_session(&remote_address).await })
        .map_err(|e| e.to_string())?
        .ok_or("Session not found after decryption")?;

    // Get the remote identity key from the session
    let their_identity_key = updated_session
        .remote_identity_key_bytes()
        .map_err(|e| e.to_string())?
        .ok_or("No remote identity key in session")?;

    let updated_session_bytes = updated_session.serialize().map_err(|e| e.to_string())?;

    Ok((plaintext, updated_session_bytes, their_identity_key.to_vec()))
}

// ============================================================================
// DECRYPT PRE-KEY MESSAGE with DartFn callbacks
// ============================================================================

/// Decrypt a pre-key Signal message (first message in a new session) with DartFn callbacks.
///
/// # Callbacks
/// - `load_session(name, device_id)` - Load existing session record (may be None)
/// - `store_session(name, device_id, record)` - Store the new session record
/// - `get_identity_key_pair()` - Get our serialized identity key pair
/// - `get_local_registration_id()` - Get our registration ID
/// - `save_identity(name, device_id, identity_key)` - Save the remote identity key
/// - `load_signed_pre_key(id)` - Load a signed pre-key by ID (may return None if not found)
/// - `load_pre_key(id)` - Load a one-time pre-key by ID (may return None)
/// - `remove_pre_key(id)` - Remove a used one-time pre-key
/// - `load_kyber_pre_key(id)` - Load a Kyber pre-key by ID (may return None)
/// - `mark_kyber_pre_key_used(kyber_id, signed_pre_key_id, base_key)` - Mark a
///   Kyber pre-key as used. The three arguments mirror libsignal's
///   `KyberPreKeyStore::mark_kyber_pre_key_used`, so a store can implement the
///   last-resort anti-replay check that trait documents.
///
/// # Write ordering
/// The write-back callbacks run in libsignal's own order — `save_identity`,
/// `mark_kyber_pre_key_used`, `remove_pre_key`, then `store_session` last. The
/// session must land after the consumption writes: if it landed first and the
/// process died before them, the redelivered message would match the
/// now-persisted session, consume nothing, and leave the pre-keys usable.
///
/// # Parameters
/// - `local_name` - Our user identifier (UUID)
/// - `local_device_id` - Our device ID
// FRB entry point: carries the session, identity, pre-key, signed-pre-key and
// Kyber store callbacks, so the argument count mirrors the Signal store
// interface rather than being a refactor smell.
#[allow(clippy::too_many_arguments)]
pub async fn message_decrypt_prekey_with_callbacks(
    remote_name: String,
    remote_device_id: u32,
    local_name: String,
    local_device_id: u32,
    ciphertext: Vec<u8>,
    load_session: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    store_session: impl Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
    get_identity_key_pair: impl Fn() -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
    get_local_registration_id: impl Fn() -> DartFnFuture<u32> + Send + Sync + 'static,
    save_identity: impl Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
    load_signed_pre_key: impl Fn(u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    load_pre_key: impl Fn(u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    remove_pre_key: impl Fn(u32) -> DartFnFuture<()> + Send + Sync + 'static,
    load_kyber_pre_key: impl Fn(u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    mark_kyber_pre_key_used: impl Fn(u32, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
    get_identity: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
) -> Result<Vec<u8>, String> {
    // Extract pre-key IDs from the message first
    let prekey_msg =
        PreKeySignalMessage::try_from(&ciphertext[..]).map_err(|e| e.to_string())?;
    let pre_key_id = prekey_msg.pre_key_id();
    let signed_pre_key_id: u32 = prekey_msg.signed_pre_key_id().into();
    let kyber_pre_key_id = prekey_msg.kyber_pre_key_id();

    // Step 1: Load data via callbacks
    let existing_session_bytes = load_session(remote_name.clone(), remote_device_id).await;
    let mut identity_key_pair_bytes = get_identity_key_pair().await;
    let local_registration_id = get_local_registration_id().await;
    // Previously-trusted identity for this sender (None on first contact).
    let known_remote_identity = get_identity(remote_name.clone(), remote_device_id).await;

    // Load pre-keys
    let signed_pre_key_bytes = load_signed_pre_key(signed_pre_key_id)
        .await
        .ok_or_else(|| format!("Signed pre-key {} not found", signed_pre_key_id))?;

    let pre_key_bytes = if let Some(pk_id) = pre_key_id {
        load_pre_key(pk_id.into()).await
    } else {
        None
    };

    let kyber_pre_key_bytes = if let Some(kpk_id) = kyber_pre_key_id {
        load_kyber_pre_key(kpk_id.into()).await
    } else {
        None
    };

    // Step 2: Decrypt
    let result = message_decrypt_prekey_inner(
        &remote_name,
        remote_device_id,
        &local_name,
        local_device_id,
        &ciphertext,
        &existing_session_bytes,
        &identity_key_pair_bytes,
        local_registration_id,
        signed_pre_key_id,
        &signed_pre_key_bytes,
        pre_key_id.map(|id| id.into()),
        &pre_key_bytes,
        kyber_pre_key_id.map(|id| id.into()),
        &kyber_pre_key_bytes,
        &known_remote_identity,
    );

    // SECURITY: Zeroize sensitive data
    identity_key_pair_bytes.zeroize();

    let outcome = result?;

    // Step 3: Store results and cleanup via callbacks, in libsignal's order.
    // `store_session` goes last on purpose — see "Write ordering" above.
    save_identity(
        remote_name.clone(),
        remote_device_id,
        outcome.remote_identity_key,
    )
    .await;

    // Mark the Kyber pre-key libsignal consumed, with the full argument triple.
    if let Some(used) = outcome.kyber_pre_key_used {
        mark_kyber_pre_key_used(
            used.kyber_pre_key_id,
            used.signed_pre_key_id,
            used.base_key,
        )
        .await;
    }

    // Remove the one-time pre-key libsignal consumed.
    if let Some(pk_id) = outcome.pre_key_to_remove {
        remove_pre_key(pk_id).await;
    }

    store_session(remote_name, remote_device_id, outcome.updated_session).await;

    Ok(outcome.plaintext)
}

// too_many_arguments: mirrors the store-callback surface above.
#[allow(clippy::too_many_arguments)]
fn message_decrypt_prekey_inner(
    remote_name: &str,
    remote_device_id: u32,
    local_name: &str,
    local_device_id: u32,
    ciphertext: &[u8],
    existing_session_bytes: &Option<Vec<u8>>,
    identity_key_pair_bytes: &[u8],
    local_registration_id: u32,
    signed_pre_key_id: u32,
    signed_pre_key_bytes: &[u8],
    pre_key_id: Option<u32>,
    pre_key_bytes: &Option<Vec<u8>>,
    kyber_pre_key_id: Option<u32>,
    kyber_pre_key_bytes: &Option<Vec<u8>>,
    known_remote_identity: &Option<Vec<u8>>,
) -> Result<PreKeyDecryptOutcome, String> {
    // Parse the message
    let message = PreKeySignalMessage::try_from(ciphertext).map_err(|e| e.to_string())?;

    // Parse our identity
    let our_identity =
        IdentityKeyPair::try_from(identity_key_pair_bytes).map_err(|e| e.to_string())?;

    // Parse existing session if provided
    let existing_session = match existing_session_bytes {
        Some(bytes) => Some(NativeSessionRecord::deserialize(bytes).map_err(|e| e.to_string())?),
        None => None,
    };

    // Create protocol addresses
    let remote_address = ProtocolAddress::new(
        remote_name.to_string(),
        remote_device_id
            .try_into()
            .map_err(|_| "Invalid remote device ID")?,
    );
    let local_address = ProtocolAddress::new(
        local_name.to_string(),
        local_device_id
            .try_into()
            .map_err(|_| "Invalid local device ID")?,
    );

    // Create in-memory stores
    let mut session_store = InMemSessionStore::new();
    let mut identity_store = InMemIdentityKeyStore::new(our_identity, local_registration_id);
    let mut signed_prekey_store = InMemSignedPreKeyStore::new();
    // Recording variants: they report what libsignal consumed rather than what
    // the message referenced. See `crate::recording_stores`.
    let mut prekey_store = RecordingPreKeyStore::new();
    let mut kyber_prekey_store = RecordingKyberPreKeyStore::new();

    // SECURITY: enforce identity-trust for the new session (see preseed_identity).
    super::preseed_identity(&mut identity_store, &remote_address, known_remote_identity)?;

    // Populate session store if we have an existing session
    if let Some(session) = existing_session {
        block_on(async { session_store.store_session(&remote_address, &session).await })
            .map_err(|e| e.to_string())?;
    }

    // Populate pre-key stores
    let signed_prekey_record =
        SignedPreKeyRecord::deserialize(signed_pre_key_bytes).map_err(|e| e.to_string())?;
    block_on(async {
        signed_prekey_store
            .save_signed_pre_key(SignedPreKeyId::from(signed_pre_key_id), &signed_prekey_record)
            .await
    })
    .map_err(|e| e.to_string())?;

    if let (Some(id), Some(bytes)) = (pre_key_id, pre_key_bytes.as_ref()) {
        let prekey_record = PreKeyRecord::deserialize(bytes).map_err(|e| e.to_string())?;
        block_on(async { prekey_store.save_pre_key(PreKeyId::from(id), &prekey_record).await })
            .map_err(|e| e.to_string())?;
    }

    if let (Some(id), Some(bytes)) = (kyber_pre_key_id, kyber_pre_key_bytes.as_ref()) {
        let kyber_prekey_record =
            KyberPreKeyRecord::deserialize(bytes).map_err(|e| e.to_string())?;
        block_on(async {
            kyber_prekey_store
                .save_kyber_pre_key(KyberPreKeyId::from(id), &kyber_prekey_record)
                .await
        })
        .map_err(|e: SignalProtocolError| e.to_string())?;
    }

    // Decrypt using the library's function
    let plaintext = block_on(async {
        libsignal_protocol::message_decrypt_prekey(
            &message,
            &remote_address,
            &local_address,
            &mut session_store,
            &mut identity_store,
            &mut prekey_store,
            &signed_prekey_store,
            &mut kyber_prekey_store,
            &mut OsRng.unwrap_err(),
        )
        .await
    })
    .map_err(|e| e.to_string())?;

    // Get the updated session
    let updated_session =
        block_on(async { SessionStore::load_session(&session_store, &remote_address).await })
            .map_err(|e: SignalProtocolError| e.to_string())?
            .ok_or("Session not found after decryption")?;

    // Get the remote identity key
    let their_identity_key = message.identity_key().serialize().to_vec();

    let updated_session_bytes = updated_session
        .serialize()
        .map_err(|e: libsignal_protocol::error::SignalProtocolError| e.to_string())?;

    Ok(PreKeyDecryptOutcome {
        plaintext,
        updated_session: updated_session_bytes,
        remote_identity_key: their_identity_key,
        // What libsignal actually consumed, straight from the stores it used.
        pre_key_to_remove: prekey_store.take_removed(),
        kyber_pre_key_used: kyber_prekey_store.take_used(),
    })
}
