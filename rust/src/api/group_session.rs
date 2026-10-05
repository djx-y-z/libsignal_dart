//! Group session API for Signal Protocol group messaging (Sender Keys).
//!
//! This module provides group messaging operations using DartFn callbacks
//! for store operations. The hybrid approach:
//! 1. Receives Dart callbacks for loading/storing sender keys
//! 2. Uses in-memory stores temporarily during operations
//! 3. Returns results for Dart to persist
//!
//! # Security
//!
//! All sensitive cryptographic data is explicitly zeroed after use via the `zeroize` crate.

use crate::api::error::{LibSignalErrorCode, LibSignalException};
use flutter_rust_bridge::DartFnFuture;
use futures::executor::block_on;
use libsignal_protocol::{
    IdentityKeyPair, InMemSenderKeyStore, ProtocolAddress, SenderKeyDistributionMessage,
    SenderKeyRecord, SenderKeyStore,
    SignalProtocolError,
};
use rand::{TryRngCore as _, rngs::OsRng};
use uuid::Uuid;
use zeroize::Zeroizing;

// ============================================================================
// GROUP KEY DISTRIBUTION with DartFn callbacks
// ============================================================================

/// Result of creating a sender key distribution message.
pub struct CreateSenderKeyDistributionResult {
    /// The sender key distribution message to share with group members.
    pub distribution_message: Vec<u8>,
    /// The updated sender key record to store.
    pub sender_key_record: Vec<u8>,
}

/// Create a new sender key distribution message with callbacks.
///
/// This creates or updates our sender key for a group and produces a
/// distribution message that should be sent to other group members.
///
/// # Callbacks
/// - `load_sender_key(sender_name, sender_device_id, distribution_id)` - Load existing sender key
/// - `store_sender_key(sender_name, sender_device_id, distribution_id, record)` - Store updated sender key
/// - `get_identity_key_pair()` - Get our identity key pair
///
/// # Returns
/// The distribution message to send to group members.
pub async fn create_sender_key_distribution_message_with_callbacks(
    sender_name: String,
    sender_device_id: u32,
    distribution_id: String,
    load_sender_key: impl Fn(String, u32, String) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    store_sender_key: impl Fn(String, u32, String, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
    get_identity_key_pair: impl Fn() -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
) -> Result<CreateSenderKeyDistributionResult, LibSignalException> {
    // Step 1: Load data via callbacks
    // SECURITY: `Zeroizing` rather than a manual `zeroize()` after the call.
    // A Dart store callback that throws panics the worker thread (FRB declares
    // these callbacks non-failable), and a manual zeroize placed after the work
    // is skipped by that unwind. `Drop` is not.
    let existing_key_bytes = Zeroizing::new(load_sender_key(sender_name.clone(), sender_device_id, distribution_id.clone()).await);
    let identity_key_pair_bytes = Zeroizing::new(get_identity_key_pair().await);

    // Step 2: Call inner function
    let result = create_sender_key_distribution_inner(
        &sender_name,
        sender_device_id,
        &distribution_id,
        &existing_key_bytes,
        &identity_key_pair_bytes,
    );

    // Clear now rather than across the write-back awaits below.
    drop(existing_key_bytes);
    drop(identity_key_pair_bytes);

    let (distribution_message, sender_key_record) = result?;

    // Step 3: Store via callback
    store_sender_key(sender_name, sender_device_id, distribution_id, sender_key_record.clone()).await;

    Ok(CreateSenderKeyDistributionResult {
        distribution_message,
        sender_key_record,
    })
}

fn create_sender_key_distribution_inner(
    sender_name: &str,
    sender_device_id: u32,
    distribution_id: &str,
    existing_key_bytes: &Option<Vec<u8>>,
    identity_key_pair_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), LibSignalException> {
    // Parse identity (unused but validates the data)
    let _our_identity = IdentityKeyPair::try_from(identity_key_pair_bytes)
        .map_err(LibSignalException::from)?;

    // Parse distribution ID as UUID
    let dist_uuid = Uuid::parse_str(distribution_id)
        .map_err(|e| {
            LibSignalException::invalid_argument(format!("Invalid distribution ID: {}", e))
        })?;

    // Create protocol address
    let sender_address = ProtocolAddress::new(
        sender_name.to_string(),
        sender_device_id.try_into().map_err(|_| LibSignalException::invalid_argument("Invalid device ID"))?,
    );

    // Create in-memory store
    let mut sender_key_store = InMemSenderKeyStore::new();

    // Load existing sender key if present
    if let Some(bytes) = existing_key_bytes {
        let record = SenderKeyRecord::deserialize(bytes)
            .map_err(|e: SignalProtocolError| LibSignalException::from(e))?;
        block_on(async {
            sender_key_store.store_sender_key(&sender_address, dist_uuid, &record).await
        }).map_err(LibSignalException::from)?;
    }

    // Create the distribution message
    let distribution_message = block_on(async {
        libsignal_protocol::create_sender_key_distribution_message(
            &sender_address,
            dist_uuid,
            &mut sender_key_store,
            &mut OsRng.unwrap_err(),
        ).await
    }).map_err(LibSignalException::from)?;

    // Get the updated sender key
    let updated_key = block_on(async {
        sender_key_store.load_sender_key(&sender_address, dist_uuid).await
    }).map_err(|e: SignalProtocolError| LibSignalException::from(e))?
        .ok_or_else(|| LibSignalException::internal("Sender key not created"))?;

    // Serialize results
    let distribution_bytes = distribution_message.serialized().to_vec();
    let key_bytes = updated_key.serialize().map_err(LibSignalException::from)?;

    Ok((distribution_bytes, key_bytes))
}

/// Process a sender key distribution message with callbacks.
///
/// This stores the sender's key so we can decrypt their messages.
///
/// # Callbacks
/// - `load_sender_key(sender_name, sender_device_id, distribution_id)` - Load existing sender key
/// - `store_sender_key(sender_name, sender_device_id, distribution_id, record)` - Store the sender key
///
/// # Returns
/// The sender key record to store.
pub async fn process_sender_key_distribution_message_with_callbacks(
    sender_name: String,
    sender_device_id: u32,
    distribution_id: String,
    distribution_message: Vec<u8>,
    load_sender_key: impl Fn(String, u32, String) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    store_sender_key: impl Fn(String, u32, String, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
) -> Result<Vec<u8>, LibSignalException> {
    // Step 1: Load existing key if any
    // SECURITY: `Zeroizing`, so the key is cleared on every exit, unwind included.
    let existing_key_bytes = Zeroizing::new(load_sender_key(sender_name.clone(), sender_device_id, distribution_id.clone()).await);

    // Step 2: Process
    let result = process_sender_key_distribution_inner(
        &sender_name,
        sender_device_id,
        &distribution_id,
        &distribution_message,
        &existing_key_bytes,
    );

    // Clear now rather than across the write-back awaits below.
    drop(existing_key_bytes);

    let sender_key_record = result?;

    // Step 3: Store via callback
    store_sender_key(sender_name, sender_device_id, distribution_id, sender_key_record.clone()).await;

    Ok(sender_key_record)
}

fn process_sender_key_distribution_inner(
    sender_name: &str,
    sender_device_id: u32,
    distribution_id: &str,
    distribution_message: &[u8],
    existing_key_bytes: &Option<Vec<u8>>,
) -> Result<Vec<u8>, LibSignalException> {
    // Parse distribution ID as UUID
    let dist_uuid = Uuid::parse_str(distribution_id)
        .map_err(|e| {
            LibSignalException::invalid_argument(format!("Invalid distribution ID: {}", e))
        })?;

    // Create protocol address
    let sender_address = ProtocolAddress::new(
        sender_name.to_string(),
        sender_device_id.try_into().map_err(|_| LibSignalException::invalid_argument("Invalid device ID"))?,
    );

    // Parse the distribution message
    let skdm = SenderKeyDistributionMessage::try_from(distribution_message)
        .map_err(|e: SignalProtocolError| LibSignalException::from(e))?;

    // SECURITY: libsignal stores the new sender-key state under the id carried
    // *inside* the message, while this wrapper's store callbacks are keyed by
    // the caller-supplied id. If the two disagree the state would be written to
    // a key we never read back — and when the caller already holds a record
    // under their id, the read-back silently returns that stale record, so the
    // distribution message is dropped without an error. Refuse instead.
    //
    // `InvalidMessage`, not `InvalidArgument`: the id inside the message comes
    // from the peer who sent it, so a mismatch is something any group member
    // can cause, not necessarily a bug in the caller.
    let msg_uuid = skdm
        .distribution_id()
        .map_err(|e: SignalProtocolError| LibSignalException::from(e))?;
    if msg_uuid != dist_uuid {
        return Err(LibSignalException::new(
            LibSignalErrorCode::InvalidMessage,
            format!(
                "Distribution ID mismatch: message carries {}, caller passed {}",
                msg_uuid, dist_uuid
            ),
        ));
    }

    // Create in-memory store
    let mut sender_key_store = InMemSenderKeyStore::new();

    // Load existing sender key if present
    if let Some(bytes) = existing_key_bytes {
        let record = SenderKeyRecord::deserialize(bytes)
            .map_err(|e: SignalProtocolError| LibSignalException::from(e))?;
        block_on(async {
            sender_key_store.store_sender_key(&sender_address, dist_uuid, &record).await
        }).map_err(LibSignalException::from)?;
    }

    // Process the distribution message
    block_on(async {
        libsignal_protocol::process_sender_key_distribution_message(
            &sender_address,
            &skdm,
            &mut sender_key_store,
        ).await
    }).map_err(LibSignalException::from)?;

    // Get the stored sender key
    let sender_key = block_on(async {
        sender_key_store.load_sender_key(&sender_address, dist_uuid).await
    }).map_err(|e: SignalProtocolError| LibSignalException::from(e))?
        .ok_or_else(|| LibSignalException::internal("Sender key not stored after processing"))?;

    sender_key.serialize().map_err(LibSignalException::from)
}

// ============================================================================
// GROUP ENCRYPTION / DECRYPTION with DartFn callbacks
// ============================================================================

/// Result of encrypting a group message.
pub struct GroupEncryptResult {
    /// The encrypted message.
    pub ciphertext: Vec<u8>,
    /// The updated sender key record.
    pub sender_key_record: Vec<u8>,
}

/// Encrypt a message to a group with callbacks.
///
/// # Callbacks
/// - `load_sender_key(sender_name, sender_device_id, distribution_id)` - Load our sender key
/// - `store_sender_key(sender_name, sender_device_id, distribution_id, record)` - Store updated sender key
/// - `get_identity_key_pair()` - Get our identity key pair (for signing)
///
/// # Returns
/// The encrypted ciphertext and updated sender key record.
pub async fn group_encrypt_with_callbacks(
    sender_name: String,
    sender_device_id: u32,
    distribution_id: String,
    plaintext: Vec<u8>,
    load_sender_key: impl Fn(String, u32, String) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    store_sender_key: impl Fn(String, u32, String, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
    get_identity_key_pair: impl Fn() -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
) -> Result<GroupEncryptResult, LibSignalException> {
    // Step 1: Load data
    // SECURITY: `Zeroizing` rather than a manual `zeroize()` after the call.
    // A Dart store callback that throws panics the worker thread (FRB declares
    // these callbacks non-failable), and a manual zeroize placed after the work
    // is skipped by that unwind. `Drop` is not.
    let sender_key_bytes = Zeroizing::new(load_sender_key(sender_name.clone(), sender_device_id, distribution_id.clone()).await);
    let identity_key_pair_bytes = Zeroizing::new(get_identity_key_pair().await);

    // Step 2: Encrypt
    let result = group_encrypt_inner(
        &sender_name,
        sender_device_id,
        &distribution_id,
        &plaintext,
        &sender_key_bytes,
        &identity_key_pair_bytes,
    );

    // Clear now rather than across the write-back awaits below.
    drop(sender_key_bytes);
    drop(identity_key_pair_bytes);

    let (ciphertext, sender_key_record) = result?;

    // Step 3: Store updated key
    store_sender_key(sender_name, sender_device_id, distribution_id, sender_key_record.clone()).await;

    Ok(GroupEncryptResult {
        ciphertext,
        sender_key_record,
    })
}

fn group_encrypt_inner(
    sender_name: &str,
    sender_device_id: u32,
    distribution_id: &str,
    plaintext: &[u8],
    sender_key_bytes: &Option<Vec<u8>>,
    identity_key_pair_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), LibSignalException> {
    // Parse identity (unused but validates the data)
    let _our_identity = IdentityKeyPair::try_from(identity_key_pair_bytes)
        .map_err(LibSignalException::from)?;

    // Parse distribution ID as UUID
    let dist_uuid = Uuid::parse_str(distribution_id)
        .map_err(|e| {
            LibSignalException::invalid_argument(format!("Invalid distribution ID: {}", e))
        })?;

    // Create protocol address
    let sender_address = ProtocolAddress::new(
        sender_name.to_string(),
        sender_device_id.try_into().map_err(|_| LibSignalException::invalid_argument("Invalid device ID"))?,
    );

    // Create in-memory store
    let mut sender_key_store = InMemSenderKeyStore::new();

    // Load sender key
    let sender_key_bytes = sender_key_bytes.as_ref()
        .ok_or_else(|| {
            LibSignalException::new(
                LibSignalErrorCode::SessionNotFound,
                "No sender key found. Create a distribution message first.",
            )
        })?;
    let record = SenderKeyRecord::deserialize(sender_key_bytes)
        .map_err(|e: SignalProtocolError| LibSignalException::from(e))?;
    block_on(async {
        sender_key_store.store_sender_key(&sender_address, dist_uuid, &record).await
    }).map_err(LibSignalException::from)?;

    // Encrypt
    let ciphertext = block_on(async {
        libsignal_protocol::group_encrypt(
            &mut sender_key_store,
            &sender_address,
            dist_uuid,
            plaintext,
            &mut OsRng.unwrap_err(),
        ).await
    }).map_err(LibSignalException::from)?;

    // Get updated sender key
    let updated_key = block_on(async {
        sender_key_store.load_sender_key(&sender_address, dist_uuid).await
    }).map_err(|e: SignalProtocolError| LibSignalException::from(e))?
        .ok_or_else(|| LibSignalException::internal("Sender key not found after encryption"))?;

    let key_bytes = updated_key.serialize().map_err(LibSignalException::from)?;

    Ok((ciphertext.serialized().to_vec(), key_bytes))
}

/// Result of decrypting a group message.
pub struct GroupDecryptResult {
    /// The decrypted plaintext.
    pub plaintext: Vec<u8>,
    /// The updated sender key record.
    pub sender_key_record: Vec<u8>,
}

/// Decrypt a message from a group member with callbacks.
///
/// # Callbacks
/// - `load_sender_key(sender_name, sender_device_id, distribution_id)` - Load the sender's key
/// - `store_sender_key(sender_name, sender_device_id, distribution_id, record)` - Store updated sender key
///
/// # Returns
/// The decrypted plaintext and updated sender key record.
pub async fn group_decrypt_with_callbacks(
    sender_name: String,
    sender_device_id: u32,
    distribution_id: String,
    ciphertext: Vec<u8>,
    load_sender_key: impl Fn(String, u32, String) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    store_sender_key: impl Fn(String, u32, String, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
) -> Result<GroupDecryptResult, LibSignalException> {
    // Step 1: Load sender key
    // SECURITY: `Zeroizing`, so the key is cleared on every exit, unwind included.
    let sender_key_bytes = Zeroizing::new(load_sender_key(sender_name.clone(), sender_device_id, distribution_id.clone()).await);

    // Step 2: Decrypt
    let result = group_decrypt_inner(
        &sender_name,
        sender_device_id,
        &distribution_id,
        &ciphertext,
        &sender_key_bytes,
    );

    // Clear now rather than across the write-back awaits below.
    drop(sender_key_bytes);

    let (plaintext, sender_key_record) = result?;

    // Step 3: Store updated key
    store_sender_key(sender_name, sender_device_id, distribution_id, sender_key_record.clone()).await;

    Ok(GroupDecryptResult {
        plaintext,
        sender_key_record,
    })
}

fn group_decrypt_inner(
    sender_name: &str,
    sender_device_id: u32,
    distribution_id: &str,
    ciphertext: &[u8],
    sender_key_bytes: &Option<Vec<u8>>,
) -> Result<(Vec<u8>, Vec<u8>), LibSignalException> {
    // Parse distribution ID as UUID
    let dist_uuid = Uuid::parse_str(distribution_id)
        .map_err(|e| {
            LibSignalException::invalid_argument(format!("Invalid distribution ID: {}", e))
        })?;

    // Create protocol address
    let sender_address = ProtocolAddress::new(
        sender_name.to_string(),
        sender_device_id.try_into().map_err(|_| LibSignalException::invalid_argument("Invalid device ID"))?,
    );

    // Create in-memory store
    let mut sender_key_store = InMemSenderKeyStore::new();

    // Load sender key
    let sender_key_bytes = sender_key_bytes.as_ref()
        .ok_or_else(|| {
            LibSignalException::new(
                LibSignalErrorCode::SessionNotFound,
                "No sender key found. Process a distribution message first.",
            )
        })?;
    let record = SenderKeyRecord::deserialize(sender_key_bytes)
        .map_err(|e: SignalProtocolError| LibSignalException::from(e))?;
    block_on(async {
        sender_key_store.store_sender_key(&sender_address, dist_uuid, &record).await
    }).map_err(LibSignalException::from)?;

    // Decrypt
    let plaintext = block_on(async {
        libsignal_protocol::group_decrypt(
            ciphertext,
            &mut sender_key_store,
            &sender_address,
        ).await
    }).map_err(LibSignalException::from)?;

    // Get updated sender key
    let updated_key = block_on(async {
        sender_key_store.load_sender_key(&sender_address, dist_uuid).await
    }).map_err(|e: SignalProtocolError| LibSignalException::from(e))?
        .ok_or_else(|| LibSignalException::internal("Sender key not found after decryption"))?;

    let key_bytes = updated_key.serialize().map_err(LibSignalException::from)?;

    Ok((plaintext, key_bytes))
}
