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

use flutter_rust_bridge::DartFnFuture;
use futures::executor::block_on;
use libsignal_protocol::{
    IdentityKeyPair, InMemSenderKeyStore, ProtocolAddress, SenderKeyDistributionMessage,
    SenderKeyRecord, SenderKeyStore,
    SignalProtocolError,
};
use rand::{TryRngCore as _, rngs::OsRng};
use uuid::Uuid;
use zeroize::Zeroize;

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
) -> Result<CreateSenderKeyDistributionResult, String> {
    // Step 1: Load data via callbacks
    let mut existing_key_bytes = load_sender_key(sender_name.clone(), sender_device_id, distribution_id.clone()).await;
    let mut identity_key_pair_bytes = get_identity_key_pair().await;

    // Step 2: Call inner function
    let result = create_sender_key_distribution_inner(
        &sender_name,
        sender_device_id,
        &distribution_id,
        &existing_key_bytes,
        &identity_key_pair_bytes,
    );

    // SECURITY: Zeroize sensitive data
    identity_key_pair_bytes.zeroize();
    if let Some(ref mut bytes) = existing_key_bytes {
        bytes.zeroize();
    }

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
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Parse identity (unused but validates the data)
    let _our_identity = IdentityKeyPair::try_from(identity_key_pair_bytes)
        .map_err(|e| e.to_string())?;

    // Parse distribution ID as UUID
    let dist_uuid = Uuid::parse_str(distribution_id)
        .map_err(|e| format!("Invalid distribution ID: {}", e))?;

    // Create protocol address
    let sender_address = ProtocolAddress::new(
        sender_name.to_string(),
        sender_device_id.try_into().map_err(|_| "Invalid device ID")?,
    );

    // Create in-memory store
    let mut sender_key_store = InMemSenderKeyStore::new();

    // Load existing sender key if present
    if let Some(bytes) = existing_key_bytes {
        let record = SenderKeyRecord::deserialize(bytes)
            .map_err(|e: SignalProtocolError| e.to_string())?;
        block_on(async {
            sender_key_store.store_sender_key(&sender_address, dist_uuid, &record).await
        }).map_err(|e| e.to_string())?;
    }

    // Create the distribution message
    let distribution_message = block_on(async {
        libsignal_protocol::create_sender_key_distribution_message(
            &sender_address,
            dist_uuid,
            &mut sender_key_store,
            &mut OsRng.unwrap_err(),
        ).await
    }).map_err(|e| e.to_string())?;

    // Get the updated sender key
    let updated_key = block_on(async {
        sender_key_store.load_sender_key(&sender_address, dist_uuid).await
    }).map_err(|e: SignalProtocolError| e.to_string())?
        .ok_or("Sender key not created")?;

    // Serialize results
    let distribution_bytes = distribution_message.serialized().to_vec();
    let key_bytes = updated_key.serialize().map_err(|e| e.to_string())?;

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
) -> Result<Vec<u8>, String> {
    // Step 1: Load existing key if any
    let mut existing_key_bytes = load_sender_key(sender_name.clone(), sender_device_id, distribution_id.clone()).await;

    // Step 2: Process
    let result = process_sender_key_distribution_inner(
        &sender_name,
        sender_device_id,
        &distribution_id,
        &distribution_message,
        &existing_key_bytes,
    );

    // SECURITY: Zeroize existing key
    if let Some(ref mut bytes) = existing_key_bytes {
        bytes.zeroize();
    }

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
) -> Result<Vec<u8>, String> {
    // Parse distribution ID as UUID
    let dist_uuid = Uuid::parse_str(distribution_id)
        .map_err(|e| format!("Invalid distribution ID: {}", e))?;

    // Create protocol address
    let sender_address = ProtocolAddress::new(
        sender_name.to_string(),
        sender_device_id.try_into().map_err(|_| "Invalid device ID")?,
    );

    // Parse the distribution message
    let skdm = SenderKeyDistributionMessage::try_from(distribution_message)
        .map_err(|e: SignalProtocolError| e.to_string())?;

    // Create in-memory store
    let mut sender_key_store = InMemSenderKeyStore::new();

    // Load existing sender key if present
    if let Some(bytes) = existing_key_bytes {
        let record = SenderKeyRecord::deserialize(bytes)
            .map_err(|e: SignalProtocolError| e.to_string())?;
        block_on(async {
            sender_key_store.store_sender_key(&sender_address, dist_uuid, &record).await
        }).map_err(|e| e.to_string())?;
    }

    // Process the distribution message
    block_on(async {
        libsignal_protocol::process_sender_key_distribution_message(
            &sender_address,
            &skdm,
            &mut sender_key_store,
        ).await
    }).map_err(|e| e.to_string())?;

    // Get the stored sender key
    let sender_key = block_on(async {
        sender_key_store.load_sender_key(&sender_address, dist_uuid).await
    }).map_err(|e: SignalProtocolError| e.to_string())?
        .ok_or("Sender key not stored after processing")?;

    sender_key.serialize().map_err(|e| e.to_string())
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
) -> Result<GroupEncryptResult, String> {
    // Step 1: Load data
    let mut sender_key_bytes = load_sender_key(sender_name.clone(), sender_device_id, distribution_id.clone()).await;
    let mut identity_key_pair_bytes = get_identity_key_pair().await;

    // Step 2: Encrypt
    let result = group_encrypt_inner(
        &sender_name,
        sender_device_id,
        &distribution_id,
        &plaintext,
        &sender_key_bytes,
        &identity_key_pair_bytes,
    );

    // SECURITY: Zeroize sensitive data
    identity_key_pair_bytes.zeroize();
    if let Some(ref mut bytes) = sender_key_bytes {
        bytes.zeroize();
    }

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
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Parse identity (unused but validates the data)
    let _our_identity = IdentityKeyPair::try_from(identity_key_pair_bytes)
        .map_err(|e| e.to_string())?;

    // Parse distribution ID as UUID
    let dist_uuid = Uuid::parse_str(distribution_id)
        .map_err(|e| format!("Invalid distribution ID: {}", e))?;

    // Create protocol address
    let sender_address = ProtocolAddress::new(
        sender_name.to_string(),
        sender_device_id.try_into().map_err(|_| "Invalid device ID")?,
    );

    // Create in-memory store
    let mut sender_key_store = InMemSenderKeyStore::new();

    // Load sender key
    let sender_key_bytes = sender_key_bytes.as_ref()
        .ok_or("No sender key found. Create a distribution message first.")?;
    let record = SenderKeyRecord::deserialize(sender_key_bytes)
        .map_err(|e: SignalProtocolError| e.to_string())?;
    block_on(async {
        sender_key_store.store_sender_key(&sender_address, dist_uuid, &record).await
    }).map_err(|e| e.to_string())?;

    // Encrypt
    let ciphertext = block_on(async {
        libsignal_protocol::group_encrypt(
            &mut sender_key_store,
            &sender_address,
            dist_uuid,
            plaintext,
            &mut OsRng.unwrap_err(),
        ).await
    }).map_err(|e| e.to_string())?;

    // Get updated sender key
    let updated_key = block_on(async {
        sender_key_store.load_sender_key(&sender_address, dist_uuid).await
    }).map_err(|e: SignalProtocolError| e.to_string())?
        .ok_or("Sender key not found after encryption")?;

    let key_bytes = updated_key.serialize().map_err(|e| e.to_string())?;

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
) -> Result<GroupDecryptResult, String> {
    // Step 1: Load sender key
    let mut sender_key_bytes = load_sender_key(sender_name.clone(), sender_device_id, distribution_id.clone()).await;

    // Step 2: Decrypt
    let result = group_decrypt_inner(
        &sender_name,
        sender_device_id,
        &distribution_id,
        &ciphertext,
        &sender_key_bytes,
    );

    // SECURITY: Zeroize loaded key
    if let Some(ref mut bytes) = sender_key_bytes {
        bytes.zeroize();
    }

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
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Parse distribution ID as UUID
    let dist_uuid = Uuid::parse_str(distribution_id)
        .map_err(|e| format!("Invalid distribution ID: {}", e))?;

    // Create protocol address
    let sender_address = ProtocolAddress::new(
        sender_name.to_string(),
        sender_device_id.try_into().map_err(|_| "Invalid device ID")?,
    );

    // Create in-memory store
    let mut sender_key_store = InMemSenderKeyStore::new();

    // Load sender key
    let sender_key_bytes = sender_key_bytes.as_ref()
        .ok_or("No sender key found. Process a distribution message first.")?;
    let record = SenderKeyRecord::deserialize(sender_key_bytes)
        .map_err(|e: SignalProtocolError| e.to_string())?;
    block_on(async {
        sender_key_store.store_sender_key(&sender_address, dist_uuid, &record).await
    }).map_err(|e| e.to_string())?;

    // Decrypt
    let plaintext = block_on(async {
        libsignal_protocol::group_decrypt(
            ciphertext,
            &mut sender_key_store,
            &sender_address,
        ).await
    }).map_err(|e| e.to_string())?;

    // Get updated sender key
    let updated_key = block_on(async {
        sender_key_store.load_sender_key(&sender_address, dist_uuid).await
    }).map_err(|e: SignalProtocolError| e.to_string())?
        .ok_or("Sender key not found after decryption")?;

    let key_bytes = updated_key.serialize().map_err(|e| e.to_string())?;

    Ok((plaintext, key_bytes))
}
