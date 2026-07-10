//! Session builder API for establishing Signal Protocol sessions.
//!
//! This module provides session establishment functions using DartFn callbacks
//! for store operations. The approach:
//! 1. Receives Dart callbacks for loading/storing sessions and identities
//! 2. Uses in-memory stores temporarily during operations
//! 3. Returns results for Dart to persist via callbacks

use flutter_rust_bridge::DartFnFuture;
use futures::executor::block_on;
use libsignal_protocol::{
    IdentityKeyPair, InMemIdentityKeyStore, InMemSessionStore, ProtocolAddress,
    SessionRecord as NativeSessionRecord, SessionStore, SignalProtocolError,
};
use rand::{rngs::OsRng, TryRngCore as _};
use zeroize::Zeroize;

use super::bundle::PreKeyBundle;

/// Result of processing a pre-key bundle.
pub struct ProcessPreKeyBundleResult {
    /// The new session record (serialized).
    pub session_record: Vec<u8>,
    /// The remote identity key that should be saved.
    pub remote_identity_key: Vec<u8>,
}

/// Process a pre-key bundle to establish a new session with DartFn callbacks.
///
/// This function establishes a session with a remote user using their pre-key bundle.
/// Store operations are performed via callbacks to the Dart side.
///
/// # Callbacks
/// - `load_session(name, device_id)` - Load existing session record
/// - `store_session(name, device_id, record)` - Store the new session record
/// - `get_identity_key_pair()` - Get our serialized identity key pair
/// - `get_local_registration_id()` - Get our registration ID
/// - `save_identity(name, device_id, identity_key)` - Save the remote identity key
///
/// # Parameters
/// - `local_name` - Our user identifier (UUID)
/// - `local_device_id` - Our device ID
///
/// # Returns
/// The result containing the new session record and identity to save.
// FRB entry point: carries the full set of store callbacks (session, identity,
// pre-key, signed-pre-key, Kyber), so the argument count mirrors the Signal
// store interface rather than being a refactor smell.
#[allow(clippy::too_many_arguments)]
pub async fn process_prekey_bundle_with_callbacks(
    remote_name: String,
    remote_device_id: u32,
    local_name: String,
    local_device_id: u32,
    bundle: &PreKeyBundle,
    load_session: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
    store_session: impl Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
    get_identity_key_pair: impl Fn() -> DartFnFuture<Vec<u8>> + Send + Sync + 'static,
    get_local_registration_id: impl Fn() -> DartFnFuture<u32> + Send + Sync + 'static,
    save_identity: impl Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,
    get_identity: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + Send + Sync + 'static,
) -> Result<(), String> {
    // Step 1: Load data via callbacks
    let mut existing_session_bytes =
        load_session(remote_name.clone(), remote_device_id).await;
    let mut identity_key_pair_bytes = get_identity_key_pair().await;
    let local_registration_id = get_local_registration_id().await;
    // The previously-trusted identity for this remote address (None on first
    // contact). Used to enforce identity-trust below.
    let known_remote_identity = get_identity(remote_name.clone(), remote_device_id).await;

    // Step 2: Process the bundle
    let result = process_prekey_bundle_inner(
        &remote_name,
        remote_device_id,
        &local_name,
        local_device_id,
        bundle,
        &existing_session_bytes,
        &identity_key_pair_bytes,
        local_registration_id,
        &known_remote_identity,
    );

    // SECURITY: Zeroize sensitive data
    identity_key_pair_bytes.zeroize();
    if let Some(ref mut bytes) = existing_session_bytes {
        bytes.zeroize();
    }

    let bundle_result = result?;

    // Step 3: Store results via callbacks
    store_session(
        remote_name.clone(),
        remote_device_id,
        bundle_result.session_record,
    )
    .await;
    save_identity(
        remote_name,
        remote_device_id,
        bundle_result.remote_identity_key,
    )
    .await;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_prekey_bundle_inner(
    remote_name: &str,
    remote_device_id: u32,
    local_name: &str,
    local_device_id: u32,
    bundle: &PreKeyBundle,
    existing_session_bytes: &Option<Vec<u8>>,
    identity_key_pair_bytes: &[u8],
    local_registration_id: u32,
    known_remote_identity: &Option<Vec<u8>>,
) -> Result<ProcessPreKeyBundleResult, String> {
    // Parse the identity key pair
    let our_identity =
        IdentityKeyPair::try_from(identity_key_pair_bytes).map_err(|e| e.to_string())?;

    // Create the protocol addresses
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

    // SECURITY: pre-seed the previously-trusted remote identity so libsignal's
    // `is_trusted_identity` rejects a changed key with `UntrustedIdentity`
    // instead of the fresh store silently trusting it (TOFU). None = first
    // contact, which is still trusted-on-first-use.
    super::preseed_identity(&mut identity_store, &remote_address, known_remote_identity)?;

    // Populate session store with existing session if provided
    if let Some(bytes) = existing_session_bytes {
        let existing = NativeSessionRecord::deserialize(bytes).map_err(|e| e.to_string())?;
        block_on(async { session_store.store_session(&remote_address, &existing).await })
            .map_err(|e: SignalProtocolError| e.to_string())?;
    }

    // Get their identity key before processing
    let their_identity_key = bundle.native().identity_key().map_err(|e| e.to_string())?;

    // Call the libsignal process_prekey_bundle
    block_on(async {
        libsignal_protocol::process_prekey_bundle(
            &remote_address,
            &local_address,
            &mut session_store,
            &mut identity_store,
            bundle.native(),
            crate::current_time(),
            &mut OsRng.unwrap_err(),
        )
        .await
    })
    .map_err(|e| e.to_string())?;

    // Get the session record from the store
    let session_record = block_on(async {
        SessionStore::load_session(&session_store, &remote_address).await
    })
    .map_err(|e: SignalProtocolError| e.to_string())?
    .ok_or("Session not created")?;

    // Serialize the results
    let session_bytes = session_record.serialize().map_err(|e| e.to_string())?;
    let identity_bytes = their_identity_key.serialize().to_vec();

    Ok(ProcessPreKeyBundleResult {
        session_record: session_bytes,
        remote_identity_key: identity_bytes,
    })
}
