//! FRB API modules for Dart.

use futures::executor::block_on;
use libsignal_protocol::{
    IdentityKey, IdentityKeyStore, InMemIdentityKeyStore, ProtocolAddress, PublicKey,
};

/// Pre-seed a per-call in-memory identity store with the previously-trusted
/// remote identity (if any).
///
/// # Security
/// The high-level ciphers build a fresh, empty `InMemIdentityKeyStore` for each
/// operation. Without seeding, libsignal's `is_trusted_identity` always sees a
/// first-use identity and silently accepts a *changed* remote key (no MITM /
/// safety-number-change detection). Seeding the known identity makes libsignal
/// return `UntrustedIdentity` on a mismatch. `None` = first contact, still
/// trusted-on-first-use.
pub(crate) fn preseed_identity(
    identity_store: &mut InMemIdentityKeyStore,
    remote_address: &ProtocolAddress,
    known_remote_identity: &Option<Vec<u8>>,
) -> Result<(), String> {
    if let Some(bytes) = known_remote_identity {
        let public_key = PublicKey::deserialize(bytes).map_err(|e| e.to_string())?;
        let identity = IdentityKey::new(public_key);
        block_on(async { identity_store.save_identity(remote_address, &identity).await })
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub mod address;
pub mod bundle;
pub mod crypto;
pub mod group_session;
pub mod init;
pub mod keys;
pub mod kyber;
pub mod message;
pub mod prekey;
pub mod sealed_sender;
pub mod session;
pub mod session_builder;
pub mod session_cipher;
pub mod signed_prekey;
