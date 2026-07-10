#![no_main]
//! Fuzz the pre-key decryption entry point — the crown-jewel attack surface,
//! since the ciphertext is fully network-controlled.
//!
//! `message_decrypt_prekey_with_callbacks` parses the `PreKeySignalMessage`
//! from the raw ciphertext *before* touching any store, so feeding it arbitrary
//! bytes stresses the wrapper's framing/ID-extraction and slice handling. The
//! callbacks supply a valid local identity and valid (signed/one-time/Kyber)
//! pre-key records, so a structurally-valid input drives past the store loads
//! into record parsing, identity pre-seeding, and libsignal's `process_prekey`.
//! `known_identity` is input-controlled: `None` exercises trust-on-first-use,
//! `Some(bytes)` exercises `preseed_identity` (public-key parsing plus the
//! `is_trusted_identity` comparison). We also fuzz
//! `extract_prekey_message_ids`, the standalone message-inspection helper.
//!
//! The future is driven by a tokio current-thread runtime (like FRB in
//! production) because the wrapper internally uses `futures::executor::block_on`,
//! which panics if nested inside another `futures` executor.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use libsignal_frb::api::keys::{IdentityKeyPair, PrivateKey};
use libsignal_frb::api::kyber::{KyberKeyPair, KyberPreKeyRecord};
use libsignal_frb::api::prekey::PreKeyRecord;
use libsignal_frb::api::session_cipher::{
    extract_prekey_message_ids, message_decrypt_prekey_with_callbacks,
};
use libsignal_frb::api::signed_prekey::SignedPreKeyRecord;
use once_cell::sync::Lazy;

/// Valid serialized local state, generated once and reused across inputs.
struct Seeds {
    /// Serialized `IdentityKeyPair` (our identity).
    identity: Vec<u8>,
    /// Serialized `SignedPreKeyRecord`, signed by the identity key.
    signed_prekey: Vec<u8>,
    /// Serialized one-time `PreKeyRecord`.
    prekey: Vec<u8>,
    /// Serialized `KyberPreKeyRecord`, signed by the identity key.
    kyber_prekey: Vec<u8>,
}

static SEEDS: Lazy<Seeds> = Lazy::new(|| {
    let identity = IdentityKeyPair::generate().expect("identity generation");
    let identity_priv = PrivateKey::deserialize(
        identity.private_key().expect("identity private key"),
    )
    .expect("identity private key parse");

    let spk_priv = PrivateKey::generate().expect("signed pre-key generation");
    let spk_pub = spk_priv.get_public_key().expect("signed pre-key public");
    let spk_sig = identity_priv
        .sign(spk_pub.serialize().expect("signed pre-key serialize"))
        .expect("signed pre-key signature");
    let signed_prekey = SignedPreKeyRecord::new(1, 0, &spk_pub, &spk_priv, spk_sig)
        .expect("signed pre-key record")
        .serialize()
        .expect("signed pre-key record serialize");

    let pk_priv = PrivateKey::generate().expect("pre-key generation");
    let pk_pub = pk_priv.get_public_key().expect("pre-key public");
    let prekey = PreKeyRecord::new(1, &pk_pub, &pk_priv)
        .expect("pre-key record")
        .serialize()
        .expect("pre-key record serialize");

    let kyber = KyberKeyPair::generate().expect("kyber generation");
    let kyber_sig = identity_priv
        .sign(
            kyber
                .get_public_key()
                .expect("kyber public")
                .serialize()
                .expect("kyber public serialize"),
        )
        .expect("kyber signature");
    let kyber_prekey = KyberPreKeyRecord::create(1, 0, &kyber, kyber_sig)
        .expect("kyber record")
        .serialize()
        .expect("kyber record serialize");

    Seeds {
        identity: identity.serialize().expect("identity serialization"),
        signed_prekey,
        prekey,
        kyber_prekey,
    }
});

/// Drives the async entry point the way FRB does in production (tokio), so the
/// wrapper's internal `futures::executor::block_on` calls do not nest inside
/// another `futures` executor.
static RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime")
});

#[derive(Arbitrary, Debug)]
struct SessionInput {
    inspect_only: bool,
    /// Previously-trusted identity handed to `get_identity`: `None` =
    /// first contact, `Some` = exercises the pre-seed / trust-check branch
    /// (arbitrary bytes stress public-key parsing; the fuzzer can evolve a
    /// valid 33-byte key to reach the identity comparison itself).
    known_identity: Option<Vec<u8>>,
    payload: Vec<u8>,
}

fuzz_target!(|input: SessionInput| {
    if input.inspect_only {
        let _ = extract_prekey_message_ids(input.payload);
        return;
    }

    let identity = SEEDS.identity.clone();
    let signed_prekey = SEEDS.signed_prekey.clone();
    let prekey = SEEDS.prekey.clone();
    let kyber_prekey = SEEDS.kyber_prekey.clone();
    let known_identity = input.known_identity.clone();

    let _ = RUNTIME.block_on(message_decrypt_prekey_with_callbacks(
        "remote".to_string(),
        1,
        "local".to_string(),
        1,
        input.payload,
        |_name, _dev| Box::pin(async { None::<Vec<u8>> }),
        |_name, _dev, _rec| Box::pin(async {}),
        move || {
            let id = identity.clone();
            Box::pin(async move { id })
        },
        || Box::pin(async { 1u32 }),
        |_name, _dev, _key| Box::pin(async {}),
        move |_id| {
            let bytes = signed_prekey.clone();
            Box::pin(async move { Some(bytes) })
        },
        move |_id| {
            let bytes = prekey.clone();
            Box::pin(async move { Some(bytes) })
        },
        |_id| Box::pin(async {}),
        move |_id| {
            let bytes = kyber_prekey.clone();
            Box::pin(async move { Some(bytes) })
        },
        |_id| Box::pin(async {}),
        move |_name, _dev| {
            let known = known_identity.clone();
            Box::pin(async move { known })
        },
    ));
});
