#![no_main]
//! Fuzz the public entry points that parse attacker-controlled key bytes.
//!
//! These `deserialize` functions sit directly on the network/storage boundary:
//! a peer or a corrupted store can hand us arbitrary bytes. We only assert that
//! they never panic / abort — a well-formed `Err(String)` is a success.

use libfuzzer_sys::fuzz_target;
use libsignal_frb::api::keys::{IdentityKeyPair, PrivateKey, PublicKey};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // First byte selects the key type so libFuzzer can attribute coverage
    // per-parser; the remainder is the candidate serialization.
    let selector = data[0];
    let payload = data[1..].to_vec();

    match selector % 3 {
        0 => {
            let _ = PublicKey::deserialize(payload);
        }
        1 => {
            let _ = PrivateKey::deserialize(payload);
        }
        _ => {
            let _ = IdentityKeyPair::deserialize(payload);
        }
    }
});
