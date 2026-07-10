#![no_main]
//! Fuzz the record deserializers. Records are what a production store persists
//! and reloads; a corrupted database row flows straight into these functions.

use libfuzzer_sys::fuzz_target;
use libsignal_frb::api::kyber::{KyberPreKeyRecord, KyberPublicKey, KyberSecretKey};
use libsignal_frb::api::prekey::PreKeyRecord;
use libsignal_frb::api::session::SessionRecord;
use libsignal_frb::api::signed_prekey::SignedPreKeyRecord;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let selector = data[0];
    let payload = data[1..].to_vec();

    match selector % 6 {
        0 => {
            let _ = PreKeyRecord::deserialize(payload);
        }
        1 => {
            let _ = SignedPreKeyRecord::deserialize(payload);
        }
        2 => {
            let _ = SessionRecord::deserialize(payload);
        }
        3 => {
            let _ = KyberPreKeyRecord::deserialize(payload);
        }
        4 => {
            let _ = KyberPublicKey::deserialize(payload);
        }
        _ => {
            let _ = KyberSecretKey::deserialize(payload);
        }
    }
});
