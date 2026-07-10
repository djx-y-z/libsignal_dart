#![no_main]
//! Fuzz the Sealed Sender certificate parsers and the validation entry point.
//! Sender certificates arrive from the server and gate anonymous delivery, so
//! their deserialization and signature-validation paths must never panic.

use libfuzzer_sys::fuzz_target;
use libsignal_frb::api::sealed_sender::{
    sender_certificate_get_expiration, sender_certificate_get_key,
    sender_certificate_get_sender_device_id, sender_certificate_get_sender_name,
    validate_sender_certificate,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    let selector = data[0];
    // Bytes 1..9 form a timestamp; the rest is the certificate material.
    let timestamp = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let rest = &data[9..];

    match selector % 5 {
        0 => {
            let _ = sender_certificate_get_sender_name(rest.to_vec());
        }
        1 => {
            let _ = sender_certificate_get_sender_device_id(rest.to_vec());
        }
        2 => {
            let _ = sender_certificate_get_key(rest.to_vec());
        }
        3 => {
            let _ = sender_certificate_get_expiration(rest.to_vec());
        }
        _ => {
            // Split `rest` into a certificate blob and a trust-root blob using a
            // 2-byte length prefix so both arguments get fuzzed independently.
            if rest.len() < 2 {
                return;
            }
            let split = u16::from_le_bytes([rest[0], rest[1]]) as usize;
            let body = &rest[2..];
            let split = split.min(body.len());
            let (cert, trust_root) = body.split_at(split);
            let _ = validate_sender_certificate(cert.to_vec(), trust_root.to_vec(), timestamp);
        }
    }
});
