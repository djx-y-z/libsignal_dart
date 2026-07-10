#![no_main]
//! Fuzz the standalone cryptographic primitives added by this wrapper:
//! HKDF, AES-256-GCM-SIV, and scannable-fingerprint comparison. Unlike the
//! deserializers these carry hand-written length/allocation logic (e.g. the
//! HKDF output-length guard), which is exactly what we want to stress.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use libsignal_frb::api::crypto::{fingerprint_compare, hkdf_derive, Aes256GcmSiv, Fingerprint};

#[derive(Arbitrary, Debug)]
struct CryptoInput {
    /// u16 keeps allocation bounded while still crossing the 8160-byte HKDF cap.
    output_length: u16,
    ikm: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: Vec<u8>,
    msg: Vec<u8>,
    do_decrypt: bool,
    iterations: u16,
    version: u8,
    fp1: Vec<u8>,
    fp2: Vec<u8>,
}

fuzz_target!(|input: CryptoInput| {
    // HKDF: exercises the output-length guard and zeroization on both paths.
    let _ = hkdf_derive(
        input.output_length as u32,
        input.ikm.clone(),
        input.salt.clone(),
        input.info.clone(),
    );

    // AES-256-GCM-SIV: key/nonce length validation, encrypt and decrypt.
    if let Ok(cipher) = Aes256GcmSiv::new(input.key.clone()) {
        if input.do_decrypt {
            let _ = cipher.decrypt(input.msg.clone(), input.nonce.clone(), input.aad.clone());
        } else {
            let _ = cipher.encrypt(input.msg.clone(), input.nonce.clone(), input.aad.clone());
        }
    }

    // Scannable fingerprint comparison over two arbitrary encodings.
    let _ = fingerprint_compare(input.fp1.clone(), input.fp2.clone());

    // Fingerprint construction parses two public keys from fp1/fp2.
    let _ = Fingerprint::new(
        input.iterations as u32,
        input.version as u32,
        input.ikm,
        input.fp1,
        input.info,
        input.fp2,
    );
});
