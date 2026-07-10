//! Seed-corpus generator for the fuzz targets.
//!
//! Produces valid serializations of keys and records so libFuzzer starts from
//! structurally-correct inputs instead of discovering the wire format blind.
//! Each seed is prefixed with the selector byte the corresponding target uses
//! to dispatch (see the `match selector % N` in each fuzz target).
//!
//! Run via `make fuzz-seed`, which invokes it from `rust/fuzz` so the default
//! output directory `corpus/<target>` matches what `cargo fuzz` expects.

use std::fs;
use std::path::Path;

use libsignal_frb::api::keys::{IdentityKeyPair, PrivateKey};
use libsignal_frb::api::kyber::{KyberKeyPair, KyberPreKeyRecord};
use libsignal_frb::api::prekey::PreKeyRecord;

fn write_seed(dir: &Path, name: &str, selector: u8, body: Vec<u8>) {
    if let Err(e) = fs::create_dir_all(dir) {
        eprintln!("skip {}: {}", dir.display(), e);
        return;
    }
    let mut bytes = Vec::with_capacity(body.len() + 1);
    bytes.push(selector);
    bytes.extend_from_slice(&body);
    let path = dir.join(name);
    if let Err(e) = fs::write(&path, &bytes) {
        eprintln!("skip {}: {}", path.display(), e);
    } else {
        println!("wrote {} ({} bytes)", path.display(), bytes.len());
    }
}

fn main() {
    let base = std::env::args().nth(1).unwrap_or_else(|| "corpus".to_string());
    let base = Path::new(&base);
    let keys_dir = base.join("keys");
    let records_dir = base.join("records");

    // --- keys target (selector % 3): 0=public, 1=private, 2=identity pair ---
    if let Ok(priv_key) = PrivateKey::generate() {
        if let Ok(bytes) = priv_key.serialize() {
            write_seed(&keys_dir, "private", 1, bytes);
        }
        if let Ok(pub_key) = priv_key.get_public_key()
            && let Ok(bytes) = pub_key.serialize()
        {
            write_seed(&keys_dir, "public", 0, bytes);
        }
    }
    if let Ok(ikp) = IdentityKeyPair::generate()
        && let Ok(bytes) = ikp.serialize()
    {
        write_seed(&keys_dir, "identity_pair", 2, bytes);
    }

    // --- records target (selector % 6) ---
    // 0 = PreKeyRecord
    if let Ok(priv_key) = PrivateKey::generate()
        && let Ok(pub_key) = priv_key.get_public_key()
        && let Ok(record) = PreKeyRecord::new(1, &pub_key, &priv_key)
        && let Ok(bytes) = record.serialize()
    {
        write_seed(&records_dir, "prekey", 0, bytes);
    }
    // 3 = KyberPreKeyRecord, 4 = KyberPublicKey, 5 = KyberSecretKey
    if let Ok(kyber) = KyberKeyPair::generate() {
        if let Ok(pub_key) = kyber.get_public_key()
            && let Ok(bytes) = pub_key.serialize()
        {
            write_seed(&records_dir, "kyber_public", 4, bytes);
        }
        if let Ok(sec_key) = kyber.get_secret_key()
            && let Ok(bytes) = sec_key.serialize()
        {
            write_seed(&records_dir, "kyber_secret", 5, bytes);
        }
        if let Ok(record) = KyberPreKeyRecord::create(1, 0, &kyber, vec![0u8; 64])
            && let Ok(bytes) = record.serialize()
        {
            write_seed(&records_dir, "kyber_prekey", 3, bytes);
        }
    }

    println!("Seed corpus generation complete.");
}
