#![no_main]
//! Fuzz the message parsers. `SignalMessage` and `DecryptionErrorMessage` are
//! reconstructed from raw bytes received over the wire, so their `try_from`
//! paths (protobuf + framing) are a prime target for malformed input.

use libfuzzer_sys::fuzz_target;
use libsignal_frb::api::message::{DecryptionErrorMessage, SignalMessage};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let selector = data[0];
    let payload = data[1..].to_vec();

    match selector % 3 {
        0 => {
            let _ = SignalMessage::deserialize(payload);
        }
        1 => {
            let _ = DecryptionErrorMessage::deserialize(payload);
        }
        _ => {
            let _ = DecryptionErrorMessage::extract_from_serialized_content(payload);
        }
    }
});
