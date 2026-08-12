//! Differential tests for the Sealed Sender v2 fan-out offsets.
//!
//! TO LAND: copy to `rust/src/ssv2_equivalence_tests.rs` and add
//!
//! ```ignore
//! #[cfg(test)]
//! mod ssv2_equivalence_tests;
//! ```
//!
//! to `rust/src/lib.rs`, next to `mod utils;`. It must stay **outside `api/`** —
//! anything under `api/` is scanned by FRB codegen. Run with `make rust-test`.
//!
//! Why this exists: `sealedSenderV2ParseSentMessage` returns *offsets* and the
//! Dart helper `SealedSenderV2SentMessage.receivedMessageFor` assembles the
//! per-recipient message from them. That assembly must stay byte-identical to
//! libsignal's own `received_message_parts_for_recipient`; if it drifts by one
//! byte, multi-recipient sealed sender silently stops decrypting. The Dart
//! suite can only observe that end-to-end, and only for the shapes it happens
//! to build. This compares against upstream directly, on a corpus plus a real
//! message, and it is where a fuzz-style sweep over the parser lives until a
//! proper `cargo-fuzz` target exists (see SECURITY.md's coverage gap note).

use crate::api::sealed_sender as ours;
use futures::executor::block_on;
use libsignal_protocol as up;

// ---------------------------------------------------------------------------
// Byte-for-byte replica of lib/src/sealed_sender/sealed_sender_v2.dart
// ---------------------------------------------------------------------------

fn dart_received_message_for(
    parsed: &ours::SealedSenderV2SentMessage,
    recipient: &ours::SealedSenderV2Recipient,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    if data.len() != parsed.parsed_length as usize {
        return Err("ArgumentError: length".to_string());
    }
    if recipient.devices.is_empty() {
        return Ok(Vec::new());
    }
    let key_start = recipient.key_material_start as usize;
    let key_end = recipient.key_material_end as usize;
    let shared = parsed.shared_bytes_offset as usize;
    let parsed_len = parsed.parsed_length as usize;
    if key_start > key_end || key_end > parsed_len || shared > parsed_len {
        return Err("ArgumentError: offsets".to_string());
    }
    let key_len = key_end - key_start;
    let shared_len = parsed_len - shared;
    let mut out = vec![0u8; 1 + key_len + shared_len];
    // Dart: `..[0] = receivedMessageVersion` on a Uint8List truncates mod 256.
    out[0] = parsed.received_message_version as u8;
    out[1..1 + key_len].copy_from_slice(&data[key_start..key_end]);
    out[1 + key_len..1 + key_len + shared_len].copy_from_slice(&data[shared..]);
    Ok(out)
}

// ---------------------------------------------------------------------------
// The differential assertion
// ---------------------------------------------------------------------------

fn assert_equivalent(label: &str, data: &[u8]) {
    let ours_res = block_on(ours::sealed_sender_v2_parse_sent_message(data.to_vec()));
    let up_res = up::SealedSenderV2SentMessage::parse(data);

    match (&ours_res, &up_res) {
        (Err(_), Err(_)) => return,
        (Ok(_), Err(e)) => panic!("[{label}] we parsed, upstream refused: {e}"),
        (Err(e), Ok(_)) => {
            // Only the deliberate u32 guard may diverge, and only above 4 GiB.
            assert!(
                e.starts_with("Message too large"),
                "[{label}] upstream parsed, we refused: {e}"
            );
            return;
        }
        (Ok(_), Ok(_)) => {}
    }

    let o = ours_res.unwrap();
    let u = up_res.unwrap();

    assert_eq!(o.version as u8, u.version, "[{label}] version");
    assert_eq!(
        o.parsed_length as usize,
        data.len(),
        "[{label}] parsed_length"
    );
    assert_eq!(
        o.shared_bytes_offset as usize,
        u.offset_of_shared_bytes(),
        "[{label}] shared offset"
    );
    assert_eq!(
        o.recipients.len(),
        u.recipients.len(),
        "[{label}] recipient count"
    );

    let shared_off = u.offset_of_shared_bytes();

    for (i, (service_id, up_rec)) in u.recipients.iter().enumerate() {
        let our_rec = &o.recipients[i];
        assert_eq!(
            our_rec.service_id,
            service_id.service_id_string(),
            "[{label}] service id order at {i}"
        );
        assert_eq!(
            our_rec.devices.len(),
            up_rec.devices.len(),
            "[{label}] device count at {i}"
        );
        for (d, (dev_id, reg_id)) in up_rec.devices.iter().enumerate() {
            assert_eq!(our_rec.devices[d].device_id, u32::from(*dev_id));
            assert_eq!(our_rec.devices[d].registration_id, u32::from(*reg_id));
        }

        let range = u.range_for_recipient_key_material(up_rec);
        assert_eq!(
            our_rec.key_material_start as usize,
            range.start,
            "[{label}] key start at {i}"
        );
        assert_eq!(
            our_rec.key_material_end as usize,
            range.end,
            "[{label}] key end at {i}"
        );

        let ours_msg = dart_received_message_for(&o, our_rec, data)
            .unwrap_or_else(|e| panic!("[{label}] Dart replica refused valid data at {i}: {e}"));
        let up_msg: Vec<u8> = u
            .received_message_parts_for_recipient(up_rec)
            .as_ref()
            .concat();

        if up_rec.devices.is_empty() {
            // Deliberate divergence from raw upstream: an excluded recipient has
            // no message. Upstream would still hand back [0x22] ++ shared.
            assert!(ours_msg.is_empty(), "[{label}] excluded recipient at {i}");
            assert_eq!(range, 0..0, "[{label}] excluded range at {i}");
        } else {
            assert_eq!(
                ours_msg, up_msg,
                "[{label}] BYTE MISMATCH for recipient {i} ({})",
                our_rec.service_id
            );
            // Key-confusion detector: a recipient's key material must sit
            // strictly before the shared run, and after the version byte.
            assert!(
                range.start >= 1 && range.end <= shared_off,
                "[{label}] key material {range:?} overlaps shared run at {shared_off} (recipient {i})"
            );
            assert_eq!(range.end - range.start, 48, "[{label}] key material size");
            assert_eq!(ours_msg[0], 0x22, "[{label}] ReceivedMessage version byte");
        }
    }
}

/// Only checks that neither parser panics, and that they agree on accept/reject.
fn assert_no_panic(label: &str, data: &[u8]) {
    let ours_res = block_on(ours::sealed_sender_v2_parse_sent_message(data.to_vec()));
    if ours_res.is_ok() {
        assert_equivalent(label, data);
    }
}

// ---------------------------------------------------------------------------
// Hand-built SSv2 SentMessages
// ---------------------------------------------------------------------------

const KEY_MATERIAL_LEN: usize = 48; // MESSAGE_KEY_LEN 32 + AUTH_TAG_LEN 16
const PUBLIC_KEY_LEN: usize = 32;

#[derive(Clone)]
struct Spec {
    /// 17-byte fixed-width binary service id (byte 0 = 0 for ACI, 1 for PNI).
    service_id: [u8; 17],
    /// (device_id, registration_id) pairs; empty = excluded recipient.
    devices: Vec<(u8, u16)>,
    fill: u8,
}

fn spec(tag: u8, kind: u8, devices: Vec<(u8, u16)>) -> Spec {
    let mut service_id = [0u8; 17];
    service_id[0] = kind;
    for (i, b) in service_id.iter_mut().enumerate().skip(1) {
        *b = tag.wrapping_add(i as u8);
    }
    Spec {
        service_id,
        devices,
        fill: tag,
    }
}

fn put_varint(v: usize, out: &mut Vec<u8>) {
    let mut v = v as u64;
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

fn build(version: u8, specs: &[Spec], shared_len: usize) -> Vec<u8> {
    let mut out = vec![version];
    put_varint(specs.len(), &mut out);
    for s in specs {
        if version == 0x22 {
            out.extend_from_slice(&s.service_id[1..]); // raw UUID only
        } else {
            out.extend_from_slice(&s.service_id);
        }
        if s.devices.is_empty() {
            out.push(0);
        } else {
            for (i, (dev, reg)) in s.devices.iter().enumerate() {
                out.push(*dev);
                let mut r = *reg & 0x3fff;
                if i + 1 < s.devices.len() {
                    r |= 0x8000;
                }
                out.extend_from_slice(&r.to_be_bytes());
            }
            out.extend((0..KEY_MATERIAL_LEN).map(|i| s.fill.wrapping_mul(3).wrapping_add(i as u8)));
        }
    }
    out.extend((0..shared_len).map(|i| 0xA0u8.wrapping_add(i as u8)));
    out
}

fn corpus() -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    for version in [0x22u8, 0x23u8] {
        let tag = |n: &str| format!("v{version:#04x} {n}");

        v.push((
            tag("single/1dev"),
            build(version, &[spec(1, 0, vec![(1, 100)])], PUBLIC_KEY_LEN + 64),
        ));
        v.push((
            tag("single/3dev"),
            build(
                version,
                &[spec(1, 0, vec![(1, 100), (2, 0x3FFF), (127, 1)])],
                PUBLIC_KEY_LEN + 5,
            ),
        ));
        v.push((
            tag("three recipients"),
            build(
                version,
                &[
                    spec(1, 0, vec![(1, 1)]),
                    spec(2, 0, vec![(1, 2), (2, 3)]),
                    spec(3, 0, vec![(9, 4)]),
                ],
                PUBLIC_KEY_LEN + 200,
            ),
        ));
        v.push((
            tag("excluded first"),
            build(
                version,
                &[spec(7, 0, vec![]), spec(1, 0, vec![(1, 1)])],
                PUBLIC_KEY_LEN,
            ),
        ));
        v.push((
            tag("excluded middle"),
            build(
                version,
                &[
                    spec(1, 0, vec![(1, 1)]),
                    spec(7, 0, vec![]),
                    spec(2, 0, vec![(2, 2)]),
                ],
                PUBLIC_KEY_LEN + 10,
            ),
        ));
        v.push((
            tag("excluded last"),
            build(
                version,
                &[spec(1, 0, vec![(1, 1)]), spec(7, 0, vec![])],
                PUBLIC_KEY_LEN + 10,
            ),
        ));
        v.push((
            tag("all excluded"),
            build(
                version,
                &[spec(7, 0, vec![]), spec(8, 0, vec![])],
                PUBLIC_KEY_LEN,
            ),
        ));
        v.push((tag("zero recipients"), build(version, &[], PUBLIC_KEY_LEN + 3)));
        // Same service id twice, both with devices: upstream merges devices and
        // keeps the FIRST occurrence's key material.
        let dup = spec(5, 0, vec![(1, 1)]);
        let mut dup2 = dup.clone();
        dup2.devices = vec![(2, 2)];
        dup2.fill = 0x77;
        v.push((
            tag("duplicate service id"),
            build(version, &[dup.clone(), dup2], PUBLIC_KEY_LEN + 8),
        ));
        // Big fan-out.
        let many: Vec<Spec> = (0..200)
            .map(|i| spec(i as u8, 0, vec![(1, i as u16 & 0x3FFF)]))
            .collect();
        v.push((
            tag("200 recipients"),
            build(version, &many, PUBLIC_KEY_LEN + 4096),
        ));
        // Large shared body.
        v.push((
            tag("large body"),
            build(
                version,
                &[spec(1, 0, vec![(1, 1)]), spec(2, 0, vec![(1, 2)])],
                300_000,
            ),
        ));
    }
    // PNI service ids only exist in the 0x23 encoding.
    v.push((
        "v0x23 pni".to_string(),
        build(
            0x23,
            &[spec(1, 1, vec![(1, 1)]), spec(2, 0, vec![(1, 2)])],
            PUBLIC_KEY_LEN,
        ),
    ));
    v
}

#[test]
fn ssv2_offsets_reassemble_exactly_like_upstream() {
    for (label, data) in corpus() {
        assert_equivalent(&label, &data);
    }
}

#[test]
fn ssv2_truncations_never_panic() {
    for (label, data) in corpus() {
        let step = if data.len() > 4096 { 97 } else { 1 };
        let mut n = 0;
        while n <= data.len() {
            assert_no_panic(&format!("{label} trunc {n}"), &data[..n]);
            n += step;
        }
    }
}

#[test]
fn ssv2_byte_mutations_never_panic_and_stay_equivalent() {
    // Deterministic LCG; no rand dependency, reproducible across runs.
    let mut state: u64 = 0x2026_0812_dead_beef;
    let mut next = move || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u32
    };

    for (label, data) in corpus() {
        if data.len() > 8192 {
            continue;
        }
        for _ in 0..400 {
            let mut m = data.clone();
            let flips = 1 + (next() % 4) as usize;
            for _ in 0..flips {
                let idx = (next() as usize) % m.len();
                m[idx] = (next() & 0xff) as u8;
            }
            assert_no_panic(&format!("{label} mutated"), &m);
        }
        for _ in 0..200 {
            let cut = (next() as usize) % (data.len() + 1);
            assert_no_panic(&format!("{label} cut"), &data[..cut]);
        }
    }
}

/// Proves `assert_equivalent` can actually fail: the same corpus, assembled the
/// way a plausible off-by-one bug would assemble it, must NOT match upstream.
#[test]
fn differential_assertion_is_not_vacuous() {
    let mut caught = 0usize;
    for (_, data) in corpus() {
        let o = match block_on(ours::sealed_sender_v2_parse_sent_message(data.clone())) {
            Ok(o) => o,
            Err(_) => continue,
        };
        let u = up::SealedSenderV2SentMessage::parse(&data).unwrap();
        for (i, (_, up_rec)) in u.recipients.iter().enumerate() {
            if up_rec.devices.is_empty() {
                continue;
            }
            let up_msg: Vec<u8> = u
                .received_message_parts_for_recipient(up_rec)
                .as_ref()
                .concat();

            // Mutation A: off-by-one on the shared run.
            if o.shared_bytes_offset > 0 {
                let mut broken = o.clone_shallow();
                broken.shared_bytes_offset = o.shared_bytes_offset - 1;
                let a = dart_received_message_for(&broken, &o.recipients[i], &data).unwrap();
                assert_ne!(a, up_msg, "mutation A went undetected at {i}");
            }

            // Mutation B: another recipient's key material (key confusion).
            if let Some(j) =
                (0..o.recipients.len()).find(|&j| j != i && !o.recipients[j].devices.is_empty())
            {
                let mut swapped = o.recipients[i].clone_shallow();
                swapped.key_material_start = o.recipients[j].key_material_start;
                swapped.key_material_end = o.recipients[j].key_material_end;
                let b = dart_received_message_for(&o, &swapped, &data).unwrap();
                assert_ne!(b, up_msg, "mutation B went undetected at {i}");
                caught += 1;
            }

            // Mutation C: wrong ReceivedMessage version byte.
            let mut wrong_version = o.clone_shallow();
            wrong_version.received_message_version = 0x23;
            let c = dart_received_message_for(&wrong_version, &o.recipients[i], &data).unwrap();
            assert_ne!(c, up_msg, "mutation C went undetected at {i}");
        }
    }
    assert!(
        caught > 0,
        "no multi-recipient corpus entry exercised swapping"
    );
}

trait ShallowClone {
    fn clone_shallow(&self) -> Self;
}
impl ShallowClone for ours::SealedSenderV2SentMessage {
    fn clone_shallow(&self) -> Self {
        Self {
            version: self.version,
            received_message_version: self.received_message_version,
            shared_bytes_offset: self.shared_bytes_offset,
            parsed_length: self.parsed_length,
            recipients: self.recipients.iter().map(|r| r.clone_shallow()).collect(),
        }
    }
}
impl ShallowClone for ours::SealedSenderV2Recipient {
    fn clone_shallow(&self) -> Self {
        Self {
            service_id: self.service_id.clone(),
            devices: self
                .devices
                .iter()
                .map(|d| ours::SealedSenderV2Device {
                    device_id: d.device_id,
                    registration_id: d.registration_id,
                })
                .collect(),
            key_material_start: self.key_material_start,
            key_material_end: self.key_material_end,
        }
    }
}

#[test]
fn ssv2_hostile_inputs_never_panic() {
    let hostile: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("version only 0x22", vec![0x22]),
        ("version only 0x23", vec![0x23]),
        ("bad version 0x00", vec![0x00, 0x01]),
        ("bad version 0x21", vec![0x21, 0x01]),
        ("bad version 0x24", vec![0x24, 0x01]),
        ("bad version 0xff", vec![0xff; 64]),
        ("huge count", {
            let mut v = vec![0x23];
            put_varint(usize::MAX, &mut v);
            v
        }),
        ("count 6000 no data", {
            let mut v = vec![0x23];
            put_varint(6000, &mut v);
            v
        }),
        ("count u32ish", {
            let mut v = vec![0x23];
            put_varint(4_000_000_000, &mut v);
            v
        }),
        ("zero device after device", {
            let mut v = vec![0x23];
            put_varint(1, &mut v);
            v.extend_from_slice(&[0u8; 17]);
            v.push(1);
            v.extend_from_slice(&0x8001u16.to_be_bytes()); // has_more
            v.push(0); // device id 0
            v.extend_from_slice(&[7u8; KEY_MATERIAL_LEN]);
            v.extend_from_slice(&[9u8; PUBLIC_KEY_LEN]);
            v
        }),
        (
            "short shared",
            build(0x23, &[spec(1, 0, vec![(1, 1)])], PUBLIC_KEY_LEN - 1),
        ),
        ("zero shared", build(0x23, &[spec(1, 0, vec![(1, 1)])], 0)),
        (
            "exactly 32 shared",
            build(0x23, &[spec(1, 0, vec![(1, 1)])], PUBLIC_KEY_LEN),
        ),
        ("dup with empty", {
            let a = spec(3, 0, vec![(1, 1)]);
            let mut b = a.clone();
            b.devices = vec![];
            build(0x23, &[a, b], PUBLIC_KEY_LEN)
        }),
        ("dup empty first", {
            let mut a = spec(3, 0, vec![]);
            let b = {
                let mut t = a.clone();
                t.devices = vec![(1, 1)];
                t
            };
            a.devices = vec![];
            build(0x23, &[a, b], PUBLIC_KEY_LEN)
        }),
        (
            "bad service id kind",
            build(0x23, &[spec(1, 9, vec![(1, 1)])], PUBLIC_KEY_LEN),
        ),
        ("count overshoot", {
            let mut v = build(0x23, &[spec(1, 0, vec![(1, 1)])], PUBLIC_KEY_LEN);
            v[1] = 5;
            v
        }),
        ("count undershoot", {
            let mut v = build(
                0x23,
                &[spec(1, 0, vec![(1, 1)]), spec(2, 0, vec![(1, 2)])],
                PUBLIC_KEY_LEN,
            );
            v[1] = 1;
            v
        }),
        ("registration id top bits set", {
            let mut v = vec![0x23];
            put_varint(1, &mut v);
            v.extend_from_slice(&[0u8; 17]);
            v.push(1);
            v.extend_from_slice(&0x7FFFu16.to_be_bytes());
            v.extend_from_slice(&[7u8; KEY_MATERIAL_LEN]);
            v.extend_from_slice(&[9u8; PUBLIC_KEY_LEN]);
            v
        }),
    ];

    for (label, data) in hostile {
        assert_no_panic(label, &data);
    }
}

// ---------------------------------------------------------------------------
// A real SentMessage, produced by upstream's own encrypt
// ---------------------------------------------------------------------------

#[test]
fn real_multi_recipient_message_reassembles_exactly() {
    use rand::TryRngCore as _;
    use up::{
        DeviceId, GenericSignedPreKey as _, IdentityKeyPair, IdentityKeyStore as _, KeyPair,
        KyberPreKeyRecord, PreKeyBundle, PreKeyRecord, ProtocolAddress, SenderCertificate,
        ServerCertificate, SignedPreKeyRecord, Timestamp, UnidentifiedSenderMessageContent, kem,
    };

    // NOTE: everything that itself calls `block_on` must stay OUTSIDE this one
    // — nesting two `LocalPool`s panics with `EnterError`.
    let sent: Vec<u8> = block_on(async {
        let mut rng = rand::rngs::OsRng.unwrap_err();

        let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
        let alice_device = DeviceId::new(23).unwrap();
        let alice_addr = ProtocolAddress::new(alice_uuid.clone(), alice_device);

        let mut alice_store =
            up::InMemSignalProtocolStore::new(IdentityKeyPair::generate(&mut rng), 11).unwrap();

        // Three recipients, one of them with two devices, plus one excluded.
        let uuids = [
            "796abedb-ca4e-4f18-8803-1fde5b921f9f",
            "3f0f4734-e331-4434-bd4f-6d8f6ea6dcc7",
            "5d088142-6fd7-4dbd-af00-fdda1b3ce988",
        ];
        let mut recipient_addrs: Vec<ProtocolAddress> = Vec::new();

        for (i, uuid) in uuids.iter().enumerate() {
            let devices: &[u32] = if i == 1 { &[1, 2] } else { &[1] };
            for dev in devices {
                let addr =
                    ProtocolAddress::new(uuid.to_string(), DeviceId::new(*dev as u8).unwrap());
                let bob_identity = IdentityKeyPair::generate(&mut rng);
                let mut bob_store =
                    up::InMemSignalProtocolStore::new(bob_identity, 100 + i as u32).unwrap();

                let pre_key_pair = KeyPair::generate(&mut rng);
                let signed_pre_key_pair = KeyPair::generate(&mut rng);
                let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

                let bob_ikp = bob_store.get_identity_key_pair().await.unwrap();
                let signed_sig = bob_ikp
                    .private_key()
                    .calculate_signature(&signed_pre_key_pair.public_key.serialize(), &mut rng)
                    .unwrap();
                let kyber_sig = bob_ikp
                    .private_key()
                    .calculate_signature(&kyber_pre_key_pair.public_key.serialize(), &mut rng)
                    .unwrap();

                let bundle = PreKeyBundle::new(
                    bob_store.get_local_registration_id().await.unwrap(),
                    addr.device_id(),
                    Some((1u32.into(), pre_key_pair.public_key)),
                    2u32.into(),
                    signed_pre_key_pair.public_key,
                    signed_sig.to_vec(),
                    3u32.into(),
                    kyber_pre_key_pair.public_key.clone(),
                    kyber_sig.to_vec(),
                    *bob_ikp.identity_key(),
                )
                .unwrap();

                let _ = PreKeyRecord::new(1u32.into(), &pre_key_pair);
                let _ = SignedPreKeyRecord::new(
                    2u32.into(),
                    Timestamp::from_epoch_millis(0),
                    &signed_pre_key_pair,
                    &signed_sig,
                );
                let _ = KyberPreKeyRecord::new(
                    3u32.into(),
                    Timestamp::from_epoch_millis(0),
                    &kyber_pre_key_pair,
                    &kyber_sig,
                );
                let _ = &mut bob_store;

                up::process_prekey_bundle(
                    &addr,
                    &alice_addr,
                    &mut alice_store.session_store,
                    &mut alice_store.identity_store,
                    &bundle,
                    std::time::SystemTime::now(),
                    &mut rng,
                )
                .await
                .unwrap();

                recipient_addrs.push(addr);
            }
        }

        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);
        let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)
                .unwrap();
        let alice_pubkey = *alice_store
            .get_identity_key_pair()
            .await
            .unwrap()
            .public_key();
        let sender_cert = SenderCertificate::new(
            alice_uuid.clone(),
            None,
            alice_pubkey,
            alice_device,
            Timestamp::from_epoch_millis(1605722925),
            server_cert,
            &server_key.private_key,
            &mut rng,
        )
        .unwrap();

        let inner = up::message_encrypt(
            &[1u8, 2, 3, 23, 99],
            &recipient_addrs[0],
            &alice_addr,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            std::time::SystemTime::now(),
            &mut rng,
        )
        .await
        .unwrap();

        let usmc = UnidentifiedSenderMessageContent::new(
            inner.message_type(),
            sender_cert,
            inner.serialize().to_vec(),
            up::ContentHint::Default,
            None,
        )
        .unwrap();

        let refs: Vec<&ProtocolAddress> = recipient_addrs.iter().collect();
        let sessions = alice_store
            .session_store
            .load_existing_sessions(&refs)
            .unwrap();

        let excluded = vec![
            up::ServiceId::parse_from_service_id_string("PNI:d1d1d1d1-0000-4000-8000-000000000001")
                .unwrap(),
        ];

        up::sealed_sender_multi_recipient_encrypt(
            &refs,
            &sessions,
            excluded,
            &usmc,
            &alice_store.identity_store,
            &mut rng,
        )
        .await
        .unwrap()
    });

    assert_eq!(sent[0], 0x23, "sanity: SentMessage version");
    assert_equivalent("REAL multi-recipient message", &sent);

    // And every truncation of it.
    for n in 0..=sent.len() {
        assert_no_panic(&format!("REAL trunc {n}"), &sent[..n]);
    }

    let parsed = block_on(ours::sealed_sender_v2_parse_sent_message(sent.clone())).unwrap();
    assert_eq!(parsed.received_message_version, 0x22);
    assert_eq!(parsed.recipients.len(), 4, "3 real + 1 excluded");
    let excluded_rec = parsed
        .recipients
        .iter()
        .find(|r| r.devices.is_empty())
        .expect("one excluded recipient");
    assert_eq!(excluded_rec.key_material_start, excluded_rec.key_material_end);
    assert!(
        dart_received_message_for(&parsed, excluded_rec, &sent)
            .unwrap()
            .is_empty()
    );

    // The two-device recipient must still get exactly ONE key-material block.
    let two_dev = parsed
        .recipients
        .iter()
        .find(|r| r.devices.len() == 2)
        .expect("one recipient with two devices");
    assert_eq!(two_dev.key_material_end - two_dev.key_material_start, 48);
}
