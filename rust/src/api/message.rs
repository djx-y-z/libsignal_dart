//! Protocol message types API using libsignal-protocol.

use libsignal_protocol::{
    CiphertextMessageType, DecryptionErrorMessage as NativeDecryptionErrorMessage,
    DeviceId, IdentityKey, PlaintextContent as NativePlaintextContent,
    PreKeySignalMessage as NativePreKeySignalMessage, ProtocolAddress,
    PublicKey as NativePublicKey,
    SenderKeyDistributionMessage as NativeSenderKeyDistributionMessage,
    SenderKeyMessage as NativeSenderKeyMessage, SignalMessage as NativeSignalMessage, Timestamp,
};

/// An encrypted Signal Protocol message (whisper message).
pub struct SignalMessage {
    inner: NativeSignalMessage,
}

impl SignalMessage {
    /// Create from native libsignal SignalMessage.
    pub(crate) fn from_native(msg: NativeSignalMessage) -> Self {
        Self { inner: msg }
    }

    /// Get the inner native message (for use by other modules).
    pub(crate) fn native(&self) -> &NativeSignalMessage {
        &self.inner
    }

    /// Deserialize a SignalMessage from bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(data: Vec<u8>) -> Result<SignalMessage, String> {
        let native = NativeSignalMessage::try_from(&data[..]).map_err(|e| e.to_string())?;
        Ok(SignalMessage { inner: native })
    }

    /// Serialize the message to bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.serialized().to_vec())
    }

    /// Get the encrypted message body (ciphertext).
    #[flutter_rust_bridge::frb(sync)]
    pub fn body(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.body().to_vec())
    }

    /// Get the message counter.
    #[flutter_rust_bridge::frb(sync)]
    pub fn counter(&self) -> Result<u32, String> {
        Ok(self.inner.counter())
    }

    /// Get the Signal Protocol message version.
    #[flutter_rust_bridge::frb(sync)]
    pub fn message_version(&self) -> Result<u32, String> {
        Ok(self.inner.message_version() as u32)
    }

    /// Get the sender's current ratchet public key (serialized).
    #[flutter_rust_bridge::frb(sync)]
    pub fn sender_ratchet_key(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.sender_ratchet_key().serialize().into_vec())
    }

    /// Get the Post-Quantum ratchet state, if present.
    #[flutter_rust_bridge::frb(sync)]
    pub fn pq_ratchet(&self) -> Result<Option<Vec<u8>>, String> {
        let pq = self.inner.pq_ratchet();
        if pq.is_empty() {
            Ok(None)
        } else {
            Ok(Some(pq.to_vec()))
        }
    }

    /// Verify the MAC on this message.
    ///
    /// Takes the sender's and recipient's protocol addresses (name + device id),
    /// the serialized public keys for the sender and receiver identity keys, and
    /// the MAC key. If the message includes embedded addresses, they are also
    /// verified against the supplied addresses for backward compatibility.
    // MAC verification needs both protocol addresses plus both identity keys
    // and the MAC key — the argument count is inherent to the operation.
    #[allow(clippy::too_many_arguments)]
    #[flutter_rust_bridge::frb(sync)]
    pub fn verify_mac(
        &self,
        sender_address_name: String,
        sender_address_device_id: u32,
        recipient_address_name: String,
        recipient_address_device_id: u32,
        sender_identity_key: Vec<u8>,
        receiver_identity_key: Vec<u8>,
        mac_key: Vec<u8>,
    ) -> Result<bool, String> {
        let sender_pub =
            NativePublicKey::deserialize(&sender_identity_key).map_err(|e| e.to_string())?;
        let receiver_pub =
            NativePublicKey::deserialize(&receiver_identity_key).map_err(|e| e.to_string())?;
        let sender_identity = IdentityKey::new(sender_pub);
        let receiver_identity = IdentityKey::new(receiver_pub);
        let sender_device_id =
            DeviceId::try_from(sender_address_device_id).map_err(|e| e.to_string())?;
        let recipient_device_id =
            DeviceId::try_from(recipient_address_device_id).map_err(|e| e.to_string())?;
        let sender_address = ProtocolAddress::new(sender_address_name, sender_device_id);
        let recipient_address = ProtocolAddress::new(recipient_address_name, recipient_device_id);
        self.inner
            .verify_mac_with_addresses(
                &sender_address,
                &recipient_address,
                &sender_identity,
                &receiver_identity,
                &mac_key,
            )
            .map_err(|e: libsignal_protocol::SignalProtocolError| e.to_string())
    }

    /// Create a copy of this message.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_message(&self) -> Result<SignalMessage, String> {
        Ok(SignalMessage {
            inner: self.inner.clone(),
        })
    }
}

/// The first message of a session, carrying the X3DH/PQXDH key material
/// alongside an ordinary [SignalMessage].
///
/// This type is for *inspecting* a pre-key message — reading which pre-keys it
/// references, or reaching the inner [SignalMessage] and its post-quantum
/// ratchet payload. Decryption still goes through `SessionCipher`, which needs
/// the stores this type has no access to.
///
/// # Security
/// Deserializing parses and structurally validates, but it does **not**
/// authenticate: the inner message's MAC is only checked during decryption,
/// once a session has produced the key to check it with. Treat everything read
/// off an un-decrypted message as attacker-controlled.
pub struct PreKeySignalMessage {
    inner: NativePreKeySignalMessage,
}

impl PreKeySignalMessage {
    /// Deserialize a PreKeySignalMessage from bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(data: Vec<u8>) -> Result<PreKeySignalMessage, String> {
        let native =
            NativePreKeySignalMessage::try_from(&data[..]).map_err(|e| e.to_string())?;
        Ok(PreKeySignalMessage { inner: native })
    }

    /// Serialize the message to bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.serialized().to_vec())
    }

    /// Get the Signal Protocol message version.
    #[flutter_rust_bridge::frb(sync)]
    pub fn message_version(&self) -> Result<u32, String> {
        Ok(self.inner.message_version() as u32)
    }

    /// Get the sender's registration ID.
    #[flutter_rust_bridge::frb(sync)]
    pub fn registration_id(&self) -> Result<u32, String> {
        Ok(self.inner.registration_id())
    }

    /// Get the one-time pre-key ID this message consumes, if any.
    #[flutter_rust_bridge::frb(sync)]
    pub fn pre_key_id(&self) -> Result<Option<u32>, String> {
        Ok(self.inner.pre_key_id().map(u32::from))
    }

    /// Get the signed pre-key ID this message was addressed to.
    #[flutter_rust_bridge::frb(sync)]
    pub fn signed_pre_key_id(&self) -> Result<u32, String> {
        Ok(self.inner.signed_pre_key_id().into())
    }

    /// Get the Kyber pre-key ID this message consumes, if any.
    #[flutter_rust_bridge::frb(sync)]
    pub fn kyber_pre_key_id(&self) -> Result<Option<u32>, String> {
        Ok(self.inner.kyber_pre_key_id().map(u32::from))
    }

    /// Get the Kyber ciphertext (KEM encapsulation), if this is a PQXDH message.
    #[flutter_rust_bridge::frb(sync)]
    pub fn kyber_ciphertext(&self) -> Result<Option<Vec<u8>>, String> {
        Ok(self.inner.kyber_ciphertext().map(|ct| ct.to_vec()))
    }

    /// Get the sender's ephemeral base public key (serialized).
    #[flutter_rust_bridge::frb(sync)]
    pub fn base_key(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.base_key().serialize().into_vec())
    }

    /// Get the sender's identity public key (serialized).
    ///
    /// Unauthenticated until the message is decrypted:
    /// <https://github.com/djx-y-z/libsignal_dart/blob/main/SECURITY.md#message-inspection-is-not-authentication>
    #[flutter_rust_bridge::frb(sync)]
    pub fn identity_key(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.identity_key().public_key().serialize().into_vec())
    }

    /// Get the wrapped [SignalMessage].
    ///
    /// This is what exposes the post-quantum ratchet payload of a session's
    /// very first message: `preKeyMessage.message().pqRatchet()`.
    #[flutter_rust_bridge::frb(sync)]
    pub fn message(&self) -> Result<SignalMessage, String> {
        Ok(SignalMessage {
            inner: self.inner.message().clone(),
        })
    }

    /// Create a copy of this message.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_message(&self) -> Result<PreKeySignalMessage, String> {
        Ok(PreKeySignalMessage {
            inner: self.inner.clone(),
        })
    }
}

/// An encrypted group message, produced by `GroupCipher.encrypt`.
///
/// Lets a recipient read which group (`distributionId`) and which point in the
/// sender's chain a message belongs to *before* decrypting it — which is what
/// `GroupCipher.decrypt` needs its `distributionId` argument for.
///
/// # Security
/// Deserializing parses and structurally validates, but it does **not**
/// authenticate. Use [SenderKeyMessage.verifySignature] with the sender's
/// signing key, or simply decrypt, before trusting any of these fields.
pub struct SenderKeyMessage {
    inner: NativeSenderKeyMessage,
}

impl SenderKeyMessage {
    /// Deserialize a SenderKeyMessage from bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(data: Vec<u8>) -> Result<SenderKeyMessage, String> {
        let native = NativeSenderKeyMessage::try_from(&data[..]).map_err(|e| e.to_string())?;
        Ok(SenderKeyMessage { inner: native })
    }

    /// Serialize the message to bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.serialized().to_vec())
    }

    /// Get the Signal Protocol message version.
    #[flutter_rust_bridge::frb(sync)]
    pub fn message_version(&self) -> Result<u32, String> {
        Ok(self.inner.message_version() as u32)
    }

    /// Get the distribution (group) ID this message belongs to, as a UUID string.
    #[flutter_rust_bridge::frb(sync)]
    pub fn distribution_id(&self) -> Result<String, String> {
        Ok(self.inner.distribution_id().to_string())
    }

    /// Get the sender key chain ID.
    #[flutter_rust_bridge::frb(sync)]
    pub fn chain_id(&self) -> Result<u32, String> {
        Ok(self.inner.chain_id())
    }

    /// Get the position of this message within the sender's chain.
    #[flutter_rust_bridge::frb(sync)]
    pub fn iteration(&self) -> Result<u32, String> {
        Ok(self.inner.iteration())
    }

    /// Get the encrypted message body.
    #[flutter_rust_bridge::frb(sync)]
    pub fn ciphertext(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.ciphertext().to_vec())
    }

    /// Verify this message's signature against the sender's signing key.
    ///
    /// The signing key is the one carried by the sender's distribution message
    /// ([SenderKeyDistributionMessage.signingKey]).
    #[flutter_rust_bridge::frb(sync)]
    pub fn verify_signature(&self, signature_key: Vec<u8>) -> Result<bool, String> {
        let key = NativePublicKey::deserialize(&signature_key).map_err(|e| e.to_string())?;
        self.inner
            .verify_signature(&key)
            .map_err(|e: libsignal_protocol::SignalProtocolError| e.to_string())
    }

    /// Create a copy of this message.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_message(&self) -> Result<SenderKeyMessage, String> {
        Ok(SenderKeyMessage {
            inner: self.inner.clone(),
        })
    }
}

/// A sender key distribution message: the bundle a group member sends so others
/// can decrypt their future group messages.
///
/// Reading [SenderKeyDistributionMessage.distributionId] is what lets a
/// recipient route the message to the right group — `processDistributionMessage`
/// requires that id and refuses a mismatch.
///
/// # Security
/// There is deliberately **no `chainKey()` accessor**: the chain key is secret
/// key material, and since this type has no from-parts constructor an accessor
/// would only add a way to leak it. Note this makes the *object* no safer than
/// the bytes behind it — the chain key is a field of the serialized message, so
/// anything holding those bytes (including the result of `serialize()`, which
/// only ever returns what was passed to `deserialize`) already has it. Treat a
/// serialized distribution message as the secret it is.
///
/// Deserializing does not authenticate — the signing key here is used to sign
/// the sender's later messages, not this one — so treat the fields as
/// attacker-controlled until the distribution message has been processed.
pub struct SenderKeyDistributionMessage {
    inner: NativeSenderKeyDistributionMessage,
}

impl SenderKeyDistributionMessage {
    /// Deserialize a SenderKeyDistributionMessage from bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(data: Vec<u8>) -> Result<SenderKeyDistributionMessage, String> {
        let native =
            NativeSenderKeyDistributionMessage::try_from(&data[..]).map_err(|e| e.to_string())?;
        Ok(SenderKeyDistributionMessage { inner: native })
    }

    /// Serialize the message to bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.serialized().to_vec())
    }

    /// Get the Signal Protocol message version.
    #[flutter_rust_bridge::frb(sync)]
    pub fn message_version(&self) -> Result<u32, String> {
        Ok(self.inner.message_version() as u32)
    }

    /// Get the distribution (group) ID this message establishes, as a UUID string.
    #[flutter_rust_bridge::frb(sync)]
    pub fn distribution_id(&self) -> Result<String, String> {
        self.inner
            .distribution_id()
            .map(|id| id.to_string())
            .map_err(|e: libsignal_protocol::SignalProtocolError| e.to_string())
    }

    /// Get the sender key chain ID.
    #[flutter_rust_bridge::frb(sync)]
    pub fn chain_id(&self) -> Result<u32, String> {
        self.inner
            .chain_id()
            .map_err(|e: libsignal_protocol::SignalProtocolError| e.to_string())
    }

    /// Get the chain position this distribution message starts from.
    #[flutter_rust_bridge::frb(sync)]
    pub fn iteration(&self) -> Result<u32, String> {
        self.inner
            .iteration()
            .map_err(|e: libsignal_protocol::SignalProtocolError| e.to_string())
    }

    /// Get the sender's public signing key (serialized).
    ///
    /// Pass this to [SenderKeyMessage.verifySignature].
    #[flutter_rust_bridge::frb(sync)]
    pub fn signing_key(&self) -> Result<Vec<u8>, String> {
        self.inner
            .signing_key()
            .map(|k| k.serialize().into_vec())
            .map_err(|e: libsignal_protocol::SignalProtocolError| e.to_string())
    }

    /// Create a copy of this message.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_message(&self) -> Result<SenderKeyDistributionMessage, String> {
        Ok(SenderKeyDistributionMessage {
            inner: self.inner.clone(),
        })
    }
}

/// A message body sent without encryption.
///
/// The only thing that may travel this way is a [DecryptionErrorMessage] — the
/// receipt asking a peer to re-establish a session after a decryption failure.
/// Build one with [PlaintextContent.fromDecryptionErrorMessage] and send its
/// [PlaintextContent.serialize] bytes as `CiphertextMessageType.plaintextContent`.
pub struct PlaintextContent {
    inner: NativePlaintextContent,
}

impl PlaintextContent {
    /// Wrap a decryption error message for sending.
    #[flutter_rust_bridge::frb(sync)]
    pub fn from_decryption_error_message(
        message: &DecryptionErrorMessage,
    ) -> Result<PlaintextContent, String> {
        Ok(PlaintextContent {
            inner: NativePlaintextContent::from(message.inner.clone()),
        })
    }

    /// Deserialize a PlaintextContent from bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(data: Vec<u8>) -> Result<PlaintextContent, String> {
        let native = NativePlaintextContent::try_from(&data[..]).map_err(|e| e.to_string())?;
        Ok(PlaintextContent { inner: native })
    }

    /// Serialize the message to bytes, ready to send.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.serialized().to_vec())
    }

    /// Get the body: the serialized protobuf `Content`, without the leading
    /// plaintext-content identifier byte.
    ///
    /// This — **not** [PlaintextContent.serialize] — is what
    /// [DecryptionErrorMessage.extractFromSerializedContent] takes; it
    /// rejects the leading identifier byte.
    #[flutter_rust_bridge::frb(sync)]
    pub fn body(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.body().to_vec())
    }

    /// Create a copy of this message.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_message(&self) -> Result<PlaintextContent, String> {
        Ok(PlaintextContent {
            inner: self.inner.clone(),
        })
    }
}

/// A message indicating that decryption failed.
pub struct DecryptionErrorMessage {
    inner: NativeDecryptionErrorMessage,
}

impl DecryptionErrorMessage {
    /// Deserialize a decryption error message from bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(bytes: Vec<u8>) -> Result<DecryptionErrorMessage, String> {
        let native =
            NativeDecryptionErrorMessage::try_from(&bytes[..]).map_err(|e| e.to_string())?;
        Ok(DecryptionErrorMessage { inner: native })
    }

    /// Create a decryption error message for a failed original message.
    #[flutter_rust_bridge::frb(sync)]
    pub fn for_original_message(
        original_bytes: Vec<u8>,
        message_type: u8,
        timestamp: u64,
        original_sender_device_id: u32,
    ) -> Result<DecryptionErrorMessage, String> {
        let msg_type = CiphertextMessageType::try_from(message_type).map_err(|_| {
            format!("Invalid message type: {}", message_type)
        })?;
        let ts = Timestamp::from_epoch_millis(timestamp);
        let native = NativeDecryptionErrorMessage::for_original(
            &original_bytes,
            msg_type,
            ts,
            original_sender_device_id,
        )
        .map_err(|e| e.to_string())?;
        Ok(DecryptionErrorMessage { inner: native })
    }

    /// Extract a decryption error message from serialized content.
    #[flutter_rust_bridge::frb(sync)]
    pub fn extract_from_serialized_content(
        bytes: Vec<u8>,
    ) -> Result<DecryptionErrorMessage, String> {
        let native =
            libsignal_protocol::extract_decryption_error_message_from_serialized_content(&bytes)
                .map_err(|e| e.to_string())?;
        Ok(DecryptionErrorMessage { inner: native })
    }

    /// Serialize this message to bytes.
    #[flutter_rust_bridge::frb(sync)]
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        Ok(self.inner.serialized().to_vec())
    }

    /// Get the timestamp of the original message.
    #[flutter_rust_bridge::frb(sync)]
    pub fn timestamp(&self) -> Result<u64, String> {
        Ok(self.inner.timestamp().epoch_millis())
    }

    /// Get the device ID of the original sender.
    #[flutter_rust_bridge::frb(sync)]
    pub fn device_id(&self) -> Result<u32, String> {
        Ok(self.inner.device_id())
    }

    /// Get the ratchet key from the failed message, if available.
    ///
    /// Returns the serialized public key bytes, or None if not available.
    #[flutter_rust_bridge::frb(sync)]
    pub fn ratchet_key(&self) -> Result<Option<Vec<u8>>, String> {
        match self.inner.ratchet_key() {
            Some(key) => Ok(Some(key.serialize().into_vec())),
            None => Ok(None),
        }
    }

    /// Create a copy of this message.
    #[flutter_rust_bridge::frb(sync)]
    pub fn clone_message(&self) -> Result<DecryptionErrorMessage, String> {
        Ok(DecryptionErrorMessage {
            inner: self.inner.clone(),
        })
    }
}
