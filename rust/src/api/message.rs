//! Protocol message types API using libsignal-protocol.

use libsignal_protocol::{
    CiphertextMessageType, DecryptionErrorMessage as NativeDecryptionErrorMessage,
    DeviceId, IdentityKey, ProtocolAddress, PublicKey as NativePublicKey,
    SignalMessage as NativeSignalMessage, Timestamp,
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
