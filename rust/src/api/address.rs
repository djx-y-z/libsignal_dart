//! Protocol address API using libsignal-protocol.

use libsignal_protocol::{DeviceId, ProtocolAddress as NativeProtocolAddress};

/// A protocol address identifying a specific device of a user.
pub struct ProtocolAddress {
    inner: NativeProtocolAddress,
}

impl ProtocolAddress {
    /// Create from native libsignal ProtocolAddress.
    pub(crate) fn from_native(address: NativeProtocolAddress) -> Self {
        Self { inner: address }
    }

    /// Get the inner native address (for use by other modules).
    pub(crate) fn native(&self) -> &NativeProtocolAddress {
        &self.inner
    }

    /// Create a new protocol address.
    ///
    /// # Arguments
    /// * `name` - The user identifier (typically a phone number or UUID)
    /// * `device_id` - The device identifier (must be 1-127)
    #[flutter_rust_bridge::frb(sync)]
    pub fn new(name: String, device_id: u32) -> Result<ProtocolAddress, String> {
        let dev_id = DeviceId::try_from(device_id)
            .map_err(|_| format!("Invalid device ID: {} (must be 1-127)", device_id))?;
        let native = NativeProtocolAddress::new(name, dev_id);
        Ok(ProtocolAddress { inner: native })
    }

    /// Get the name (user identifier) of this address.
    #[flutter_rust_bridge::frb(sync)]
    pub fn name(&self) -> Result<String, String> {
        Ok(self.inner.name().to_string())
    }

    /// Get the device ID of this address.
    #[flutter_rust_bridge::frb(sync)]
    pub fn device_id(&self) -> Result<u32, String> {
        Ok(self.inner.device_id().into())
    }
}
