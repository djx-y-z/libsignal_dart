//! Library initialization API.

/// Initialize the libsignal library.
///
/// With the pure Rust implementation using libsignal-protocol crate,
/// this function is no longer required but kept for API compatibility.
/// The library_path parameter is ignored.
#[flutter_rust_bridge::frb(sync)]
pub fn init_libsignal(_library_path: String) -> Result<(), String> {
    // No initialization needed - libsignal-protocol is statically linked
    Ok(())
}

/// Check if the libsignal library is initialized.
///
/// With the pure Rust implementation, this always returns true.
#[flutter_rust_bridge::frb(sync)]
pub fn is_libsignal_initialized() -> bool {
    // Always initialized with pure Rust implementation
    true
}
