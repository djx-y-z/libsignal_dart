//! Library initialization API.

/// Initialize the libsignal library.
///
/// This function is called from Dart during library initialization.
/// The library_path parameter is typically used for loading external
/// dependencies if needed.
#[flutter_rust_bridge::frb(sync)]
pub fn init_libsignal(_library_path: String) -> Result<(), String> {
    // Add any initialization logic here
    Ok(())
}

/// Check if the libsignal library is initialized.
///
/// Returns true if the library has been successfully initialized.
#[flutter_rust_bridge::frb(sync)]
pub fn is_libsignal_initialized() -> bool {
    // Add initialization state check logic here
    true
}
