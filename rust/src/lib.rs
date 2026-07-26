//! libsignal_dart Rust bridge layer.
//!
//! This crate provides the Rust side of Flutter Rust Bridge bindings
//! for libsignal operations using libsignal-protocol.

// Allow dead code for internal helper methods (from_native, native, native_mut).
// These maintain a consistent wrapper pattern across all types and may be used
// in future API expansions.
#![allow(dead_code)]

// The FRB-generated bridge is the only module allowed to contain unsafe code;
// everything hand-written is covered by `unsafe_code = "deny"` in Cargo.toml.
#[allow(unsafe_code)]
mod frb_generated;
// Deliberately outside `api/`: these are internal store wrappers, and anything
// under `api/` is scanned by FRB codegen.
mod recording_stores;
mod utils;

pub mod api;

// Re-export utilities for internal use
pub use utils::current_time;
