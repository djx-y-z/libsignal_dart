//! libsignal_dart Rust bridge layer.
//!
//! This crate provides the Rust side of Flutter Rust Bridge bindings
//! for libsignal operations using libsignal-protocol.

// Allow dead code for internal helper methods (from_native, native, native_mut).
// These maintain a consistent wrapper pattern across all types and may be used
// in future API expansions.
#![allow(dead_code)]

mod frb_generated;

pub mod api;
