---
name: frb-patterns
description: Flutter Rust Bridge patterns and best practices for libsignal. Use when writing Rust API code, adding new bindings, implementing DartFn callbacks, or troubleshooting FRB issues.
---

# FRB Patterns for libsignal

Patterns and templates for writing correct Flutter Rust Bridge code in this project.

## Architecture Overview

```
┌─────────────────────────────────────────────┐
│     libsignal-protocol (Rust crate)         │  ← Pure Rust, statically linked
├─────────────────────────────────────────────┤
│       rust/src/api/*.rs (Rust wrappers)     │  ← FRB-annotated functions
├─────────────────────────────────────────────┤
│      lib/src/rust/*.dart (FRB generated)    │  ← Auto-generated Dart API
├─────────────────────────────────────────────┤
│           lib/src/stores/*.dart             │  ← Dart store interfaces
└─────────────────────────────────────────────┘
```

## Constructor-Style API Pattern

Use `impl` blocks for constructors so FRB generates idiomatic Dart:

```rust
// ✅ CORRECT - generates PrivateKey.generate() in Dart
impl PrivateKey {
    #[flutter_rust_bridge::frb(sync)]
    pub fn generate() -> Result<PrivateKey, String> {
        let key = libsignal_protocol::PrivateKey::generate(&mut OsRng);
        Ok(PrivateKey { native: key })
    }

    #[flutter_rust_bridge::frb(sync)]
    pub fn deserialize(bytes: Vec<u8>) -> Result<PrivateKey, String> {
        let key = libsignal_protocol::PrivateKey::deserialize(&bytes)
            .map_err(|e| e.to_string())?;
        Ok(PrivateKey { native: key })
    }
}

// ❌ WRONG - generates privateKeyGenerate() as a top-level function in Dart
pub fn private_key_generate() -> Result<PrivateKey, String> { ... }
```

**Dart usage:**
```dart
final key = PrivateKey.generate();      // Constructor-style
final bytes = key.serialize();           // Method
final restored = PrivateKey.deserialize(bytes: bytes);
```

## Opaque Type Pattern

Wrap libsignal types in opaque structs:

```rust
#[frb(opaque)]
pub struct PrivateKey {
    pub(crate) native: libsignal_protocol::PrivateKey,
}

impl PrivateKey {
    // Access native type internally
    pub(crate) fn native(&self) -> &libsignal_protocol::PrivateKey {
        &self.native
    }
}
```

FRB manages the lifecycle automatically - no `dispose()` needed in Dart.

## Transparent Struct Pattern

For data types that cross FFI as plain values:

```rust
pub struct MyResult {
    pub data: Vec<u8>,
    pub count: u32,
}

pub enum MyEnum {
    OptionA,
    OptionB,
    OptionC,
}
```

FRB generates Dart classes/enums with constructors automatically.

## DartFn Callbacks for Store Operations

For operations requiring Dart store callbacks:

```rust
pub async fn process_prekey_bundle_with_callbacks(
    remote_name: String,
    remote_device_id: u32,
    bundle_bytes: Vec<u8>,
    // Store callbacks
    load_session: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + 'static,
    store_session: impl Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + 'static,
    get_identity_key_pair: impl Fn() -> DartFnFuture<Vec<u8>> + 'static,
    get_local_registration_id: impl Fn() -> DartFnFuture<u32> + 'static,
    save_identity: impl Fn(String, u32, Vec<u8>) -> DartFnFuture<bool> + 'static,
    is_trusted_identity: impl Fn(String, u32, Vec<u8>, u8) -> DartFnFuture<bool> + 'static,
) -> Result<(), String> {
    // Implementation uses callbacks to access Dart stores
}
```

### Bridging Sync Traits to Async Callbacks

If the upstream crate has sync trait methods but DartFn is async, use `futures::executor::block_on()`:

```rust
// In Cargo.toml: futures = "0.3"

fn sync_trait_method(&self) -> Result<(), Error> {
    futures::executor::block_on((self.callback)(data));
    Ok(())
}
```

This works because FRB runs Rust functions on separate threads, not the Dart isolate.

### Adapter Pattern for libsignal Traits

Create adapter structs that implement libsignal traits using DartFn callbacks:

```rust
struct SessionStoreAdapter<L, S>
where
    L: Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + 'static,
    S: Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + 'static,
{
    load_session: L,
    store_session: S,
}

#[async_trait(?Send)]
impl<L, S> SessionStore for SessionStoreAdapter<L, S>
where
    L: Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + 'static,
    S: Fn(String, u32, Vec<u8>) -> DartFnFuture<()> + 'static,
{
    async fn load_session(&self, addr: &ProtocolAddress) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let result = (self.load_session)(addr.name().to_string(), addr.device_id().into()).await;
        match result {
            Some(bytes) => Ok(Some(SessionRecord::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn store_session(&mut self, addr: &ProtocolAddress, record: &SessionRecord) -> Result<(), SignalProtocolError> {
        (self.store_session)(addr.name().to_string(), addr.device_id().into(), record.serialize()?).await;
        Ok(())
    }
}
```

This lets Dart-side store implementations satisfy Rust trait requirements via callbacks.

## Sync vs Async Functions

### Sync Functions (Simple Operations)

```rust
impl PrivateKey {
    #[flutter_rust_bridge::frb(sync)]  // Mark as sync
    pub fn serialize(&self) -> Vec<u8> {
        self.native.serialize().to_vec()
    }
}
```

### Async Functions (Store Operations)

```rust
// No #[frb(sync)] - FRB generates Future<T> in Dart
pub async fn encrypt_with_callbacks(
    plaintext: Vec<u8>,
    load_session: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + 'static,
    // ...
) -> Result<Vec<u8>, String> {
    // async implementation
}
```

## Error Handling

Convert libsignal errors to String for FRB:

```rust
pub fn deserialize(bytes: Vec<u8>) -> Result<Self, String> {
    libsignal_protocol::PrivateKey::deserialize(&bytes)
        .map(|native| PrivateKey { native })
        .map_err(|e| e.to_string())
}
```

FRB automatically converts `Result<T, String>` to Dart exceptions.

## Memory Management

**FRB handles cleanup automatically via Rust's ownership system.**

- No manual `dispose()` needed in Dart
- No finalizers to register
- No double-free concerns
- Opaque types are dropped when Dart GC collects them

```dart
// Dart - no cleanup needed!
final key = PrivateKey.generate();
final signature = key.sign(message: data);
// key is automatically cleaned up when no longer referenced
```

## Vec<u8> for Serialization

Use `Vec<u8>` for all serialized data crossing FFI boundary:

```rust
// Serialize returns Vec<u8>
pub fn serialize(&self) -> Vec<u8> {
    self.native.serialize().to_vec()
}

// Deserialize takes Vec<u8> (or List<int> in Dart)
pub fn deserialize(bytes: Vec<u8>) -> Result<Self, String> {
    // ...
}
```

## UUID Handling

Convert UUIDs to/from strings for Dart compatibility:

```rust
pub fn uuid_from_string(uuid_str: String) -> Result<Vec<u8>, String> {
    let uuid = uuid::Uuid::parse_str(&uuid_str)
        .map_err(|e| e.to_string())?;
    Ok(uuid.as_bytes().to_vec())
}

pub fn uuid_to_string(uuid_bytes: Vec<u8>) -> Result<String, String> {
    let bytes: [u8; 16] = uuid_bytes.try_into()
        .map_err(|_| "UUID must be 16 bytes")?;
    Ok(uuid::Uuid::from_bytes(bytes).to_string())
}
```

## Regenerating Bindings

After modifying Rust code in `rust/src/api/`:

```bash
make codegen
```

This runs `flutter_rust_bridge_codegen generate` using `flutter_rust_bridge.yaml` config.

**When to regenerate:**
- After modifying any `pub fn` or `pub async fn` in `rust/src/api/`
- After changing struct/enum definitions
- After updating upstream crate version (if API changed)

## Files to Reference

| Pattern | Reference File |
|---------|----------------|
| Opaque types | `rust/src/api/keys.rs` |
| DartFn callbacks | `rust/src/api/session_builder.rs` |
| Adapter pattern | `rust/src/api/session_cipher.rs` |
| UUID handling | `rust/src/api/group_session.rs` |
| Store callbacks | `rust/src/api/group_session.rs` |

## Common Issues

### "method not found" after codegen

- Check that the method is `pub`
- Check that return types are supported by FRB
- Run `make codegen` after any Rust changes

### Callback lifetime issues

Ensure callbacks have `'static` lifetime:

```rust
load_session: impl Fn(String, u32) -> DartFnFuture<Option<Vec<u8>>> + 'static,
```

### Type not transferable

Use `Vec<u8>` for complex types instead of trying to pass libsignal types directly.

### `block_on` panics

`futures::executor::block_on()` requires a non-async context. This works because FRB runs Rust functions on separate threads. Do NOT call storage callbacks from an async Rust context without `block_on`.

## Web/WASM Considerations

FRB automatically handles web platform differences, but keep in mind:

### RNG on Web
The `getrandom` crate uses Web Crypto API (`crypto.getRandomValues()`) on WASM.
Configuration in `rust/.cargo/config.toml`:
```toml
[target.wasm32-unknown-unknown]
rustflags = ['--cfg', 'getrandom_backend="wasm_js"']
```

### No Threading on WASM
- Avoid `parking_lot::Mutex` in hot paths on web
- Use single-threaded alternatives when possible
- FRB handles this automatically for most cases

### Building WASM
```bash
make build-web  # Builds to rust/target/wasm32/
```

### WASM File Structure
Web builds require these files in `web/pkg/`:
- `libsignal_frb.js` - JavaScript glue code
- `libsignal_frb_bg.wasm` - WebAssembly binary

These are downloaded automatically by `hook/build.dart` during web builds.
