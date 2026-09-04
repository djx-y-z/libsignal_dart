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

### Write Ordering and Durability (requirement, not style)

The `.await` on `storage_write` above is load-bearing. When a wrapper delegates
state persistence to Dart callbacks, two rules apply:

1. **Await every write callback before returning the operation's result.** A
   fire-and-forget write (or one awaited after `Ok(...)` is built) lets the
   caller act on output whose state may never be stored.
2. **The Dart callback must not resolve its future until the write is durable.**
   Resolving once the value is in a map, an unflushed file or a write-behind
   queue satisfies rule 1 while still losing the write to a crash.

Together these give "persist, then release". Rule 1 is the wrapper's job and
holds by construction once every callback is awaited; rule 2 is the
application's, so the wrapper has to *state* it — the caller cannot infer it
from the signature. What a lost or rolled-back write actually costs is
protocol-specific, so document that price in the package's own `SECURITY.md`
rather than here.

### Callbacks Are Not Failable

A `DartFnFuture<T>` has no error channel. If the Dart closure throws, FRB does
**not** turn it into a `Result` the Rust side can handle — it panics the worker
thread:

```
thread 'tokio-rt-worker' panicked at src/frb_generated.rs:
Dart throws exception but Rust side assume it is not failable: <the error>
```

This does not mirror Error Handling below, and the asymmetry is easy to assume
away: a `Result<T, String>` returned *from* Rust becomes a clean Dart exception,
but an exception thrown *into* Rust from a callback is a panic. Nothing in the
signature says so, and nothing fails at compile time.

Two consequences:

1. **Document that callbacks must not throw**, and say it on the Dart-facing
   interface — the implementer is the one who has to honour it.
2. **A callback cannot act as a veto.** To let the Dart side reject something,
   give the callback a return type that expresses rejection, so Rust decides:

   ```rust
   // Cannot work: the Dart side has no way to signal "no" but to throw.
   check: impl Fn(Vec<u8>) -> DartFnFuture<()> + Send + Sync + 'static,

   // Works: the Dart side reports, the Rust side branches on it.
   check: impl Fn(Vec<u8>) -> DartFnFuture<bool> + Send + Sync + 'static,
   ```

Note that a write-back callback invoked *after* the operation's real work is
done cannot abort that work whatever it returns — the result already exists. If
a check has to be able to stop an operation, it must run before it, which
usually means a read callback rather than a write one.

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

This works in one direction only. A Dart exception thrown *into* Rust from a
DartFn callback is not converted — it panics the worker thread. See "Callbacks
Are Not Failable" above before designing a callback that needs to reject.

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

### A JS handle inside an opaque type is not `Send + Sync`

FRB requires the types it exposes to be `Send + Sync`. A handle obtained from
the browser — anything wrapping a `JsValue`, such as a `web_sys` object — is
neither, because `JsValue` holds a raw pointer into the JS heap. Holding one in
a struct FRB exposes fails to compile with a `Send`/`Sync` bound error that
names a type you did not write.

The fix is a newtype whose safety argument is the target itself:

```rust
/// `wasm32-unknown-unknown` is single-threaded: there is no second thread for
/// this handle to be sent to, so the bound FRB requires is vacuously true.
/// This reasoning is target-specific and does NOT transfer to native code.
struct WebHandle(web_sys::SomeJsType);
unsafe impl Send for WebHandle {}
unsafe impl Sync for WebHandle {}
```

Keep it behind `#[cfg(target_arch = "wasm32")]` alongside the code that needs
it. The same struct on a native target would be an unsound `unsafe impl` rather
than a workaround, and nothing in the compiler would object.

### Building WASM
```bash
make build-web  # Builds to rust/target/wasm32/
```

### WASM File Structure
Web builds require these files in `web/pkg/`:
- `libsignal_frb.js` - JavaScript glue code
- `libsignal_frb_bg.wasm` - WebAssembly binary

These are downloaded automatically by `hook/build.dart` during web builds.
