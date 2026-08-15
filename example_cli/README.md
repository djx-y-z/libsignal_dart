# libsignal CLI Example

A command-line example demonstrating the libsignal library usage without Flutter dependencies.

## Features Demonstrated

- **Keys**: Key generation (Curve25519), digital signatures (Ed25519), identity key pairs
- **Crypto**: AES-256-GCM-SIV symmetric encryption
- **Groups**: Group messaging using SenderKey protocol
- **Session**: 1-to-1 messaging (X3DH/PQXDH + Double Ratchet)
- **Fingerprint**: Safety Number generation for identity verification
- **Durable stores**: a reference persistent store, and a conversation that
  survives a restart

## Reference durable store

`lib/stores/durable_file_stores.dart` implements all six Signal Protocol stores
on an append-only journal that **flushes every write to stable storage before
the write's future completes** — the contract described in
[`SECURITY.md`](../SECURITY.md#store-durability-write-ordering-and-rollback).
Because libsignal derives message keys deterministically, a store write lost to
a crash makes the next send reuse a message key; that is why this is worth
copying rather than reinventing.

`lib/demos/durable_store_demo.dart` proves it: it establishes a session,
exchanges messages, closes the stores, reopens them from disk and continues the
same conversation (the message after the restart is a `SignalMessage`, not a
pre-key message, so the ratchet really was resumed). It also shows the second
half of the contract — cipher calls serialized per address at the call site via
`AddressLocks`, since a lock inside a store cannot cover `load → ratchet →
store`.

The example is deliberately not encrypted at rest and has no rollback
protection; read the file header and `SECURITY.md` before adapting it.

## Prerequisites

The native Rust library must be built before running the CLI example:

```bash
# From the project root directory
cargo build --release --manifest-path rust/Cargo.toml
```

## Running

You can run the example from **any directory**:

```bash
# From the project root
dart run example_cli/bin/main.dart

# Or from example_cli/ directory
cd example_cli
dart run bin/main.dart
```

The library is automatically located via `package_config.json`.

## Expected Output

```
╔══════════════════════════════════════╗
║       libsignal CLI Example          ║
╚══════════════════════════════════════╝

═══ Keys Demo ═══
1. PrivateKey generated
   Size: 32 bytes
   ...

═══ Crypto Demo ═══
1. Key and nonce generated
   ...

═══ Groups Demo ═══
1. Protocol addresses created
   ...

═══ Fingerprint Demo ═══
1. Identity keys generated
   ...

═══ Durable Store Demo ═══
1. Durable stores opened (journal per participant)
   ...
8. Alice → Bob, after the restart
   ...

✓ All demos completed successfully!
```

## How Library Loading Works

`LibSignal.init()` searches for the native library in this order:

1. Custom path (if provided via `libraryPath` parameter)
2. Build hook locations, in order: `.dart_tool/lib/` (`dart run`/`dart test`),
   `../lib/` relative to the executable (AOT bundle), then
   `build/native_assets/<os>/` (`flutter test`)
3. FRB's default loader (flutter_rust_bridge)

For a pure Dart CLI, run `dart pub get` so the package's build hook downloads and
registers the native library; alternatively build it locally with `make build`
in the libsignal package and the hook picks up the `rust/target/` build.
