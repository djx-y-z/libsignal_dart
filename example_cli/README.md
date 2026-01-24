# libsignal CLI Example

A command-line example demonstrating the libsignal library usage without Flutter dependencies.

## Features Demonstrated

- **Keys**: Key generation (Curve25519), digital signatures (Ed25519), identity key pairs
- **Crypto**: AES-256-GCM-SIV symmetric encryption
- **Groups**: Group messaging using SenderKey protocol
- **Fingerprint**: Safety Number generation for identity verification

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

✓ All demos completed successfully!
```

## How Library Loading Works

`LibSignal.init()` automatically searches for the native library in this order:

1. Custom path (if provided via `libraryPath` parameter)
2. libsignal package's `rust/target/release/` directory (found via `package_config.json`)
3. Current working directory's `rust/target/release/`
4. FRB's default loading mechanism (for Flutter apps with Cargokit)

This means pure Dart CLI apps work correctly as long as the library is built in the libsignal package.
