# libsignal CLI Example

A command-line example demonstrating the libsignal library usage without Flutter dependencies.

## Features Demonstrated

- **Keys**: Key generation (Curve25519), digital signatures (Ed25519), identity key pairs
- **Crypto**: AES-256-GCM-SIV symmetric encryption
- **Groups**: Group messaging using SenderKey protocol
- **Fingerprint**: Safety Number generation for identity verification

## Running

```bash
cd example_cli
dart pub get
dart run bin/main.dart
```

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
