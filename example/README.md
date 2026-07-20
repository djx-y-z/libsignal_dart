# libsignal Flutter Example

Interactive demo app showcasing the libsignal library for end-to-end encryption
using the Signal Protocol.

## Features

The app provides five demo tabs:

### Keys
Demonstrates key generation and digital signatures:
- Generate Curve25519 private/public key pairs
- Create Ed25519 signatures
- Verify signatures
- Generate IdentityKeyPair for Signal Protocol

### Crypto
Shows symmetric encryption using AES-256-GCM-SIV:
- Generate 256-bit keys and 96-bit nonces
- Encrypt and decrypt messages
- Demonstrates deterministic behavior (same key + nonce = same ciphertext)
- Shows nonce importance for security

### Groups
Demonstrates group messaging using SenderKey protocol:
- Create protocol addresses for participants
- Generate and process distribution messages
- Encrypt messages for the group
- Decrypt group messages

### Session
Shows 1-to-1 encrypted messaging using the full Signal Protocol:
- Generate all required keys (identity, pre-key, signed pre-key, Kyber)
- Establish sessions via PreKeyBundle
- Exchange encrypted messages using Double Ratchet
- Demonstrates PreKeySignalMessage vs SignalMessage types

### Verify
Creates Safety Number fingerprints for identity verification:
- Generate 60-digit Safety Numbers
- Demonstrate symmetry (both parties see the same number)
- Create scannable encodings for QR codes

## Running

```bash
# From the example directory
cd example
flutter run

# Or specify a platform
flutter run -d macos
flutter run -d chrome
```

## Requirements

- Flutter 3.38.4 or later
- Native library (downloaded and registered automatically by the package's Dart build hook, `hook/build.dart`)

## Platform Support

| Platform | Status |
|----------|--------|
| macOS    | ✅     |
| iOS      | ✅     |
| Android  | ✅     |
| Linux    | ✅     |
| Windows  | ✅     |
| Web      | ✅     |

## Notes

- In-memory stores are used for demonstration purposes only
- For production, implement persistent stores with secure storage
- FRB handles memory management automatically (no manual disposal needed)
