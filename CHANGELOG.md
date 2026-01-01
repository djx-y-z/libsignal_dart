# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Refactored CI update workflow: moved AI analysis from bash to Dart script
- Simplified `check-libsignal-updates.yml` workflow (~530 → ~220 lines)
- Added `--ai`, `--no-ai`, `--ci` flags to `check_updates.dart` script
- Script now writes directly to `GITHUB_OUTPUT` in CI mode (no jq parsing needed)

## [1.0.0] - 2025-12-31

### Added

- Pre-built native libraries for all platforms (iOS, Android, macOS, Linux, Windows)
- **Signal Protocol**: Double Ratchet algorithm for forward secrecy and break-in recovery
- **X3DH**: Extended Triple Diffie-Hellman for asynchronous key agreement
- **Key Management**: Curve25519 key pairs (`PrivateKey`, `PublicKey`, `IdentityKeyPair`)
- **Pre-keys**: `PreKeyRecord`, `SignedPreKeyRecord`, `PreKeyBundle` for session establishment
- **Post-quantum**: Kyber key pairs (`KyberKeyPair`, `KyberPreKeyRecord`) for quantum resistance
- **Sessions**: `SessionRecord`, `ProtocolAddress` for session management
- **Messages**: `SignalMessage`, `PreKeySignalMessage` for encrypted communication
- **Sealed Sender**: Anonymous message sending (`ServerCertificate`, `SenderCertificate`)
- **Group Messaging**: SenderKey distribution (`GroupSession`, `SenderKeyRecord`, `SenderKeyDistributionMessage`)
- **Cryptographic utilities**: AES-256-GCM-SIV (`Aes256GcmSiv`), HKDF (`Hkdf`), identity fingerprints (`Fingerprint`)
- **Storage interfaces**: `SessionStore`, `IdentityKeyStore`, `PreKeyStore`, `SignedPreKeyStore`, `KyberPreKeyStore`, `SenderKeyStore`
- In-memory store implementations for testing and prototyping
- Automatic native library download via build hooks
- SHA256 verification for native library integrity
- `LibSignal.init()` for optional library pre-initialization
- Comprehensive exception handling with `SignalException`
- GitHub Actions CI/CD pipeline for automated testing and publishing
- Automated upstream version tracking with AI-powered changelog generation
- Cross-platform build scripts for native library compilation
- Example Flutter application and CLI example demonstrating all features

### Security

- Based on libsignal v0.86.9 from Signal Foundation
- Secret keys are handled securely with proper memory management
- Cryptographic operations use constant-time implementations where applicable

[Unreleased]: https://github.com/djx-y-z/libsignal_dart/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/djx-y-z/libsignal_dart/releases/tag/v1.0.0
