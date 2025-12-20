/// Store interfaces and implementations for Signal Protocol.
///
/// This module provides abstract store interfaces that must be implemented
/// for persistent storage of Signal Protocol state:
///
/// - [SessionStore] - Session records for each recipient
/// - [IdentityKeyStore] - Identity keys (own and remote)
/// - [PreKeyStore] - One-time pre-keys
/// - [SignedPreKeyStore] - Signed pre-keys
/// - [KyberPreKeyStore] - Post-quantum Kyber pre-keys
/// - [SenderKeyStore] - Sender keys for group messaging
///
/// In-memory implementations are provided for testing:
/// - [InMemorySessionStore]
/// - [InMemoryIdentityKeyStore]
/// - [InMemoryPreKeyStore]
/// - [InMemorySignedPreKeyStore]
/// - [InMemoryKyberPreKeyStore]
/// - [InMemorySenderKeyStore]
library;

export 'identity_key_store.dart';
export 'in_memory/in_memory_stores.dart';
export 'kyber_pre_key_store.dart';
export 'pre_key_store.dart';
export 'sender_key_store.dart';
export 'session_store.dart';
export 'signed_pre_key_store.dart';
