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
///
/// Every store write is part of the protocol's correctness, not a cache: a
/// write that is lost or rolled back rewinds ratchet state and causes
/// message-key reuse. [SessionStore] documents the contract each
/// implementation must honour (durable before the operation's output is
/// released, deletes included, operations serialized per address); `SECURITY.md`
/// has the deployment-level detail.
library;

export 'identity_key_store.dart';
export 'in_memory/in_memory_stores.dart';
export 'kyber_pre_key_store.dart';
export 'pre_key_store.dart';
export 'sender_key_store.dart';
export 'session_store.dart';
export 'signed_pre_key_store.dart';
