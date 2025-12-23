/// Session builder for Signal Protocol session establishment.
///
/// Uses NativeCallable.isolateLocal for FFI callbacks, providing a cleaner
/// and safer approach than global state management.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../keys/identity_key_pair.dart';
import '../keys/public_key.dart';
import '../libsignal.dart';
import '../prekeys/pre_key_bundle.dart';
import '../stores/identity_key_store.dart';
import '../stores/session_store.dart';
import 'protocol_address.dart';
import 'session_record.dart';

/// Holds pre-loaded data for FFI callbacks.
///
/// This class captures the state needed by synchronous FFI callbacks.
/// Data is pre-loaded asynchronously before the FFI call, then accessed
/// synchronously during the callback.
class _SessionCallbackContext {
  /// Pre-loaded session record bytes (null if no session exists).
  Uint8List? sessionRecordBytes;

  /// Session record to store after the FFI call completes.
  Uint8List? pendingSessionStore;

  /// The identity key pair for signing.
  final IdentityKeyPair identityKeyPair;

  /// The local registration ID.
  final int localRegistrationId;

  /// Pre-loaded remote identity key bytes (null if not known).
  Uint8List? remoteIdentityBytes;

  /// Remote identity to save after the FFI call completes.
  ({ProtocolAddress address, Uint8List identityBytes})? pendingIdentitySave;

  /// Address being processed.
  final ProtocolAddress address;

  _SessionCallbackContext({
    required this.identityKeyPair,
    required this.localRegistrationId,
    required this.address,
    this.sessionRecordBytes,
    this.remoteIdentityBytes,
  });
}

/// Manages NativeCallable instances for FFI callbacks.
///
/// This class creates and manages the lifecycle of NativeCallable.isolateLocal
/// callbacks, ensuring proper cleanup after use.
class _FfiStoreCallbacks {
  final _SessionCallbackContext _context;

  // Session store callbacks
  late final NativeCallable<SignalLoadSessionFunction> _loadSession;
  late final NativeCallable<SignalStoreSessionFunction> _storeSession;

  // Identity store callbacks
  late final NativeCallable<SignalGetIdentityKeyPairFunction>
  _getIdentityKeyPair;
  late final NativeCallable<SignalGetLocalRegistrationIdFunction>
  _getLocalRegistrationId;
  late final NativeCallable<SignalSaveIdentityKeyFunction> _saveIdentity;
  late final NativeCallable<SignalGetIdentityKeyFunction> _getIdentity;
  late final NativeCallable<SignalIsTrustedIdentityFunction> _isTrustedIdentity;

  _FfiStoreCallbacks(this._context) {
    _initializeCallbacks();
  }

  void _initializeCallbacks() {
    // Session store callbacks
    _loadSession = NativeCallable<SignalLoadSessionFunction>.isolateLocal(
      _loadSessionCallback,
      exceptionalReturn: -1,
    );

    _storeSession = NativeCallable<SignalStoreSessionFunction>.isolateLocal(
      _storeSessionCallback,
      exceptionalReturn: -1,
    );

    // Identity store callbacks
    _getIdentityKeyPair =
        NativeCallable<SignalGetIdentityKeyPairFunction>.isolateLocal(
          _getIdentityKeyPairCallback,
          exceptionalReturn: -1,
        );

    _getLocalRegistrationId =
        NativeCallable<SignalGetLocalRegistrationIdFunction>.isolateLocal(
          _getLocalRegistrationIdCallback,
          exceptionalReturn: -1,
        );

    _saveIdentity = NativeCallable<SignalSaveIdentityKeyFunction>.isolateLocal(
      _saveIdentityCallback,
      exceptionalReturn: -1,
    );

    _getIdentity = NativeCallable<SignalGetIdentityKeyFunction>.isolateLocal(
      _getIdentityCallback,
      exceptionalReturn: -1,
    );

    _isTrustedIdentity =
        NativeCallable<SignalIsTrustedIdentityFunction>.isolateLocal(
          _isTrustedIdentityCallback,
          exceptionalReturn: -1,
        );
  }

  // ============================================
  // Session Store Callbacks
  // ============================================

  int _loadSessionCallback(
    Pointer<Void> ctx,
    Pointer<SignalMutPointerSessionRecord> recordp,
    SignalConstPointerProtocolAddress address,
  ) {
    try {
      final sessionBytes = _context.sessionRecordBytes;
      if (sessionBytes == null) {
        recordp.ref.raw = nullptr;
        return 0; // No session (not an error)
      }

      // Deserialize the session record
      final dataPtr = calloc<Uint8>(sessionBytes.length);
      dataPtr.asTypedList(sessionBytes.length).setAll(0, sessionBytes);

      final buffer = calloc<SignalBorrowedBuffer>();
      buffer.ref.base = dataPtr.cast<UnsignedChar>();
      buffer.ref.length = sessionBytes.length;

      final outPtr = calloc<SignalMutPointerSessionRecord>();

      try {
        final error = signal_session_record_deserialize(outPtr, buffer.ref);
        if (error == nullptr && outPtr.ref.raw != nullptr) {
          recordp.ref.raw = outPtr.ref.raw;
          return 0;
        }
      } finally {
        calloc.free(dataPtr);
        calloc.free(buffer);
        calloc.free(outPtr);
      }

      recordp.ref.raw = nullptr;
      return 0;
    } catch (_) {
      return -1;
    }
  }

  int _storeSessionCallback(
    Pointer<Void> ctx,
    SignalConstPointerProtocolAddress address,
    SignalConstPointerSessionRecord record,
  ) {
    try {
      if (record.raw == nullptr) {
        return 0;
      }

      // Serialize the session record
      final outPtr = calloc<SignalOwnedBuffer>();
      try {
        final error = signal_session_record_serialize(outPtr, record);
        if (error == nullptr) {
          _context.pendingSessionStore = FfiHelpers.fromOwnedBuffer(outPtr.ref);
        }
      } finally {
        calloc.free(outPtr);
      }

      return 0;
    } catch (_) {
      return -1;
    }
  }

  // ============================================
  // Identity Store Callbacks
  // ============================================

  int _getIdentityKeyPairCallback(
    Pointer<Void> ctx,
    Pointer<SignalMutPointerPrivateKey> keyp,
  ) {
    try {
      // Clone the private key to return to libsignal
      final privateKey = _context.identityKeyPair.privateKey;

      final outPtr = calloc<SignalMutPointerPrivateKey>();
      final constPtr = calloc<SignalConstPointerPrivateKey>();
      constPtr.ref.raw = privateKey.pointer;

      try {
        final error = signal_privatekey_clone(outPtr, constPtr.ref);
        if (error == nullptr && outPtr.ref.raw != nullptr) {
          keyp.ref.raw = outPtr.ref.raw;
          return 0;
        }
      } finally {
        calloc.free(outPtr);
        calloc.free(constPtr);
      }

      return -1;
    } catch (_) {
      return -1;
    }
  }

  int _getLocalRegistrationIdCallback(Pointer<Void> ctx, Pointer<Uint32> idp) {
    try {
      idp.value = _context.localRegistrationId;
      return 0;
    } catch (_) {
      return -1;
    }
  }

  int _saveIdentityCallback(
    Pointer<Void> ctx,
    SignalConstPointerProtocolAddress address,
    SignalConstPointerPublicKey publicKey,
  ) {
    try {
      if (publicKey.raw == nullptr) {
        return 0;
      }

      // Serialize the public key
      final outPtr = calloc<SignalOwnedBuffer>();
      try {
        final error = signal_publickey_serialize(outPtr, publicKey);
        if (error == nullptr) {
          final bytes = FfiHelpers.fromOwnedBuffer(outPtr.ref);
          _context.pendingIdentitySave = (
            address: _context.address,
            identityBytes: bytes,
          );
        }
      } finally {
        calloc.free(outPtr);
      }

      return 0;
    } catch (_) {
      return -1;
    }
  }

  int _getIdentityCallback(
    Pointer<Void> ctx,
    Pointer<SignalMutPointerPublicKey> publicKeyp,
    SignalConstPointerProtocolAddress address,
  ) {
    try {
      final identityBytes = _context.remoteIdentityBytes;
      if (identityBytes == null) {
        publicKeyp.ref.raw = nullptr;
        return 0;
      }

      // Deserialize the public key
      final dataPtr = calloc<Uint8>(identityBytes.length);
      dataPtr.asTypedList(identityBytes.length).setAll(0, identityBytes);

      final buffer = calloc<SignalBorrowedBuffer>();
      buffer.ref.base = dataPtr.cast<UnsignedChar>();
      buffer.ref.length = identityBytes.length;

      final outPtr = calloc<SignalMutPointerPublicKey>();

      try {
        final error = signal_publickey_deserialize(outPtr, buffer.ref);
        if (error == nullptr && outPtr.ref.raw != nullptr) {
          publicKeyp.ref.raw = outPtr.ref.raw;
          return 0;
        }
      } finally {
        calloc.free(dataPtr);
        calloc.free(buffer);
        calloc.free(outPtr);
      }

      publicKeyp.ref.raw = nullptr;
      return 0;
    } catch (_) {
      return -1;
    }
  }

  int _isTrustedIdentityCallback(
    Pointer<Void> ctx,
    SignalConstPointerProtocolAddress address,
    SignalConstPointerPublicKey publicKey,
    int direction,
  ) {
    try {
      // TOFU (Trust On First Use) policy:
      // - If no stored identity, trust this one
      // - If stored identity matches, trust
      // - If stored identity differs, don't trust

      final storedBytes = _context.remoteIdentityBytes;
      if (storedBytes == null) {
        return 1; // Trust on first use
      }

      // Serialize incoming key to compare
      final outPtr = calloc<SignalOwnedBuffer>();
      try {
        final error = signal_publickey_serialize(outPtr, publicKey);
        if (error != nullptr) {
          return 0; // Error = don't trust
        }

        final incomingBytes = FfiHelpers.fromOwnedBuffer(outPtr.ref);

        // Compare bytes
        if (storedBytes.length != incomingBytes.length) {
          return 0; // Different = don't trust
        }

        for (var i = 0; i < storedBytes.length; i++) {
          if (storedBytes[i] != incomingBytes[i]) {
            return 0; // Different = don't trust
          }
        }

        return 1; // Same = trust
      } finally {
        calloc.free(outPtr);
      }
    } catch (_) {
      return 0; // Error = don't trust
    }
  }

  // ============================================
  // Create FFI structs
  // ============================================

  /// Creates the session store struct with callbacks.
  Pointer<SignalSessionStore> createSessionStore() {
    final store = calloc<SignalSessionStore>();
    store.ref.ctx = nullptr;
    store.ref.load_session = _loadSession.nativeFunction;
    store.ref.store_session = _storeSession.nativeFunction;
    return store;
  }

  /// Creates the identity store struct with callbacks.
  Pointer<SignalIdentityKeyStore> createIdentityStore() {
    final store = calloc<SignalIdentityKeyStore>();
    store.ref.ctx = nullptr;
    store.ref.get_identity_key_pair = _getIdentityKeyPair.nativeFunction;
    store.ref.get_local_registration_id =
        _getLocalRegistrationId.nativeFunction;
    store.ref.save_identity = _saveIdentity.nativeFunction;
    store.ref.get_identity = _getIdentity.nativeFunction;
    store.ref.is_trusted_identity = _isTrustedIdentity.nativeFunction;
    return store;
  }

  /// Closes all NativeCallable instances.
  void close() {
    _loadSession.close();
    _storeSession.close();
    _getIdentityKeyPair.close();
    _getLocalRegistrationId.close();
    _saveIdentity.close();
    _getIdentity.close();
    _isTrustedIdentity.close();
  }
}

/// Builds Signal Protocol sessions using X3DH key agreement.
///
/// The SessionBuilder processes pre-key bundles from remote users to establish
/// encrypted sessions. Once a session is established, it can be used to
/// encrypt and decrypt messages.
///
/// Example:
/// ```dart
/// final builder = SessionBuilder(
///   sessionStore: mySessionStore,
///   identityKeyStore: myIdentityStore,
/// );
///
/// // Process a pre-key bundle from another user
/// await builder.processPreKeyBundle(
///   remoteAddress,
///   preKeyBundle,
/// );
///
/// // Now you can encrypt messages to remoteAddress
/// ```
class SessionBuilder {
  final SessionStore _sessionStore;
  final IdentityKeyStore _identityKeyStore;

  /// Creates a new session builder.
  ///
  /// The [sessionStore] is used to load and store session records.
  /// The [identityKeyStore] is used to access identity keys and manage trust.
  SessionBuilder({
    required SessionStore sessionStore,
    required IdentityKeyStore identityKeyStore,
  }) : _sessionStore = sessionStore,
       _identityKeyStore = identityKeyStore {
    LibSignal.ensureInitialized();
  }

  /// Processes a pre-key bundle to establish a session with a remote user.
  ///
  /// This performs the X3DH key agreement protocol to create a new session.
  /// The session can then be used to encrypt messages to [remoteAddress].
  ///
  /// If a session already exists, this will create a new session that
  /// archives the old one (for receiving late messages).
  ///
  /// Throws [LibSignalException] if:
  /// - The pre-key bundle is invalid
  /// - The signature verification fails
  /// - The identity key is not trusted
  Future<void> processPreKeyBundle(
    ProtocolAddress remoteAddress,
    PreKeyBundle bundle,
  ) async {
    // Pre-load data from async stores
    final existingSession = await _sessionStore.loadSession(remoteAddress);
    final identityKeyPair = await _identityKeyStore.getIdentityKeyPair();
    final localRegistrationId = await _identityKeyStore
        .getLocalRegistrationId();
    final existingIdentity = await _identityKeyStore.getIdentity(remoteAddress);

    // Create callback context with pre-loaded data
    final context = _SessionCallbackContext(
      identityKeyPair: identityKeyPair,
      localRegistrationId: localRegistrationId,
      address: remoteAddress,
      sessionRecordBytes: existingSession?.serialize(),
      remoteIdentityBytes: existingIdentity?.serialize(),
    );

    // Create FFI callbacks using NativeCallable.isolateLocal
    final callbacks = _FfiStoreCallbacks(context);

    try {
      // Create FFI structs
      final sessionStorePtr = callbacks.createSessionStore();
      final identityStorePtr = callbacks.createIdentityStore();

      final sessionStoreConstPtr =
          calloc<SignalConstPointerFfiSessionStoreStruct>();
      sessionStoreConstPtr.ref.raw = sessionStorePtr;

      final identityStoreConstPtr =
          calloc<SignalConstPointerFfiIdentityKeyStoreStruct>();
      identityStoreConstPtr.ref.raw = identityStorePtr;

      final bundleConstPtr = calloc<SignalConstPointerPreKeyBundle>();
      bundleConstPtr.ref.raw = bundle.pointer;

      final addressConstPtr = calloc<SignalConstPointerProtocolAddress>();
      addressConstPtr.ref.raw = remoteAddress.pointer;

      // Current time in milliseconds (UTC)
      final now = DateTime.now().toUtc().millisecondsSinceEpoch;

      try {
        // Call libsignal to process the pre-key bundle
        final error = signal_process_prekey_bundle(
          bundleConstPtr.ref,
          addressConstPtr.ref,
          sessionStoreConstPtr.ref,
          identityStoreConstPtr.ref,
          now,
        );
        FfiHelpers.checkError(error, 'signal_process_prekey_bundle');

        // Save any pending session update
        if (context.pendingSessionStore != null) {
          final newSession = SessionRecord.deserialize(
            context.pendingSessionStore!,
          );
          await _sessionStore.storeSession(remoteAddress, newSession);
          newSession.dispose();
        }

        // Save any pending identity update
        if (context.pendingIdentitySave != null) {
          final pending = context.pendingIdentitySave!;
          final publicKey = PublicKey.deserialize(pending.identityBytes);
          // Note: We don't dispose publicKey here - the store takes ownership
          await _identityKeyStore.saveIdentity(pending.address, publicKey);
        }
      } finally {
        calloc.free(sessionStorePtr);
        calloc.free(identityStorePtr);
        calloc.free(sessionStoreConstPtr);
        calloc.free(identityStoreConstPtr);
        calloc.free(bundleConstPtr);
        calloc.free(addressConstPtr);
      }
    } finally {
      // Always close the NativeCallable instances
      callbacks.close();
    }
  }
}
