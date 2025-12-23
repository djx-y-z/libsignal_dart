/// Session cipher for Signal Protocol message encryption/decryption.
///
/// Uses NativeCallable.isolateLocal for FFI callbacks.
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
import '../stores/identity_key_store.dart';
import '../stores/kyber_pre_key_store.dart';
import '../stores/pre_key_store.dart';
import '../stores/session_store.dart';
import '../stores/signed_pre_key_store.dart';
import '../utils.dart';
import 'ciphertext_message_type.dart';
import 'protocol_address.dart';
import 'session_record.dart';

/// Result of encrypting a message.
class CiphertextMessage {
  /// The encrypted message bytes.
  final Uint8List bytes;

  /// The type of ciphertext message.
  final CiphertextMessageType type;

  const CiphertextMessage(this.bytes, this.type);
}

/// Holds pre-loaded data for encryption FFI callbacks.
class _EncryptionContext {
  Uint8List? sessionRecordBytes;
  Uint8List? pendingSessionStore;
  final IdentityKeyPair identityKeyPair;
  final int localRegistrationId;
  Uint8List? remoteIdentityBytes;
  ({ProtocolAddress address, Uint8List identityBytes})? pendingIdentitySave;
  final ProtocolAddress address;

  _EncryptionContext({
    required this.identityKeyPair,
    required this.localRegistrationId,
    required this.address,
    this.sessionRecordBytes,
    this.remoteIdentityBytes,
  });

  /// Securely clears all sensitive data from the context.
  void clear() {
    LibSignalUtils.zeroBytes(sessionRecordBytes);
    LibSignalUtils.zeroBytes(pendingSessionStore);
    LibSignalUtils.zeroBytes(remoteIdentityBytes);
    if (pendingIdentitySave != null) {
      LibSignalUtils.zeroBytes(pendingIdentitySave!.identityBytes);
    }
    sessionRecordBytes = null;
    pendingSessionStore = null;
    remoteIdentityBytes = null;
    pendingIdentitySave = null;
  }
}

/// Holds pre-loaded data for decryption FFI callbacks.
class _DecryptionContext {
  Uint8List? sessionRecordBytes;
  Uint8List? pendingSessionStore;
  final IdentityKeyPair identityKeyPair;
  final int localRegistrationId;
  Uint8List? remoteIdentityBytes;
  ({ProtocolAddress address, Uint8List identityBytes})? pendingIdentitySave;
  final ProtocolAddress address;

  // Pre-key stores for PreKeySignalMessage decryption
  final Map<int, Uint8List> preKeys;
  final Map<int, Uint8List> signedPreKeys;
  final Map<int, Uint8List> kyberPreKeys;

  // Pending removals
  int? pendingPreKeyRemoval;
  int? pendingKyberPreKeyRemoval;

  _DecryptionContext({
    required this.identityKeyPair,
    required this.localRegistrationId,
    required this.address,
    this.sessionRecordBytes,
    this.remoteIdentityBytes,
    this.preKeys = const {},
    this.signedPreKeys = const {},
    this.kyberPreKeys = const {},
  });

  /// Securely clears all sensitive data from the context.
  void clear() {
    LibSignalUtils.zeroBytes(sessionRecordBytes);
    LibSignalUtils.zeroBytes(pendingSessionStore);
    LibSignalUtils.zeroBytes(remoteIdentityBytes);
    if (pendingIdentitySave != null) {
      LibSignalUtils.zeroBytes(pendingIdentitySave!.identityBytes);
    }
    // Clear pre-key data
    for (final data in preKeys.values) {
      LibSignalUtils.zeroBytes(data);
    }
    for (final data in signedPreKeys.values) {
      LibSignalUtils.zeroBytes(data);
    }
    for (final data in kyberPreKeys.values) {
      LibSignalUtils.zeroBytes(data);
    }
    sessionRecordBytes = null;
    pendingSessionStore = null;
    remoteIdentityBytes = null;
    pendingIdentitySave = null;
  }
}

/// Manages NativeCallable instances for encryption.
class _EncryptionCallbacks {
  final _EncryptionContext _context;

  late final NativeCallable<SignalLoadSessionFunction> _loadSession;
  late final NativeCallable<SignalStoreSessionFunction> _storeSession;
  late final NativeCallable<SignalGetIdentityKeyPairFunction>
      _getIdentityKeyPair;
  late final NativeCallable<SignalGetLocalRegistrationIdFunction>
      _getLocalRegistrationId;
  late final NativeCallable<SignalSaveIdentityKeyFunction> _saveIdentity;
  late final NativeCallable<SignalGetIdentityKeyFunction> _getIdentity;
  late final NativeCallable<SignalIsTrustedIdentityFunction> _isTrustedIdentity;

  _EncryptionCallbacks(this._context) {
    _loadSession = NativeCallable<SignalLoadSessionFunction>.isolateLocal(
      _loadSessionCallback,
      exceptionalReturn: -1,
    );
    _storeSession = NativeCallable<SignalStoreSessionFunction>.isolateLocal(
      _storeSessionCallback,
      exceptionalReturn: -1,
    );
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

  int _loadSessionCallback(
    Pointer<Void> ctx,
    Pointer<SignalMutPointerSessionRecord> recordp,
    SignalConstPointerProtocolAddress address,
  ) {
    try {
      final sessionBytes = _context.sessionRecordBytes;
      if (sessionBytes == null) {
        recordp.ref.raw = nullptr;
        return 0;
      }

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
      if (record.raw == nullptr) return 0;

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

  int _getIdentityKeyPairCallback(
    Pointer<Void> ctx,
    Pointer<SignalMutPointerPrivateKey> keyp,
  ) {
    try {
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

  int _getLocalRegistrationIdCallback(
    Pointer<Void> ctx,
    Pointer<Uint32> idp,
  ) {
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
      if (publicKey.raw == nullptr) return 0;

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
      final storedBytes = _context.remoteIdentityBytes;
      if (storedBytes == null) return 1;

      final outPtr = calloc<SignalOwnedBuffer>();
      try {
        final error = signal_publickey_serialize(outPtr, publicKey);
        if (error != nullptr) return 0;

        final incomingBytes = FfiHelpers.fromOwnedBuffer(outPtr.ref);

        // Use constant-time comparison to prevent timing attacks
        return LibSignalUtils.constantTimeEquals(storedBytes, incomingBytes)
            ? 1
            : 0;
      } finally {
        calloc.free(outPtr);
      }
    } catch (_) {
      return 0;
    }
  }

  Pointer<SignalSessionStore> createSessionStore() {
    final store = calloc<SignalSessionStore>();
    store.ref.ctx = nullptr;
    store.ref.load_session = _loadSession.nativeFunction;
    store.ref.store_session = _storeSession.nativeFunction;
    return store;
  }

  Pointer<SignalIdentityKeyStore> createIdentityStore() {
    final store = calloc<SignalIdentityKeyStore>();
    store.ref.ctx = nullptr;
    store.ref.get_identity_key_pair = _getIdentityKeyPair.nativeFunction;
    store.ref.get_local_registration_id = _getLocalRegistrationId.nativeFunction;
    store.ref.save_identity = _saveIdentity.nativeFunction;
    store.ref.get_identity = _getIdentity.nativeFunction;
    store.ref.is_trusted_identity = _isTrustedIdentity.nativeFunction;
    return store;
  }

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

/// Manages NativeCallable instances for decryption (includes pre-key stores).
class _DecryptionCallbacks {
  final _DecryptionContext _context;

  // Session store
  late final NativeCallable<SignalLoadSessionFunction> _loadSession;
  late final NativeCallable<SignalStoreSessionFunction> _storeSession;

  // Identity store
  late final NativeCallable<SignalGetIdentityKeyPairFunction>
      _getIdentityKeyPair;
  late final NativeCallable<SignalGetLocalRegistrationIdFunction>
      _getLocalRegistrationId;
  late final NativeCallable<SignalSaveIdentityKeyFunction> _saveIdentity;
  late final NativeCallable<SignalGetIdentityKeyFunction> _getIdentity;
  late final NativeCallable<SignalIsTrustedIdentityFunction> _isTrustedIdentity;

  // Pre-key store
  late final NativeCallable<SignalLoadPreKeyFunction> _loadPreKey;
  late final NativeCallable<SignalStorePreKeyFunction> _storePreKey;
  late final NativeCallable<SignalRemovePreKeyFunction> _removePreKey;

  // Signed pre-key store
  late final NativeCallable<SignalLoadSignedPreKeyFunction> _loadSignedPreKey;
  late final NativeCallable<SignalStoreSignedPreKeyFunction> _storeSignedPreKey;

  // Kyber pre-key store
  late final NativeCallable<SignalLoadKyberPreKeyFunction> _loadKyberPreKey;
  late final NativeCallable<SignalStoreKyberPreKeyFunction> _storeKyberPreKey;
  late final NativeCallable<SignalMarkKyberPreKeyUsedFunction>
      _markKyberPreKeyUsed;

  _DecryptionCallbacks(this._context) {
    _initializeSessionCallbacks();
    _initializeIdentityCallbacks();
    _initializePreKeyCallbacks();
    _initializeSignedPreKeyCallbacks();
    _initializeKyberPreKeyCallbacks();
  }

  void _initializeSessionCallbacks() {
    _loadSession = NativeCallable<SignalLoadSessionFunction>.isolateLocal(
      _loadSessionCallback,
      exceptionalReturn: -1,
    );
    _storeSession = NativeCallable<SignalStoreSessionFunction>.isolateLocal(
      _storeSessionCallback,
      exceptionalReturn: -1,
    );
  }

  void _initializeIdentityCallbacks() {
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

  void _initializePreKeyCallbacks() {
    _loadPreKey = NativeCallable<SignalLoadPreKeyFunction>.isolateLocal(
      _loadPreKeyCallback,
      exceptionalReturn: -1,
    );
    _storePreKey = NativeCallable<SignalStorePreKeyFunction>.isolateLocal(
      _storePreKeyCallback,
      exceptionalReturn: -1,
    );
    _removePreKey = NativeCallable<SignalRemovePreKeyFunction>.isolateLocal(
      _removePreKeyCallback,
      exceptionalReturn: -1,
    );
  }

  void _initializeSignedPreKeyCallbacks() {
    _loadSignedPreKey =
        NativeCallable<SignalLoadSignedPreKeyFunction>.isolateLocal(
      _loadSignedPreKeyCallback,
      exceptionalReturn: -1,
    );
    _storeSignedPreKey =
        NativeCallable<SignalStoreSignedPreKeyFunction>.isolateLocal(
      _storeSignedPreKeyCallback,
      exceptionalReturn: -1,
    );
  }

  void _initializeKyberPreKeyCallbacks() {
    _loadKyberPreKey =
        NativeCallable<SignalLoadKyberPreKeyFunction>.isolateLocal(
      _loadKyberPreKeyCallback,
      exceptionalReturn: -1,
    );
    _storeKyberPreKey =
        NativeCallable<SignalStoreKyberPreKeyFunction>.isolateLocal(
      _storeKyberPreKeyCallback,
      exceptionalReturn: -1,
    );
    _markKyberPreKeyUsed =
        NativeCallable<SignalMarkKyberPreKeyUsedFunction>.isolateLocal(
      _markKyberPreKeyUsedCallback,
      exceptionalReturn: -1,
    );
  }

  // Session callbacks (same as encryption)
  int _loadSessionCallback(
    Pointer<Void> ctx,
    Pointer<SignalMutPointerSessionRecord> recordp,
    SignalConstPointerProtocolAddress address,
  ) {
    try {
      final sessionBytes = _context.sessionRecordBytes;
      if (sessionBytes == null) {
        recordp.ref.raw = nullptr;
        return 0;
      }

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
      if (record.raw == nullptr) return 0;

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

  // Identity callbacks
  int _getIdentityKeyPairCallback(
    Pointer<Void> ctx,
    Pointer<SignalMutPointerPrivateKey> keyp,
  ) {
    try {
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

  int _getLocalRegistrationIdCallback(
    Pointer<Void> ctx,
    Pointer<Uint32> idp,
  ) {
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
      if (publicKey.raw == nullptr) return 0;

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
      final storedBytes = _context.remoteIdentityBytes;
      if (storedBytes == null) return 1;

      final outPtr = calloc<SignalOwnedBuffer>();
      try {
        final error = signal_publickey_serialize(outPtr, publicKey);
        if (error != nullptr) return 0;

        final incomingBytes = FfiHelpers.fromOwnedBuffer(outPtr.ref);

        // Use constant-time comparison to prevent timing attacks
        return LibSignalUtils.constantTimeEquals(storedBytes, incomingBytes)
            ? 1
            : 0;
      } finally {
        calloc.free(outPtr);
      }
    } catch (_) {
      return 0;
    }
  }

  // Pre-key callbacks
  int _loadPreKeyCallback(
    Pointer<Void> ctx,
    Pointer<SignalMutPointerPreKeyRecord> recordp,
    int id,
  ) {
    try {
      final preKeyBytes = _context.preKeys[id];
      if (preKeyBytes == null) {
        recordp.ref.raw = nullptr;
        return 0;
      }

      final dataPtr = calloc<Uint8>(preKeyBytes.length);
      dataPtr.asTypedList(preKeyBytes.length).setAll(0, preKeyBytes);

      final buffer = calloc<SignalBorrowedBuffer>();
      buffer.ref.base = dataPtr.cast<UnsignedChar>();
      buffer.ref.length = preKeyBytes.length;

      final outPtr = calloc<SignalMutPointerPreKeyRecord>();

      try {
        final error = signal_pre_key_record_deserialize(outPtr, buffer.ref);
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

  int _storePreKeyCallback(
    Pointer<Void> ctx,
    int id,
    SignalConstPointerPreKeyRecord record,
  ) {
    // We don't need to store pre-keys during decryption
    return 0;
  }

  int _removePreKeyCallback(
    Pointer<Void> ctx,
    int id,
  ) {
    try {
      _context.pendingPreKeyRemoval = id;
      return 0;
    } catch (_) {
      return -1;
    }
  }

  // Signed pre-key callbacks
  int _loadSignedPreKeyCallback(
    Pointer<Void> ctx,
    Pointer<SignalMutPointerSignedPreKeyRecord> recordp,
    int id,
  ) {
    try {
      final signedPreKeyBytes = _context.signedPreKeys[id];
      if (signedPreKeyBytes == null) {
        recordp.ref.raw = nullptr;
        return 0;
      }

      final dataPtr = calloc<Uint8>(signedPreKeyBytes.length);
      dataPtr.asTypedList(signedPreKeyBytes.length).setAll(0, signedPreKeyBytes);

      final buffer = calloc<SignalBorrowedBuffer>();
      buffer.ref.base = dataPtr.cast<UnsignedChar>();
      buffer.ref.length = signedPreKeyBytes.length;

      final outPtr = calloc<SignalMutPointerSignedPreKeyRecord>();

      try {
        final error =
            signal_signed_pre_key_record_deserialize(outPtr, buffer.ref);
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

  int _storeSignedPreKeyCallback(
    Pointer<Void> ctx,
    int id,
    SignalConstPointerSignedPreKeyRecord record,
  ) {
    // We don't need to store signed pre-keys during decryption
    return 0;
  }

  // Kyber pre-key callbacks
  int _loadKyberPreKeyCallback(
    Pointer<Void> ctx,
    Pointer<SignalMutPointerKyberPreKeyRecord> recordp,
    int id,
  ) {
    try {
      final kyberPreKeyBytes = _context.kyberPreKeys[id];
      if (kyberPreKeyBytes == null) {
        recordp.ref.raw = nullptr;
        return 0;
      }

      final dataPtr = calloc<Uint8>(kyberPreKeyBytes.length);
      dataPtr.asTypedList(kyberPreKeyBytes.length).setAll(0, kyberPreKeyBytes);

      final buffer = calloc<SignalBorrowedBuffer>();
      buffer.ref.base = dataPtr.cast<UnsignedChar>();
      buffer.ref.length = kyberPreKeyBytes.length;

      final outPtr = calloc<SignalMutPointerKyberPreKeyRecord>();

      try {
        final error =
            signal_kyber_pre_key_record_deserialize(outPtr, buffer.ref);
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

  int _storeKyberPreKeyCallback(
    Pointer<Void> ctx,
    int id,
    SignalConstPointerKyberPreKeyRecord record,
  ) {
    // We don't need to store Kyber pre-keys during decryption
    return 0;
  }

  int _markKyberPreKeyUsedCallback(
    Pointer<Void> ctx,
    int id,
    int signedPreKeyId,
    SignalConstPointerPublicKey baseKey,
  ) {
    try {
      _context.pendingKyberPreKeyRemoval = id;
      return 0;
    } catch (_) {
      return -1;
    }
  }

  // Create FFI structs
  Pointer<SignalSessionStore> createSessionStore() {
    final store = calloc<SignalSessionStore>();
    store.ref.ctx = nullptr;
    store.ref.load_session = _loadSession.nativeFunction;
    store.ref.store_session = _storeSession.nativeFunction;
    return store;
  }

  Pointer<SignalIdentityKeyStore> createIdentityStore() {
    final store = calloc<SignalIdentityKeyStore>();
    store.ref.ctx = nullptr;
    store.ref.get_identity_key_pair = _getIdentityKeyPair.nativeFunction;
    store.ref.get_local_registration_id = _getLocalRegistrationId.nativeFunction;
    store.ref.save_identity = _saveIdentity.nativeFunction;
    store.ref.get_identity = _getIdentity.nativeFunction;
    store.ref.is_trusted_identity = _isTrustedIdentity.nativeFunction;
    return store;
  }

  Pointer<SignalPreKeyStore> createPreKeyStore() {
    final store = calloc<SignalPreKeyStore>();
    store.ref.ctx = nullptr;
    store.ref.load_pre_key = _loadPreKey.nativeFunction;
    store.ref.store_pre_key = _storePreKey.nativeFunction;
    store.ref.remove_pre_key = _removePreKey.nativeFunction;
    return store;
  }

  Pointer<SignalSignedPreKeyStore> createSignedPreKeyStore() {
    final store = calloc<SignalSignedPreKeyStore>();
    store.ref.ctx = nullptr;
    store.ref.load_signed_pre_key = _loadSignedPreKey.nativeFunction;
    store.ref.store_signed_pre_key = _storeSignedPreKey.nativeFunction;
    return store;
  }

  Pointer<SignalKyberPreKeyStore> createKyberPreKeyStore() {
    final store = calloc<SignalKyberPreKeyStore>();
    store.ref.ctx = nullptr;
    store.ref.load_kyber_pre_key = _loadKyberPreKey.nativeFunction;
    store.ref.store_kyber_pre_key = _storeKyberPreKey.nativeFunction;
    store.ref.mark_kyber_pre_key_used = _markKyberPreKeyUsed.nativeFunction;
    return store;
  }

  void close() {
    _loadSession.close();
    _storeSession.close();
    _getIdentityKeyPair.close();
    _getLocalRegistrationId.close();
    _saveIdentity.close();
    _getIdentity.close();
    _isTrustedIdentity.close();
    _loadPreKey.close();
    _storePreKey.close();
    _removePreKey.close();
    _loadSignedPreKey.close();
    _storeSignedPreKey.close();
    _loadKyberPreKey.close();
    _storeKyberPreKey.close();
    _markKyberPreKeyUsed.close();
  }
}

/// Encrypts and decrypts messages using Signal Protocol sessions.
///
/// The SessionCipher requires an established session (via SessionBuilder)
/// to encrypt messages. For decryption, it can also establish sessions
/// from pre-key messages.
///
/// Example:
/// ```dart
/// final cipher = SessionCipher(
///   sessionStore: mySessionStore,
///   identityKeyStore: myIdentityStore,
///   preKeyStore: myPreKeyStore,
///   signedPreKeyStore: mySignedPreKeyStore,
///   kyberPreKeyStore: myKyberPreKeyStore,
/// );
///
/// // Encrypt a message
/// final encrypted = await cipher.encrypt(remoteAddress, plaintext);
///
/// // Decrypt a message
/// final decrypted = await cipher.decrypt(remoteAddress, ciphertext);
/// ```
class SessionCipher {
  final SessionStore _sessionStore;
  final IdentityKeyStore _identityKeyStore;
  final PreKeyStore? _preKeyStore;
  final SignedPreKeyStore? _signedPreKeyStore;
  final KyberPreKeyStore? _kyberPreKeyStore;

  /// Creates a new session cipher.
  ///
  /// For encryption, only [sessionStore] and [identityKeyStore] are required.
  /// For decryption of pre-key messages, all stores are needed.
  SessionCipher({
    required SessionStore sessionStore,
    required IdentityKeyStore identityKeyStore,
    PreKeyStore? preKeyStore,
    SignedPreKeyStore? signedPreKeyStore,
    KyberPreKeyStore? kyberPreKeyStore,
  })  : _sessionStore = sessionStore,
        _identityKeyStore = identityKeyStore,
        _preKeyStore = preKeyStore,
        _signedPreKeyStore = signedPreKeyStore,
        _kyberPreKeyStore = kyberPreKeyStore {
    LibSignal.ensureInitialized();
  }

  /// Encrypts a message for the remote address.
  ///
  /// Requires an established session with [remoteAddress].
  /// Returns a [CiphertextMessage] containing the encrypted bytes and type.
  ///
  /// Throws [LibSignalException] if no session exists.
  Future<CiphertextMessage> encrypt(
    ProtocolAddress remoteAddress,
    Uint8List plaintext,
  ) async {
    // Pre-load data
    final existingSession = await _sessionStore.loadSession(remoteAddress);
    if (existingSession == null) {
      throw LibSignalException(
        'No session for $remoteAddress',
        context: 'SessionCipher.encrypt',
      );
    }

    final identityKeyPair = await _identityKeyStore.getIdentityKeyPair();
    final localRegistrationId = await _identityKeyStore.getLocalRegistrationId();
    final existingIdentity = await _identityKeyStore.getIdentity(remoteAddress);

    final context = _EncryptionContext(
      identityKeyPair: identityKeyPair,
      localRegistrationId: localRegistrationId,
      address: remoteAddress,
      sessionRecordBytes: existingSession.serialize(),
      remoteIdentityBytes: existingIdentity?.serialize(),
    );

    final callbacks = _EncryptionCallbacks(context);

    try {
      final sessionStorePtr = callbacks.createSessionStore();
      final identityStorePtr = callbacks.createIdentityStore();

      final sessionStoreConstPtr =
          calloc<SignalConstPointerFfiSessionStoreStruct>();
      sessionStoreConstPtr.ref.raw = sessionStorePtr;

      final identityStoreConstPtr =
          calloc<SignalConstPointerFfiIdentityKeyStoreStruct>();
      identityStoreConstPtr.ref.raw = identityStorePtr;

      final addressConstPtr = calloc<SignalConstPointerProtocolAddress>();
      addressConstPtr.ref.raw = remoteAddress.pointer;

      final plaintextPtr = calloc<Uint8>(plaintext.length);
      plaintextPtr.asTypedList(plaintext.length).setAll(0, plaintext);

      final plaintextBuffer = calloc<SignalBorrowedBuffer>();
      plaintextBuffer.ref.base = plaintextPtr.cast<UnsignedChar>();
      plaintextBuffer.ref.length = plaintext.length;

      final outPtr = calloc<SignalMutPointerCiphertextMessage>();

      final now = DateTime.now().toUtc().millisecondsSinceEpoch;

      try {
        final error = signal_encrypt_message(
          outPtr,
          plaintextBuffer.ref,
          addressConstPtr.ref,
          sessionStoreConstPtr.ref,
          identityStoreConstPtr.ref,
          now,
        );
        FfiHelpers.checkError(error, 'signal_encrypt_message');

        if (outPtr.ref.raw == nullptr) {
          throw LibSignalException.nullPointer('signal_encrypt_message');
        }

        // Get message type
        final typePtr = calloc<Uint8>();
        final ciphertextConstPtr = calloc<SignalConstPointerCiphertextMessage>();
        ciphertextConstPtr.ref.raw = outPtr.ref.raw;

        final typeError = signal_ciphertext_message_type(
          typePtr,
          ciphertextConstPtr.ref,
        );
        FfiHelpers.checkError(typeError, 'signal_ciphertext_message_type');

        final messageType = CiphertextMessageType.fromValue(typePtr.value);

        // Serialize the message
        final serializedPtr = calloc<SignalOwnedBuffer>();
        final serializeError = signal_ciphertext_message_serialize(
          serializedPtr,
          ciphertextConstPtr.ref,
        );
        FfiHelpers.checkError(serializeError, 'signal_ciphertext_message_serialize');

        final encryptedBytes = FfiHelpers.fromOwnedBuffer(serializedPtr.ref);

        calloc.free(typePtr);
        calloc.free(ciphertextConstPtr);
        calloc.free(serializedPtr);

        // Destroy the ciphertext message
        final destroyPtr = calloc<SignalMutPointerCiphertextMessage>();
        destroyPtr.ref.raw = outPtr.ref.raw;
        signal_ciphertext_message_destroy(destroyPtr.ref);
        calloc.free(destroyPtr);

        // Save pending session update
        if (context.pendingSessionStore != null) {
          final newSession =
              SessionRecord.deserialize(context.pendingSessionStore!);
          await _sessionStore.storeSession(remoteAddress, newSession);
          newSession.dispose();
        }

        return CiphertextMessage(encryptedBytes, messageType);
      } finally {
        // Securely zero plaintext before freeing
        LibSignalUtils.zeroBytes(plaintextPtr.asTypedList(plaintext.length));
        calloc.free(sessionStorePtr);
        calloc.free(identityStorePtr);
        calloc.free(sessionStoreConstPtr);
        calloc.free(identityStoreConstPtr);
        calloc.free(addressConstPtr);
        calloc.free(plaintextPtr);
        calloc.free(plaintextBuffer);
        calloc.free(outPtr);
      }
    } finally {
      callbacks.close();
      context.clear();
    }
  }

  /// Decrypts a Signal message from the remote address.
  ///
  /// For regular SignalMessage, an existing session must exist.
  /// For PreKeySignalMessage, a new session will be established.
  ///
  /// Returns the decrypted plaintext.
  Future<Uint8List> decryptSignalMessage(
    ProtocolAddress remoteAddress,
    Uint8List ciphertext,
  ) async {
    // Pre-load data
    final existingSession = await _sessionStore.loadSession(remoteAddress);
    final identityKeyPair = await _identityKeyStore.getIdentityKeyPair();
    final localRegistrationId = await _identityKeyStore.getLocalRegistrationId();
    final existingIdentity = await _identityKeyStore.getIdentity(remoteAddress);

    final context = _DecryptionContext(
      identityKeyPair: identityKeyPair,
      localRegistrationId: localRegistrationId,
      address: remoteAddress,
      sessionRecordBytes: existingSession?.serialize(),
      remoteIdentityBytes: existingIdentity?.serialize(),
    );

    final callbacks = _DecryptionCallbacks(context);

    try {
      // Deserialize the SignalMessage
      final messagePtr = calloc<SignalMutPointerSignalMessage>();
      final ciphertextPtr = calloc<Uint8>(ciphertext.length);
      ciphertextPtr.asTypedList(ciphertext.length).setAll(0, ciphertext);

      final ciphertextBuffer = calloc<SignalBorrowedBuffer>();
      ciphertextBuffer.ref.base = ciphertextPtr.cast<UnsignedChar>();
      ciphertextBuffer.ref.length = ciphertext.length;

      final deserializeError = signal_message_deserialize(
        messagePtr,
        ciphertextBuffer.ref,
      );
      FfiHelpers.checkError(deserializeError, 'signal_message_deserialize');

      final sessionStorePtr = callbacks.createSessionStore();
      final identityStorePtr = callbacks.createIdentityStore();

      final sessionStoreConstPtr =
          calloc<SignalConstPointerFfiSessionStoreStruct>();
      sessionStoreConstPtr.ref.raw = sessionStorePtr;

      final identityStoreConstPtr =
          calloc<SignalConstPointerFfiIdentityKeyStoreStruct>();
      identityStoreConstPtr.ref.raw = identityStorePtr;

      final addressConstPtr = calloc<SignalConstPointerProtocolAddress>();
      addressConstPtr.ref.raw = remoteAddress.pointer;

      final messageConstPtr = calloc<SignalConstPointerSignalMessage>();
      messageConstPtr.ref.raw = messagePtr.ref.raw;

      final outPtr = calloc<SignalOwnedBuffer>();

      try {
        final error = signal_decrypt_message(
          outPtr,
          messageConstPtr.ref,
          addressConstPtr.ref,
          sessionStoreConstPtr.ref,
          identityStoreConstPtr.ref,
        );
        FfiHelpers.checkError(error, 'signal_decrypt_message');

        final plaintext = FfiHelpers.fromOwnedBuffer(outPtr.ref);

        // Save pending session update
        if (context.pendingSessionStore != null) {
          final newSession =
              SessionRecord.deserialize(context.pendingSessionStore!);
          await _sessionStore.storeSession(remoteAddress, newSession);
          newSession.dispose();
        }

        // Save pending identity update
        if (context.pendingIdentitySave != null) {
          final pending = context.pendingIdentitySave!;
          final publicKey = PublicKey.deserialize(pending.identityBytes);
          // Note: We don't dispose publicKey here - the store takes ownership
          await _identityKeyStore.saveIdentity(pending.address, publicKey);
        }

        return plaintext;
      } finally {
        // Destroy the message
        final destroyPtr = calloc<SignalMutPointerSignalMessage>();
        destroyPtr.ref.raw = messagePtr.ref.raw;
        signal_message_destroy(destroyPtr.ref);
        calloc.free(destroyPtr);

        // Securely zero ciphertext before freeing
        LibSignalUtils.zeroBytes(ciphertextPtr.asTypedList(ciphertext.length));
        calloc.free(messagePtr);
        calloc.free(ciphertextPtr);
        calloc.free(ciphertextBuffer);
        calloc.free(sessionStorePtr);
        calloc.free(identityStorePtr);
        calloc.free(sessionStoreConstPtr);
        calloc.free(identityStoreConstPtr);
        calloc.free(addressConstPtr);
        calloc.free(messageConstPtr);
        calloc.free(outPtr);
      }
    } finally {
      callbacks.close();
      context.clear();
    }
  }

  /// Decrypts a PreKeySignalMessage, establishing a new session.
  ///
  /// This requires all pre-key stores to be provided.
  Future<Uint8List> decryptPreKeySignalMessage(
    ProtocolAddress remoteAddress,
    Uint8List ciphertext,
  ) async {
    if (_preKeyStore == null ||
        _signedPreKeyStore == null ||
        _kyberPreKeyStore == null) {
      throw LibSignalException(
        'Pre-key stores required for PreKeySignalMessage decryption',
        context: 'SessionCipher.decryptPreKeySignalMessage',
      );
    }

    // First, deserialize the message to extract key IDs
    final messagePtr = calloc<SignalMutPointerPreKeySignalMessage>();
    final ciphertextPtr = calloc<Uint8>(ciphertext.length);
    ciphertextPtr.asTypedList(ciphertext.length).setAll(0, ciphertext);

    final ciphertextBuffer = calloc<SignalBorrowedBuffer>();
    ciphertextBuffer.ref.base = ciphertextPtr.cast<UnsignedChar>();
    ciphertextBuffer.ref.length = ciphertext.length;

    final deserializeError = signal_pre_key_signal_message_deserialize(
      messagePtr,
      ciphertextBuffer.ref,
    );
    FfiHelpers.checkError(
      deserializeError,
      'signal_pre_key_signal_message_deserialize',
    );

    // Extract key IDs from the message
    final preKeyId = _extractPreKeyId(messagePtr);
    final signedPreKeyId = _extractSignedPreKeyId(messagePtr);

    // Pre-load session and identity data
    final existingSession = await _sessionStore.loadSession(remoteAddress);
    final identityKeyPair = await _identityKeyStore.getIdentityKeyPair();
    final localRegistrationId = await _identityKeyStore.getLocalRegistrationId();
    final existingIdentity = await _identityKeyStore.getIdentity(remoteAddress);

    // Load only the specific pre-keys we need
    final preKeys = <int, Uint8List>{};
    if (preKeyId != null) {
      final preKeyBytes = await _loadPreKeyById(preKeyId);
      if (preKeyBytes != null) {
        preKeys[preKeyId] = preKeyBytes;
      }
    }

    final signedPreKeys = <int, Uint8List>{};
    final signedPreKeyBytes = await _loadSignedPreKeyById(signedPreKeyId);
    if (signedPreKeyBytes != null) {
      signedPreKeys[signedPreKeyId] = signedPreKeyBytes;
    }

    // Load all Kyber pre-keys.
    //
    // TODO(libsignal): The Kyber pre-key ID is not exposed by the libsignal C API.
    // Unlike preKeyId and signedPreKeyId, there is no
    // `signal_pre_key_signal_message_get_kyber_pre_key_id` function.
    //
    // The Kyber ciphertext is included in the message internally, but the ID
    // is not accessible. When/if libsignal adds this getter, we can optimize
    // to load only the specific Kyber key needed.
    //
    // Current workaround: Load all Kyber pre-keys. This is acceptable because:
    // 1. Typically only 1-2 Kyber keys are stored at a time
    // 2. The keys are ~1.5KB each, so memory impact is minimal
    //
    // Potential future workarounds (not recommended):
    // - Parse the protobuf manually (fragile, may break with updates)
    // - Assume kyberPreKeyId == signedPreKeyId (not guaranteed by protocol)
    //
    // See: https://github.com/signalapp/libsignal (check for API updates)
    final kyberPreKeys = await _loadAllKyberPreKeys();

    final context = _DecryptionContext(
      identityKeyPair: identityKeyPair,
      localRegistrationId: localRegistrationId,
      address: remoteAddress,
      sessionRecordBytes: existingSession?.serialize(),
      remoteIdentityBytes: existingIdentity?.serialize(),
      preKeys: preKeys,
      signedPreKeys: signedPreKeys,
      kyberPreKeys: kyberPreKeys,
    );

    final callbacks = _DecryptionCallbacks(context);

    try {

      final sessionStorePtr = callbacks.createSessionStore();
      final identityStorePtr = callbacks.createIdentityStore();
      final preKeyStorePtr = callbacks.createPreKeyStore();
      final signedPreKeyStorePtr = callbacks.createSignedPreKeyStore();
      final kyberPreKeyStorePtr = callbacks.createKyberPreKeyStore();

      final sessionStoreConstPtr =
          calloc<SignalConstPointerFfiSessionStoreStruct>();
      sessionStoreConstPtr.ref.raw = sessionStorePtr;

      final identityStoreConstPtr =
          calloc<SignalConstPointerFfiIdentityKeyStoreStruct>();
      identityStoreConstPtr.ref.raw = identityStorePtr;

      final preKeyStoreConstPtr =
          calloc<SignalConstPointerFfiPreKeyStoreStruct>();
      preKeyStoreConstPtr.ref.raw = preKeyStorePtr;

      final signedPreKeyStoreConstPtr =
          calloc<SignalConstPointerFfiSignedPreKeyStoreStruct>();
      signedPreKeyStoreConstPtr.ref.raw = signedPreKeyStorePtr;

      final kyberPreKeyStoreConstPtr =
          calloc<SignalConstPointerFfiKyberPreKeyStoreStruct>();
      kyberPreKeyStoreConstPtr.ref.raw = kyberPreKeyStorePtr;

      final addressConstPtr = calloc<SignalConstPointerProtocolAddress>();
      addressConstPtr.ref.raw = remoteAddress.pointer;

      final messageConstPtr = calloc<SignalConstPointerPreKeySignalMessage>();
      messageConstPtr.ref.raw = messagePtr.ref.raw;

      final outPtr = calloc<SignalOwnedBuffer>();

      try {
        final error = signal_decrypt_pre_key_message(
          outPtr,
          messageConstPtr.ref,
          addressConstPtr.ref,
          sessionStoreConstPtr.ref,
          identityStoreConstPtr.ref,
          preKeyStoreConstPtr.ref,
          signedPreKeyStoreConstPtr.ref,
          kyberPreKeyStoreConstPtr.ref,
        );
        FfiHelpers.checkError(error, 'signal_decrypt_pre_key_message');

        final plaintext = FfiHelpers.fromOwnedBuffer(outPtr.ref);

        // Save pending session update
        if (context.pendingSessionStore != null) {
          final newSession =
              SessionRecord.deserialize(context.pendingSessionStore!);
          await _sessionStore.storeSession(remoteAddress, newSession);
          newSession.dispose();
        }

        // Save pending identity update
        if (context.pendingIdentitySave != null) {
          final pending = context.pendingIdentitySave!;
          final publicKey = PublicKey.deserialize(pending.identityBytes);
          // Note: We don't dispose publicKey here - the store takes ownership
          await _identityKeyStore.saveIdentity(pending.address, publicKey);
        }

        // Remove used pre-key
        final preKeyToRemove = context.pendingPreKeyRemoval;
        if (preKeyToRemove != null) {
          await _preKeyStore.removePreKey(preKeyToRemove);
        }

        // Mark Kyber pre-key as used (optionally remove)
        final kyberPreKeyToMark = context.pendingKyberPreKeyRemoval;
        if (kyberPreKeyToMark != null) {
          await _kyberPreKeyStore.markKyberPreKeyUsed(kyberPreKeyToMark);
        }

        return plaintext;
      } finally {
        // Destroy the message
        final destroyPtr = calloc<SignalMutPointerPreKeySignalMessage>();
        destroyPtr.ref.raw = messagePtr.ref.raw;
        signal_pre_key_signal_message_destroy(destroyPtr.ref);
        calloc.free(destroyPtr);

        // Securely zero ciphertext before freeing
        LibSignalUtils.zeroBytes(ciphertextPtr.asTypedList(ciphertext.length));
        calloc.free(messagePtr);
        calloc.free(ciphertextPtr);
        calloc.free(ciphertextBuffer);
        calloc.free(sessionStorePtr);
        calloc.free(identityStorePtr);
        calloc.free(preKeyStorePtr);
        calloc.free(signedPreKeyStorePtr);
        calloc.free(kyberPreKeyStorePtr);
        calloc.free(sessionStoreConstPtr);
        calloc.free(identityStoreConstPtr);
        calloc.free(preKeyStoreConstPtr);
        calloc.free(signedPreKeyStoreConstPtr);
        calloc.free(kyberPreKeyStoreConstPtr);
        calloc.free(addressConstPtr);
        calloc.free(messageConstPtr);
        calloc.free(outPtr);
      }
    } finally {
      callbacks.close();
      context.clear();
    }
  }

  // ============================================
  // Helper methods to extract key IDs from message
  // ============================================

  /// Extracts pre-key ID from a serialized PreKeySignalMessage.
  ///
  /// Returns null if the message doesn't contain a one-time pre-key.
  int? _extractPreKeyId(Pointer<SignalMutPointerPreKeySignalMessage> messagePtr) {
    final idPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerPreKeySignalMessage>();
    constPtr.ref.raw = messagePtr.ref.raw;

    try {
      final error = signal_pre_key_signal_message_get_pre_key_id(idPtr, constPtr.ref);
      // If error occurs, the message might not have a pre-key (optional field)
      if (error != nullptr) {
        signal_error_free(error);
        return null;
      }
      return idPtr.value;
    } finally {
      calloc.free(idPtr);
      calloc.free(constPtr);
    }
  }

  /// Extracts signed pre-key ID from a serialized PreKeySignalMessage.
  int _extractSignedPreKeyId(Pointer<SignalMutPointerPreKeySignalMessage> messagePtr) {
    final idPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerPreKeySignalMessage>();
    constPtr.ref.raw = messagePtr.ref.raw;

    try {
      final error = signal_pre_key_signal_message_get_signed_pre_key_id(
        idPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_pre_key_signal_message_get_signed_pre_key_id');
      return idPtr.value;
    } finally {
      calloc.free(idPtr);
      calloc.free(constPtr);
    }
  }

  // ============================================
  // Helper methods to load specific keys
  // ============================================

  /// Loads a specific pre-key by ID and returns its serialized bytes.
  ///
  /// Note: This method should only be called after verifying that
  /// [_preKeyStore] is not null.
  Future<Uint8List?> _loadPreKeyById(int id) async {
    final preKeyStore = _preKeyStore;
    if (preKeyStore == null) return null;

    final record = await preKeyStore.loadPreKey(id);
    return record?.serialize();
  }

  /// Loads a specific signed pre-key by ID and returns its serialized bytes.
  ///
  /// Note: This method should only be called after verifying that
  /// [_signedPreKeyStore] is not null.
  Future<Uint8List?> _loadSignedPreKeyById(int id) async {
    final signedPreKeyStore = _signedPreKeyStore;
    if (signedPreKeyStore == null) return null;

    final record = await signedPreKeyStore.loadSignedPreKey(id);
    return record?.serialize();
  }

  /// Loads all Kyber pre-keys as a map of ID to serialized bytes.
  ///
  /// We load all Kyber keys because the ID is not directly available
  /// from the PreKeySignalMessage. Typically there are only a few
  /// Kyber pre-keys, so this is acceptable.
  ///
  /// Note: This method should only be called after verifying that
  /// [_kyberPreKeyStore] is not null.
  Future<Map<int, Uint8List>> _loadAllKyberPreKeys() async {
    final kyberStore = _kyberPreKeyStore;
    if (kyberStore == null) {
      return {};
    }

    final result = <int, Uint8List>{};
    final ids = await kyberStore.getAllKyberPreKeyIds();

    for (final id in ids) {
      final record = await kyberStore.loadKyberPreKey(id);
      if (record != null) {
        result[id] = record.serialize();
      }
    }

    return result;
  }
}
