/// Sealed sender cipher for Signal Protocol anonymous messaging.
///
/// Uses NativeCallable.isolateLocal for FFI callbacks.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart' as bindings;
import '../bindings/libsignal_bindings.dart' show
    SignalBorrowedBuffer,
    SignalConstPointerCiphertextMessage,
    SignalConstPointerFfiIdentityKeyStoreStruct,
    SignalConstPointerFfiPreKeyStoreStruct,
    SignalConstPointerFfiSessionStoreStruct,
    SignalConstPointerFfiSignedPreKeyStoreStruct,
    SignalConstPointerPreKeyRecord,
    SignalConstPointerPrivateKey,
    SignalConstPointerProtocolAddress,
    SignalConstPointerPublicKey,
    SignalConstPointerSenderCertificate,
    SignalConstPointerSessionRecord,
    SignalConstPointerSignedPreKeyRecord,
    SignalConstPointerUnidentifiedSenderMessageContent,
    SignalGetIdentityKeyFunction,
    SignalGetIdentityKeyPairFunction,
    SignalGetLocalRegistrationIdFunction,
    SignalIdentityKeyStore,
    SignalIsTrustedIdentityFunction,
    SignalLoadPreKeyFunction,
    SignalLoadSessionFunction,
    SignalLoadSignedPreKeyFunction,
    SignalMutPointerCiphertextMessage,
    SignalMutPointerPreKeyRecord,
    SignalMutPointerPrivateKey,
    SignalMutPointerPublicKey,
    SignalMutPointerSessionRecord,
    SignalMutPointerSignedPreKeyRecord,
    SignalMutPointerUnidentifiedSenderMessageContent,
    SignalOwnedBuffer,
    SignalPreKeyStore,
    SignalRemovePreKeyFunction,
    SignalSaveIdentityKeyFunction,
    SignalSessionStore,
    SignalSignedPreKeyStore,
    SignalStorePreKeyFunction,
    SignalStoreSessionFunction,
    SignalStoreSignedPreKeyFunction;
import '../exception.dart';
import '../ffi_helpers.dart';
import '../keys/identity_key_pair.dart';
import '../keys/public_key.dart';
import '../libsignal.dart';
import '../protocol/protocol_address.dart';
import '../protocol/session_record.dart';
import '../stores/identity_key_store.dart';
import '../stores/pre_key_store.dart';
import '../stores/session_store.dart';
import '../stores/signed_pre_key_store.dart';
import 'sender_certificate.dart';
import 'unidentified_sender_message_content.dart';

/// Result of sealed sender decryption.
class SealedSenderDecryptionResult {
  /// The decrypted plaintext.
  final Uint8List plaintext;

  /// The sender's E164 phone number (may be null).
  final String? senderE164;

  /// The sender's UUID.
  final String senderUuid;

  /// The sender's device ID.
  final int senderDeviceId;

  const SealedSenderDecryptionResult({
    required this.plaintext,
    required this.senderE164,
    required this.senderUuid,
    required this.senderDeviceId,
  });
}

/// Context for sealed sender encryption callbacks.
class _SealedSenderEncryptContext {
  final IdentityKeyPair identityKeyPair;
  final int localRegistrationId;
  Uint8List? sessionRecordBytes;
  Uint8List? pendingSessionStore;
  Uint8List? remoteIdentityBytes;
  ({ProtocolAddress address, Uint8List identityBytes})? pendingIdentitySave;
  final ProtocolAddress address;

  _SealedSenderEncryptContext({
    required this.identityKeyPair,
    required this.localRegistrationId,
    required this.address,
    this.sessionRecordBytes,
    this.remoteIdentityBytes,
  });
}

/// Context for sealed sender decryption callbacks.
class _SealedSenderDecryptContext {
  final IdentityKeyPair identityKeyPair;
  final int localRegistrationId;

  // Session state
  final Map<String, Uint8List> sessions;
  final Map<String, Uint8List> pendingSessionStores = {};

  // Identity state
  final Map<String, Uint8List> identities;
  final Map<String, Uint8List> pendingIdentitySaves = {};

  // Pre-key stores
  final Map<int, Uint8List> preKeys;
  final Map<int, Uint8List> signedPreKeys;

  // Pending removals
  int? pendingPreKeyRemoval;

  _SealedSenderDecryptContext({
    required this.identityKeyPair,
    required this.localRegistrationId,
    this.sessions = const {},
    this.identities = const {},
    this.preKeys = const {},
    this.signedPreKeys = const {},
  });

  String _addressKey(String name, int deviceId) => '$name:$deviceId';
}

/// Callbacks for sealed sender encryption.
class _SealedSenderEncryptCallbacks {
  final _SealedSenderEncryptContext _context;

  late final NativeCallable<SignalLoadSessionFunction> _loadSession;
  late final NativeCallable<SignalStoreSessionFunction> _storeSession;
  late final NativeCallable<SignalGetIdentityKeyPairFunction>
      _getIdentityKeyPair;
  late final NativeCallable<SignalGetLocalRegistrationIdFunction>
      _getLocalRegistrationId;
  late final NativeCallable<SignalSaveIdentityKeyFunction> _saveIdentity;
  late final NativeCallable<SignalGetIdentityKeyFunction> _getIdentity;
  late final NativeCallable<SignalIsTrustedIdentityFunction> _isTrustedIdentity;

  _SealedSenderEncryptCallbacks(this._context) {
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
        final error = bindings.signal_session_record_deserialize(outPtr, buffer.ref);
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
        final error = bindings.signal_session_record_serialize(outPtr, record);
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
        final error = bindings.signal_privatekey_clone(outPtr, constPtr.ref);
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
        final error = bindings.signal_publickey_serialize(outPtr, publicKey);
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
        final error = bindings.signal_publickey_deserialize(outPtr, buffer.ref);
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
        final error = bindings.signal_publickey_serialize(outPtr, publicKey);
        if (error != nullptr) return 0;

        final incomingBytes = FfiHelpers.fromOwnedBuffer(outPtr.ref);
        if (storedBytes.length != incomingBytes.length) return 0;

        for (var i = 0; i < storedBytes.length; i++) {
          if (storedBytes[i] != incomingBytes[i]) return 0;
        }
        return 1;
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

/// Callbacks for sealed sender decryption.
class _SealedSenderDecryptCallbacks {
  final _SealedSenderDecryptContext _context;

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

  _SealedSenderDecryptCallbacks(this._context) {
    _initializeSessionCallbacks();
    _initializeIdentityCallbacks();
    _initializePreKeyCallbacks();
    _initializeSignedPreKeyCallbacks();
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

  // Session callbacks

  int _loadSessionCallback(
    Pointer<Void> ctx,
    Pointer<SignalMutPointerSessionRecord> recordp,
    SignalConstPointerProtocolAddress address,
  ) {
    try {
      // Get address name and device ID
      final namePtr = calloc<Pointer<Char>>();
      final devicePtr = calloc<Uint32>();

      try {
        bindings.signal_address_get_name(namePtr, address);
        bindings.signal_address_get_device_id(devicePtr, address);

        final name = namePtr.value.cast<Utf8>().toDartString();
        final deviceId = devicePtr.value;
        final key = _context._addressKey(name, deviceId);

        bindings.signal_free_string(namePtr.value);

        final sessionBytes = _context.sessions[key];
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
          final error = bindings.signal_session_record_deserialize(outPtr, buffer.ref);
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
      } finally {
        calloc.free(namePtr);
        calloc.free(devicePtr);
      }
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

      final namePtr = calloc<Pointer<Char>>();
      final devicePtr = calloc<Uint32>();

      try {
        bindings.signal_address_get_name(namePtr, address);
        bindings.signal_address_get_device_id(devicePtr, address);

        final name = namePtr.value.cast<Utf8>().toDartString();
        final deviceId = devicePtr.value;
        final key = _context._addressKey(name, deviceId);

        bindings.signal_free_string(namePtr.value);

        final outPtr = calloc<SignalOwnedBuffer>();
        try {
          final error = bindings.signal_session_record_serialize(outPtr, record);
          if (error == nullptr) {
            _context.pendingSessionStores[key] =
                FfiHelpers.fromOwnedBuffer(outPtr.ref);
          }
        } finally {
          calloc.free(outPtr);
        }
        return 0;
      } finally {
        calloc.free(namePtr);
        calloc.free(devicePtr);
      }
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
        final error = bindings.signal_privatekey_clone(outPtr, constPtr.ref);
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

      final namePtr = calloc<Pointer<Char>>();
      final devicePtr = calloc<Uint32>();

      try {
        bindings.signal_address_get_name(namePtr, address);
        bindings.signal_address_get_device_id(devicePtr, address);

        final name = namePtr.value.cast<Utf8>().toDartString();
        final deviceId = devicePtr.value;
        final key = _context._addressKey(name, deviceId);

        bindings.signal_free_string(namePtr.value);

        final outPtr = calloc<SignalOwnedBuffer>();
        try {
          final error = bindings.signal_publickey_serialize(outPtr, publicKey);
          if (error == nullptr) {
            _context.pendingIdentitySaves[key] =
                FfiHelpers.fromOwnedBuffer(outPtr.ref);
          }
        } finally {
          calloc.free(outPtr);
        }
        return 0;
      } finally {
        calloc.free(namePtr);
        calloc.free(devicePtr);
      }
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
      final namePtr = calloc<Pointer<Char>>();
      final devicePtr = calloc<Uint32>();

      try {
        bindings.signal_address_get_name(namePtr, address);
        bindings.signal_address_get_device_id(devicePtr, address);

        final name = namePtr.value.cast<Utf8>().toDartString();
        final deviceId = devicePtr.value;
        final key = _context._addressKey(name, deviceId);

        bindings.signal_free_string(namePtr.value);

        final identityBytes = _context.identities[key];
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
          final error = bindings.signal_publickey_deserialize(outPtr, buffer.ref);
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
      } finally {
        calloc.free(namePtr);
        calloc.free(devicePtr);
      }
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
      final namePtr = calloc<Pointer<Char>>();
      final devicePtr = calloc<Uint32>();

      try {
        bindings.signal_address_get_name(namePtr, address);
        bindings.signal_address_get_device_id(devicePtr, address);

        final name = namePtr.value.cast<Utf8>().toDartString();
        final deviceId = devicePtr.value;
        final key = _context._addressKey(name, deviceId);

        bindings.signal_free_string(namePtr.value);

        final storedBytes = _context.identities[key];
        if (storedBytes == null) return 1;

        final outPtr = calloc<SignalOwnedBuffer>();
        try {
          final error = bindings.signal_publickey_serialize(outPtr, publicKey);
          if (error != nullptr) return 0;

          final incomingBytes = FfiHelpers.fromOwnedBuffer(outPtr.ref);
          if (storedBytes.length != incomingBytes.length) return 0;

          for (var i = 0; i < storedBytes.length; i++) {
            if (storedBytes[i] != incomingBytes[i]) return 0;
          }
          return 1;
        } finally {
          calloc.free(outPtr);
        }
      } finally {
        calloc.free(namePtr);
        calloc.free(devicePtr);
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
        final error = bindings.signal_pre_key_record_deserialize(outPtr, buffer.ref);
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
    // Not implemented for sealed sender - pre-keys are not stored during decrypt
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
            bindings.signal_signed_pre_key_record_deserialize(outPtr, buffer.ref);
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
    // Not implemented for sealed sender
    return 0;
  }

  // Store creators

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
  }
}

/// Sealed sender cipher for anonymous message sending.
///
/// Sealed sender allows sending messages where the server cannot determine
/// the sender. The recipient can decrypt the message and learn the sender's
/// identity from the embedded sender certificate.
///
/// Example:
/// ```dart
/// final cipher = SealedSessionCipher(
///   sessionStore: mySessionStore,
///   identityKeyStore: myIdentityKeyStore,
///   preKeyStore: myPreKeyStore,
///   signedPreKeyStore: mySignedPreKeyStore,
/// );
///
/// // Encrypt a message
/// final sealed = await cipher.encrypt(
///   destination,
///   Uint8List.fromList(utf8.encode('Hello!')),
///   senderCertificate,
/// );
///
/// // Decrypt a received message
/// final result = await cipher.decrypt(
///   sealedMessage,
///   trustRoot: serverTrustRoot,
///   timestamp: DateTime.now(),
///   localUuid: myUuid,
///   localDeviceId: myDeviceId,
/// );
/// print('From: ${result.senderUuid}');
/// print('Message: ${utf8.decode(result.plaintext)}');
/// ```
class SealedSessionCipher {
  final SessionStore _sessionStore;
  final IdentityKeyStore _identityKeyStore;
  final PreKeyStore? _preKeyStore;
  final SignedPreKeyStore? _signedPreKeyStore;

  /// Creates a sealed sender cipher.
  ///
  /// The [sessionStore] and [identityKeyStore] are required.
  /// The [preKeyStore] and [signedPreKeyStore] are needed for decryption
  /// of PreKeySignalMessages.
  SealedSessionCipher({
    required SessionStore sessionStore,
    required IdentityKeyStore identityKeyStore,
    PreKeyStore? preKeyStore,
    SignedPreKeyStore? signedPreKeyStore,
  })  : _sessionStore = sessionStore,
        _identityKeyStore = identityKeyStore,
        _preKeyStore = preKeyStore,
        _signedPreKeyStore = signedPreKeyStore {
    LibSignal.ensureInitialized();
  }

  /// Encrypts a message using sealed sender.
  ///
  /// This is a high-level API that:
  /// 1. Encrypts the [plaintext] using the existing session with [destination]
  /// 2. Wraps the encrypted message in an [UnidentifiedSenderMessageContent]
  /// 3. Encrypts the USMC for anonymous delivery
  ///
  /// The [senderCertificate] proves the sender's identity to the recipient.
  /// The [contentHint] indicates how to handle the message if decryption fails.
  /// The [groupId] is set if this is a group message.
  ///
  /// An existing session must exist with [destination].
  Future<Uint8List> encrypt(
    ProtocolAddress destination,
    Uint8List plaintext,
    SenderCertificate senderCertificate, {
    int contentHint = ContentHint.none,
    Uint8List? groupId,
  }) async {
    senderCertificate.pointer; // Check not disposed

    // Pre-load data
    final existingSession = await _sessionStore.loadSession(destination);
    if (existingSession == null) {
      throw LibSignalException(
        'No session found for $destination',
        context: 'SealedSessionCipher.encrypt',
      );
    }

    final identityKeyPair = await _identityKeyStore.getIdentityKeyPair();
    final localRegistrationId = await _identityKeyStore.getLocalRegistrationId();
    final existingIdentity = await _identityKeyStore.getIdentity(destination);

    // Serialize before creating context - stores may return shared references
    final sessionBytes = existingSession.serialize();
    final identityBytes = existingIdentity?.serialize();

    final context = _SealedSenderEncryptContext(
      identityKeyPair: identityKeyPair,
      localRegistrationId: localRegistrationId,
      address: destination,
      sessionRecordBytes: sessionBytes,
      remoteIdentityBytes: identityBytes,
    );

    final callbacks = _SealedSenderEncryptCallbacks(context);

    try {
      // Create stores
      final sessionStorePtr = callbacks.createSessionStore();
      final identityStorePtr = callbacks.createIdentityStore();

      final sessionStoreConstPtr =
          calloc<SignalConstPointerFfiSessionStoreStruct>();
      sessionStoreConstPtr.ref.raw = sessionStorePtr;

      final identityStoreConstPtr =
          calloc<SignalConstPointerFfiIdentityKeyStoreStruct>();
      identityStoreConstPtr.ref.raw = identityStorePtr;

      final addressConstPtr = calloc<SignalConstPointerProtocolAddress>();
      addressConstPtr.ref.raw = destination.pointer;

      final plaintextPtr = calloc<Uint8>(plaintext.length);
      plaintextPtr.asTypedList(plaintext.length).setAll(0, plaintext);

      final plaintextBuffer = calloc<SignalBorrowedBuffer>();
      plaintextBuffer.ref.base = plaintextPtr.cast<UnsignedChar>();
      plaintextBuffer.ref.length = plaintext.length;

      final ciphertextOutPtr = calloc<SignalMutPointerCiphertextMessage>();
      final now = DateTime.now().millisecondsSinceEpoch;

      try {
        // Step 1: Encrypt the message using session
        final encryptError = bindings.signal_encrypt_message(
          ciphertextOutPtr,
          plaintextBuffer.ref,
          addressConstPtr.ref,
          sessionStoreConstPtr.ref,
          identityStoreConstPtr.ref,
          now,
        );
        FfiHelpers.checkError(encryptError, 'bindings.signal_encrypt_message');

        if (ciphertextOutPtr.ref.raw == nullptr) {
          throw LibSignalException.nullPointer('bindings.signal_encrypt_message');
        }

        // Step 2: Create USMC from ciphertext + sender certificate
        final ciphertextConstPtr =
            calloc<SignalConstPointerCiphertextMessage>();
        ciphertextConstPtr.ref.raw = ciphertextOutPtr.ref.raw;

        final senderCertConstPtr =
            calloc<SignalConstPointerSenderCertificate>();
        senderCertConstPtr.ref.raw = senderCertificate.pointer;

        final groupIdPtr = groupId != null ? calloc<Uint8>(groupId.length) : null;
        if (groupId != null) {
          groupIdPtr!.asTypedList(groupId.length).setAll(0, groupId);
        }

        final groupIdBuffer = calloc<SignalBorrowedBuffer>();
        if (groupId != null) {
          groupIdBuffer.ref.base = groupIdPtr!.cast<UnsignedChar>();
          groupIdBuffer.ref.length = groupId.length;
        } else {
          groupIdBuffer.ref.base = nullptr;
          groupIdBuffer.ref.length = 0;
        }

        final usmcOutPtr =
            calloc<SignalMutPointerUnidentifiedSenderMessageContent>();

        try {
          final usmcError = bindings.signal_unidentified_sender_message_content_new(
            usmcOutPtr,
            ciphertextConstPtr.ref,
            senderCertConstPtr.ref,
            contentHint,
            groupIdBuffer.ref,
          );
          FfiHelpers.checkError(
            usmcError,
            'bindings.signal_unidentified_sender_message_content_new',
          );

          if (usmcOutPtr.ref.raw == nullptr) {
            throw LibSignalException.nullPointer(
              'bindings.signal_unidentified_sender_message_content_new',
            );
          }

          // Step 3: Encrypt USMC using sealed sender
          final usmcConstPtr =
              calloc<SignalConstPointerUnidentifiedSenderMessageContent>();
          usmcConstPtr.ref.raw = usmcOutPtr.ref.raw;

          final sealedOutPtr = calloc<SignalOwnedBuffer>();

          try {
            final sealedError = bindings.signal_sealed_session_cipher_encrypt(
              sealedOutPtr,
              addressConstPtr.ref,
              usmcConstPtr.ref,
              identityStoreConstPtr.ref,
            );
            FfiHelpers.checkError(
              sealedError,
              'signal_sealed_session_cipher_encrypt',
            );

            final sealedBytes = FfiHelpers.fromOwnedBuffer(sealedOutPtr.ref);

            // Save pending session update
            if (context.pendingSessionStore != null) {
              final newSession =
                  SessionRecord.deserialize(context.pendingSessionStore!);
              await _sessionStore.storeSession(destination, newSession);
              newSession.dispose();
            }

            // Save pending identity
            if (context.pendingIdentitySave != null) {
              final identity =
                  PublicKey.deserialize(context.pendingIdentitySave!.identityBytes);
              await _identityKeyStore.saveIdentity(
                context.pendingIdentitySave!.address,
                identity,
              );
              identity.dispose();
            }

            return sealedBytes;
          } finally {
            calloc.free(usmcConstPtr);
            calloc.free(sealedOutPtr);
          }
        } finally {
          // Destroy USMC
          final usmcDestroyPtr =
              calloc<SignalMutPointerUnidentifiedSenderMessageContent>();
          usmcDestroyPtr.ref.raw = usmcOutPtr.ref.raw;
          bindings.signal_unidentified_sender_message_content_destroy(
            usmcDestroyPtr.ref,
          );
          calloc.free(usmcDestroyPtr);

          calloc.free(ciphertextConstPtr);
          calloc.free(senderCertConstPtr);
          if (groupIdPtr != null) calloc.free(groupIdPtr);
          calloc.free(groupIdBuffer);
          calloc.free(usmcOutPtr);
        }
      } finally {
        // Destroy ciphertext message
        final destroyPtr = calloc<SignalMutPointerCiphertextMessage>();
        destroyPtr.ref.raw = ciphertextOutPtr.ref.raw;
        bindings.signal_ciphertext_message_destroy(destroyPtr.ref);
        calloc.free(destroyPtr);

        calloc.free(sessionStorePtr);
        calloc.free(identityStorePtr);
        calloc.free(sessionStoreConstPtr);
        calloc.free(identityStoreConstPtr);
        calloc.free(addressConstPtr);
        calloc.free(plaintextPtr);
        calloc.free(plaintextBuffer);
        calloc.free(ciphertextOutPtr);
      }
    } finally {
      callbacks.close();
    }
  }

  /// Decrypts a sealed sender message.
  ///
  /// Returns the decrypted plaintext along with sender information.
  ///
  /// The [trustRoot] is used to validate the sender certificate.
  /// The [timestamp] is used for certificate expiration checking.
  /// The [localUuid] and [localDeviceId] identify the recipient.
  /// The [localE164] is the recipient's phone number (optional).
  Future<SealedSenderDecryptionResult> decrypt(
    Uint8List ciphertext, {
    required PublicKey trustRoot,
    required DateTime timestamp,
    String? localE164,
    required String localUuid,
    required int localDeviceId,
  }) async {
    trustRoot.pointer; // Check not disposed

    // Pre-load all data
    final identityKeyPair = await _identityKeyStore.getIdentityKeyPair();
    final localRegistrationId = await _identityKeyStore.getLocalRegistrationId();

    // Pre-load sessions - we need to load all sessions the sender might use
    final sessions = <String, Uint8List>{};
    final identities = <String, Uint8List>{};
    final preKeys = <int, Uint8List>{};
    final signedPreKeys = <int, Uint8List>{};

    // Load all pre-keys if store is available
    if (_preKeyStore != null) {
      final allPreKeyIds = await _preKeyStore.getAllPreKeyIds();
      for (final id in allPreKeyIds) {
        final preKey = await _preKeyStore.loadPreKey(id);
        if (preKey != null) {
          preKeys[id] = preKey.serialize();
          preKey.dispose();
        }
      }
    }

    // Load all signed pre-keys if store is available
    if (_signedPreKeyStore != null) {
      final allSignedPreKeyIds = await _signedPreKeyStore.getAllSignedPreKeyIds();
      for (final id in allSignedPreKeyIds) {
        final signedPreKey = await _signedPreKeyStore.loadSignedPreKey(id);
        if (signedPreKey != null) {
          signedPreKeys[id] = signedPreKey.serialize();
          signedPreKey.dispose();
        }
      }
    }

    final context = _SealedSenderDecryptContext(
      identityKeyPair: identityKeyPair,
      localRegistrationId: localRegistrationId,
      sessions: sessions,
      identities: identities,
      preKeys: preKeys,
      signedPreKeys: signedPreKeys,
    );

    final callbacks = _SealedSenderDecryptCallbacks(context);

    try {
      final sessionStorePtr = callbacks.createSessionStore();
      final identityStorePtr = callbacks.createIdentityStore();
      final preKeyStorePtr = callbacks.createPreKeyStore();
      final signedPreKeyStorePtr = callbacks.createSignedPreKeyStore();

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

      final trustRootConstPtr = calloc<SignalConstPointerPublicKey>();
      trustRootConstPtr.ref.raw = trustRoot.pointer;

      final ctextPtr = calloc<Uint8>(ciphertext.length);
      ctextPtr.asTypedList(ciphertext.length).setAll(0, ciphertext);

      final ctextBuffer = calloc<SignalBorrowedBuffer>();
      ctextBuffer.ref.base = ctextPtr.cast<UnsignedChar>();
      ctextBuffer.ref.length = ciphertext.length;

      final localUuidPtr = localUuid.toNativeUtf8().cast<Char>();
      final localE164Ptr =
          localE164 != null ? localE164.toNativeUtf8().cast<Char>() : nullptr;

      final outPtr = calloc<SignalOwnedBuffer>();
      final senderE164Ptr = calloc<Pointer<Char>>();
      final senderUuidPtr = calloc<Pointer<Char>>();
      final senderDeviceIdPtr = calloc<Uint32>();

      try {
        final error = bindings.signal_sealed_session_cipher_decrypt(
          outPtr,
          senderE164Ptr,
          senderUuidPtr,
          senderDeviceIdPtr,
          ctextBuffer.ref,
          trustRootConstPtr.ref,
          timestamp.millisecondsSinceEpoch,
          localE164Ptr,
          localUuidPtr,
          localDeviceId,
          sessionStoreConstPtr.ref,
          identityStoreConstPtr.ref,
          preKeyStoreConstPtr.ref,
          signedPreKeyStoreConstPtr.ref,
        );
        FfiHelpers.checkError(error, 'signal_sealed_session_cipher_decrypt');

        final plaintext = FfiHelpers.fromOwnedBuffer(outPtr.ref);

        String? senderE164;
        if (senderE164Ptr.value != nullptr) {
          senderE164 = senderE164Ptr.value.cast<Utf8>().toDartString();
          bindings.signal_free_string(senderE164Ptr.value);
        }

        final senderUuid = senderUuidPtr.value.cast<Utf8>().toDartString();
        bindings.signal_free_string(senderUuidPtr.value);

        final senderDeviceId = senderDeviceIdPtr.value;

        // Save pending sessions
        for (final entry in context.pendingSessionStores.entries) {
          final parts = entry.key.split(':');
          final name = parts[0];
          final deviceId = int.parse(parts[1]);
          final address = ProtocolAddress(name, deviceId);
          final session = SessionRecord.deserialize(entry.value);
          await _sessionStore.storeSession(address, session);
          session.dispose();
          address.dispose();
        }

        // Save pending identities
        for (final entry in context.pendingIdentitySaves.entries) {
          final parts = entry.key.split(':');
          final name = parts[0];
          final deviceId = int.parse(parts[1]);
          final address = ProtocolAddress(name, deviceId);
          final identity = PublicKey.deserialize(entry.value);
          await _identityKeyStore.saveIdentity(address, identity);
          identity.dispose();
          address.dispose();
        }

        // Remove used pre-key
        if (context.pendingPreKeyRemoval != null) {
          await _preKeyStore?.removePreKey(context.pendingPreKeyRemoval!);
        }

        return SealedSenderDecryptionResult(
          plaintext: plaintext,
          senderE164: senderE164,
          senderUuid: senderUuid,
          senderDeviceId: senderDeviceId,
        );
      } finally {
        calloc.free(sessionStorePtr);
        calloc.free(identityStorePtr);
        calloc.free(preKeyStorePtr);
        calloc.free(signedPreKeyStorePtr);
        calloc.free(sessionStoreConstPtr);
        calloc.free(identityStoreConstPtr);
        calloc.free(preKeyStoreConstPtr);
        calloc.free(signedPreKeyStoreConstPtr);
        calloc.free(trustRootConstPtr);
        calloc.free(ctextPtr);
        calloc.free(ctextBuffer);
        calloc.free(localUuidPtr);
        if (localE164Ptr != nullptr) calloc.free(localE164Ptr);
        calloc.free(outPtr);
        calloc.free(senderE164Ptr);
        calloc.free(senderUuidPtr);
        calloc.free(senderDeviceIdPtr);
      }
    } finally {
      callbacks.close();
    }
  }

  /// Decrypts a sealed sender message to USMC without full decryption.
  ///
  /// This can be used to inspect the sender certificate and message type
  /// before performing full decryption.
  Future<UnidentifiedSenderMessageContent> decryptToUsmc(
    Uint8List ciphertext,
  ) async {
    final identityKeyPair = await _identityKeyStore.getIdentityKeyPair();
    final localRegistrationId = await _identityKeyStore.getLocalRegistrationId();

    final context = _SealedSenderDecryptContext(
      identityKeyPair: identityKeyPair,
      localRegistrationId: localRegistrationId,
    );

    final callbacks = _SealedSenderDecryptCallbacks(context);

    try {
      final identityStorePtr = callbacks.createIdentityStore();

      final identityStoreConstPtr =
          calloc<SignalConstPointerFfiIdentityKeyStoreStruct>();
      identityStoreConstPtr.ref.raw = identityStorePtr;

      final ctextPtr = calloc<Uint8>(ciphertext.length);
      ctextPtr.asTypedList(ciphertext.length).setAll(0, ciphertext);

      final ctextBuffer = calloc<SignalBorrowedBuffer>();
      ctextBuffer.ref.base = ctextPtr.cast<UnsignedChar>();
      ctextBuffer.ref.length = ciphertext.length;

      final outPtr =
          calloc<SignalMutPointerUnidentifiedSenderMessageContent>();

      try {
        final error = bindings.signal_sealed_session_cipher_decrypt_to_usmc(
          outPtr,
          ctextBuffer.ref,
          identityStoreConstPtr.ref,
        );
        FfiHelpers.checkError(
          error,
          'signal_sealed_session_cipher_decrypt_to_usmc',
        );

        if (outPtr.ref.raw == nullptr) {
          throw LibSignalException.nullPointer(
            'signal_sealed_session_cipher_decrypt_to_usmc',
          );
        }

        return UnidentifiedSenderMessageContent.fromPointer(outPtr.ref.raw);
      } finally {
        calloc.free(identityStorePtr);
        calloc.free(identityStoreConstPtr);
        calloc.free(ctextPtr);
        calloc.free(ctextBuffer);
        calloc.free(outPtr);
      }
    } finally {
      callbacks.close();
    }
  }
}
