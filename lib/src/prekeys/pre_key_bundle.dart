/// Pre-key bundle for Signal Protocol session establishment.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../keys/public_key.dart';
import '../kyber/kyber_public_key.dart';
import '../libsignal.dart';

/// Finalizer for PreKeyBundle.
final Finalizer<Pointer<SignalPreKeyBundle>> _preKeyBundleFinalizer = Finalizer(
  (ptr) {
    final mutPtr = calloc<SignalMutPointerPreKeyBundle>();
    mutPtr.ref.raw = ptr;
    signal_pre_key_bundle_destroy(mutPtr.ref);
    calloc.free(mutPtr);
  },
);

/// A pre-key bundle for Signal Protocol session establishment.
///
/// A pre-key bundle contains all the public keys and signatures needed
/// to establish a session with another user. It includes:
/// - Registration ID and device ID
/// - One-time pre-key (optional)
/// - Signed pre-key with signature
/// - Identity key
/// - Kyber pre-key for post-quantum security (optional)
///
/// Example:
/// ```dart
/// final bundle = PreKeyBundle.create(
///   registrationId: 12345,
///   deviceId: 1,
///   signedPreKeyId: 1,
///   signedPreKey: signedPublicKey,
///   signedPreKeySignature: signature,
///   identityKey: identityPublicKey,
/// );
/// ```
final class PreKeyBundle {
  final Pointer<SignalPreKeyBundle> _ptr;
  bool _disposed = false;

  PreKeyBundle._(this._ptr) {
    _preKeyBundleFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a PreKeyBundle from a raw pointer.
  factory PreKeyBundle.fromPointer(Pointer<SignalPreKeyBundle> ptr) {
    return PreKeyBundle._(ptr);
  }

  /// Creates a new pre-key bundle.
  ///
  /// Required parameters:
  /// - [registrationId]: The registration ID of the device
  /// - [deviceId]: The device ID
  /// - [signedPreKeyId]: The ID of the signed pre-key
  /// - [signedPreKey]: The signed pre-key public key
  /// - [signedPreKeySignature]: The signature over the signed pre-key
  /// - [identityKey]: The identity public key
  ///
  /// Optional parameters:
  /// - [preKeyId]: The ID of the one-time pre-key (0 if not present)
  /// - [preKey]: The one-time pre-key public key
  /// - [kyberPreKeyId]: The ID of the Kyber pre-key (0 if not present)
  /// - [kyberPreKey]: The Kyber pre-key public key
  /// - [kyberPreKeySignature]: The signature over the Kyber pre-key
  static PreKeyBundle create({
    required int registrationId,
    required int deviceId,
    int preKeyId = 0,
    PublicKey? preKey,
    required int signedPreKeyId,
    required PublicKey signedPreKey,
    required Uint8List signedPreKeySignature,
    required PublicKey identityKey,
    int kyberPreKeyId = 0,
    KyberPublicKey? kyberPreKey,
    Uint8List? kyberPreKeySignature,
  }) {
    LibSignal.ensureInitialized();

    final outPtr = calloc<SignalMutPointerPreKeyBundle>();

    // Pre-key (optional)
    final preKeyPtr = calloc<SignalConstPointerPublicKey>();
    if (preKey != null) {
      preKeyPtr.ref.raw = preKey.pointer;
    } else {
      preKeyPtr.ref.raw = nullptr;
    }

    // Signed pre-key
    final signedPreKeyPtr = calloc<SignalConstPointerPublicKey>();
    signedPreKeyPtr.ref.raw = signedPreKey.pointer;

    // Signed pre-key signature
    final signedPreKeySigPtr = calloc<Uint8>(signedPreKeySignature.length);
    signedPreKeySigPtr
        .asTypedList(signedPreKeySignature.length)
        .setAll(0, signedPreKeySignature);

    final signedPreKeySigBuffer = calloc<SignalBorrowedBuffer>();
    signedPreKeySigBuffer.ref.base = signedPreKeySigPtr.cast<UnsignedChar>();
    signedPreKeySigBuffer.ref.length = signedPreKeySignature.length;

    // Identity key
    final identityKeyPtr = calloc<SignalConstPointerPublicKey>();
    identityKeyPtr.ref.raw = identityKey.pointer;

    // Kyber pre-key (optional)
    final kyberPreKeyPtr = calloc<SignalConstPointerKyberPublicKey>();
    if (kyberPreKey != null) {
      kyberPreKeyPtr.ref.raw = kyberPreKey.pointer;
    } else {
      kyberPreKeyPtr.ref.raw = nullptr;
    }

    // Kyber pre-key signature
    // When kyberPreKey is null, we must also pass an empty/null signature
    // to indicate "no Kyber pre-key" to libsignal
    final kyberSig = kyberPreKeySignature ?? Uint8List(0);
    final kyberSigPtr = calloc<Uint8>(kyberSig.isEmpty ? 1 : kyberSig.length);
    if (kyberSig.isNotEmpty) {
      kyberSigPtr.asTypedList(kyberSig.length).setAll(0, kyberSig);
    }

    final kyberSigBuffer = calloc<SignalBorrowedBuffer>();
    // If no Kyber pre-key, set base to nullptr to indicate absence
    if (kyberPreKey == null) {
      kyberSigBuffer.ref.base = nullptr;
      kyberSigBuffer.ref.length = 0;
    } else {
      kyberSigBuffer.ref.base = kyberSigPtr.cast<UnsignedChar>();
      kyberSigBuffer.ref.length = kyberSig.length;
    }

    try {
      final error = signal_pre_key_bundle_new(
        outPtr,
        registrationId,
        deviceId,
        preKeyId,
        preKeyPtr.ref,
        signedPreKeyId,
        signedPreKeyPtr.ref,
        signedPreKeySigBuffer.ref,
        identityKeyPtr.ref,
        kyberPreKeyId,
        kyberPreKeyPtr.ref,
        kyberSigBuffer.ref,
      );
      FfiHelpers.checkError(error, 'signal_pre_key_bundle_new');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_pre_key_bundle_new');
      }

      return PreKeyBundle._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(preKeyPtr);
      calloc.free(signedPreKeyPtr);
      calloc.free(signedPreKeySigPtr);
      calloc.free(signedPreKeySigBuffer);
      calloc.free(identityKeyPtr);
      calloc.free(kyberPreKeyPtr);
      calloc.free(kyberSigPtr);
      calloc.free(kyberSigBuffer);
    }
  }

  /// Gets the registration ID.
  int get registrationId {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerPreKeyBundle>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_bundle_get_registration_id(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_pre_key_bundle_get_registration_id');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the device ID.
  int get deviceId {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerPreKeyBundle>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_bundle_get_device_id(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_pre_key_bundle_get_device_id');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the pre-key ID (0 if no one-time pre-key).
  int get preKeyId {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerPreKeyBundle>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_bundle_get_pre_key_id(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_pre_key_bundle_get_pre_key_id');

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the one-time pre-key public key.
  ///
  /// Returns null if no one-time pre-key is present.
  PublicKey? getPreKeyPublic() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPublicKey>();
    final constPtr = calloc<SignalConstPointerPreKeyBundle>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_bundle_get_pre_key_public(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_pre_key_bundle_get_pre_key_public');

      if (outPtr.ref.raw == nullptr) {
        return null;
      }

      return PublicKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the signed pre-key ID.
  int get signedPreKeyId {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerPreKeyBundle>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_bundle_get_signed_pre_key_id(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_pre_key_bundle_get_signed_pre_key_id',
      );

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the signed pre-key public key.
  PublicKey getSignedPreKeyPublic() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPublicKey>();
    final constPtr = calloc<SignalConstPointerPreKeyBundle>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_bundle_get_signed_pre_key_public(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_pre_key_bundle_get_signed_pre_key_public',
      );

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_pre_key_bundle_get_signed_pre_key_public',
        );
      }

      return PublicKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the signed pre-key signature.
  Uint8List get signedPreKeySignature {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerPreKeyBundle>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_bundle_get_signed_pre_key_signature(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_pre_key_bundle_get_signed_pre_key_signature',
      );

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the identity public key.
  PublicKey getIdentityKey() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPublicKey>();
    final constPtr = calloc<SignalConstPointerPreKeyBundle>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_bundle_get_identity_key(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(error, 'signal_pre_key_bundle_get_identity_key');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer(
          'signal_pre_key_bundle_get_identity_key',
        );
      }

      return PublicKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the Kyber pre-key ID (0 if no Kyber pre-key).
  int get kyberPreKeyId {
    _checkDisposed();

    final outPtr = calloc<Uint32>();
    final constPtr = calloc<SignalConstPointerPreKeyBundle>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_bundle_get_kyber_pre_key_id(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_pre_key_bundle_get_kyber_pre_key_id',
      );

      return outPtr.value;
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the Kyber pre-key public key.
  ///
  /// Returns null if no Kyber pre-key is present.
  KyberPublicKey? getKyberPreKeyPublic() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerKyberPublicKey>();
    final constPtr = calloc<SignalConstPointerPreKeyBundle>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_bundle_get_kyber_pre_key_public(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_pre_key_bundle_get_kyber_pre_key_public',
      );

      if (outPtr.ref.raw == nullptr) {
        return null;
      }

      return KyberPublicKey.fromPointer(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Gets the Kyber pre-key signature.
  ///
  /// Returns empty if no Kyber pre-key is present.
  Uint8List get kyberPreKeySignature {
    _checkDisposed();

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerPreKeyBundle>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_bundle_get_kyber_pre_key_signature(
        outPtr,
        constPtr.ref,
      );
      FfiHelpers.checkError(
        error,
        'signal_pre_key_bundle_get_kyber_pre_key_signature',
      );

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Creates a copy of this pre-key bundle.
  PreKeyBundle clone() {
    _checkDisposed();

    final outPtr = calloc<SignalMutPointerPreKeyBundle>();
    final constPtr = calloc<SignalConstPointerPreKeyBundle>();
    constPtr.ref.raw = _ptr;

    try {
      final error = signal_pre_key_bundle_clone(outPtr, constPtr.ref);
      FfiHelpers.checkError(error, 'signal_pre_key_bundle_clone');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_pre_key_bundle_clone');
      }

      return PreKeyBundle._(outPtr.ref.raw);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
    }
  }

  /// Returns the raw pointer.
  Pointer<SignalPreKeyBundle> get pointer {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('PreKeyBundle');
    }
  }

  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _preKeyBundleFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerPreKeyBundle>();
      mutPtr.ref.raw = _ptr;
      signal_pre_key_bundle_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  bool get isDisposed => _disposed;
}
