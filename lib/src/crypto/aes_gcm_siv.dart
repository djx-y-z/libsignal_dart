/// AES-256-GCM-SIV encryption for Signal Protocol.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../libsignal.dart';

/// Finalizer for Aes256GcmSiv.
final Finalizer<Pointer<SignalAes256GcmSiv>> _aes256GcmSivFinalizer =
    Finalizer((ptr) {
  final mutPtr = calloc<SignalMutPointerAes256GcmSiv>();
  mutPtr.ref.raw = ptr;
  signal_aes256_gcm_siv_destroy(mutPtr.ref);
  calloc.free(mutPtr);
});

/// AES-256-GCM-SIV encryption/decryption.
///
/// AES-GCM-SIV is a nonce-misuse resistant AEAD (Authenticated Encryption
/// with Associated Data). It provides strong security guarantees even if
/// a nonce is accidentally reused.
///
/// Example:
/// ```dart
/// // Create a cipher with a 32-byte key
/// final cipher = Aes256GcmSiv(key);
///
/// // Encrypt with a 12-byte nonce
/// final ciphertext = cipher.encrypt(
///   plaintext: data,
///   nonce: nonce,
///   associatedData: aad,
/// );
///
/// // Decrypt
/// final decrypted = cipher.decrypt(
///   ciphertext: ciphertext,
///   nonce: nonce,
///   associatedData: aad,
/// );
///
/// cipher.dispose();
/// ```
final class Aes256GcmSiv {
  final Pointer<SignalAes256GcmSiv> _ptr;
  bool _disposed = false;

  Aes256GcmSiv._(this._ptr) {
    _aes256GcmSivFinalizer.attach(this, _ptr, detach: this);
  }

  /// Creates a new AES-256-GCM-SIV cipher with the given key.
  ///
  /// The [key] must be exactly 32 bytes (256 bits).
  factory Aes256GcmSiv(Uint8List key) {
    LibSignal.ensureInitialized();

    if (key.length != 32) {
      throw LibSignalException.invalidArgument(
        'key',
        'Must be 32 bytes (256 bits)',
      );
    }

    final keyPtr = calloc<Uint8>(key.length);
    keyPtr.asTypedList(key.length).setAll(0, key);

    final keyBuffer = calloc<SignalBorrowedBuffer>();
    keyBuffer.ref.base = keyPtr.cast<UnsignedChar>();
    keyBuffer.ref.length = key.length;

    final outPtr = calloc<SignalMutPointerAes256GcmSiv>();

    try {
      final error = signal_aes256_gcm_siv_new(outPtr, keyBuffer.ref);
      FfiHelpers.checkError(error, 'signal_aes256_gcm_siv_new');

      if (outPtr.ref.raw == nullptr) {
        throw LibSignalException.nullPointer('signal_aes256_gcm_siv_new');
      }

      return Aes256GcmSiv._(outPtr.ref.raw);
    } finally {
      calloc.free(keyPtr);
      calloc.free(keyBuffer);
      calloc.free(outPtr);
    }
  }

  /// Encrypts data with associated data and a nonce.
  ///
  /// Parameters:
  /// - [plaintext]: The data to encrypt
  /// - [nonce]: A 12-byte nonce (should be unique for each encryption)
  /// - [associatedData]: Additional authenticated data (not encrypted)
  ///
  /// Returns the ciphertext with authentication tag appended.
  Uint8List encrypt({
    required Uint8List plaintext,
    required Uint8List nonce,
    Uint8List? associatedData,
  }) {
    _checkDisposed();

    if (nonce.length != 12) {
      throw LibSignalException.invalidArgument('nonce', 'Must be 12 bytes');
    }

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerAes256GcmSiv>();
    constPtr.ref.raw = _ptr;

    final ptextPtr = calloc<Uint8>(plaintext.length);
    ptextPtr.asTypedList(plaintext.length).setAll(0, plaintext);
    final ptextBuffer = calloc<SignalBorrowedBuffer>();
    ptextBuffer.ref.base = ptextPtr.cast<UnsignedChar>();
    ptextBuffer.ref.length = plaintext.length;

    final noncePtr = calloc<Uint8>(nonce.length);
    noncePtr.asTypedList(nonce.length).setAll(0, nonce);
    final nonceBuffer = calloc<SignalBorrowedBuffer>();
    nonceBuffer.ref.base = noncePtr.cast<UnsignedChar>();
    nonceBuffer.ref.length = nonce.length;

    final aad = associatedData ?? Uint8List(0);
    final aadPtr = calloc<Uint8>(aad.length);
    if (aad.isNotEmpty) {
      aadPtr.asTypedList(aad.length).setAll(0, aad);
    }
    final aadBuffer = calloc<SignalBorrowedBuffer>();
    aadBuffer.ref.base = aadPtr.cast<UnsignedChar>();
    aadBuffer.ref.length = aad.length;

    try {
      final error = signal_aes256_gcm_siv_encrypt(
        outPtr,
        constPtr.ref,
        ptextBuffer.ref,
        nonceBuffer.ref,
        aadBuffer.ref,
      );
      FfiHelpers.checkError(error, 'signal_aes256_gcm_siv_encrypt');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
      calloc.free(ptextPtr);
      calloc.free(ptextBuffer);
      calloc.free(noncePtr);
      calloc.free(nonceBuffer);
      calloc.free(aadPtr);
      calloc.free(aadBuffer);
    }
  }

  /// Decrypts data with associated data and a nonce.
  ///
  /// Parameters:
  /// - [ciphertext]: The encrypted data with authentication tag
  /// - [nonce]: The same 12-byte nonce used for encryption
  /// - [associatedData]: The same associated data used for encryption
  ///
  /// Returns the decrypted plaintext.
  ///
  /// Throws [LibSignalException] if authentication fails.
  Uint8List decrypt({
    required Uint8List ciphertext,
    required Uint8List nonce,
    Uint8List? associatedData,
  }) {
    _checkDisposed();

    if (nonce.length != 12) {
      throw LibSignalException.invalidArgument('nonce', 'Must be 12 bytes');
    }

    final outPtr = calloc<SignalOwnedBuffer>();
    final constPtr = calloc<SignalConstPointerAes256GcmSiv>();
    constPtr.ref.raw = _ptr;

    final ctextPtr = calloc<Uint8>(ciphertext.length);
    ctextPtr.asTypedList(ciphertext.length).setAll(0, ciphertext);
    final ctextBuffer = calloc<SignalBorrowedBuffer>();
    ctextBuffer.ref.base = ctextPtr.cast<UnsignedChar>();
    ctextBuffer.ref.length = ciphertext.length;

    final noncePtr = calloc<Uint8>(nonce.length);
    noncePtr.asTypedList(nonce.length).setAll(0, nonce);
    final nonceBuffer = calloc<SignalBorrowedBuffer>();
    nonceBuffer.ref.base = noncePtr.cast<UnsignedChar>();
    nonceBuffer.ref.length = nonce.length;

    final aad = associatedData ?? Uint8List(0);
    final aadPtr = calloc<Uint8>(aad.length);
    if (aad.isNotEmpty) {
      aadPtr.asTypedList(aad.length).setAll(0, aad);
    }
    final aadBuffer = calloc<SignalBorrowedBuffer>();
    aadBuffer.ref.base = aadPtr.cast<UnsignedChar>();
    aadBuffer.ref.length = aad.length;

    try {
      final error = signal_aes256_gcm_siv_decrypt(
        outPtr,
        constPtr.ref,
        ctextBuffer.ref,
        nonceBuffer.ref,
        aadBuffer.ref,
      );
      FfiHelpers.checkError(error, 'signal_aes256_gcm_siv_decrypt');

      return FfiHelpers.fromOwnedBuffer(outPtr.ref);
    } finally {
      calloc.free(outPtr);
      calloc.free(constPtr);
      calloc.free(ctextPtr);
      calloc.free(ctextBuffer);
      calloc.free(noncePtr);
      calloc.free(nonceBuffer);
      calloc.free(aadPtr);
      calloc.free(aadBuffer);
    }
  }

  void _checkDisposed() {
    if (_disposed) {
      throw StateError('Aes256GcmSiv has been disposed');
    }
  }

  /// Releases the native resources.
  void dispose() {
    if (!_disposed) {
      _disposed = true;
      _aes256GcmSivFinalizer.detach(this);

      final mutPtr = calloc<SignalMutPointerAes256GcmSiv>();
      mutPtr.ref.raw = _ptr;
      signal_aes256_gcm_siv_destroy(mutPtr.ref);
      calloc.free(mutPtr);
    }
  }

  /// Whether this cipher has been disposed.
  bool get isDisposed => _disposed;
}
