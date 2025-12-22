/// Pre-validation utilities for serialized Signal Protocol data.
///
/// These validators check the basic structure of serialized data BEFORE
/// passing it to native libsignal functions. This prevents crashes from
/// the native library when processing obviously invalid data.
///
/// Validations include:
/// - Length and type byte checks
/// - Low-order point detection for Curve25519 (small subgroup attack prevention)
///
/// **Note**: These validators catch most invalid data but cannot detect all
/// semantically invalid data (e.g., points not on the curve but not in blocklist).
library;

import 'dart:typed_data';

import 'exception.dart';

/// Low-order points blocklist for Curve25519 (X25519).
///
/// These points have small order (1, 2, 4, or 8) and should be rejected
/// to prevent small subgroup attacks.
///
/// Source: libsodium x25519_ref10.c
/// https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c
const List<List<int>> _curve25519LowOrderPoints = [
  // 0 (order 4)
  [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ],
  // 1 (order 1)
  [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ],
  // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
  [
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, //
    0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
    0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
    0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
  ],
  // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
  [
    0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, //
    0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
    0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
    0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
  ],
  // p-1 (order 2)
  [
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  ],
  // p (=0, order 4) - non-canonical encoding
  [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  ],
  // p+1 (=1, order 1) - non-canonical encoding
  [
    0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  ],
];

/// Checks if the 32-byte key material is a low-order point on Curve25519.
///
/// Returns `true` if the point is in the blocklist (should be rejected).
bool _isLowOrderPoint(Uint8List keyBytes) {
  assert(keyBytes.length == 32);

  for (final blocked in _curve25519LowOrderPoints) {
    var match = true;
    for (var i = 0; i < 32; i++) {
      if (keyBytes[i] != blocked[i]) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}

/// Key type constants used in Signal Protocol serialization.
abstract final class KeyType {
  /// Curve25519/Ed25519 key type (DJB type).
  static const int djb = 0x05;

  /// Identity key pair type byte.
  static const int identityKeyPair = 0x0a;

  /// Kyber1024 key type.
  static const int kyber1024 = 0x08;
}

/// Expected sizes for various serialized key types.
abstract final class KeySize {
  /// Serialized public key size (1 type byte + 32 key bytes).
  static const int publicKey = 33;

  /// Serialized private key size (32 bytes, no type prefix).
  static const int privateKey = 32;

  /// Serialized identity key pair size.
  /// Format: protobuf-encoded structure containing public and private keys.
  static const int identityKeyPair = 69;

  /// Serialized Kyber public key size (1 type byte + 1568 key bytes).
  static const int kyberPublicKey = 1569;

  /// Serialized Kyber secret key size.
  static const int kyberSecretKey = 3169;
}

/// Minimum sizes for serialized record types (protobuf-encoded).
abstract final class RecordSize {
  /// Minimum PreKeyRecord size.
  /// Contains: id (varint, 1-2 bytes) + publicKey (33 bytes) + privateKey (32 bytes) + overhead.
  /// Note: ID=0 uses 1-byte varint encoding, so minimum is 69 bytes.
  static const int preKeyRecordMin = 69;

  /// Minimum SignedPreKeyRecord size.
  /// Contains: id + timestamp + publicKey + privateKey + signature (64 bytes) + overhead.
  static const int signedPreKeyRecordMin = 140;

  /// Minimum KyberPreKeyRecord size.
  /// Conservative estimate for Kyber key-based records.
  static const int kyberPreKeyRecordMin = 100;

  /// Minimum SessionRecord size.
  /// Complex nested protobuf structure containing session states,
  /// identity keys, base keys, etc.
  static const int sessionRecordMin = 50;

  /// Minimum SenderKeyRecord size.
  /// Contains chain key, public signing key, and message keys.
  static const int senderKeyRecordMin = 20;

  /// Minimum SenderCertificate size.
  static const int senderCertificateMin = 10;

  /// Minimum ServerCertificate size.
  static const int serverCertificateMin = 10;

  /// Minimum SignalMessage size.
  /// Contains version byte + ephemeral key + counter + ciphertext + MAC.
  static const int signalMessageMin = 10;

  /// Minimum DecryptionErrorMessage size.
  static const int decryptionErrorMessageMin = 10;

  /// Minimum SenderKeyMessage size.
  static const int senderKeyMessageMin = 10;

  /// Minimum SenderKeyDistributionMessage size.
  static const int senderKeyDistributionMessageMin = 10;
}

/// Validates serialized data before passing to native libsignal functions.
///
/// This helps prevent native crashes by rejecting obviously invalid data
/// at the Dart level with proper exceptions.
abstract final class SerializationValidator {
  /// Validates serialized public key data.
  ///
  /// Checks:
  /// - Length is exactly 33 bytes
  /// - First byte is valid key type (0x05 for Curve25519)
  /// - Key material is not a low-order point (small subgroup attack prevention)
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validatePublicKey(Uint8List data) {
    if (data.isEmpty) {
      throw LibSignalException.invalidArgument(
        'publicKey',
        'Cannot be empty',
      );
    }

    if (data.length != KeySize.publicKey) {
      throw LibSignalException.invalidArgument(
        'publicKey',
        'Invalid length: expected ${KeySize.publicKey} bytes, got ${data.length}',
      );
    }

    if (data[0] != KeyType.djb) {
      throw LibSignalException.invalidArgument(
        'publicKey',
        'Invalid key type: expected 0x${KeyType.djb.toRadixString(16)}, '
            'got 0x${data[0].toRadixString(16)}',
      );
    }

    // Check for low-order points (32 bytes after type prefix)
    final keyBytes = Uint8List.sublistView(data, 1);
    if (_isLowOrderPoint(keyBytes)) {
      throw LibSignalException.invalidArgument(
        'publicKey',
        'Low-order point detected (potential small subgroup attack)',
      );
    }
  }

  /// Validates serialized private key data.
  ///
  /// Checks:
  /// - Length is exactly 32 bytes
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validatePrivateKey(Uint8List data) {
    if (data.isEmpty) {
      throw LibSignalException.invalidArgument(
        'privateKey',
        'Cannot be empty',
      );
    }

    if (data.length != KeySize.privateKey) {
      throw LibSignalException.invalidArgument(
        'privateKey',
        'Invalid length: expected ${KeySize.privateKey} bytes, got ${data.length}',
      );
    }
  }

  /// Validates serialized identity key pair data.
  ///
  /// Checks:
  /// - Length is exactly 65 bytes (1 type + 32 public + 32 private)
  /// - First byte is valid key type
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validateIdentityKeyPair(Uint8List data) {
    if (data.isEmpty) {
      throw LibSignalException.invalidArgument(
        'identityKeyPair',
        'Cannot be empty',
      );
    }

    if (data.length != KeySize.identityKeyPair) {
      throw LibSignalException.invalidArgument(
        'identityKeyPair',
        'Invalid length: expected ${KeySize.identityKeyPair} bytes, got ${data.length}',
      );
    }

    if (data[0] != KeyType.identityKeyPair) {
      throw LibSignalException.invalidArgument(
        'identityKeyPair',
        'Invalid key type: expected 0x${KeyType.identityKeyPair.toRadixString(16)}, '
            'got 0x${data[0].toRadixString(16)}',
      );
    }
  }

  /// Validates serialized Kyber public key data.
  ///
  /// Checks:
  /// - Length is correct for Kyber1024
  /// - First byte is Kyber key type
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validateKyberPublicKey(Uint8List data) {
    if (data.isEmpty) {
      throw LibSignalException.invalidArgument(
        'kyberPublicKey',
        'Cannot be empty',
      );
    }

    if (data.length != KeySize.kyberPublicKey) {
      throw LibSignalException.invalidArgument(
        'kyberPublicKey',
        'Invalid length: expected ${KeySize.kyberPublicKey} bytes, got ${data.length}',
      );
    }

    if (data[0] != KeyType.kyber1024) {
      throw LibSignalException.invalidArgument(
        'kyberPublicKey',
        'Invalid key type: expected 0x${KeyType.kyber1024.toRadixString(16)}, '
            'got 0x${data[0].toRadixString(16)}',
      );
    }
  }

  /// Validates serialized Kyber secret key data.
  ///
  /// Checks:
  /// - Length is correct for Kyber1024
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validateKyberSecretKey(Uint8List data) {
    if (data.isEmpty) {
      throw LibSignalException.invalidArgument(
        'kyberSecretKey',
        'Cannot be empty',
      );
    }

    if (data.length != KeySize.kyberSecretKey) {
      throw LibSignalException.invalidArgument(
        'kyberSecretKey',
        'Invalid length: expected ${KeySize.kyberSecretKey} bytes, got ${data.length}',
      );
    }
  }

  /// Validates that data has minimum required length.
  ///
  /// Used for types with variable-length serialization (records, messages).
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validateMinLength(
    Uint8List data,
    int minLength,
    String typeName,
  ) {
    if (data.isEmpty) {
      throw LibSignalException.invalidArgument(typeName, 'Cannot be empty');
    }

    if (data.length < minLength) {
      throw LibSignalException.invalidArgument(
        typeName,
        'Data too short: expected at least $minLength bytes, got ${data.length}',
      );
    }
  }

  /// Validates serialized PreKeyRecord data.
  ///
  /// Checks:
  /// - Minimum length for protobuf structure
  /// - First byte is valid protobuf field tag (0x08 for field 1 varint)
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validatePreKeyRecord(Uint8List data) {
    validateMinLength(data, RecordSize.preKeyRecordMin, 'preKeyRecord');

    // Allow field 1 (0x08 = id varint) or field 2 (0x12 = publicKey bytes)
    // when id=0 is omitted from serialization (protobuf default value behavior)
    final tag = data[0];
    if (tag != 0x08 && tag != 0x12) {
      throw LibSignalException.invalidArgument(
        'preKeyRecord',
        'Invalid protobuf structure: expected field 1 or 2, '
            'got 0x${tag.toRadixString(16)}',
      );
    }
  }

  /// Validates serialized SignedPreKeyRecord data.
  ///
  /// Checks:
  /// - Minimum length for protobuf structure
  /// - First byte is valid protobuf field tag (0x08 for field 1 varint)
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validateSignedPreKeyRecord(Uint8List data) {
    validateMinLength(
      data,
      RecordSize.signedPreKeyRecordMin,
      'signedPreKeyRecord',
    );

    // Allow field 1 (0x08 = id varint) or field 2 (0x10/0x12 = timestamp)
    // when id=0 is omitted from serialization (protobuf default value behavior)
    final tag = data[0];
    if (tag != 0x08 && tag != 0x10 && tag != 0x12) {
      throw LibSignalException.invalidArgument(
        'signedPreKeyRecord',
        'Invalid protobuf structure: expected field 1 or 2, '
            'got 0x${tag.toRadixString(16)}',
      );
    }
  }

  /// Validates serialized KyberPreKeyRecord data.
  ///
  /// Checks:
  /// - Minimum length for Kyber key-based protobuf structure
  /// - First byte is valid protobuf field tag (0x08 for field 1 varint)
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validateKyberPreKeyRecord(Uint8List data) {
    validateMinLength(
      data,
      RecordSize.kyberPreKeyRecordMin,
      'kyberPreKeyRecord',
    );

    // Allow field 1 (0x08 = id varint) or field 2 (0x10/0x12 = timestamp or publicKey)
    // when id=0 is omitted from serialization (protobuf default value behavior)
    final tag = data[0];
    if (tag != 0x08 && tag != 0x10 && tag != 0x12) {
      throw LibSignalException.invalidArgument(
        'kyberPreKeyRecord',
        'Invalid protobuf structure: expected field 1 or 2, '
            'got 0x${tag.toRadixString(16)}',
      );
    }
  }

  /// Validates serialized SessionRecord data.
  ///
  /// SessionRecord has complex nested protobuf structure that can start
  /// with different fields. We check for valid protobuf field tags.
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validateSessionRecord(Uint8List data) {
    validateMinLength(data, RecordSize.sessionRecordMin, 'sessionRecord');

    // SessionRecord can start with field 1 (0x0a) or field 2 (0x12)
    final tag = data[0];
    if (tag != 0x0a && tag != 0x12) {
      throw LibSignalException.invalidArgument(
        'sessionRecord',
        'Invalid protobuf structure: expected field tag 0x0a or 0x12, '
            'got 0x${tag.toRadixString(16)}',
      );
    }
  }

  /// Validates serialized SenderKeyRecord data.
  ///
  /// Checks:
  /// - Minimum length
  /// - First byte is valid protobuf field tag (0x0a for field 1 length-delimited)
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validateSenderKeyRecord(Uint8List data) {
    validateMinLength(data, RecordSize.senderKeyRecordMin, 'senderKeyRecord');

    if (data[0] != 0x0a) {
      throw LibSignalException.invalidArgument(
        'senderKeyRecord',
        'Invalid protobuf structure: expected field 1 length-delimited (0x0a), '
            'got 0x${data[0].toRadixString(16)}',
      );
    }
  }

  /// Validates serialized SenderCertificate data.
  ///
  /// Checks:
  /// - Minimum length
  /// - First byte is valid protobuf field tag (0x0a for field 1 length-delimited)
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validateSenderCertificate(Uint8List data) {
    validateMinLength(
      data,
      RecordSize.senderCertificateMin,
      'senderCertificate',
    );

    if (data[0] != 0x0a) {
      throw LibSignalException.invalidArgument(
        'senderCertificate',
        'Invalid protobuf structure: expected field 1 length-delimited (0x0a), '
            'got 0x${data[0].toRadixString(16)}',
      );
    }
  }

  /// Validates serialized ServerCertificate data.
  ///
  /// Checks:
  /// - Minimum length
  /// - First byte is valid protobuf field tag (0x0a for field 1 length-delimited)
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validateServerCertificate(Uint8List data) {
    validateMinLength(
      data,
      RecordSize.serverCertificateMin,
      'serverCertificate',
    );

    if (data[0] != 0x0a) {
      throw LibSignalException.invalidArgument(
        'serverCertificate',
        'Invalid protobuf structure: expected field 1 length-delimited (0x0a), '
            'got 0x${data[0].toRadixString(16)}',
      );
    }
  }

  /// Validates serialized SignalMessage data.
  ///
  /// SignalMessage has a custom wire format (not protobuf):
  /// - First byte contains version info (high nibble = current, low nibble = max)
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validateSignalMessage(Uint8List data) {
    validateMinLength(data, RecordSize.signalMessageMin, 'signalMessage');

    // SignalMessage version byte: high nibble is current version (should be 3)
    // Low nibble is max supported version
    final version = (data[0] >> 4) & 0x0f;
    if (version < 2 || version > 4) {
      throw LibSignalException.invalidArgument(
        'signalMessage',
        'Invalid message version: expected 2-4, got $version',
      );
    }
  }

  /// Validates serialized DecryptionErrorMessage data.
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validateDecryptionErrorMessage(Uint8List data) {
    validateMinLength(
      data,
      RecordSize.decryptionErrorMessageMin,
      'decryptionErrorMessage',
    );

    // DecryptionErrorMessage is protobuf, starts with field tag
    // Can start with various fields, so just check for valid protobuf tag format
    final tag = data[0];
    // Valid protobuf field tags have wire type in low 3 bits (0-5)
    final wireType = tag & 0x07;
    if (wireType > 5) {
      throw LibSignalException.invalidArgument(
        'decryptionErrorMessage',
        'Invalid protobuf wire type: got $wireType',
      );
    }
  }

  /// Validates serialized SenderKeyMessage data.
  ///
  /// SenderKeyMessage has a custom wire format similar to SignalMessage.
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validateSenderKeyMessage(Uint8List data) {
    validateMinLength(data, RecordSize.senderKeyMessageMin, 'senderKeyMessage');

    // SenderKeyMessage version byte: high nibble is current version
    final version = (data[0] >> 4) & 0x0f;
    if (version < 2 || version > 4) {
      throw LibSignalException.invalidArgument(
        'senderKeyMessage',
        'Invalid message version: expected 2-4, got $version',
      );
    }
  }

  /// Validates serialized SenderKeyDistributionMessage data.
  ///
  /// SenderKeyDistributionMessage has a custom wire format.
  ///
  /// Throws [LibSignalException] if validation fails.
  static void validateSenderKeyDistributionMessage(Uint8List data) {
    validateMinLength(
      data,
      RecordSize.senderKeyDistributionMessageMin,
      'senderKeyDistributionMessage',
    );

    // SenderKeyDistributionMessage version byte: high nibble is current version
    final version = (data[0] >> 4) & 0x0f;
    if (version < 2 || version > 4) {
      throw LibSignalException.invalidArgument(
        'senderKeyDistributionMessage',
        'Invalid message version: expected 2-4, got $version',
      );
    }
  }
}
