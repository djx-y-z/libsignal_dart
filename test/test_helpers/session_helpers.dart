/// Test helpers for creating session-related test data.
library;

import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

/// Result of generating remote party keys for session establishment.
///
/// Note: libsignal requires all Kyber pre-key arguments (id, key, signature)
/// to be either all present or all absent. This class includes Kyber keys.
class RemotePartyKeys {
  final IdentityKeyPair identityKeyPair;
  final int registrationId;
  final int deviceId;
  final PrivateKey preKeyPrivate;
  final PublicKey preKeyPublic;
  final int preKeyId;
  final PrivateKey signedPreKeyPrivate;
  final PublicKey signedPreKeyPublic;
  final int signedPreKeyId;
  final Uint8List signedPreKeySignature;
  final KyberKeyPair kyberKeyPair;
  final KyberPublicKey kyberPreKey;
  final int kyberPreKeyId;
  final Uint8List kyberPreKeySignature;

  RemotePartyKeys._({
    required this.identityKeyPair,
    required this.registrationId,
    required this.deviceId,
    required this.preKeyPrivate,
    required this.preKeyPublic,
    required this.preKeyId,
    required this.signedPreKeyPrivate,
    required this.signedPreKeyPublic,
    required this.signedPreKeyId,
    required this.signedPreKeySignature,
    required this.kyberKeyPair,
    required this.kyberPreKey,
    required this.kyberPreKeyId,
    required this.kyberPreKeySignature,
  });

  /// Creates a PreKeyBundle from these keys.
  PreKeyBundle toBundle() {
    return PreKeyBundle.create(
      registrationId: registrationId,
      deviceId: deviceId,
      preKeyId: preKeyId,
      preKey: preKeyPublic,
      signedPreKeyId: signedPreKeyId,
      signedPreKey: signedPreKeyPublic,
      signedPreKeySignature: signedPreKeySignature,
      identityKey: identityKeyPair.publicKey,
      kyberPreKeyId: kyberPreKeyId,
      kyberPreKey: kyberPreKey,
      kyberPreKeySignature: kyberPreKeySignature,
    );
  }

  /// Disposes all keys.
  void dispose() {
    identityKeyPair.dispose();
    preKeyPrivate.dispose();
    preKeyPublic.dispose();
    signedPreKeyPrivate.dispose();
    signedPreKeyPublic.dispose();
    kyberKeyPair.dispose();
    kyberPreKey.dispose();
  }
}

/// Generates all keys needed for a remote party in session establishment.
///
/// This includes:
/// - Identity key pair
/// - One-time pre-key pair
/// - Signed pre-key pair with signature
/// - Kyber pre-key pair with signature (required by libsignal)
///
/// The [registrationId] defaults to 12345 if not specified.
/// The [deviceId] defaults to 1 if not specified.
/// The [preKeyId] defaults to 1 if not specified.
/// The [signedPreKeyId] defaults to 1 if not specified.
/// The [kyberPreKeyId] defaults to 1 if not specified.
RemotePartyKeys generateRemotePartyKeys({
  int registrationId = 12345,
  int deviceId = 1,
  int preKeyId = 1,
  int signedPreKeyId = 1,
  int kyberPreKeyId = 1,
}) {
  // Generate identity key pair
  final identityKeyPair = IdentityKeyPair.generate();

  // Generate one-time pre-key
  final preKeyPrivate = PrivateKey.generate();
  final preKeyPublic = preKeyPrivate.getPublicKey();

  // Generate signed pre-key
  final signedPreKeyPrivate = PrivateKey.generate();
  final signedPreKeyPublic = signedPreKeyPrivate.getPublicKey();

  // Sign the signed pre-key with the identity key
  final signedPreKeySignature = identityKeyPair.privateKey.sign(
    signedPreKeyPublic.serialize(),
  );

  // Generate Kyber pre-key (required by libsignal)
  final kyberKeyPair = KyberKeyPair.generate();
  final kyberPreKey = kyberKeyPair.getPublicKey();
  final kyberPreKeySignature = identityKeyPair.privateKey.sign(
    kyberPreKey.serialize(),
  );

  return RemotePartyKeys._(
    identityKeyPair: identityKeyPair,
    registrationId: registrationId,
    deviceId: deviceId,
    preKeyPrivate: preKeyPrivate,
    preKeyPublic: preKeyPublic,
    preKeyId: preKeyId,
    signedPreKeyPrivate: signedPreKeyPrivate,
    signedPreKeyPublic: signedPreKeyPublic,
    signedPreKeyId: signedPreKeyId,
    signedPreKeySignature: signedPreKeySignature,
    kyberKeyPair: kyberKeyPair,
    kyberPreKey: kyberPreKey,
    kyberPreKeyId: kyberPreKeyId,
    kyberPreKeySignature: kyberPreKeySignature,
  );
}

/// Creates a PreKeyBundle for testing.
///
/// This is a convenience function that generates all necessary keys
/// and returns a ready-to-use PreKeyBundle.
///
/// **Warning**: This function creates keys that are not automatically disposed.
/// Use [generateRemotePartyKeys] for proper resource management.
PreKeyBundle createTestPreKeyBundle({
  int registrationId = 12345,
  int deviceId = 1,
  int preKeyId = 1,
  int signedPreKeyId = 1,
  int kyberPreKeyId = 1,
}) {
  final keys = generateRemotePartyKeys(
    registrationId: registrationId,
    deviceId: deviceId,
    preKeyId: preKeyId,
    signedPreKeyId: signedPreKeyId,
    kyberPreKeyId: kyberPreKeyId,
  );

  final bundle = keys.toBundle();

  // Dispose the keys since we only need the bundle
  keys.dispose();

  return bundle;
}

/// Creates a ProtocolAddress for testing.
ProtocolAddress createTestAddress({
  String name = 'test-user',
  int deviceId = 1,
}) {
  return ProtocolAddress(name, deviceId);
}
