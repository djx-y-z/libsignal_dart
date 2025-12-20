/// Sealed sender support for Signal Protocol.
///
/// Sealed sender provides sender anonymity by hiding the sender's
/// identity from the server. The recipient can still verify the
/// sender using the sender certificate.
///
/// This module provides:
/// - [ServerCertificate] - Server's certificate (trust anchor)
/// - [SenderCertificate] - Sender's certificate (sender identity)
///
/// Example:
/// ```dart
/// // Create certificates for sealed sender
/// final serverCert = ServerCertificate.create(
///   keyId: 1,
///   serverKey: serverPublicKey,
///   trustRoot: trustRootPrivateKey,
/// );
///
/// final senderCert = SenderCertificate.create(
///   senderUuid: 'user-uuid',
///   deviceId: 1,
///   senderKey: senderPublicKey,
///   expiration: DateTime.now().add(Duration(days: 30)),
///   signerCertificate: serverCert,
///   signerKey: serverPrivateKey,
/// );
///
/// // Validate a received certificate
/// final isValid = senderCert.validate(trustRootPublicKey);
/// ```
library;

export 'sender_certificate.dart';
export 'server_certificate.dart';
