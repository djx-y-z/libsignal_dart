//! Failures of this crate's API, as a value Dart can switch on.
//!
//! `LibSignalException` is the error type of the functions in `crate::api`.
//! Its `code` is part of this package's API. Its `message` is for people: where
//! libsignal raised the error it is that error's `Display` output, which
//! libsignal may change in any release.
//!
//! # Choosing a code
//!
//! The codes are taken from libsignal's own app bindings (`SignalErrorCode` in
//! `rust/bridge/shared/types/src/ffi/error.rs` upstream): the ones its protocol
//! and fingerprint errors map to. Each `SignalProtocolError` variant gets the
//! code upstream gives it, except `InvalidProtocolAddress` and
//! `ApplicationCallbackError`, whose upstream codes this package does not have;
//! their arms in `code_for` say why. Separately, a sender certificate that fails
//! validation is `VerificationFailure` wherever this crate checks one. A code
//! stands for a decision the caller makes, not for the line that failed, so a
//! variant upstream adds later normally fits an existing code.
//!
//! # No conversion from text
//!
//! `LibSignalException` has no `From<String>` or `From<&str>`. With one, a
//! `format!("…: {}", e)?` would compile and quietly replace a libsignal error's
//! code with a generic one. Errors this crate raises name their code through
//! `LibSignalException::new` or one of its shorthands, and a libsignal error
//! that gets a prefix goes through `LibSignalException::context`, which keeps
//! the code. Nothing stops a bridged function from declaring another error
//! type, such as `-> Result<T, String>`; the
//! `generated_bindings_use_no_other_error_type` test below fails if one does.

use libsignal_core::InvalidDeviceId;
use libsignal_core::curve::CurveError;
use libsignal_protocol::{FingerprintError, SignalProtocolError};

/// The kind of failure, for a caller to `switch` on.
///
/// Codes are added, removed or renamed only in a major release, so a `switch`
/// that lists every code keeps compiling through minor and patch releases. A
/// condition libsignal introduces in between is given the closest existing
/// code. The order of the codes is part of the bridge between Dart and the
/// native library as well, which is another reason it moves only in a major.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibSignalErrorCode {
    /// A caller-supplied value is out of range or malformed: a device id
    /// outside 1–127, an AES-GCM-SIV key or nonce of the wrong length, an HKDF
    /// output length over the limit, an empty destination list.
    InvalidArgument,
    /// The operation cannot succeed in the object's current state, for example
    /// a session record with no current session.
    InvalidState,
    /// An invariant inside this package or libsignal did not hold. Not caused
    /// by the input; worth reporting as a bug.
    InternalError,
    /// Bytes that should hold a serialized message, record or certificate do
    /// not parse. A session record that does not parse is `invalidSession`
    /// instead.
    ProtobufError,
    /// The message claims a protocol version too old to be read. That byte is
    /// checked before the message is authenticated, so anyone can produce this.
    LegacyCiphertextVersion,
    /// The message claims a ciphertext version this libsignal does not know. A
    /// sender on a newer protocol version produces it, but so does anyone who
    /// changes that byte: it is checked before the message is authenticated.
    UnknownCiphertextVersion,
    /// A message or sealed-sender envelope claims a version this libsignal does
    /// not know, or a sender-key message's version does not match the stored
    /// sender-key state.
    UnrecognizedMessageVersion,
    /// The message is malformed, failed authentication, or does not belong to
    /// the context the caller named: too short, a bad MAC, a ciphertext that
    /// does not decrypt, a sealed-sender envelope that does not open, a
    /// sender-key distribution message for a different distribution id. A group
    /// message whose signature does not verify is `invalidSignature` instead.
    InvalidMessage,
    /// A sealed-sender message names this very device as its sender.
    SealedSenderSelfSend,
    /// A public, private, Kyber or MAC key is malformed, of the wrong type or
    /// length, or unusable for the operation (for example a low-order point).
    /// An AES-GCM-SIV key of the wrong length is `invalidArgument`.
    InvalidKey,
    /// A signature did not verify, for example on a pre-key bundle or a group
    /// message.
    InvalidSignature,
    /// The two fingerprints being compared were made with different versions.
    FingerprintVersionMismatch,
    /// Bytes that should hold a scannable fingerprint do not parse.
    FingerprintParsingError,
    /// An identity key presented for an address differs from the one stored
    /// for it. On a pre-key message the key is the one the message carries,
    /// compared before anything in the message is authenticated, so this code
    /// alone does not show that the peer's key changed.
    UntrustedIdentity,
    /// A message refers to a pre-key, signed pre-key or Kyber pre-key id that
    /// the store does not hold.
    InvalidKeyIdentifier,
    /// There is no session, or no sender-key state, to use for this address,
    /// or for the chain a group message names.
    SessionNotFound,
    /// A session's stored registration id is invalid, for example wider than
    /// the 14 bits a multi-recipient sealed-sender message carries.
    InvalidRegistrationId,
    /// A session record is malformed, including one given to
    /// `SessionRecord.deserialize`.
    InvalidSession,
    /// A stored sender-key record holds no state to use.
    InvalidSenderKeySession,
    /// The session's chain has moved past the counter this message carries and
    /// holds no key for it any more, which normally means the message was
    /// decrypted before. Decided before the message is authenticated.
    DuplicatedMessage,
    /// A sender certificate did not validate: expired at the given time, its
    /// server certificate not signed by the trust root or revoked, the sender
    /// certificate not signed by that server certificate, or a reference to a
    /// server certificate that is not a known one.
    ///
    /// This says nothing about who sent the message. The certificate in a
    /// sealed-sender envelope is chosen by whoever sealed it, and anyone who
    /// knows your public identity key can seal one that fails here. Treat it as
    /// a rejected message: log it, and never let it change settings such as the
    /// trust root or the clock, or make you stop sending sealed messages.
    /// libsignal's own sealed-sender decrypt reports this case as an invalid
    /// message; this package gives it a code of its own so that a log can tell a
    /// certificate problem from a damaged envelope.
    VerificationFailure,
}

/// Thrown by a call into the native library that fails.
///
/// Decide what to do from `code`, which changes only in a major release.
/// `message` explains the failure for a log or a bug report, in libsignal's
/// wording where libsignal raised it, and can change in any release.
/// `toString()` returns `LibSignalException(<code>): <message>`.
///
/// Some failures arrive as other types:
/// - A store callback that throws cannot be reported through this type,
///   because the store interfaces cannot return an error across the bridge.
///   The call panics instead. Every call that takes store callbacks is
///   asynchronous, so on the web it never completes (see below).
/// - A panic in the native code is `flutter_rust_bridge`'s `PanicException`
///   on native platforms. On the web the WebAssembly module traps: a
///   synchronous call then throws `PanicException`, and an asynchronous call
///   never completes.
/// - A call on an object after its `dispose()` throws `flutter_rust_bridge`'s
///   `DroppableDisposedException`. flutter_rust_bridge does not export that
///   type, so catch it as `FrbException`.
/// - Checks made in Dart before the native call throw `ArgumentError` or
///   `StateError`.
///
/// `FrbException` and `PanicException` come from
/// `package:flutter_rust_bridge/flutter_rust_bridge.dart`; this package does
/// not re-export them.
#[flutter_rust_bridge::frb(dart_code = "
  @override
  String toString() => 'LibSignalException(${code.name}): $message';
")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibSignalException {
    /// What kind of failure this is. Stable across minor releases.
    pub code: LibSignalErrorCode,
    /// Details for a log; the wording can change in any release.
    pub message: String,
}

impl LibSignalException {
    /// An error raised by this crate, with the code it stands for.
    pub(crate) fn new(code: LibSignalErrorCode, message: impl Into<String>) -> Self {
        LibSignalException {
            code,
            message: message.into(),
        }
    }

    /// A caller-supplied value was rejected.
    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(LibSignalErrorCode::InvalidArgument, message)
    }

    /// An invariant this crate relies on did not hold.
    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(LibSignalErrorCode::InternalError, message)
    }

    /// Put `prefix` in front of the message, as `"<prefix>: <message>"`,
    /// leaving the code alone.
    pub(crate) fn context(self, prefix: &str) -> Self {
        LibSignalException {
            message: format!("{prefix}: {}", self.message),
            ..self
        }
    }
}

impl std::fmt::Display for LibSignalException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LibSignalException {}

/// The code for a libsignal protocol error.
///
/// No wildcard arm: a variant libsignal adds is a compile error here until it
/// is given a code.
fn code_for(error: &SignalProtocolError) -> LibSignalErrorCode {
    use LibSignalErrorCode as Code;
    match error {
        SignalProtocolError::InvalidArgument(_) => Code::InvalidArgument,
        SignalProtocolError::InvalidState(_, _) => Code::InvalidState,
        SignalProtocolError::InvalidProtobufEncoding => Code::ProtobufError,
        SignalProtocolError::CiphertextMessageTooShort(_)
        | SignalProtocolError::InvalidMessage(_, _)
        | SignalProtocolError::InvalidSealedSenderMessage(_)
        | SignalProtocolError::BadKEMCiphertextLength(_, _) => Code::InvalidMessage,
        SignalProtocolError::LegacyCiphertextVersion(_) => Code::LegacyCiphertextVersion,
        SignalProtocolError::UnrecognizedCiphertextVersion(_) => Code::UnknownCiphertextVersion,
        SignalProtocolError::UnrecognizedMessageVersion(_)
        | SignalProtocolError::UnknownSealedSenderVersion(_) => Code::UnrecognizedMessageVersion,
        SignalProtocolError::NoKeyTypeIdentifier
        | SignalProtocolError::BadKeyType(_)
        | SignalProtocolError::BadKeyLength(_, _)
        | SignalProtocolError::InvalidKeyAgreement
        | SignalProtocolError::InvalidMacKeyLength(_)
        | SignalProtocolError::BadKEMKeyType(_)
        | SignalProtocolError::WrongKEMKeyType(_, _)
        | SignalProtocolError::BadKEMKeyLength(_, _) => Code::InvalidKey,
        SignalProtocolError::SignatureValidationFailed => Code::InvalidSignature,
        SignalProtocolError::UntrustedIdentity(_) => Code::UntrustedIdentity,
        SignalProtocolError::InvalidPreKeyId
        | SignalProtocolError::InvalidSignedPreKeyId
        | SignalProtocolError::InvalidKyberPreKeyId => Code::InvalidKeyIdentifier,
        SignalProtocolError::NoSenderKeyState { .. }
        | SignalProtocolError::SessionNotFound(_) => Code::SessionNotFound,
        SignalProtocolError::InvalidSessionStructure(_) => Code::InvalidSession,
        SignalProtocolError::InvalidSenderKeySession { .. } => Code::InvalidSenderKeySession,
        SignalProtocolError::InvalidRegistrationId(_, _) => Code::InvalidRegistrationId,
        // Upstream's bindings give this a code of its own and raise it from
        // `ProtocolAddress_New` for a device id out of range. libsignal-protocol
        // itself never constructs it, and this crate reports a device id out of
        // range as an invalid argument everywhere.
        SignalProtocolError::InvalidProtocolAddress { .. } => Code::InvalidArgument,
        SignalProtocolError::DuplicatedMessage(_, _) => Code::DuplicatedMessage,
        // Upstream gives `ApplicationCallbackError` a callback code of its own.
        // Nothing in this crate can produce it: the stores libsignal calls are
        // in-memory ones, and a Dart callback that throws panics instead of
        // returning an error. Reaching it would be a bug here.
        SignalProtocolError::FfiBindingError(_)
        | SignalProtocolError::ApplicationCallbackError(_, _) => Code::InternalError,
        SignalProtocolError::SealedSenderSelfSend => Code::SealedSenderSelfSend,
        SignalProtocolError::UnknownSealedSenderServerCertificateId(_) => {
            Code::VerificationFailure
        }
    }
}

impl From<SignalProtocolError> for LibSignalException {
    fn from(error: SignalProtocolError) -> Self {
        let code = code_for(&error);
        LibSignalException::new(code, error.to_string())
    }
}

/// The code comes from libsignal's own conversion of a `CurveError` into a
/// `SignalProtocolError`. The message is the `CurveError`'s text, which is what
/// these calls reported before; for `InvalidKeyAgreement` it differs from the
/// converted error's.
impl From<CurveError> for LibSignalException {
    fn from(error: CurveError) -> Self {
        let message = error.to_string();
        let code = code_for(&SignalProtocolError::from(error));
        LibSignalException::new(code, message)
    }
}

/// A `u32` that is not a valid `DeviceId`: 0, or above 127.
impl From<InvalidDeviceId> for LibSignalException {
    fn from(error: InvalidDeviceId) -> Self {
        Self::invalid_argument(error.to_string())
    }
}

/// Fingerprint errors keep codes of their own, as in libsignal's bindings.
impl From<FingerprintError> for LibSignalException {
    fn from(error: FingerprintError) -> Self {
        let code = match &error {
            FingerprintError::VersionMismatch { .. } => LibSignalErrorCode::FingerprintVersionMismatch,
            FingerprintError::ParsingError(_) => LibSignalErrorCode::FingerprintParsingError,
            FingerprintError::InvalidIterationCount(_) => LibSignalErrorCode::InvalidArgument,
        };
        LibSignalException::new(code, error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_core::curve::KeyType;
    use libsignal_protocol::{CiphertextMessageType, DeviceId, ProtocolAddress, SessionNotFound, kem};
    use uuid::Uuid;

    fn bob_seven() -> ProtocolAddress {
        ProtocolAddress::new("bob".to_owned(), DeviceId::new(7).expect("7 is a valid device id"))
    }

    /// The variant's name. The match has no wildcard arm, so a variant
    /// libsignal adds breaks this module as well as `code_for`, and the table
    /// below is where its row then goes.
    fn variant_name(error: &SignalProtocolError) -> &'static str {
        use SignalProtocolError as P;
        match error {
            P::InvalidArgument(_) => "InvalidArgument",
            P::InvalidState(_, _) => "InvalidState",
            P::InvalidProtobufEncoding => "InvalidProtobufEncoding",
            P::CiphertextMessageTooShort(_) => "CiphertextMessageTooShort",
            P::LegacyCiphertextVersion(_) => "LegacyCiphertextVersion",
            P::UnrecognizedCiphertextVersion(_) => "UnrecognizedCiphertextVersion",
            P::UnrecognizedMessageVersion(_) => "UnrecognizedMessageVersion",
            P::NoKeyTypeIdentifier => "NoKeyTypeIdentifier",
            P::BadKeyType(_) => "BadKeyType",
            P::BadKeyLength(_, _) => "BadKeyLength",
            P::InvalidKeyAgreement => "InvalidKeyAgreement",
            P::SignatureValidationFailed => "SignatureValidationFailed",
            P::UntrustedIdentity(_) => "UntrustedIdentity",
            P::InvalidPreKeyId => "InvalidPreKeyId",
            P::InvalidSignedPreKeyId => "InvalidSignedPreKeyId",
            P::InvalidKyberPreKeyId => "InvalidKyberPreKeyId",
            P::InvalidMacKeyLength(_) => "InvalidMacKeyLength",
            P::NoSenderKeyState { .. } => "NoSenderKeyState",
            P::InvalidProtocolAddress { .. } => "InvalidProtocolAddress",
            P::SessionNotFound(_) => "SessionNotFound",
            P::InvalidSessionStructure(_) => "InvalidSessionStructure",
            P::InvalidSenderKeySession { .. } => "InvalidSenderKeySession",
            P::InvalidRegistrationId(_, _) => "InvalidRegistrationId",
            P::DuplicatedMessage(_, _) => "DuplicatedMessage",
            P::InvalidMessage(_, _) => "InvalidMessage",
            P::FfiBindingError(_) => "FfiBindingError",
            P::ApplicationCallbackError(_, _) => "ApplicationCallbackError",
            P::InvalidSealedSenderMessage(_) => "InvalidSealedSenderMessage",
            P::UnknownSealedSenderVersion(_) => "UnknownSealedSenderVersion",
            P::SealedSenderSelfSend => "SealedSenderSelfSend",
            P::UnknownSealedSenderServerCertificateId(_) => "UnknownSealedSenderServerCertificateId",
            P::BadKEMKeyType(_) => "BadKEMKeyType",
            P::WrongKEMKeyType(_, _) => "WrongKEMKeyType",
            P::BadKEMKeyLength(_, _) => "BadKEMKeyLength",
            P::BadKEMCiphertextLength(_, _) => "BadKEMCiphertextLength",
        }
    }

    /// One row per `SignalProtocolError` variant: the whole mapping, pinned.
    /// Changing a row is changing what a consumer's `switch` sees.
    #[test]
    fn every_protocol_error_variant_has_its_code() {
        use LibSignalErrorCode as Code;
        use SignalProtocolError as P;
        let table: Vec<(SignalProtocolError, LibSignalErrorCode)> = vec![
            (P::InvalidArgument("negative length".into()), Code::InvalidArgument),
            (P::InvalidState("encrypt", "no sender chain".into()), Code::InvalidState),
            (P::InvalidProtobufEncoding, Code::ProtobufError),
            (P::CiphertextMessageTooShort(4), Code::InvalidMessage),
            (P::LegacyCiphertextVersion(1), Code::LegacyCiphertextVersion),
            (P::UnrecognizedCiphertextVersion(5), Code::UnknownCiphertextVersion),
            (P::UnrecognizedMessageVersion(5), Code::UnrecognizedMessageVersion),
            (P::NoKeyTypeIdentifier, Code::InvalidKey),
            (P::BadKeyType(0x42), Code::InvalidKey),
            (P::BadKeyLength(KeyType::Djb, 31), Code::InvalidKey),
            (P::InvalidKeyAgreement, Code::InvalidKey),
            (P::SignatureValidationFailed, Code::InvalidSignature),
            (P::UntrustedIdentity(bob_seven()), Code::UntrustedIdentity),
            (P::InvalidPreKeyId, Code::InvalidKeyIdentifier),
            (P::InvalidSignedPreKeyId, Code::InvalidKeyIdentifier),
            (P::InvalidKyberPreKeyId, Code::InvalidKeyIdentifier),
            (P::InvalidMacKeyLength(16), Code::InvalidKey),
            (P::NoSenderKeyState { distribution_id: Uuid::nil() }, Code::SessionNotFound),
            (
                P::InvalidProtocolAddress { name: "bob".into(), device_id: 0 },
                Code::InvalidArgument,
            ),
            (P::SessionNotFound(SessionNotFound::without_address("encrypt")), Code::SessionNotFound),
            (P::InvalidSessionStructure("no current state"), Code::InvalidSession),
            (
                P::InvalidSenderKeySession { distribution_id: Uuid::nil() },
                Code::InvalidSenderKeySession,
            ),
            (P::InvalidRegistrationId(bob_seven(), 0x4000), Code::InvalidRegistrationId),
            (P::DuplicatedMessage(12, 8), Code::DuplicatedMessage),
            (
                P::InvalidMessage(CiphertextMessageType::SenderKey, "bad signature".into()),
                Code::InvalidMessage,
            ),
            (P::FfiBindingError("bridge".into()), Code::InternalError),
            (
                P::ApplicationCallbackError("load_session", Box::new(std::fmt::Error)),
                Code::InternalError,
            ),
            (P::InvalidSealedSenderMessage("truncated".into()), Code::InvalidMessage),
            (P::UnknownSealedSenderVersion(9), Code::UnrecognizedMessageVersion),
            (P::SealedSenderSelfSend, Code::SealedSenderSelfSend),
            (P::UnknownSealedSenderServerCertificateId(77), Code::VerificationFailure),
            (P::BadKEMKeyType(0x09), Code::InvalidKey),
            (P::WrongKEMKeyType(0x08, 0x09), Code::InvalidKey),
            (P::BadKEMKeyLength(kem::KeyType::Kyber1024, 3), Code::InvalidKey),
            (P::BadKEMCiphertextLength(kem::KeyType::Kyber1024, 3), Code::InvalidMessage),
        ];
        assert_eq!(table.len(), 35, "SignalProtocolError has 35 variants at v0.103");
        let variants: std::collections::BTreeSet<&str> =
            table.iter().map(|(error, _)| variant_name(error)).collect();
        assert_eq!(variants.len(), table.len(), "each variant has exactly one row");
        for (error, expected) in table {
            let upstream_text = error.to_string();
            let thrown = LibSignalException::from(error);
            assert_eq!(thrown.code, expected, "code for `{upstream_text}`");
            assert_eq!(thrown.message, upstream_text, "message is upstream's own text");
        }
    }

    #[test]
    fn context_prefixes_the_text_and_keeps_the_code() {
        let wrapped = LibSignalException::from(SignalProtocolError::InvalidSessionStructure("missing chain"))
            .context("Failed to restore the session");
        assert_eq!(wrapped.code, LibSignalErrorCode::InvalidSession);
        assert_eq!(wrapped.message, "Failed to restore the session: invalid session: missing chain");
    }

    #[test]
    fn fingerprint_errors_have_codes_of_their_own() {
        let mismatch = LibSignalException::from(FingerprintError::VersionMismatch { theirs: 2, ours: 1 });
        assert_eq!(mismatch.code, LibSignalErrorCode::FingerprintVersionMismatch);
        let unparsable = LibSignalException::from(FingerprintError::ParsingError("too short"));
        assert_eq!(unparsable.code, LibSignalErrorCode::FingerprintParsingError);
        let zero_iterations = LibSignalException::from(FingerprintError::InvalidIterationCount(0));
        assert_eq!(zero_iterations.code, LibSignalErrorCode::InvalidArgument);
    }

    #[test]
    fn curve_errors_take_the_protocol_code_and_keep_their_own_text() {
        let samples = [
            CurveError::NoKeyTypeIdentifier,
            CurveError::BadKeyType(0x42),
            CurveError::BadKeyLength(KeyType::Djb, 5),
            CurveError::InvalidKeyAgreement,
        ];
        for curve in samples {
            let curve_text = curve.to_string();
            let thrown = LibSignalException::from(curve);
            assert_eq!(thrown.code, LibSignalErrorCode::InvalidKey, "code for `{curve_text}`");
            assert_eq!(thrown.message, curve_text);
        }
        // For the other three variants both types print the same text, so only
        // this one can tell the two sources of `message` apart.
        assert_ne!(
            CurveError::InvalidKeyAgreement.to_string(),
            SignalProtocolError::InvalidKeyAgreement.to_string(),
        );
    }

    #[test]
    fn device_id_out_of_range_is_an_invalid_argument() {
        let rejected: InvalidDeviceId = DeviceId::try_from(200u32).expect_err("200 is out of range");
        assert_eq!(LibSignalException::from(rejected).code, LibSignalErrorCode::InvalidArgument);
    }

    /// The bridge sends a code as its position in the enum. Moving, inserting
    /// or removing one desynchronises every Dart side and native library not
    /// generated together, so this list changes only in a major release.
    #[test]
    fn codes_keep_their_wire_positions() {
        use LibSignalErrorCode as Code;
        let wire_order = [
            Code::InvalidArgument,
            Code::InvalidState,
            Code::InternalError,
            Code::ProtobufError,
            Code::LegacyCiphertextVersion,
            Code::UnknownCiphertextVersion,
            Code::UnrecognizedMessageVersion,
            Code::InvalidMessage,
            Code::SealedSenderSelfSend,
            Code::InvalidKey,
            Code::InvalidSignature,
            Code::FingerprintVersionMismatch,
            Code::FingerprintParsingError,
            Code::UntrustedIdentity,
            Code::InvalidKeyIdentifier,
            Code::SessionNotFound,
            Code::InvalidRegistrationId,
            Code::InvalidSession,
            Code::InvalidSenderKeySession,
            Code::DuplicatedMessage,
            Code::VerificationFailure,
        ];
        for (position, code) in wire_order.into_iter().enumerate() {
            assert_eq!(code as usize, position, "{code:?}");
        }

        // What crosses the bridge is the number the generated glue writes for
        // each code, so every encoder and decoder in it is checked as well.
        // Errors reach Dart through `IntoDart`, which must cover every code.
        let names: Vec<String> = wire_order.iter().map(|code| format!("{code:?}")).collect();
        let prefix = "crate::api::error::LibSignalErrorCode::";
        let (mut arms, mut into_dart_arms, mut in_into_dart) = (0, 0, false);
        for line in include_str!("../frb_generated.rs").lines().map(str::trim) {
            if line.starts_with("impl flutter_rust_bridge::IntoDart for crate::api::error::LibSignalErrorCode") {
                in_into_dart = true;
                continue;
            }
            if in_into_dart && line.starts_with("_ =>") {
                in_into_dart = false;
            }
            let arm = if let Some(rest) = line.strip_prefix(prefix) {
                rest.split_once(" => ").map(|(name, number)| (name, number.trim_end_matches(',')))
            } else if let Some((number, name)) = line.split_once(&format!(" => {prefix}")) {
                Some((name.trim_end_matches(','), number))
            } else if in_into_dart {
                line.strip_prefix("Self::")
                    .and_then(|rest| rest.split_once(" => "))
                    .map(|(name, number)| (name, number.trim_end_matches(".into_dart(),")))
            } else {
                None
            };
            let Some((name, number)) = arm else { continue };
            let position: usize = number.parse().unwrap_or_else(|_| panic!("no number in `{line}`"));
            assert_eq!(names.get(position).map(String::as_str), Some(name), "`{line}`");
            arms += 1;
            if in_into_dart {
                into_dart_arms += 1;
            }
        }
        assert_eq!(into_dart_arms, wire_order.len(), "IntoDart has an arm for every code");
        assert!(arms > into_dart_arms, "the other encoders and decoders were found too");
    }

    /// A function declared `-> Result<T, String>`, or with any other error
    /// type, still compiles, and Dart then gets that type instead of this one.
    /// The generated glue wraps every bridged call in
    /// `transform_result_<codec>::<…, E>` with `E` its error type, whatever the
    /// codec, so that is where it shows.
    #[test]
    fn generated_bindings_use_no_other_error_type() {
        let generated = include_str!("../frb_generated.rs");
        let marker = "transform_result_";
        let mut ours = 0;
        for (at, _) in generated.match_indices(marker) {
            let after = &generated[at + marker.len()..];
            let codec_len = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            let Some(arguments) = after[codec_len..].strip_prefix("::<") else {
                let line_start = generated[..at].rfind('\n').map_or(0, |i| i + 1);
                assert!(
                    generated[line_start..].trim_start().starts_with("use "),
                    "`{marker}` outside a call or an import, at byte {at}",
                );
                continue;
            };
            // The error type is the last argument at the top level of `<…>`.
            let (mut depth, mut last, mut end) = (0usize, 0usize, None);
            for (i, c) in arguments.char_indices() {
                match c {
                    '<' => depth += 1,
                    '>' if depth == 0 => {
                        end = Some(i);
                        break;
                    }
                    '>' => depth -= 1,
                    ',' if depth == 0 => last = i + 1,
                    _ => {}
                }
            }
            let end = end.unwrap_or_else(|| panic!("unterminated `<` after byte {at}"));
            match arguments[last..end].trim() {
                "crate::api::error::LibSignalException" => ours += 1,
                // A call that cannot fail.
                "()" => {}
                other => panic!("a bridged function fails with `{other}`, not LibSignalException"),
            }
        }
        assert!(ours > 0, "no bridged function found; has the generated glue changed shape?");
    }
}
