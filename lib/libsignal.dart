/// Dart FFI bindings for libsignal - Signal Protocol implementation.
///
/// This package provides end-to-end encryption using the Signal Protocol,
/// including key management, session establishment, sealed sender, and
/// group messaging capabilities.
///
/// ## Getting Started
///
/// ```dart
/// import 'package:libsignal/libsignal.dart';
///
/// void main() {
///   // Initialize the library
///   LibSignal.init();
///
///   // Generate identity key pair
///   final identity = IdentityKeyPair.generate();
///   print('Public key: ${identity.publicKey}');
///
///   // Clean up when done
///   identity.dispose();
/// }
/// ```
///
/// ## Features
///
/// - **Key Management**: Generate and manage cryptographic keys
/// - **Signal Protocol**: End-to-end encryption with forward secrecy
/// - **Sealed Sender**: Anonymous message sending
/// - **Group Messaging**: Efficient group message encryption
///
/// See the [README](https://github.com/djx-y-z/libsignal_dart) for more details.
library;

export 'src/exception.dart';
export 'src/libsignal.dart';
// TODO: Export more modules as they are implemented
// export 'src/keys.dart';
// export 'src/protocol.dart';
// export 'src/sealed_sender.dart';
// export 'src/groups.dart';
// export 'src/stores.dart';
