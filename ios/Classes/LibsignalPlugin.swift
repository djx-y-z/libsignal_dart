import Flutter

/// Minimal Flutter plugin class for libsignal FFI bindings.
public class LibsignalPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    // No method channel - cryptographic functions accessed via Dart FFI
  }
}
