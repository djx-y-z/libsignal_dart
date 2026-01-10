---
name: ffi-patterns
description: Dart FFI patterns and best practices for libsignal. Use when writing FFI code, working with native memory, creating wrappers, implementing new bindings, or fixing ARM64 issues.
---

# FFI Patterns for libsignal_dart

Patterns and templates for writing correct Dart FFI code in this project.

## Memory Allocation

### Basic Pattern

```dart
final ptr = calloc<Uint8>(length);
try {
  // Use ptr...
} finally {
  LibSignalUtils.zeroBytes(ptr.asTypedList(length)); // Zero sensitive data!
  calloc.free(ptr);
}
```

### Convert Uint8List to Pointer

```dart
Pointer<Uint8> _uint8ListToPointer(Uint8List data) {
  final ptr = calloc<Uint8>(data.length);
  ptr.asTypedList(data.length).setAll(0, data);
  return ptr;
}
```

### Convert Pointer to Uint8List

```dart
Uint8List _pointerToUint8List(Pointer<Uint8> ptr, int length) {
  return Uint8List.fromList(ptr.asTypedList(length));
}
```

## Wrapper Class Pattern

```dart
// Finalizer for automatic cleanup
final Finalizer<Pointer<signal.SignalKyberKeyPair>> _kyberKeyPairFinalizer =
    Finalizer((ptr) => signal.signal_kyber_key_pair_destroy(ptr));

class KyberKeyPair {
  final Pointer<signal.SignalKyberKeyPair> _ptr;
  bool _disposed = false;

  KyberKeyPair._(this._ptr) {
    _kyberKeyPairFinalizer.attach(this, _ptr, detach: this);
  }

  void _checkDisposed() {
    if (_disposed) {
      throw LibSignalException.disposed('KyberKeyPair');
    }
  }

  // Factory constructor
  static KyberKeyPair generate() {
    final ptr = calloc<Pointer<signal.SignalKyberKeyPair>>();
    try {
      final result = signal.signal_kyber_key_pair_generate(ptr);
      if (result != 0) {
        throw LibSignalException.fromNative(result, 'generate kyber key pair');
      }
      return KyberKeyPair._(ptr.value);
    } finally {
      calloc.free(ptr);
    }
  }

  void dispose() {
    if (!_disposed) {
      _disposed = true;
      signal.signal_kyber_key_pair_destroy(_ptr);
      _kyberKeyPairFinalizer.detach(this);
    }
  }
}
```

## SecureBytes for Sensitive Data

```dart
import 'secure_bytes.dart';

// Wrap sensitive data
final secureKey = SecureBytes(keyBytes);
try {
  // Use secureKey.bytes
  final result = encrypt(secureKey.bytes);
} finally {
  secureKey.dispose(); // Zeros memory automatically
}
```

## ARM64 Known Issues

On ARM64, Dart FFI has issues passing 16-byte structs by value ([dart-lang/sdk#36730](https://github.com/dart-lang/sdk/issues/36730)).

### Problem: SignalUuid (16 bytes)

```dart
// This FAILS on ARM64:
// signal.signal_group_session_encrypt(..., signalUuid, ...)
```

### Solution: Split into Two Int64

```dart
// ARM64 AAPCS64: 16-byte struct passed in two 64-bit registers (x2, x3)
(int, int) _uuidToInt64Pair(Uint8List uuid) {
  if (uuid.length != 16) {
    throw ArgumentError('UUID must be exactly 16 bytes');
  }

  // Pack bytes into two 64-bit integers (little-endian)
  final buffer = ByteData.view(uuid.buffer, uuid.offsetInBytes, 16);
  final low = buffer.getInt64(0, Endian.little);   // bytes 0-7 -> x2
  final high = buffer.getInt64(8, Endian.little);  // bytes 8-15 -> x3

  return (low, high);
}

// Usage
final (uuidLow, uuidHigh) = _uuidToInt64Pair(distributionId);
final result = signal.signal_group_session_encrypt_with_uuid_int64(
  ...,
  uuidLow,
  uuidHigh,
  ...
);
```

### Problem: SignalBorrowedSliceOfConstPointerPublicKey

```dart
// This FAILS on ARM64 - struct passed by value
// signal_sender_certificate_validate(cert, time, &trustRoot)
```

### Solution: Pure Dart Verification

```dart
// Implemented pure Dart signature verification in sender_certificate.dart
// Uses existing PublicKey.verifySignature() which works correctly
```

### 8-Byte Wrapper Structs

8-byte wrapper structs (like `SignalConstPointerProtocolAddress`) pass their inner pointer directly:

```dart
// Pass address._ptr directly instead of wrapping in struct
final result = signal.some_function(address._ptr);
```

## String Handling

```dart
final namePtr = name.toNativeUtf8();
try {
  final result = signal.signal_some_function(namePtr.cast());
  // ...
} finally {
  calloc.free(namePtr);
}
```

## Error Handling

```dart
final result = signal.signal_native_function(args);
if (result != 0) {
  throw LibSignalException.fromNative(result, 'operation description');
}
```

## Serialization Pattern

```dart
Uint8List serialize() {
  _checkDisposed();

  final sizePtr = calloc<Size>();
  try {
    // Get size first
    final sizeResult = signal.signal_type_serialized_len(_ptr, sizePtr);
    if (sizeResult != 0) {
      throw LibSignalException.fromNative(sizeResult, 'get serialized length');
    }

    final size = sizePtr.value;
    final buffer = calloc<Uint8>(size);
    try {
      final writeResult = signal.signal_type_serialize(_ptr, buffer, size);
      if (writeResult != 0) {
        throw LibSignalException.fromNative(writeResult, 'serialize');
      }
      return Uint8List.fromList(buffer.asTypedList(size));
    } finally {
      calloc.free(buffer);
    }
  } finally {
    calloc.free(sizePtr);
  }
}
```

## Deserialization Pattern

```dart
static MyType deserialize(Uint8List data) {
  SerializationValidator.validateMyType(data); // Validate size first!

  final ptr = calloc<Pointer<signal.SignalMyType>>();
  final dataPtr = calloc<Uint8>(data.length);
  try {
    dataPtr.asTypedList(data.length).setAll(0, data);

    final result = signal.signal_my_type_deserialize(
      ptr,
      dataPtr,
      data.length,
    );
    if (result != 0) {
      throw LibSignalException.fromNative(result, 'deserialize');
    }
    return MyType._(ptr.value);
  } finally {
    LibSignalUtils.zeroBytes(dataPtr.asTypedList(data.length)); // Zero if sensitive!
    calloc.free(dataPtr);
    calloc.free(ptr);
  }
}
```

## Utilities Reference

| Utility | Use For |
|---------|---------|
| `calloc<T>(n)` | Allocate n elements of type T |
| `calloc.free(ptr)` | Free allocated memory |
| `LibSignalUtils.zeroBytes(list)` | Zero sensitive Uint8List |
| `LibSignalUtils.constantTimeEquals(a, b)` | Compare secrets safely |
| `SerializationValidator.validate*()` | Validate serialized data sizes |
| `SecureBytes(data)` | Wrap sensitive data with auto-zeroing |

## Files to Reference

| Pattern | Reference File |
|---------|----------------|
| Key wrapper | `lib/src/keys/private_key.dart` |
| Serialization | `lib/src/protocol/session_record.dart` |
| ARM64 workaround | `lib/src/groups/group_session.dart` |
| SecureBytes usage | `lib/src/secure_bytes.dart` |
| Validation | `lib/src/serialization_validator.dart` |
