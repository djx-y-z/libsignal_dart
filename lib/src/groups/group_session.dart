/// Group session for Signal Protocol group messaging.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bindings/libsignal_bindings.dart';
import '../exception.dart';
import '../ffi_helpers.dart';
import '../libsignal.dart';
import '../protocol/protocol_address.dart';
import '../stores/sender_key_store.dart';
import '../utils.dart';
import 'sender_key_distribution_message.dart';

/// A map to store sender key record bytes during FFI callback execution.
///
/// This is used to pass data between Dart and native code during
/// group encryption/decryption operations.
final _pendingSenderKeyRecordBytes = <int, Uint8List>{};
final _pendingStoreOperations = <int, _StoreOperation>{};
int _operationCounter = 0;

/// Gets a unique operation ID with overflow protection.
int _nextOperationId() {
  _operationCounter++;
  // Reset if approaching max int to prevent overflow
  if (_operationCounter > 0x7FFFFFFFFFFFFFF) {
    _operationCounter = 1;
  }
  return _operationCounter;
}

class _StoreOperation {
  final SenderKeyStore store;
  final ProtocolAddress sender;
  final Uint8List distributionId;

  _StoreOperation(this.store, this.sender, this.distributionId);
}

/// Native callback for loading sender keys.
int _loadSenderKeyCallback(
  Pointer<Void> ctx,
  Pointer<SignalMutPointerSenderKeyRecord> out,
  SignalConstPointerProtocolAddress sender,
  Pointer<Pointer<Uint8>> distributionId,
) {
  try {
    final operationId = ctx.address;
    final operation = _pendingStoreOperations[operationId];

    if (operation == null) {
      return -1; // Error
    }

    // This is synchronous - we pre-loaded the key before starting
    final recordBytes = _pendingSenderKeyRecordBytes[operationId];
    if (recordBytes != null) {
      // Deserialize the record directly via FFI without creating a wrapper
      // (to avoid double-free issues with finalizer)
      final dataPtr = calloc<Uint8>(recordBytes.length);
      dataPtr.asTypedList(recordBytes.length).setAll(0, recordBytes);

      final buffer = calloc<SignalBorrowedBuffer>();
      buffer.ref.base = dataPtr.cast<UnsignedChar>();
      buffer.ref.length = recordBytes.length;

      final recordPtr = calloc<SignalMutPointerSenderKeyRecord>();

      final error =
          signal_sender_key_record_deserialize(recordPtr, buffer.ref);

      // Free the temporary buffers (libsignal makes a copy of the data)
      calloc.free(dataPtr);
      calloc.free(buffer);

      if (error == nullptr && recordPtr.ref.raw != nullptr) {
        out.ref.raw = recordPtr.ref.raw;
        calloc.free(recordPtr); // Free the pointer holder, not the record
        return 0; // Success
      }

      calloc.free(recordPtr);
    }

    out.ref.raw = nullptr;
    return 0; // No record (not an error)
  } catch (e) {
    return -1; // Error
  }
}

/// Native callback for storing sender keys.
int _storeSenderKeyCallback(
  Pointer<Void> ctx,
  SignalConstPointerProtocolAddress sender,
  Pointer<Pointer<Uint8>> distributionId,
  SignalConstPointerSenderKeyRecord record,
) {
  try {
    final operationId = ctx.address;
    final operation = _pendingStoreOperations[operationId];

    if (operation == null) {
      return -1;
    }

    // Serialize the record to bytes because the original pointer is owned
    // by libsignal and may be freed after callback returns
    if (record.raw != nullptr) {
      final outPtr = calloc<SignalOwnedBuffer>();

      try {
        final error = signal_sender_key_record_serialize(outPtr, record);
        if (error == nullptr) {
          _pendingSenderKeyRecordBytes[operationId] =
              FfiHelpers.fromOwnedBuffer(outPtr.ref);
        }
      } finally {
        calloc.free(outPtr);
      }
    }

    return 0;
  } catch (e) {
    return -1;
  }
}

/// Converts a 16-byte UUID to a string.
String _uuidToString(Uint8List uuid) {
  if (uuid.length != 16) {
    throw ArgumentError('UUID must be 16 bytes');
  }

  final hex = uuid.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
      '${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

/// Converts a UUID string to 16 bytes.
Uint8List _stringToUuid(String uuid) {
  final hex = uuid.replaceAll('-', '');
  if (hex.length != 32) {
    throw ArgumentError('Invalid UUID string: $uuid');
  }

  final result = Uint8List(16);
  for (var i = 0; i < 16; i++) {
    result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

/// A group session for encrypting and decrypting group messages.
///
/// Group messaging uses sender keys to enable efficient encryption for
/// multiple recipients. Each group member maintains sender keys for all
/// other members.
///
/// Example:
/// ```dart
/// // Create a group session
/// final session = GroupSession(
///   senderAddress,
///   distributionId,
///   senderKeyStore,
/// );
///
/// // Create and distribute the sender key
/// final distMessage = await session.createDistributionMessage();
/// // Send distMessage to all group members...
///
/// // Encrypt a message
/// final encrypted = await session.encrypt(Uint8List.fromList(utf8.encode('Hello')));
/// ```
class GroupSession {
  final ProtocolAddress _senderAddress;
  final Uint8List _distributionId;
  final SenderKeyStore _store;

  /// Creates a new group session.
  ///
  /// The [senderAddress] is the address of the message sender (typically us).
  /// The [distributionId] is a UUID identifying this group/distribution.
  /// The [store] provides persistent storage for sender keys.
  GroupSession(this._senderAddress, this._distributionId, this._store) {
    LibSignal.ensureInitialized();

    if (_distributionId.length != 16) {
      throw ArgumentError('distributionId must be a 16-byte UUID');
    }
  }

  /// Creates a sender key distribution message for this group.
  ///
  /// This message should be sent to all group members so they can
  /// decrypt messages from this sender.
  Future<SenderKeyDistributionMessage> createDistributionMessage() async {
    final operationId = _nextOperationId();

    // Pre-load existing sender key record if any
    final senderKeyName = SenderKeyName(
      _senderAddress,
      _uuidToString(_distributionId),
    );
    final existingData = await _store.loadSenderKey(senderKeyName);
    if (existingData != null) {
      _pendingSenderKeyRecordBytes[operationId] = existingData;
    }

    _pendingStoreOperations[operationId] = _StoreOperation(
      _store,
      _senderAddress,
      _distributionId,
    );

    try {
      final outPtr = calloc<SignalMutPointerSenderKeyDistributionMessage>();
      final senderPtr = calloc<SignalConstPointerProtocolAddress>();
      senderPtr.ref.raw = _senderAddress.pointer;

      // The C function expects uint8_t (*distribution_id)[16] - a pointer to a
      // 16-byte array. The binding incorrectly uses Pointer<Pointer<Uint8>>,
      // so we allocate a 16-byte buffer and cast it appropriately.
      final distIdData = calloc<Uint8>(16);
      distIdData.asTypedList(16).setAll(0, _distributionId);

      // Create the store struct with callbacks
      final storePtr = calloc<SignalSenderKeyStore>();
      storePtr.ref.ctx = Pointer.fromAddress(operationId);
      storePtr.ref.load_sender_key =
          Pointer.fromFunction<SignalLoadSenderKeyFunction>(
        _loadSenderKeyCallback,
        -1,
      );
      storePtr.ref.store_sender_key =
          Pointer.fromFunction<SignalStoreSenderKeyFunction>(
        _storeSenderKeyCallback,
        -1,
      );

      final storeConstPtr = calloc<SignalConstPointerFfiSenderKeyStoreStruct>();
      storeConstPtr.ref.raw = storePtr;

      try {
        final error = signal_sender_key_distribution_message_create(
          outPtr,
          senderPtr.ref,
          distIdData.cast<Pointer<Uint8>>(),
          storeConstPtr.ref,
        );
        FfiHelpers.checkError(
          error,
          'signal_sender_key_distribution_message_create',
        );

        if (outPtr.ref.raw == nullptr) {
          throw LibSignalException.nullPointer(
            'signal_sender_key_distribution_message_create',
          );
        }

        // Save any updated sender key record
        final updatedRecordBytes = _pendingSenderKeyRecordBytes[operationId];
        if (updatedRecordBytes != null) {
          await _store.storeSenderKey(senderKeyName, updatedRecordBytes);
        }

        return SenderKeyDistributionMessage.fromPointer(outPtr.ref.raw);
      } finally {
        calloc.free(outPtr);
        calloc.free(senderPtr);
        calloc.free(distIdData);
        calloc.free(storePtr);
        calloc.free(storeConstPtr);
      }
    } finally {
      _pendingStoreOperations.remove(operationId);
      _pendingSenderKeyRecordBytes.remove(operationId);
    }
  }

  /// Processes a sender key distribution message from another group member.
  ///
  /// The [senderAddress] is the address of the member who sent this
  /// distribution message. This stores their key material so their
  /// messages can be decrypted.
  Future<void> processDistributionMessage(
    ProtocolAddress senderAddress,
    SenderKeyDistributionMessage message,
  ) async {
    final operationId = _nextOperationId();

    // Pre-load existing sender key record if any
    final senderKeyName = SenderKeyName(
      senderAddress,
      _uuidToString(_distributionId),
    );
    final existingData = await _store.loadSenderKey(senderKeyName);
    if (existingData != null) {
      _pendingSenderKeyRecordBytes[operationId] = existingData;
    }

    _pendingStoreOperations[operationId] = _StoreOperation(
      _store,
      senderAddress,
      _distributionId,
    );

    try {
      final senderPtr = calloc<SignalConstPointerProtocolAddress>();
      senderPtr.ref.raw = senderAddress.pointer;

      final msgPtr = calloc<SignalConstPointerSenderKeyDistributionMessage>();
      msgPtr.ref.raw = message.pointer;

      // Create the store struct with callbacks
      final storePtr = calloc<SignalSenderKeyStore>();
      storePtr.ref.ctx = Pointer.fromAddress(operationId);
      storePtr.ref.load_sender_key =
          Pointer.fromFunction<SignalLoadSenderKeyFunction>(
        _loadSenderKeyCallback,
        -1,
      );
      storePtr.ref.store_sender_key =
          Pointer.fromFunction<SignalStoreSenderKeyFunction>(
        _storeSenderKeyCallback,
        -1,
      );

      final storeConstPtr = calloc<SignalConstPointerFfiSenderKeyStoreStruct>();
      storeConstPtr.ref.raw = storePtr;

      try {
        final error = signal_process_sender_key_distribution_message(
          senderPtr.ref,
          msgPtr.ref,
          storeConstPtr.ref,
        );
        FfiHelpers.checkError(
          error,
          'signal_process_sender_key_distribution_message',
        );

        // Save any updated sender key record
        final updatedRecordBytes = _pendingSenderKeyRecordBytes[operationId];
        if (updatedRecordBytes != null) {
          await _store.storeSenderKey(senderKeyName, updatedRecordBytes);
        }
      } finally {
        calloc.free(senderPtr);
        calloc.free(msgPtr);
        calloc.free(storePtr);
        calloc.free(storeConstPtr);
      }
    } finally {
      _pendingStoreOperations.remove(operationId);
      _pendingSenderKeyRecordBytes.remove(operationId);
    }
  }

  /// Encrypts a message for the group.
  ///
  /// Returns the encrypted message bytes.
  Future<Uint8List> encrypt(Uint8List plaintext) async {
    final operationId = _nextOperationId();

    // Pre-load existing sender key record
    final senderKeyName = SenderKeyName(
      _senderAddress,
      _uuidToString(_distributionId),
    );
    final existingData = await _store.loadSenderKey(senderKeyName);
    if (existingData != null) {
      _pendingSenderKeyRecordBytes[operationId] = existingData;
    }

    _pendingStoreOperations[operationId] = _StoreOperation(
      _store,
      _senderAddress,
      _distributionId,
    );

    try {
      final outPtr = calloc<SignalMutPointerCiphertextMessage>();
      final senderPtr = calloc<SignalConstPointerProtocolAddress>();
      senderPtr.ref.raw = _senderAddress.pointer;

      // The C function expects uint8_t (*distribution_id)[16] - a pointer to a
      // 16-byte array. The binding incorrectly uses Pointer<Pointer<Uint8>>,
      // so we allocate a 16-byte buffer and cast it appropriately.
      final distIdData = calloc<Uint8>(16);
      distIdData.asTypedList(16).setAll(0, _distributionId);

      final msgPtr = calloc<Uint8>(plaintext.length);
      msgPtr.asTypedList(plaintext.length).setAll(0, plaintext);

      final buffer = calloc<SignalBorrowedBuffer>();
      buffer.ref.base = msgPtr.cast<UnsignedChar>();
      buffer.ref.length = plaintext.length;

      // Create the store struct with callbacks
      final storePtr = calloc<SignalSenderKeyStore>();
      storePtr.ref.ctx = Pointer.fromAddress(operationId);
      storePtr.ref.load_sender_key =
          Pointer.fromFunction<SignalLoadSenderKeyFunction>(
        _loadSenderKeyCallback,
        -1,
      );
      storePtr.ref.store_sender_key =
          Pointer.fromFunction<SignalStoreSenderKeyFunction>(
        _storeSenderKeyCallback,
        -1,
      );

      final storeConstPtr = calloc<SignalConstPointerFfiSenderKeyStoreStruct>();
      storeConstPtr.ref.raw = storePtr;

      try {
        final error = signal_group_encrypt_message(
          outPtr,
          senderPtr.ref,
          distIdData.cast<Pointer<Uint8>>(),
          buffer.ref,
          storeConstPtr.ref,
        );
        FfiHelpers.checkError(error, 'signal_group_encrypt_message');

        if (outPtr.ref.raw == nullptr) {
          throw LibSignalException.nullPointer('signal_group_encrypt_message');
        }

        // Save any updated sender key record
        final updatedRecordBytes = _pendingSenderKeyRecordBytes[operationId];
        if (updatedRecordBytes != null) {
          await _store.storeSenderKey(senderKeyName, updatedRecordBytes);
        }

        // Serialize the ciphertext message
        final resultPtr = calloc<SignalOwnedBuffer>();
        final ciphertextConstPtr = calloc<SignalConstPointerCiphertextMessage>();
        ciphertextConstPtr.ref.raw = outPtr.ref.raw;

        try {
          final serError = signal_ciphertext_message_serialize(
            resultPtr,
            ciphertextConstPtr.ref,
          );
          FfiHelpers.checkError(serError, 'signal_ciphertext_message_serialize');

          return FfiHelpers.fromOwnedBuffer(resultPtr.ref);
        } finally {
          calloc.free(resultPtr);
          calloc.free(ciphertextConstPtr);

          // Destroy the ciphertext message
          final destroyPtr = calloc<SignalMutPointerCiphertextMessage>();
          destroyPtr.ref.raw = outPtr.ref.raw;
          signal_ciphertext_message_destroy(destroyPtr.ref);
          calloc.free(destroyPtr);
        }
      } finally {
        // Securely zero plaintext before freeing
        LibSignalUtils.zeroBytes(msgPtr.asTypedList(plaintext.length));
        calloc.free(outPtr);
        calloc.free(senderPtr);
        calloc.free(distIdData);
        calloc.free(msgPtr);
        calloc.free(buffer);
        calloc.free(storePtr);
        calloc.free(storeConstPtr);
      }
    } finally {
      _pendingStoreOperations.remove(operationId);
      _pendingSenderKeyRecordBytes.remove(operationId);
    }
  }

  /// Decrypts a group message.
  ///
  /// The [senderAddress] is the address of the message sender.
  /// Returns the decrypted plaintext.
  Future<Uint8List> decrypt(
    ProtocolAddress senderAddress,
    Uint8List ciphertext,
  ) async {
    final operationId = _nextOperationId();

    // Pre-load existing sender key record
    final senderKeyName = SenderKeyName(
      senderAddress,
      _uuidToString(_distributionId),
    );
    final existingData = await _store.loadSenderKey(senderKeyName);
    if (existingData != null) {
      _pendingSenderKeyRecordBytes[operationId] = existingData;
    }

    _pendingStoreOperations[operationId] = _StoreOperation(
      _store,
      senderAddress,
      _distributionId,
    );

    try {
      final outPtr = calloc<SignalOwnedBuffer>();
      final senderPtr = calloc<SignalConstPointerProtocolAddress>();
      senderPtr.ref.raw = senderAddress.pointer;

      final msgPtr = calloc<Uint8>(ciphertext.length);
      msgPtr.asTypedList(ciphertext.length).setAll(0, ciphertext);

      final buffer = calloc<SignalBorrowedBuffer>();
      buffer.ref.base = msgPtr.cast<UnsignedChar>();
      buffer.ref.length = ciphertext.length;

      // Create the store struct with callbacks
      final storePtr = calloc<SignalSenderKeyStore>();
      storePtr.ref.ctx = Pointer.fromAddress(operationId);
      storePtr.ref.load_sender_key =
          Pointer.fromFunction<SignalLoadSenderKeyFunction>(
        _loadSenderKeyCallback,
        -1,
      );
      storePtr.ref.store_sender_key =
          Pointer.fromFunction<SignalStoreSenderKeyFunction>(
        _storeSenderKeyCallback,
        -1,
      );

      final storeConstPtr = calloc<SignalConstPointerFfiSenderKeyStoreStruct>();
      storeConstPtr.ref.raw = storePtr;

      try {
        final error = signal_group_decrypt_message(
          outPtr,
          senderPtr.ref,
          buffer.ref,
          storeConstPtr.ref,
        );
        FfiHelpers.checkError(error, 'signal_group_decrypt_message');

        // Save any updated sender key record
        final updatedRecordBytes = _pendingSenderKeyRecordBytes[operationId];
        if (updatedRecordBytes != null) {
          await _store.storeSenderKey(senderKeyName, updatedRecordBytes);
        }

        return FfiHelpers.fromOwnedBuffer(outPtr.ref);
      } finally {
        // Securely zero ciphertext before freeing
        LibSignalUtils.zeroBytes(msgPtr.asTypedList(ciphertext.length));
        calloc.free(outPtr);
        calloc.free(senderPtr);
        calloc.free(msgPtr);
        calloc.free(buffer);
        calloc.free(storePtr);
        calloc.free(storeConstPtr);
      }
    } finally {
      _pendingStoreOperations.remove(operationId);
      _pendingSenderKeyRecordBytes.remove(operationId);
    }
  }

  /// The sender address for this session.
  ProtocolAddress get senderAddress => _senderAddress;

  /// The distribution ID (UUID) for this group.
  Uint8List get distributionId => Uint8List.fromList(_distributionId);

  /// Converts a UUID string to bytes.
  static Uint8List uuidFromString(String uuid) => _stringToUuid(uuid);

  /// Converts UUID bytes to a string.
  static String uuidToString(Uint8List uuid) => _uuidToString(uuid);
}
