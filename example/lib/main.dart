import 'dart:convert';
import 'dart:math';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:libsignal/libsignal.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  bool _isInitialized = false;

  // State for each demo
  String? _keysResult;
  String? _cryptoResult;
  String? _groupsResult;
  String? _fingerprintResult;

  bool _keysLoading = false;
  bool _cryptoLoading = false;
  bool _groupsLoading = false;
  bool _fingerprintLoading = false;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 4, vsync: this);
    _initLibSignal();
  }

  void _initLibSignal() {
    LibSignal.init();
    setState(() => _isInitialized = true);
  }

  @override
  void dispose() {
    _tabController.dispose();
    LibSignal.cleanup();
    super.dispose();
  }

  // Helper: Generate random bytes
  Uint8List _randomBytes(int length) {
    final random = Random.secure();
    return Uint8List.fromList(
      List.generate(length, (_) => random.nextInt(256)),
    );
  }

  // Helper: Convert bytes to hex string
  String _bytesToHex(Uint8List bytes, {int? maxLength}) {
    final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    if (maxLength != null && hex.length > maxLength) {
      return '${hex.substring(0, maxLength)}...';
    }
    return hex;
  }

  // Helper: Format fingerprint (60 digits -> groups of 5)
  String _formatFingerprint(String fingerprint) {
    final buffer = StringBuffer();
    for (var i = 0; i < fingerprint.length; i += 5) {
      if (i > 0) buffer.write(' ');
      final end = (i + 5 < fingerprint.length) ? i + 5 : fingerprint.length;
      buffer.write(fingerprint.substring(i, end));
    }
    return buffer.toString();
  }

  // ============================================
  // Keys Demo
  // ============================================
  Future<void> _runKeysDemo() async {
    setState(() {
      _keysLoading = true;
      _keysResult = null;
    });

    PrivateKey? privateKey;
    PublicKey? publicKey;
    IdentityKeyPair? identityKeyPair;

    try {
      final result = StringBuffer();

      // 1. Generate PrivateKey
      privateKey = PrivateKey.generate();
      final privateBytes = privateKey.serialize();
      result.writeln('1. PrivateKey generated');
      result.writeln('   Size: ${privateBytes.bytes.length} bytes');
      result.writeln('   Hex: ${_bytesToHex(privateBytes.bytes, maxLength: 32)}');
      result.writeln();

      // 2. Get PublicKey from PrivateKey
      publicKey = privateKey.getPublicKey();
      final publicBytes = publicKey.serialize();
      result.writeln('2. PublicKey derived');
      result.writeln('   Size: ${publicBytes.length} bytes (1 type + 32 key)');
      result.writeln('   Hex: ${_bytesToHex(publicBytes, maxLength: 32)}');
      result.writeln();

      // 3. Sign a message
      const messageText = 'Hello, Signal Protocol!';
      final message = Uint8List.fromList(utf8.encode(messageText));
      final signature = privateKey.sign(message);
      result.writeln('3. Message signed (Ed25519)');
      result.writeln('   Message: "$messageText"');
      result.writeln('   Signature size: ${signature.length} bytes');
      result.writeln('   Signature: ${_bytesToHex(signature, maxLength: 32)}');
      result.writeln();

      // 4. Verify signature
      final isValid = publicKey.verify(message, signature);
      result.writeln('4. Signature verification');
      result.writeln('   Valid: $isValid');
      result.writeln();

      // 5. Verify with wrong message fails
      final wrongMessage = Uint8List.fromList(utf8.encode('Wrong message'));
      final isInvalid = publicKey.verify(wrongMessage, signature);
      result.writeln('5. Wrong message verification');
      result.writeln('   Valid: $isInvalid (expected: false)');
      result.writeln();

      // 6. Generate IdentityKeyPair
      identityKeyPair = IdentityKeyPair.generate();
      final identitySerialized = identityKeyPair.serialize();
      result.writeln('6. IdentityKeyPair generated');
      result.writeln('   Serialized size: ${identitySerialized.bytes.length} bytes');
      result.writeln('   Public key: ${_bytesToHex(identityKeyPair.publicKey.serialize(), maxLength: 32)}');

      setState(() => _keysResult = result.toString());
    } catch (e) {
      setState(() => _keysResult = 'Error: $e');
    } finally {
      // Proper disposal
      privateKey?.dispose();
      publicKey?.dispose();
      identityKeyPair?.dispose();
      setState(() => _keysLoading = false);
    }
  }

  // ============================================
  // Crypto Demo (AES-256-GCM-SIV)
  // ============================================
  Future<void> _runCryptoDemo() async {
    setState(() {
      _cryptoLoading = true;
      _cryptoResult = null;
    });

    Aes256GcmSiv? cipher;

    try {
      final result = StringBuffer();

      // 1. Generate key and nonce
      final key = _randomBytes(32);
      final nonce = _randomBytes(12);
      result.writeln('1. Key and nonce generated');
      result.writeln('   Key size: ${key.length} bytes (256 bits)');
      result.writeln('   Key: ${_bytesToHex(key, maxLength: 32)}');
      result.writeln('   Nonce size: ${nonce.length} bytes (96 bits)');
      result.writeln('   Nonce: ${_bytesToHex(nonce)}');
      result.writeln();

      // 2. Create cipher
      cipher = Aes256GcmSiv(key);
      result.writeln('2. AES-256-GCM-SIV cipher created');
      result.writeln();

      // 3. Encrypt message
      const messageText = 'Secret message for encryption';
      final plaintext = Uint8List.fromList(utf8.encode(messageText));
      final ciphertext = cipher.encrypt(plaintext: plaintext, nonce: nonce);
      result.writeln('3. Message encrypted');
      result.writeln('   Plaintext: "$messageText"');
      result.writeln('   Plaintext size: ${plaintext.length} bytes');
      result.writeln('   Ciphertext size: ${ciphertext.length} bytes');
      result.writeln('   Size diff: +${ciphertext.length - plaintext.length} bytes (auth tag)');
      result.writeln('   Ciphertext: ${_bytesToHex(ciphertext, maxLength: 40)}');
      result.writeln();

      // 4. Decrypt message
      final decrypted = cipher.decrypt(ciphertext: ciphertext, nonce: nonce);
      final decryptedText = utf8.decode(decrypted);
      result.writeln('4. Message decrypted');
      result.writeln('   Decrypted: "$decryptedText"');
      result.writeln('   Match: ${decryptedText == messageText}');
      result.writeln();

      // 5. Demonstrate determinism
      final ciphertext2 = cipher.encrypt(plaintext: plaintext, nonce: nonce);
      final isSame = _bytesToHex(ciphertext) == _bytesToHex(ciphertext2);
      result.writeln('5. Determinism test (same key + nonce)');
      result.writeln('   Same ciphertext: $isSame');
      result.writeln();

      // 6. Different nonce = different ciphertext
      final nonce2 = _randomBytes(12);
      final ciphertext3 = cipher.encrypt(plaintext: plaintext, nonce: nonce2);
      final isDifferent = _bytesToHex(ciphertext) != _bytesToHex(ciphertext3);
      result.writeln('6. Different nonce test');
      result.writeln('   Different ciphertext: $isDifferent');

      setState(() => _cryptoResult = result.toString());
    } catch (e) {
      setState(() => _cryptoResult = 'Error: $e');
    } finally {
      cipher?.dispose();
      setState(() => _cryptoLoading = false);
    }
  }

  // ============================================
  // Groups Demo (SenderKey)
  // ============================================
  Future<void> _runGroupsDemo() async {
    setState(() {
      _groupsLoading = true;
      _groupsResult = null;
    });

    ProtocolAddress? aliceAddress;
    ProtocolAddress? bobAddress;
    SenderKeyDistributionMessage? distMessage;

    try {
      final result = StringBuffer();

      // 1. Create protocol addresses
      aliceAddress = ProtocolAddress('alice', 1);
      bobAddress = ProtocolAddress('bob', 1);
      result.writeln('1. Protocol addresses created');
      result.writeln('   Alice: ${aliceAddress.name}:${aliceAddress.deviceId}');
      result.writeln('   Bob: ${bobAddress.name}:${bobAddress.deviceId}');
      result.writeln();

      // 2. Generate distribution ID (UUID)
      final distributionId = GroupSession.uuidFromString(
        '01234567-89ab-cdef-0123-456789abcdef',
      );
      final uuidString = GroupSession.uuidToString(distributionId);
      result.writeln('2. Distribution ID (UUID)');
      result.writeln('   UUID: $uuidString');
      result.writeln('   Size: ${distributionId.length} bytes');
      result.writeln();

      // 3. Create stores and sessions
      final aliceStore = InMemorySenderKeyStore();
      final bobStore = InMemorySenderKeyStore();
      final aliceSession = GroupSession(aliceAddress, distributionId, aliceStore);
      final bobSession = GroupSession(bobAddress, distributionId, bobStore);
      result.writeln('3. Group sessions created');
      result.writeln('   Alice store: InMemorySenderKeyStore');
      result.writeln('   Bob store: InMemorySenderKeyStore');
      result.writeln();

      // 4. Alice creates distribution message
      distMessage = await aliceSession.createDistributionMessage();
      result.writeln('4. Alice created distribution message');
      result.writeln('   Distribution ID: ${GroupSession.uuidToString(distMessage.distributionId)}');
      result.writeln('   Chain key size: ${distMessage.chainKey.length} bytes');
      result.writeln('   Iteration: ${distMessage.iteration}');
      result.writeln();

      // 5. Bob processes distribution message
      await bobSession.processDistributionMessage(aliceAddress, distMessage);
      result.writeln('5. Bob processed distribution message');
      result.writeln('   Bob store entries: ${bobStore.length}');
      result.writeln();

      // 6. Alice encrypts message
      const messageText = 'Hello, group!';
      final plaintext = Uint8List.fromList(utf8.encode(messageText));
      final ciphertext = await aliceSession.encrypt(plaintext);
      result.writeln('6. Alice encrypted message');
      result.writeln('   Message: "$messageText"');
      result.writeln('   Ciphertext size: ${ciphertext.length} bytes');
      result.writeln();

      // 7. Bob decrypts message
      final decrypted = await bobSession.decrypt(aliceAddress, ciphertext);
      final decryptedText = utf8.decode(decrypted);
      result.writeln('7. Bob decrypted message');
      result.writeln('   Decrypted: "$decryptedText"');
      result.writeln('   Match: ${decryptedText == messageText}');

      setState(() => _groupsResult = result.toString());
    } catch (e) {
      setState(() => _groupsResult = 'Error: $e');
    } finally {
      aliceAddress?.dispose();
      bobAddress?.dispose();
      distMessage?.dispose();
      setState(() => _groupsLoading = false);
    }
  }

  // ============================================
  // Fingerprint Demo
  // ============================================
  Future<void> _runFingerprintDemo() async {
    setState(() {
      _fingerprintLoading = true;
      _fingerprintResult = null;
    });

    IdentityKeyPair? aliceIdentity;
    IdentityKeyPair? bobIdentity;
    Fingerprint? aliceFingerprint;
    Fingerprint? bobFingerprint;

    try {
      final result = StringBuffer();

      // 1. Generate identity keys
      aliceIdentity = IdentityKeyPair.generate();
      bobIdentity = IdentityKeyPair.generate();
      result.writeln('1. Identity keys generated');
      result.writeln('   Alice public key: ${_bytesToHex(aliceIdentity.publicKey.serialize(), maxLength: 24)}');
      result.writeln('   Bob public key: ${_bytesToHex(bobIdentity.publicKey.serialize(), maxLength: 24)}');
      result.writeln();

      // 2. Create identifiers
      final aliceId = Uint8List.fromList(utf8.encode('alice-uuid-12345'));
      final bobId = Uint8List.fromList(utf8.encode('bob-uuid-67890'));
      result.writeln('2. User identifiers');
      result.writeln('   Alice: ${utf8.decode(aliceId)}');
      result.writeln('   Bob: ${utf8.decode(bobId)}');
      result.writeln();

      // 3. Create Alice's fingerprint (her view)
      aliceFingerprint = Fingerprint.create(
        localIdentifier: aliceId,
        localKey: aliceIdentity.publicKey,
        remoteIdentifier: bobId,
        remoteKey: bobIdentity.publicKey,
      );
      final aliceDisplay = aliceFingerprint.displayString;
      result.writeln('3. Alice\'s Safety Number');
      result.writeln('   ${_formatFingerprint(aliceDisplay)}');
      result.writeln('   Length: ${aliceDisplay.length} digits');
      result.writeln();

      // 4. Create Bob's fingerprint (his view - swapped)
      bobFingerprint = Fingerprint.create(
        localIdentifier: bobId,
        localKey: bobIdentity.publicKey,
        remoteIdentifier: aliceId,
        remoteKey: aliceIdentity.publicKey,
      );
      final bobDisplay = bobFingerprint.displayString;
      result.writeln('4. Bob\'s Safety Number');
      result.writeln('   ${_formatFingerprint(bobDisplay)}');
      result.writeln();

      // 5. Verify symmetry
      final isSymmetric = aliceDisplay == bobDisplay;
      result.writeln('5. Symmetry verification');
      result.writeln('   Alice and Bob see same number: $isSymmetric');
      result.writeln();

      // 6. Scannable encoding
      final scannable = aliceFingerprint.scannableEncoding;
      result.writeln('6. Scannable encoding (for QR codes)');
      result.writeln('   Size: ${scannable.length} bytes');
      result.writeln('   Hex: ${_bytesToHex(scannable, maxLength: 32)}');

      setState(() => _fingerprintResult = result.toString());
    } catch (e) {
      setState(() => _fingerprintResult = 'Error: $e');
    } finally {
      aliceIdentity?.dispose();
      bobIdentity?.dispose();
      aliceFingerprint?.dispose();
      bobFingerprint?.dispose();
      setState(() => _fingerprintLoading = false);
    }
  }

  // ============================================
  // UI
  // ============================================

  Widget _buildDemoCard({
    required String title,
    required String description,
    required VoidCallback onRun,
    required bool isLoading,
    String? result,
  }) {
    return Card(
      margin: const EdgeInsets.all(16),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 8),
            Text(
              description,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Colors.grey[600],
                  ),
            ),
            const SizedBox(height: 16),
            ElevatedButton.icon(
              onPressed: isLoading ? null : onRun,
              icon: isLoading
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.play_arrow),
              label: Text(isLoading ? 'Running...' : 'Run Demo'),
            ),
            if (result != null) ...[
              const SizedBox(height: 16),
              const Divider(),
              const SizedBox(height: 8),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'Result:',
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                  IconButton(
                    icon: const Icon(Icons.copy, size: 18),
                    tooltip: 'Copy to clipboard',
                    onPressed: () {
                      Clipboard.setData(ClipboardData(text: result));
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(
                          content: Text('Copied to clipboard'),
                          duration: Duration(seconds: 1),
                        ),
                      );
                    },
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.grey[100],
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Colors.grey[300]!),
                ),
                child: SelectableText(
                  result,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildKeysTab() {
    return SingleChildScrollView(
      child: _buildDemoCard(
        title: 'Key Generation & Signatures',
        description:
            'Generate Curve25519 key pairs, sign messages with Ed25519, '
            'and verify signatures. Demonstrates PrivateKey, PublicKey, '
            'and IdentityKeyPair classes.',
        onRun: _runKeysDemo,
        isLoading: _keysLoading,
        result: _keysResult,
      ),
    );
  }

  Widget _buildCryptoTab() {
    return SingleChildScrollView(
      child: _buildDemoCard(
        title: 'AES-256-GCM-SIV Encryption',
        description:
            'Symmetric encryption using AES-256-GCM-SIV (nonce-misuse resistant). '
            'Demonstrates encryption, decryption, and deterministic behavior.',
        onRun: _runCryptoDemo,
        isLoading: _cryptoLoading,
        result: _cryptoResult,
      ),
    );
  }

  Widget _buildGroupsTab() {
    return SingleChildScrollView(
      child: _buildDemoCard(
        title: 'Group Messaging (SenderKey)',
        description:
            'Efficient group encryption using Sender Keys. Alice creates a '
            'distribution message, Bob processes it, then they can exchange '
            'encrypted group messages.',
        onRun: _runGroupsDemo,
        isLoading: _groupsLoading,
        result: _groupsResult,
      ),
    );
  }

  Widget _buildFingerprintTab() {
    return SingleChildScrollView(
      child: _buildDemoCard(
        title: 'Safety Number Verification',
        description:
            'Create fingerprints for identity verification. Both parties '
            'see the same 60-digit Safety Number, which can be compared '
            'to verify encryption keys.',
        onRun: _runFingerprintDemo,
        isLoading: _fingerprintLoading,
        result: _fingerprintResult,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'libsignal Example',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      home: Scaffold(
        appBar: AppBar(
          title: const Text('libsignal Example'),
          centerTitle: true,
          bottom: TabBar(
            controller: _tabController,
            tabs: const [
              Tab(icon: Icon(Icons.key), text: 'Keys'),
              Tab(icon: Icon(Icons.lock), text: 'Crypto'),
              Tab(icon: Icon(Icons.group), text: 'Groups'),
              Tab(icon: Icon(Icons.fingerprint), text: 'Verify'),
            ],
          ),
        ),
        body: _isInitialized
            ? TabBarView(
                controller: _tabController,
                children: [
                  _buildKeysTab(),
                  _buildCryptoTab(),
                  _buildGroupsTab(),
                  _buildFingerprintTab(),
                ],
              )
            : const Center(child: CircularProgressIndicator()),
      ),
    );
  }
}
