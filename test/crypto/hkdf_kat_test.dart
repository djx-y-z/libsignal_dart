// Known-answer tests for HKDF-SHA256 against RFC 5869 Appendix A.
//
// The round-trip tests next door prove that `hkdfDerive` is deterministic and
// that its output moves when its inputs do. They would keep passing if every
// derived byte changed, which is exactly what an implementation swap can do.
// These pin the output to the specification instead, so a future bump of the
// `hkdf` crate cannot silently change a key this package derived under an
// earlier release.
//
// RFC 5869 publishes seven vectors. A.4-A.7 are HMAC-SHA1 and this package
// exposes no SHA-1 derivation, so the three SHA-256 cases are the whole of
// what applies: A.1 (salt and info both present), A.2 (80-octet inputs and an
// 82-octet output — the only case that runs the expansion past two rounds, so
// the only one that pins the block counter), and A.3 (zero-length salt and
// info).
//
// A.3 is the one that needs a word. `hkdfDerive` maps an empty `salt` to
// HKDF's "salt not provided", which RFC 5869 section 2.2 defines as HashLen
// zero bytes. HMAC pads a zero-length key and 32 zero bytes to the same
// 64-byte block, so that is the PRK the RFC computed A.3 against and the
// published output applies unchanged — which is what makes A.3 a test of this
// package's empty-salt path rather than of a path it never takes.
//
// Each field is transcribed in the RFC's own 16-octet grouping wherever it
// does not fit on one line, so it can be diffed against Appendix A by eye.

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

typedef _Vector = ({
  String name,
  String ikm,
  String salt,
  String info,
  String okm,
});

const _vectors = <_Vector>[
  (
    name: 'A.1',
    ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    salt: '000102030405060708090a0b0c',
    info: 'f0f1f2f3f4f5f6f7f8f9',
    okm:
        '3cb25f25faacd57a90434f64d0362f2a'
        '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
        '34007208d5b887185865',
  ),
  (
    name: 'A.2',
    ikm:
        '000102030405060708090a0b0c0d0e0f'
        '101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f'
        '303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f',
    salt:
        '606162636465666768696a6b6c6d6e6f'
        '707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f'
        '909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    info:
        'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
        'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
        'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    okm:
        'b11e398dc80327a1c8e7f78c596a4934'
        '4f012eda2d4efad8a050cc4c19afa97c'
        '59045a99cac7827271cb41c65e590e09'
        'da3275600c2f09b8367793a9aca3db71'
        'cc30c58179ec3e87c14c01d5c1f3434f'
        '1d87',
  ),
  (
    name: 'A.3',
    ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    salt: '',
    info: '',
    okm:
        '8da4e775a563c18f715f802a063c5a31'
        'b8a11f5c5ee1879ec3454e5f3c738d2d'
        '9d201395faa4b61a96c8',
  ),
];

List<int> _hex(String s) => [
  for (var i = 0; i < s.length; i += 2)
    int.parse(s.substring(i, i + 2), radix: 16),
];

String _hexOf(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  setUpAll(LibSignal.init);
  tearDownAll(LibSignal.cleanup);

  group('HKDF-SHA256 RFC 5869 Appendix A known-answer vectors', () {
    for (final v in _vectors) {
      test('${v.name} derives the published output key material', () {
        final actual = hkdfDerive(
          inputKeyMaterial: _hex(v.ikm),
          salt: _hex(v.salt),
          info: _hex(v.info),
          outputLength: v.okm.length ~/ 2,
        );

        expect(_hexOf(actual), equals(v.okm));
      });
    }
  });
}
