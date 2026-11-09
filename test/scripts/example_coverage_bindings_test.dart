// This project's own. The template renders example_coverage_test.dart next to
// it and never this file, so a template update leaves it as it is.
import 'dart:io';

import 'package:test/test.dart';

import '../../scripts/src/example_coverage.dart';

void main() {
  // The template's test of the real generated file asks only that the parser
  // found some functions, since it cannot name another project's. Its other
  // test compares the abstract class with the bodies, and a generator that wrote
  // part of the bindings in another shape in both places would pass it, leaving
  // `make coverage-example` measuring the rest. So this one holds the parser to
  // ours: more than 100 functions, one of the keys and the session cipher's.
  test("the parser reads every one of this project's bridged functions", () {
    final functions = bridgedFunctions(
      File(generatedBindings).readAsStringSync(),
    );
    expect(functions.length, greaterThan(100));
    expect(functions, contains('KeysPrivateKeyGenerate'));
    expect(functions, contains('SessionCipherMessageEncryptWithCallbacks'));
  });
}
