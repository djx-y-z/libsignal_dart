/// Matchers for the coded errors the native layer throws.
library;

import 'package:libsignal/libsignal.dart';
import 'package:test/test.dart';

/// A call, or a future, that fails with a [LibSignalException] whose `code`
/// is [code].
Matcher failsWith(LibSignalErrorCode code) =>
    throwsA(isA<LibSignalException>().having((e) => e.code, 'code', code));
