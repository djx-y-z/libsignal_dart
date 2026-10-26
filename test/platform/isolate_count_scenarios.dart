// The scenarios `isolate_count_test.dart` runs, each in a child process of its
// own and never inside the test runner: they drive this library's Rust-to-Dart
// post function to flutter_rust_bridge's no-op on purpose, and that function
// is process-wide. Inside the runner it would cut off the async calls of every
// other suite, which is how the flake this guards against looked in the first
// place.
//
//   dart --disable-dart-dev test/platform/isolate_count_scenarios.dart \
//       <second-library|init-race>
//
// The bare VM, not `dart run`, which would copy the hooked library over the
// one the test runner has loaded (the test says more). The library is the one
// a `dart test` or `dart run` of this package left in .dart_tool/lib/.
//
// It prints one line `verdict: OK ...`, `verdict: HANG ...` or
// `verdict: SKIP ...`, which the test reads.
import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
// ignore: implementation_imports
import 'package:flutter_rust_bridge/src/generalized_frb_rust_binding/generalized_frb_rust_binding.dart';
import 'package:libsignal/libsignal.dart';
import 'package:libsignal/src/platform/platform_io.dart'
    show getLibraryName, nativeAssetSearchPaths;

/// Whether an async call is answered. An isolate this library no longer
/// counts, once the last counted one has shut down, posts every answer to a
/// no-op, so the call never completes; sync calls, which post nothing, would
/// not notice.
Future<bool> answers() async {
  try {
    await sealedSenderV2ParseSentMessage(
      data: const [],
    ).timeout(const Duration(seconds: 3));
    return true;
  } on TimeoutException {
    return false;
  } on LibSignalException {
    return true; // the answer arrived: an empty message does not parse
  }
}

/// The library `LibSignal.init` loads here, by the same search.
String loadedLibraryPath() => File(
  nativeAssetSearchPaths(
    getLibraryName(),
  ).firstWhere((path) => File(path).existsSync()),
).absolute.path;

/// Runs [body] in an isolate and returns its result once that isolate has shut
/// down, which is when its native finalizers run and its counts are undone.
///
/// The isolate leaves through `Isolate.exit`: flutter_rust_bridge keeps a port
/// open in every isolate it initializes, so one that merely returned would
/// never shut down.
Future<T> inIsolate<T>(Future<T> Function() body) async {
  final result = ReceivePort();
  final exited = ReceivePort();
  await Isolate.spawn(
    (SendPort reply) async => Isolate.exit(reply, await body()),
    result.sendPort,
    onExit: exited.sendPort,
  );
  final value = await result.first as T;
  await exited.first;
  // The exit notice can arrive just before the finalizers have run.
  await Future<void>.delayed(const Duration(milliseconds: 100));
  result.close();
  exited.close();
  return value;
}

/// Another flutter_rust_bridge library is initialized first in the main
/// isolate; then a worker initializes only this one and exits.
///
/// flutter_rust_bridge counts an isolate only in the first library it
/// initializes there, so without a count of its own this library forgets the
/// main isolate, and the worker's exit takes its count to zero. Deterministic.
Future<String> secondLibrary() async {
  final ours = loadedLibraryPath();
  final extension = ours.substring(ours.lastIndexOf('.'));
  final other =
      '${Directory.systemTemp.createTempSync('frb_second_library_').path}'
      '/other_frb_library$extension';
  File(ours).copySync(other);
  // A copy under another name and path is a native image of its own, with
  // its own count — what a second FRB package's library is.
  final a = DynamicLibrary.open(
    ours,
  ).lookup<Void>('frb_create_shutdown_callback');
  final b = DynamicLibrary.open(
    other,
  ).lookup<Void>('frb_create_shutdown_callback');
  if (a.address == b.address) {
    return 'SKIP the copy of the library is not a separate native image here';
  }

  // What any other flutter_rust_bridge package's init does first: it takes
  // flutter_rust_bridge's one shutdown watcher of this isolate, for its own
  // library.
  GeneralizedFrbRustBinding(ExternalLibrary.open(other)).initShutdownWatcher();
  await LibSignal.init();
  if (!await answers()) return 'HANG before any worker ran';

  final workerAnswered = await inIsolate(() async {
    await LibSignal.init();
    return answers();
  });
  if (!workerAnswered) return 'HANG in the worker';
  return await answers()
      ? 'OK the main isolate is answered after the worker exited'
      : 'HANG the main isolate lost its answers when the worker exited';
}

typedef _Create =
    Pointer<NativeFunction<Void Function(Pointer<Void>)>> Function();

/// Counts an isolate in and out of the library as fast as it can, for
/// [args]`[1]` milliseconds: each time the count drops back to zero,
/// flutter_rust_bridge installs its no-op.
void _hammer(List<Object> args) {
  final library = DynamicLibrary.open(args[0] as String);
  final deadline = DateTime.now().add(Duration(milliseconds: args[1] as int));
  final create = library.lookupFunction<_Create, _Create>(
    'frb_create_shutdown_callback',
  );
  while (DateTime.now().isBefore(deadline)) {
    create().asFunction<void Function(Pointer<Void>)>()(nullptr);
  }
  Isolate.exit(args[2] as SendPort);
}

/// A fresh isolate initializes while another keeps taking the count to zero.
///
/// Counted only after the post function is installed — `RustLib.init`'s own
/// order — the fresh isolate is left with the no-op in most rounds. The main
/// isolate never initializes the library, or it would hold the count up and
/// hide exactly this. One hang in [rounds] is tolerated: a finalizer that has
/// already counted to zero and not yet written its no-op can still land last,
/// and only flutter_rust_bridge can close that.
Future<String> initRace({int rounds = 6}) async {
  final path = loadedLibraryPath();
  var hung = 0;
  for (var round = 0; round < rounds; round++) {
    final hammerDone = ReceivePort();
    await Isolate.spawn(_hammer, [path, 600, hammerDone.sendPort]);
    await Future<void>.delayed(const Duration(milliseconds: 50));
    final answered = await inIsolate(() async {
      await LibSignal.init();
      return answers();
    });
    if (!answered) hung++;
    await hammerDone.first;
    hammerDone.close();
  }
  return hung <= 1
      ? 'OK $hung of $rounds rounds hung'
      : 'HANG $hung of $rounds rounds hung';
}

Future<void> main(List<String> args) async {
  final verdict = switch (args.single) {
    'second-library' => await secondLibrary(),
    'init-race' => await initRace(),
    final other => 'FAIL unknown scenario $other',
  };
  stdout.writeln('verdict: $verdict');
  // flutter_rust_bridge keeps a port open, so returning would never exit.
  exit(0);
}
