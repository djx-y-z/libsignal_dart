import 'package:flutter/material.dart';
import 'package:libsignal/libsignal.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String _version = 'Unknown';
  Map<String, List<String>> _algorithms = {};

  @override
  void initState() {
    super.initState();
    _initLibsignal();
  }

  void _initLibsignal() {
    LibSignal.init();
    setState(() {
      _version = LibSignal.getVersion();
      _algorithms = LibSignal.getSupportedAlgorithms();
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('libsignal Example'),
        ),
        body: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'libsignal version: $_version',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 24),
              Text(
                'Supported Algorithms:',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              ..._algorithms.entries.map((entry) => Padding(
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '${entry.key}:',
                          style: const TextStyle(fontWeight: FontWeight.bold),
                        ),
                        Text('  ${entry.value.join(", ")}'),
                      ],
                    ),
                  )),
            ],
          ),
        ),
      ),
    );
  }
}
