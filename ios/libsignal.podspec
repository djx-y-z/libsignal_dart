Pod::Spec.new do |s|
  s.name             = 'libsignal'
  s.version          = '1.0.0'
  s.summary          = 'Dart wrapper for libsignal. Signal Protocol implementation for end-to-end encryption, sealed sender, group messaging, and secure cryptographic operations.'
  s.description      = <<-DESC
Dart wrapper for libsignal. Signal Protocol implementation for end-to-end encryption, sealed sender, group messaging, and secure cryptographic operations.
Native libraries are bundled automatically via Flutter's native assets system.
                       DESC
  s.homepage         = 'https://github.com/djx-y-z/libsignal_dart'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'libsignal' => 'dev@libsignal.org' }
  s.source           = { :path => '.' }

  s.dependency 'Flutter'
  s.platform = :ios, '13.0'
  s.swift_version = '5.0'
end
