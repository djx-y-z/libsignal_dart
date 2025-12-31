# Task: Analyze libsignal Release Notes

You are analyzing release notes for libsignal (Signal Protocol library) to determine how to update our Dart FFI wrapper package.

## Critical Rules

1. **ONLY use information explicitly stated in the release notes below**
2. **DO NOT invent or assume changes not mentioned in the release notes**
3. **If release notes are vague, be conservative** - default to "patch" and "none"
4. **If unsure, say "unclear from release notes"** instead of guessing

## Our Package Context

We maintain a Dart FFI wrapper that:
- Auto-generates bindings via ffigen from C headers
- Wraps the Signal Protocol implementation (Double Ratchet, X3DH)
- Provides Sealed Sender (anonymous messaging) functionality
- Provides Group Messaging (SenderKey distribution)
- Exposes key types: IdentityKeyPair, PreKeyBundle, SignedPreKey, etc.
- Exposes protocol operations: encrypt, decrypt, session management

## Version Information

- Current libsignal: CURRENT_VERSION
- New libsignal: NEW_VERSION

## Release Notes

```
RELEASE_NOTES_CONTENT
```

## Analysis Steps

Think step by step:

1. **Scan for API changes**: Look for words like "removed", "renamed", "changed signature", "deprecated", "breaking"
2. **Check struct changes**: Any mentions of struct modifications in FFI layer?
3. **Find new features**: Look for "added", "new feature", "new protocol support"
4. **Security items**: Look for "CVE", "vulnerability", "security fix", "cryptographic"
5. **Determine impact**: Based on FACTS found, classify the version bump

## Version Bump Rules

- **major**: ONLY if release notes explicitly mention:
  - Struct field changes (added/removed/reordered fields)
  - Removed functions that were previously available
  - Changed function signatures in FFI layer
  - "Breaking change" or "API break" keywords

- **minor**: If release notes mention:
  - New protocol features added
  - New optional functions added
  - New features that don't break existing code

- **patch**: Default for:
  - Bug fixes
  - Performance improvements
  - Documentation updates
  - Internal refactoring
  - Security patches (unless they change API)

## Response Format

Respond with EXACTLY this format (copy the structure precisely):

VERSION_BUMP: [major|minor|patch]
BREAKING_CHANGES: [list specific changes from release notes, or "none"]
NEW_FEATURES: [list feature names from release notes, or "none"]
SECURITY_NOTES: [quote security-related items from release notes, or "none"]
BINDING_CHANGES: [yes|no] - [one sentence explanation based on facts]
CHANGELOG_ENTRY:
- [First bullet point - most important change]
- [Second bullet point - if applicable]

## Example Response (for reference)

For a release that adds a new sealed sender version and fixes a crypto bug:

VERSION_BUMP: minor
BREAKING_CHANGES: none
NEW_FEATURES: Sealed Sender v2 support
SECURITY_NOTES: Fixed timing side-channel in signature verification
BINDING_CHANGES: yes - new sealed sender functions require binding regeneration
CHANGELOG_ENTRY:
- Added support for Sealed Sender v2 protocol
- Fixed timing side-channel vulnerability in signature verification

Now analyze the release notes above and respond:
