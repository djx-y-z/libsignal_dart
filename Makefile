# libsignal - Makefile
# Cross-platform build and development commands
#
# Usage: make <target> [ARGS="..."]
# Example: make build ARGS="macos --arch arm64"
# Example: make analyze ARGS="--fatal-infos"
#
# On Windows CI (Git Bash), use cmd to run fvm.bat from PATH:
# Example: make build ARGS="windows" FVM="cmd //c fvm"

.PHONY: help setup build regen check combine test analyze format format-check get clean version publish publish-dry-run

# FVM command - can be overridden to provide full path on Windows CI
FVM ?= fvm

# Arguments are passed via ARGS variable
ARGS ?=

# Default target
.DEFAULT_GOAL := help

# =============================================================================
# Help
# =============================================================================

help:
	@echo ""
	@echo "libsignal - Available commands:"
	@echo ""
	@echo "  Pass arguments via ARGS variable: make <target> ARGS=\"...\""
	@echo ""
	@echo "  SETUP"
	@echo "    make setup                        - Install FVM and project Flutter version (run once)"
	@echo ""
	@echo "  BUILD"
	@echo "    make build ARGS=\"<platform>\"      - Build native libraries"
	@echo "                                        Platforms: macos, ios, android, linux, windows, all, list"
	@echo "                                        Example: make build ARGS=\"macos --arch arm64\""
	@echo ""
	@echo "  DEVELOPMENT"
	@echo "    make regen                        - Regenerate Dart FFI bindings from libsignal headers"
	@echo "    make check                        - Check for libsignal updates"
	@echo "                                        Example: make check ARGS=\"--update --version v0.68.0\""
	@echo "    make combine                      - Combine CI artifacts (used by GitHub Actions)"
	@echo ""
	@echo "  QUALITY ASSURANCE"
	@echo "    make test                         - Run tests"
	@echo "                                        Example: make test ARGS=\"test/keys_test.dart\""
	@echo "    make analyze                      - Run static analysis"
	@echo "                                        Example: make analyze ARGS=\"--fatal-infos\""
	@echo "    make format                       - Format Dart code"
	@echo "    make format-check                 - Check Dart code formatting"
	@echo ""
	@echo "  PUBLISHING"
	@echo "    make publish-dry-run              - Validate package before publishing"
	@echo "    make publish                      - Publish package (CI only, blocked locally)"
	@echo ""
	@echo "  UTILITIES"
	@echo "    make get                          - Get dependencies"
	@echo "    make clean                        - Clean build artifacts"
	@echo "    make version                      - Show current libsignal version"
	@echo "    make help                         - Show this help message"
	@echo ""

# =============================================================================
# Setup
# =============================================================================

setup:
	@echo "Installing FVM (Flutter Version Management)..."
	dart pub global activate fvm
	@echo ""
	@echo "Installing project Flutter version..."
	$(FVM) install
	@echo ""
	@echo "Getting dependencies..."
	$(FVM) dart pub get --no-example
	@echo ""
	@echo "Setup complete! You can now use 'make help' to see available commands."

# =============================================================================
# Build
# =============================================================================

build:
	@touch .skip_libsignal_hook
	@$(FVM) dart run scripts/build.dart $(ARGS); ret=$$?; rm -f .skip_libsignal_hook; exit $$ret

# =============================================================================
# Development
# =============================================================================

regen:
	@touch .skip_libsignal_hook
	@$(FVM) dart run scripts/regenerate_bindings.dart $(ARGS); ret=$$?; rm -f .skip_libsignal_hook; exit $$ret

check:
	@touch .skip_libsignal_hook
	@$(FVM) dart run scripts/check_updates.dart $(ARGS); ret=$$?; rm -f .skip_libsignal_hook; exit $$ret

combine:
	@touch .skip_libsignal_hook
	@$(FVM) dart run scripts/combine_artifacts.dart $(ARGS); ret=$$?; rm -f .skip_libsignal_hook; exit $$ret

# =============================================================================
# Quality Assurance
# =============================================================================

test:
	$(FVM) dart test $(ARGS)

analyze:
	$(FVM) flutter analyze $(ARGS)

format:
	$(FVM) dart format . $(ARGS)

format-check:
	$(FVM) dart format --set-exit-if-changed . $(ARGS)

# =============================================================================
# Utilities
# =============================================================================

get:
	$(FVM) dart pub get --no-example

clean:
	rm -rf .dart_tool build
	$(FVM) dart pub get --no-example

version:
	@echo "libsignal version: $$(cat LIBSIGNAL_VERSION)"
	@echo "Native build:      $$(cat NATIVE_BUILD 2>/dev/null || echo '1')"
	@echo "Full version:      $$(cat LIBSIGNAL_VERSION | tr -d 'v')-$$(cat NATIVE_BUILD 2>/dev/null || echo '1')"

# =============================================================================
# Publishing
# =============================================================================

publish-dry-run:
	$(FVM) dart pub publish --dry-run

publish:
ifndef CI
	@echo ""
	@echo "ERROR: Local publishing is disabled."
	@echo ""
	@echo "This package uses automated publishing via GitHub Actions."
	@echo "To publish a new version:"
	@echo ""
	@echo "  1. Update version in pubspec.yaml"
	@echo "  2. Update CHANGELOG.md"
	@echo "  3. Commit and push changes"
	@echo "  4. Create and push a tag: git tag v0.1.0 && git push origin v0.1.0"
	@echo "  5. GitHub Actions will automatically publish to pub.dev"
	@echo ""
	@echo "To validate the package locally, use: make publish-dry-run"
	@echo ""
	@exit 1
else
	$(FVM) dart pub publish $(ARGS)
endif
