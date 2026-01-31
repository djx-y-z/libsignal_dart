# libsignal - Makefile
# Cross-platform build and development commands
#
# Usage: make <target> [ARGS="..."]
# Example: make analyze ARGS="--fatal-infos"
#
# On Windows CI (Git Bash), use cmd to run fvm.bat from PATH:
# Example: make test ARGS="test/keys/" FVM="cmd //c fvm"

.PHONY: help setup setup-fvm setup-protoc setup-rust-tools setup-web setup-android codegen build build-android build-web check-new-libsignal-version update update-changelog test coverage analyze format format-check get clean check-exists-libsignal-frb-release doc publish publish-dry-run rust-audit rust-check

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
	@echo "    make setup                        - Install all required tools for development"
	@echo "    make setup-fvm                    - Install FVM and project Flutter version"
	@echo "    make setup-protoc                 - Install protoc (Protocol Buffers compiler)"
	@echo "    make setup-rust-tools             - Install Rust tools (cargo-audit, flutter_rust_bridge_codegen)"
	@echo "    make setup-web                    - Install wasm-pack for web builds (optional)"
	@echo "    make setup-android                - Install cargo-ndk for Android builds (optional)"
	@echo ""
	@echo "  DEVELOPMENT"
	@echo "    make codegen                      - Regenerate Flutter Rust Bridge bindings"
	@echo "    make build                        - Build Rust library locally (native)"
	@echo "                                        Example: make build ARGS=\"--target aarch64-apple-ios\""
	@echo "    make build-android                - Build for Android (requires cargo-ndk + NDK)"
	@echo "                                        Example: make build-android ARGS=\"--target aarch64-linux-android\""
	@echo "    make build-web                    - Build WASM for web (requires wasm-pack)"
	@echo ""
	@echo "  CI / VERSION CHECKS"
	@echo "    make check-new-libsignal-version  - Check for new upstream libsignal version"
	@echo "                                        Example: make check-new-libsignal-version ARGS=\"--update\""
	@echo "    make check-exists-libsignal-frb-release - Check if FRB release exists on GitHub"
	@echo "    make update                       - Update rust/Cargo.lock (cargo update)"
	@echo "    make update-changelog             - Update CHANGELOG.md with AI (requires GITHUB_TOKEN)"
	@echo "                                        Example: make update-changelog ARGS=\"--version v0.87.0\""
	@echo ""
	@echo "  QUALITY ASSURANCE"
	@echo "    make test                         - Run tests"
	@echo "                                        Example: make test ARGS=\"test/keys/\""
	@echo "    make coverage                     - Run tests with coverage report"
	@echo "    make analyze                      - Run static analysis"
	@echo "                                        Example: make analyze ARGS=\"--fatal-infos\""
	@echo "    make rust-audit                   - Check Rust dependencies for vulnerabilities"
	@echo "    make rust-check                   - Quick Rust type check (updates Cargo.lock)"
	@echo "    make format                       - Format Dart code"
	@echo "    make format-check                 - Check Dart code formatting"
	@echo "    make doc                          - Generate API documentation"
	@echo ""
	@echo "  PUBLISHING"
	@echo "    make publish-dry-run              - Validate package before publishing"
	@echo "    make publish                      - Publish package (CI only, blocked locally)"
	@echo ""
	@echo "  UTILITIES"
	@echo "    make get                          - Get dependencies"
	@echo "    make clean                        - Clean build artifacts"
	@echo "    make help                         - Show this help message"
	@echo ""

# =============================================================================
# Setup
# =============================================================================

# Detect OS for platform-specific commands
UNAME_S := $(shell uname -s)

setup:
	@echo "============================================="
	@echo "libsignal - Development Environment Setup"
	@echo "============================================="
	@echo ""
	@# Check Rust toolchain
	@if ! command -v cargo >/dev/null 2>&1; then \
		echo "ERROR: Rust toolchain not found!"; \
		echo ""; \
		echo "Please install Rust first:"; \
		echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
		echo ""; \
		echo "Or visit: https://rustup.rs"; \
		exit 1; \
	fi
	@echo "[1/4] Rust toolchain: OK ($(shell rustc --version 2>/dev/null || echo 'unknown'))"
	@echo ""
	@$(MAKE) setup-fvm
	@echo ""
	@$(MAKE) setup-protoc
	@echo ""
	@$(MAKE) setup-rust-tools
	@echo ""
	@echo "============================================="
	@echo "Setup complete!"
	@echo "============================================="
	@echo ""
	@echo "You can now use 'make help' to see available commands."
	@echo ""
	@echo "Optional platform-specific setup:"
	@echo "  make setup-web      - Install wasm-pack for web builds"
	@echo "  make setup-android  - Install cargo-ndk for Android builds"
	@echo ""

setup-fvm:
	@echo "[2/4] Setting up FVM and Flutter..."
	@if ! command -v dart >/dev/null 2>&1; then \
		echo "ERROR: Dart SDK not found!"; \
		echo "Please install Dart SDK first: https://dart.dev/get-dart"; \
		exit 1; \
	fi
	@dart pub global activate fvm
	@$(FVM) install
	@touch .skip_libsignal_hook
	@$(FVM) dart pub get --no-example; rm -f .skip_libsignal_hook
	@git config core.hooksPath .githooks
	@echo "FVM setup complete!"

setup-protoc:
	@echo "[3/4] Setting up protoc (Protocol Buffers compiler)..."
	@if command -v protoc >/dev/null 2>&1; then \
		echo "protoc already installed: $$(protoc --version)"; \
	else \
		echo "Installing protoc..."; \
		if [ "$(UNAME_S)" = "Darwin" ]; then \
			if command -v brew >/dev/null 2>&1; then \
				brew install protobuf; \
			else \
				echo "ERROR: Homebrew not found. Please install protoc manually:"; \
				echo "  brew install protobuf"; \
				exit 1; \
			fi; \
		elif [ "$(UNAME_S)" = "Linux" ]; then \
			if command -v apt-get >/dev/null 2>&1; then \
				sudo apt-get update && sudo apt-get install -y protobuf-compiler; \
			elif command -v dnf >/dev/null 2>&1; then \
				sudo dnf install -y protobuf-compiler; \
			elif command -v pacman >/dev/null 2>&1; then \
				sudo pacman -S --noconfirm protobuf; \
			else \
				echo "ERROR: Could not detect package manager."; \
				echo "Please install protoc manually for your distribution."; \
				exit 1; \
			fi; \
		else \
			echo "ERROR: Unsupported OS for automatic protoc installation."; \
			echo "Please install protoc manually:"; \
			echo "  Windows: choco install protoc"; \
			echo "  Or download from: https://github.com/protocolbuffers/protobuf/releases"; \
			exit 1; \
		fi; \
	fi
	@echo "protoc setup complete!"

setup-rust-tools:
	@echo "[4/4] Setting up Rust tools..."
	@if command -v cargo-audit >/dev/null 2>&1; then \
		echo "cargo-audit already installed"; \
	else \
		echo "Installing cargo-audit..."; \
		cargo install cargo-audit; \
	fi
	@if command -v flutter_rust_bridge_codegen >/dev/null 2>&1; then \
		echo "flutter_rust_bridge_codegen already installed"; \
	else \
		echo "Installing flutter_rust_bridge_codegen..."; \
		cargo install flutter_rust_bridge_codegen; \
	fi
	@echo "Rust tools setup complete!"

setup-web:
	@echo "Setting up wasm-pack for web builds..."
	@if command -v wasm-pack >/dev/null 2>&1; then \
		echo "wasm-pack already installed: $$(wasm-pack --version)"; \
	else \
		echo "Installing wasm-pack..."; \
		cargo install wasm-pack; \
	fi
	@echo "Web setup complete! You can now use 'make build-web'."

setup-android:
	@echo "Setting up cargo-ndk for Android builds..."
	@if command -v cargo-ndk >/dev/null 2>&1; then \
		echo "cargo-ndk already installed"; \
	else \
		echo "Installing cargo-ndk..."; \
		cargo install cargo-ndk; \
	fi
	@echo ""
	@echo "Android setup complete!"
	@echo ""
	@echo "Note: You also need Android NDK installed."
	@echo "Set ANDROID_NDK_HOME environment variable to your NDK path."
	@echo "You can now use 'make build-android'."

# =============================================================================
# Development
# =============================================================================

codegen:
	@touch .skip_libsignal_hook
	@flutter_rust_bridge_codegen generate $(ARGS); ret=$$?; rm -f .skip_libsignal_hook; exit $$ret

build:
	@echo "Building Rust library..."
	@cargo build --release --manifest-path rust/Cargo.toml $(ARGS)
	@echo ""
	@echo "Build complete! Library at: rust/target/"

build-android:
	@echo "Building Rust library for Android..."
	@cd rust && cargo ndk --platform 21 build --release $(ARGS)
	@echo ""
	@echo "Build complete! Library at: rust/target/<arch>/release/"

build-web:
	@echo "Building WASM for web..."
	@cd rust && wasm-pack build --target no-modules --release --out-dir target/wasm32 --out-name libsignal_frb --no-typescript $(ARGS)
	@rm -f rust/target/wasm32/.gitignore rust/target/wasm32/package.json
	@echo ""
	@echo "Build complete! WASM files at: rust/target/wasm32/"

check-new-libsignal-version:
	@touch .skip_libsignal_hook
	@$(FVM) dart run scripts/check_new_libsignal_version.dart $(ARGS); ret=$$?; rm -f .skip_libsignal_hook; exit $$ret

update:
	@echo "Updating Cargo.lock..."
	@cd rust && cargo update
	@echo ""
	@echo "Cargo.lock updated!"

update-changelog:
	@touch .skip_libsignal_hook
	@$(FVM) dart run scripts/update_changelog.dart $(ARGS); ret=$$?; rm -f .skip_libsignal_hook; exit $$ret

# =============================================================================
# Quality Assurance
# =============================================================================

test:
	$(FVM) dart test $(ARGS)

coverage:
	$(FVM) dart test --coverage=coverage
	$(FVM) dart run coverage:format_coverage --check-ignore --lcov --in=coverage --out=coverage/lcov.info --report-on=lib --ignore-files '**/frb_generated*.dart'
	lcov --summary coverage/lcov.info

analyze:
	$(FVM) flutter analyze $(ARGS)

rust-audit:
	cargo audit --file rust/Cargo.lock $(ARGS)

rust-check:
	cargo check --manifest-path rust/Cargo.toml $(ARGS)

format:
	$(FVM) dart format . $(ARGS)

format-check:
	$(FVM) dart format --set-exit-if-changed . $(ARGS)

doc:
	@touch .skip_libsignal_hook
	@rm -rf doc; $(FVM) dart doc $(ARGS); ret=$$?; rm -f .skip_libsignal_hook; echo ""; echo "Documentation generated in doc/api/"; echo "Open doc/api/index.html to view locally"; exit $$ret

# =============================================================================
# Utilities
# =============================================================================

get:
	@touch .skip_libsignal_hook
	@$(FVM) dart pub get --no-example; ret=$$?; rm -f .skip_libsignal_hook; exit $$ret

clean:
	@touch .skip_libsignal_hook
	@rm -rf .dart_tool build rust/target; $(FVM) dart pub get --no-example; ret=$$?; rm -f .skip_libsignal_hook; exit $$ret

check-exists-libsignal-frb-release:
	@touch .skip_libsignal_hook
	@$(FVM) dart run scripts/check_exists_libsignal_frb_release.dart $(ARGS); ret=$$?; rm -f .skip_libsignal_hook; exit $$ret

# =============================================================================
# Publishing
# =============================================================================

publish-dry-run:
	@touch .skip_libsignal_hook
	@$(FVM) dart pub publish --dry-run; ret=$$?; rm -f .skip_libsignal_hook; exit $$ret

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
	@touch .skip_libsignal_hook
	@$(FVM) dart pub publish $(ARGS); ret=$$?; rm -f .skip_libsignal_hook; exit $$ret
endif
