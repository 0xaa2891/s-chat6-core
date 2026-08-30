# Local commands — CI runs the same cargo invocations.

build:
    cargo build --workspace

test:
    cargo test --workspace

clippy:
    cargo clippy --workspace -- -D warnings

fmt:
    cargo fmt --check

fmt-fix:
    cargo fmt

ping: build
    cargo run -p schat-cli -- ping

# UniFFI bindings from the host cdylib (any language UniFFI supports).
# Output is under target/ (gitignored). Not a second core.
ffi-kotlin: build
    cargo run -p schat-core --bin uniffi-bindgen -- generate \
        --library {{ library_path }} \
        --language kotlin \
        --out-dir target/uniffi/kotlin

ffi-python: build
    cargo run -p schat-core --bin uniffi-bindgen -- generate \
        --library {{ library_path }} \
        --language python \
        --out-dir target/uniffi/python

# Optional Android *client* .so check. The core API does not change.
ffi-ndk:
    cargo ndk -t arm64-v8a -t x86_64 build -p schat-core

library_path := if os() == "windows" {
    "target/debug/schat_core.dll"
} else if os() == "macos" {
    "target/debug/libschat_core.dylib"
} else {
    "target/debug/libschat_core.so"
}

testnet *args:
    bash tools/testnet/run-testnet.sh {{ args }}
