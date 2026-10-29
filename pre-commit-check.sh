#!/bin/sh

# This script is used to run checks before committing changes to the repository.
# It is a good approximation of what CI will do.

# Fail if any command fails
set -e

# Check formatting
cargo +nightly fmt --check --all

# Check clippy
cargo +nightly clippy --workspace --exclude mpz-wasm-bench --all-targets --all-features -- -D warnings

# Check clippy on wasm-bench (needs wasm32 target + rust-src; declared in rust-toolchain.toml)
# Both feature configurations: `{}` compiles the ST benches and `rayon` the MT
# ones, so neither invocation covers the other.
(cd crates/wasm-bench && cargo +nightly clippy --benches -- -D warnings)
(cd crates/wasm-bench && cargo +nightly clippy --benches --all-features -- -D warnings)
