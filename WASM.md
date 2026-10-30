# Running tests and benchmarks on WASM

Tests and benchmarks can run against WASM targets using
[`wasm-harness`](https://github.com/tlsnotary/wasm-harness). It is configured as
the cargo runner for the `wasm32-wasip1` and `wasm32-wasip1-threads` targets in
[`.cargo/config.toml`](./.cargo/config.toml), through
[`scripts/wasm-runner.sh`](./scripts/wasm-runner.sh).

> **Browser benchmarks:** [`crates/wasm-bench`](./crates/wasm-bench/) uses a
> different setup. It compiles to `wasm32-unknown-unknown` and runs in headless
> Chrome via `wasm-bindgen-test`, giving it the full browser environment and
> therefore a better reflection of browser deployment conditions than running
> standalone WASI binaries in an engine such as V8 or wasmtime. See
> [`crates/wasm-bench/README.md`](./crates/wasm-bench/README.md).

## Prerequisites

Install a WASM target, the harness, and an execution engine:

```bash
rustup target add wasm32-wasip1 wasm32-wasip1-threads

cargo install wasm-harness --version '=0.2.1' --locked
```

`wasm-harness` requires an engine: [wasmtime](https://wasmtime.dev/), or a
JavaScript shell such as V8, installed through
[jsvu](https://github.com/GoogleChromeLabs/jsvu):

```bash
npm install -g jsvu
jsvu --os=linux64 --engines=v8
```

The harness auto-discovers an installed engine, or one can be selected with
`--engine` or the `WASM_HARNESS_ENGINE` environment variable (for example,
`WASM_HARNESS_ENGINE=v8`).

## Running tests

```bash
# Whole workspace. mpz-wasm-bench has its own browser runner and target.
cargo test --workspace --exclude mpz-wasm-bench --target wasm32-wasip1-threads

# A single crate
cargo test -p mpz-ot --target wasm32-wasip1-threads

# Single-threaded target, for crates which do not need rayon or threads
cargo test -p mpz-fields --target wasm32-wasip1
```

Benchmark targets which compile for WASM can be run the same way:

```bash
cargo bench -p mpz-ot --target wasm32-wasip1-threads
```

Note that under JavaScript shells, criterion's baseline and report files are
written to a filesystem which does not persist between runs.

## Limitations

- **No persistent filesystem under JavaScript shells.** Writes appear to
  succeed but are discarded, and reads return EOF. Test fixtures must be
  embedded with `include_bytes!` or `include_str!` rather than loaded at
  runtime.
- **No `poll_oneoff`.** The JavaScript WASI shim does not implement it, so
  `std::thread::sleep` is unavailable. Tests which need to sleep must be gated
  off on WASM.
- **Threading.** `wasm32-wasip1-threads` works under V8. WASI's libstd reports
  `available_parallelism() == 1`, so libraries such as rayon run serially
  unless the pool size is set explicitly:

  ```bash
  WASM_HARNESS_ENV_RAYON_NUM_THREADS=2 \
    cargo test -p mpz-ot --target wasm32-wasip1-threads
  ```

- Engine support differs. If the threaded target fails to instantiate, check
  that the selected engine supports WASI threads. V8 is known to work.
