# mpz-wasm-bench

Browser benchmarks for the mpz libraries, compiled to `wasm32-unknown-unknown`
with atomics + SIMD and run in headless Chrome via `wasm-bindgen-test`. They mirror
the native criterion benches and share each measurement body verbatim (`#[path]`)
with the corresponding native bench, so the WASM numbers measure the same code.

## Prerequisites

- Rust **nightly** with the `wasm32-unknown-unknown` target and the `rust-src`
  component (`-Zbuild-std` rebuilds std with atomics + SIMD). `rust-toolchain.toml`
  requests all three, so `rustup` installs them automatically the first time you
  run `cargo` here; manually:

  ```sh
  rustup toolchain install nightly --target wasm32-unknown-unknown --component rust-src
  ```

- `wasm-bindgen-test-runner`, which ships with `wasm-bindgen-cli`. The version
  must match the `wasm-bindgen` crate pinned in `Cargo.lock` (currently
  `0.2.128`):

  ```sh
  cargo install wasm-bindgen-cli --version 0.2.128
  ```

- Chrome and a matching `chromedriver` on `PATH` (or `CHROMEDRIVER` pointing at
  it). `wasm-bindgen-test` drives the broker through WebDriver.

## Running

Run these **from this directory** (`crates/wasm-bench`). When cargo is invoked
from the workspace root it does not read this member's `.cargo/config.toml`, so
the wasm target and runner would not apply, and the benches would try to build
for the host and fail.

```sh
cd crates/wasm-bench
cargo bench --bench zk_prover   # one bench
cargo bench                     # every bench
```

MT benches are behind the `rayon` feature; without it only the ST benches are
built:

```sh
cargo bench --bench ot_ferret_sender --features rayon
```

`webdriver.json` (auto-loaded from this directory by `wasm-bindgen-test-runner`)
raises ChromeDriver's default 30 second script timeout to match
`WASM_BINDGEN_TEST_TIMEOUT`. Without it, any benchmark whose synchronous body
blocks the renderer for more than 30 seconds fails with
`Error: missing field 'chunk'` / `Timed out receiving message from renderer`.

List them without launching Chrome (this still needs `wasm-bindgen-test-runner`
from Prerequisites — cargo runs the bench through the runner even to list):

```sh
cargo bench -- --list                    # all bench targets, entry points
cargo bench --bench zk_prover -- --list  # just one target
cargo bench --bench zk_prover -- --help  # runner filters/options
```

