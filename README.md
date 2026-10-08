[![CI](https://github.com/privacy-scaling-explorations/mpz/actions/workflows/rust.yml/badge.svg)](https://github.com/privacy-scaling-explorations/mpz/actions)

<p align="center">
    <img src="./mpz-banner.png" width=1280 />
</p>

# mpz

mpz is a collection of multi-party computation libraries written in Rust 🦀.

The scope of this project is currently limited to being used to implement [TLSNotary](https://github.com/tlsnotary/tlsn). It is not intended for general public use.

See [our design doc](./DESIGN.md) for information on design choices, standards and project structure.

## ⚠️ Notice

This project is currently under active development and should not be used in production. Expect bugs and regular major breaking changes. Use at your own risk.

## Crates

  - [`core`](./crates/core/) - Core cryptographic primitives.
  - [`common`](./crates/common) - Common functionalities needed for modeling protocol execution, I/O, and multi-threading.
  - [`fields`](./crates/fields/) - Finite-fields.
  - [`circuits`](./crates/circuits/) - Boolean circuit DSL.
  - [`ot`](./crates/ot) ([`core`](./crates/ot-core/)) - Oblivious transfer protocols.
  - [`garble`](./crates/garble/) ([`core`](./crates/garble-core/)) - Boolean garbled circuit protocols.
  - [`share-conversion`](./crates/share-conversion/) ([`core`](./crates/share-conversion-core/)) - Multiplicative-to-Additive and Additive-to-Multiplicative share conversion protocols for a variety of fields.
  - [`cointoss`](./crates/cointoss/) ([`core`](./crates/cointoss-core/)) - 2-party cointoss protocol.
  - [`matrix-transpose`](./crates/matrix-transpose/) - Bit-wise matrix transposition.
  - [`clmul`](./crates/clmul/) - Carry-less multiplication.

## Running tests/benches on WASM

Tests and benchmarks can be run against WASM targets using [`wasm-harness`](https://github.com/sinui0/wasm-harness), which is configured as the cargo runner for the `wasm32-wasip1` and `wasm32-wasip1-threads` targets in [`.cargo/config.toml`](./.cargo/config.toml).

Install the harness and a supported WASM target:

```bash
cargo install wasm-harness
rustup target add wasm32-wasip1-threads
```

`wasm-harness` requires a WASM execution engine ([wasmtime](https://wasmtime.dev/), or V8/SpiderMonkey via [jsvu](https://github.com/GoogleChromeLabs/jsvu)). It auto-discovers an available engine, or one can be selected explicitly with `--engine` or the `WASM_HARNESS_ENGINE` environment variable.

Then run tests/benches as usual, passing the WASM target:

```bash
# Run tests (use the threaded target for crates relying on rayon)
cargo test -p <crate> --target wasm32-wasip1-threads

# Run benches
cargo bench -p <crate> --target wasm32-wasip1-threads
```

## License
All crates in this repository are licensed under either of

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributors

- [TLSNotary](https://github.com/tlsnotary)
- [Primus (formerly "PADO")](https://github.com/primus-labs)


### Pronunciation

mpz is pronounced "em-peasy".
