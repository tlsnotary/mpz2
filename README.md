[![CI](https://github.com/tlsnotary/mpz2/actions/workflows/rust.yml/badge.svg)](https://github.com/tlsnotary/mpz2/actions)

<p align="center">
    <img src="./mpz-banner.png" width=1280 />
</p>

# mpz

mpz is a collection of multi-party computation libraries written in Rust 🦀.

The scope of this project is currently limited to being used to implement [TLSNotary](https://github.com/tlsnotary/tlsn). It is not intended for general public use.

See [our design doc](./DESIGN.md) for information on design choices, standards and project structure.

## ⚠️ Notice

This project is currently under active development and should not be used in production. Expect bugs and regular major breaking changes. Use at your own risk.

## Protocol crates

These crates implement complete, high-level protocols. Each top-level crate is
paired with an IO-free `*-core` crate containing the protocol logic; supporting
crates (primitives, circuits, execution, VM, and tooling) are intentionally not
listed here.

- [`ot`](./crates/ot/) ([`ot-core`](./crates/ot-core/)) - Oblivious transfer.
- [`garble`](./crates/garble/) ([`garble-core`](./crates/garble-core/)) - Garbled circuits.
- [`ole`](./crates/ole/) ([`ole-core`](./crates/ole-core/)) - Oblivious linear evaluation.
- [`zk`](./crates/zk/) ([`zk-core`](./crates/zk-core/)) - Zero-knowledge proofs.
- [`share-conversion`](./crates/share-conversion/) ([`share-conversion-core`](./crates/share-conversion-core/)) - Multiplicative-to-additive and additive-to-multiplicative share conversion.
- [`cointoss`](./crates/cointoss/) ([`cointoss-core`](./crates/cointoss-core/)) - Two-party coin toss.

## Testing on WASM

Tests and benchmarks can run on `wasm32-wasip1` and `wasm32-wasip1-threads` through [`wasm-harness`](https://github.com/tlsnotary/wasm-harness). See [WASM.md](./WASM.md) for setup, engines, commands, and limitations.

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
