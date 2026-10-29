# LPN Estimator

This crate estimates the security of LPN instances, by computing the bit
security from different attacks based on <https://eprint.iacr.org/2022/712>.
So far exact and regular LPN over F_2 are supported.

- There exists a [reference
  implementation](https://github.com/tlsnotary/LPN-Estimator/blob/main/home/estimator.py)
  from the paper, which we forked from <https://github.com/RabbitCabbage/LPN-Estimator>
- `src/lpn.rs` is our own implementation

In `src/bin` there are executable binaries to confirm the bit security of a
chosen `(n, k, t)` instance:

- `exact.rs` estimates the bit security for an exact LPN instance.
- `regular.rs` estimates the bit security for a regular LPN instance.

For example `cargo run --release --bin regular -- 6225920 262144 1520` reports
the security of one of Ferret's regular-LPN presets. The Ferret parameter table
in `crates/ot-core/src/ferret/config/regular.rs` is curated by hand (adapted
from EMP-OT's tuning presets) and verified with these binaries — this crate no
longer generates that file.
