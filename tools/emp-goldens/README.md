# emp-ot golden extractors

Revisions the goldens were captured against:

| component | revision | note |
|---|---|---|
| emp-ot (LPN, cGGM) | `2fca139ff1974c039422af545bd4681e8d55acc1` | upstream |
| emp-tool | `bd036a9ee2d0a271129c6c2f98ff56de0cf2ef93` | upstream |
| emp-ot (ferret) | upstream + `emp-ot-seeded-bootstrap.patch` | one-line `virtual bootstrap_()`; run with `EMP_TEST_MODE=1` |

`dump_lpn_golden.cpp`, `dump_cggm_golden.cpp` and `dump_ferret_golden.cpp`
produce the goldens; each header documents usage and output format.
