// LPN golden-vector extractor.
//
// Drives emp-ot's own Lpn<AuthValueFerret, 10> through its public API:
//
//     y = A * x + e        (computed in place: `out` starts as e, ends as y)
//
// The harness links no emp-ot objects (Lpn and AuthValueFerret are
// header-only) and performs no I/O, so it is fully deterministic: the LPN
// index PRG is keyed only by `seed`, and x / e are filled from `fill_seed`.
// It exists to freeze a byte-for-byte reference for a reimplementation of the
// LPN stage.
//
// Usage:
//     ./emp-ot-dump-lpn [k_log] [n]        # k = 2^k_log (default 9), default n = 200
//
// Output (hex unless noted):
//     k_log <decimal>
//     n     <decimal>
//     seed  <32 hex>          LPN matrix seed (AES key for the index PRG)
//     fill_seed <32 hex>      PRG key for x (k blocks) then e (n blocks)
//     y     <n*32 hex>        result = A*x + e
//     sha256_y <64 hex>       SHA-256 of the `y` bytes
//
// x and e are not printed: they are exactly the first `k` then `n` blocks of
// the `fill_seed` PRG stream, so a consumer regenerates them.
//
// `n` must be a multiple of 4: the sub-4 tail consumes its PRG blocks in a
// different quantization (each single-row batch is padded to a block and the
// padding words are discarded), so it has no simple position-addressed form.

#include "emp-tool/emp-tool.h"
#include "emp-ot/common/lpn.h"
#include "emp-ot/ot_extension/ferret/ferret.h"
#include <cstdio>
#include <cstdlib>
#include <vector>
using namespace emp;

static void dump(const char* label, const void* p, long nbytes) {
    const unsigned char* b = (const unsigned char*)p;
    printf("%s ", label);
    for (long i = 0; i < nbytes; ++i) printf("%02x", b[i]);
    printf("\n");
}

static void dump_sha256(const char* label, const void* p, long nbytes) {
    HashT<HashOption::sha256> h;
    h.put(p, nbytes);
    unsigned char out[HashT<HashOption::sha256>::DIGEST_SIZE];
    h.digest(out);
    printf("%s ", label);
    for (size_t i = 0; i < sizeof(out); ++i) printf("%02x", out[i]);
    printf("\n");
}

int main(int argc, char** argv) {
    int k_log = (argc > 1) ? atoi(argv[1]) : 9;    // k = 2^9 = 512
    int n     = (argc > 2) ? atoi(argv[2]) : 200;  // must be a multiple of 4
    long k = 1L << k_log;
    if (n % 4 != 0) { fprintf(stderr, "n must be a multiple of 4\n"); return 1; }

    // Fixed LPN matrix seed == the AES key for the index PRG.
    block seed = makeBlock(0x0123456789abcdefULL, 0xfedcba9876543210ULL);

    // Fixed x (length k) and e (length n) from a fixed PRG key.
    block fill_seed = makeBlock(0x1111111111111111ULL, 0x2222222222222222ULL);
    PRG fill(&fill_seed);
    std::vector<block> x(k), e(n);
    fill.random_block(x.data(), k);
    fill.random_block(e.data(), n);

    Lpn<AuthValueFerret, 10> lpn((int)k);
    lpn.reseed(seed);
    lpn.compute_slice(reinterpret_cast<AuthValueFerret*>(e.data()),
                      reinterpret_cast<const AuthValueFerret*>(x.data()),
                      n);   // e now holds y

    printf("k_log %d\n", k_log);
    printf("n %d\n", n);
    dump("seed", &seed, 16);
    dump("fill_seed", &fill_seed, 16);
    dump("y", e.data(), (long)n * 16);
    dump_sha256("sha256_y", e.data(), (long)n * 16);
    return 0;
}
