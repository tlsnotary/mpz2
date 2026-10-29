// cGGM golden-vector extractor.
//
// Dumps emp-ot's Ferret-style cGGM tree (Half-Tree, ePrint 2022/1431) for a
// fixed (Delta, seed) and puncturing index, so a reimplementation of the
// `mpz_core::cggm` stage can be compared byte-for-byte.
//
// It exercises the same instantiation Ferret's MPCOT uses:
//   cggm::build_sender<kTile, /*ClearLeafLSB=*/true>   (sender)
//   cggm::eval_receiver<kTile, /*ClearLeafLSB=*/true>  (receiver)
//
// The receiver is handed the off-path sibling sums derived from the sender's
// K0 (K_recv[i] = K0[i] ^ (alpha_i ? 0 : Delta)), which is exactly what a real
// receiver reconstructs from its base COTs.
//
// Layout on stdout (hex unless noted):
//   depth   <dec>              tree depth d
//   rev     <dec>             punctured storage index = bit_reverse(alpha, d)
//   delta   <32 hex>          global offset (LSB must be 1 for Ferret)
//   seed    <32 hex>          left level-1 node
//   sender  <2^d * 32 hex>    build_sender leaves
//   k0      <d * 32 hex>      build_sender per-level left sums
//   krecv   <d * 32 hex>      receiver off-path corrections
//   recv    <2^d * 32 hex>    eval_receiver leaves (punctured slot = 0)
//
// Header-only consumer, no I/O; deterministic.
//
// Usage: ./emp-ot-dump-cggm [depth] [rev]

#include "emp-tool/emp-tool.h"
#include "emp-ot/common/cggm.h"
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

int main(int argc, char** argv) {
    int d = (argc > 1) ? atoi(argv[1]) : 4;
    uint32_t rev = (argc > 2) ? (uint32_t)strtoul(argv[2], nullptr, 0) : 5;
    long n = 1L << d;

    // LSB pinned to 1, matching Ferret's COT LSB convention.
    block delta = makeBlock(0x0123456789abcdefULL, 0xfedcba9876543211ULL);
    block seed = makeBlock(0x1111111111111111ULL, 0x2222222222222222ULL);

    std::vector<block> leaves(n), K0(d);
    cggm::build_sender<cggm::kTile, /*ClearLeafLSB=*/true>(
        d, delta, seed, leaves.data(), K0.data());

    // Receiver path: alpha is MSB-first, storage index is bit_reverse(alpha).
    uint32_t alpha = cggm::bit_reverse(rev, d);
    std::vector<block> Krecv(d);
    for (int i = 0; i < d; ++i) {
        // alpha_{i+1} = bit (d-1-i) of alpha (MSB-first); the off-path side is
        // the right sum when alpha != 0.
        int alpha_i = (alpha >> (d - 1 - i)) & 1;
        Krecv[i] = K0[i] ^ (alpha_i ? zero_block : delta);
    }

    std::vector<block> rleaves(n);
    cggm::eval_receiver<cggm::kTile, /*ClearLeafLSB=*/true>(
        d, (int)alpha, Krecv.data(), rleaves.data());

    printf("depth %d\n", d);
    printf("rev %u\n", rev);
    dump("delta", &delta, 16);
    dump("seed", &seed, 16);
    dump("sender", leaves.data(), n * 16);
    dump("k0", K0.data(), d * 16);
    dump("krecv", Krecv.data(), d * 16);
    dump("recv", rleaves.data(), n * 16);
    return 0;
}
