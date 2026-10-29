// Seeded-bootstrap Ferret golden extractor.
//
// Demonstrates the "inject the base correlations" hook: a Ferret subclass
// whose bootstrap is replaced by a deterministic, public-seed RCOT, so the
// extension starts from reproducible base COTs instead of the SoftSpoken
// bootstrap. Both parties feed it the same (public, test-only) seed and Δ, so
// the base correlations — and, with EMP_TEST_MODE making the remaining PRG
// streams deterministic, the whole run — are reproducible.
//
// It runs `FERRET_TRACE_ROUNDS` rcot() calls (default one round), verifies the
// correlations (verify_rcot), optionally tees the wire bytes to
// `<TRACE_PREFIX>_<A|B>.{send,recv}`, and prints a digest of each party's
// output. Only the semi-honest extend stream is traced; the consistency check
// is not part of the golden.
//
// Usage: ./run ./emp-ot-dump-ferret

#include "emp-ot/emp-ot.h"
#include "emp-ot/ot_extension/ferret/ferret.h"
#include "emp-tool/runtime/io/trace_io.h"
#include "test/test.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
using namespace emp;

// Ferret whose bootstrap is replaced by a seed-derived RCOT.
//
// The base COTs are a valid Δ-correlated COT: both parties draw the same key
// stream from `seed` (LSBs cleared), and the receiver XORs Δ at its choice
// positions (a second stream from `seed`). Δ is public for the test.
class SeededFerret : public Ferret {
public:
    SeededFerret(int party, IOChannel *io,
                 PrimalLPNParameter param, block seed, block delta)
        : Ferret(party, io, /*malicious=*/false, nullptr, param), boot_seed_(seed) {
        this->Delta = delta;
        if (is_ot_sender()) gadget_send_->set_cggm_delta(delta);
    }

protected:
    void bootstrap_() override {
        if (setup_done) return;
        if (!io->fs_enabled()) io->enable_fs(is_ot_sender());

        const int64_t m = param.M;
        const block clear = makeBlock(0xFFFFFFFFFFFFFFFFULL,
                                      0xFFFFFFFFFFFFFFFEULL);

        // Same key stream on both sides (LSB cleared -> sender LSB = 0, so the
        // receiver's LSB encodes its choice, matching the COT LSB convention).
        PRG key_prg(&boot_seed_);
        key_prg.random_block(carry_next_.data(), m);
        for (int64_t i = 0; i < m; ++i)
            carry_next_[i] = carry_next_[i] & clear;

        if (!is_ot_sender()) {
            block choice_seed = boot_seed_ ^ makeBlock(0ULL, 1ULL);
            PRG choice_prg(&choice_seed);
            default_init_vector<unsigned char> bo(m);
            choice_prg.random_bool(reinterpret_cast<bool *>(bo.data()), m);
            for (int64_t i = 0; i < m; ++i)
                if (bo[i]) carry_next_[i] = carry_next_[i] ^ Delta;
        }

        setup_done = true;
    }

private:
    block boot_seed_;
};

// Parses 32 hex chars into a block with the same byte order as emp-tool's
// makeBlock(hi, lo) and the Rust `Block` (first 8 bytes = low half, LE).
static block block_from_hex(const char *hex) {
    auto nib = [](char c) -> uint64_t {
        if (c >= '0' && c <= '9') return (uint64_t)(c - '0');
        if (c >= 'a' && c <= 'f') return (uint64_t)(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return (uint64_t)(c - 'A' + 10);
        fprintf(stderr, "block_from_hex: bad hex digit '%c'\n", c);
        exit(2);
    };
    if (strlen(hex) != 32) {
        fprintf(stderr, "block_from_hex: expected 32 hex chars, got '%s'\n", hex);
        exit(2);
    }
    uint8_t bytes[16];
    for (int i = 0; i < 16; ++i)
        bytes[i] = (uint8_t)((nib(hex[2 * i]) << 4) | nib(hex[2 * i + 1]));
    uint64_t lo = 0, hi = 0;
    for (int i = 0; i < 8; ++i) lo |= (uint64_t)bytes[i] << (8 * i);
    for (int i = 0; i < 8; ++i) hi |= (uint64_t)bytes[8 + i] << (8 * i);
    return makeBlock(hi, lo);
}

// Env override for a block-valued knob, with a fallback default.
static block env_block(const char *name, block dflt) {
    if (const char *v = std::getenv(name)) return block_from_hex(v);
    return dflt;
}

// Env-selected LPN parameter preset: FERRET_PARAM = b10 | b11 | b12 | b13.
static PrimalLPNParameter env_param() {
    const char *v = std::getenv("FERRET_PARAM");
    std::string s = v ? v : "b11";
    if (s == "b10") return tuning::ferret_b10;
    if (s == "b11") return tuning::ferret_b11;
    if (s == "b12") return tuning::ferret_b12;
    if (s == "b13") return tuning::ferret_b13;
    fprintf(stderr, "FERRET_PARAM: unknown preset '%s'\n", s.c_str());
    exit(2);
}

int main(int argc, char **argv) {
    int party = parse_party(argv);
    int port = peer_port();
    auto raw = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

    // Optionally tee the wire bytes to <TRACE_PREFIX>_<A|B>.{send,recv}.
    std::unique_ptr<TraceIO> traced;
    IOChannel *io = raw.get();
    if (const char *prefix = std::getenv("TRACE_PREFIX")) {
        std::string p = std::string(prefix) + (party == ALICE ? "_A" : "_B");
        traced = std::make_unique<TraceIO>(raw.get(), p);
        io = traced.get();
    }

    // Public, test-only seed and Δ (LSB = 1 as Ferret requires). Both, plus
    // the session id and parameter preset, are env-overridable.
    block seed = env_block("FERRET_BOOT_SEED",
                           makeBlock(0x0123456789abcdefULL, 0xfedcba9876543210ULL));
    block delta = env_block("FERRET_DELTA",
                            makeBlock(0x1122334455667788ULL, 0x99aabbccddeeff01ULL));

    SeededFerret ot(party, io, env_param(), seed, delta);
    ot.set_sid(env_block("FERRET_SID", zero_block));

    // One full round: the user-visible trees (t - refill_trees), which makes
    // end() add the refill_trees trees, for t trees of corrections total.
    // Number of full rounds to trace: FERRET_TRACE_ROUNDS (default 1).
    int64_t rounds = 1;
    if (const char *r = getenv("FERRET_TRACE_ROUNDS")) rounds = atoll(r);
    const int64_t length = rounds * (ot.param.t - ot.param.refill_trees) * ot.chunk_size();
    block *b = new block[length];
    ot.rcot(b, length);

    verify_rcot(&ot, raw.get(), party, b, length);

    block fold = zero_block;
    for (int64_t i = 0; i < length; ++i) fold = fold ^ b[i];
    printf("dump-ferret length=%lld fold=%s\n", (long long)length,
           to_hex(&fold, 8).c_str());
    delete[] b;
    return 0;
}
