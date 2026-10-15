// Generator and verifier for Fe25519::square()'s merged factors.
//
// WHY THIS IS A PROGRAM AND NOT A COMMENT
//
// docs/history/09-field-and-aead.md records two attempts at writing a dedicated squaring for
// `Fe25519`, and both were wrong. The reason is specific: the 2^25.5 radix applies its
// corrections *asymmetrically* -- the odd-index doubling belongs to one operand and the
// 19-fold to the other -- so the product matrix is symmetric in value but not in
// correction. The merged factor for an off-diagonal pair is therefore the SUM of the two
// single-term factors, not twice one of them, and deriving that sum by hand is exactly
// what produces a square() that agrees with itself and with nothing else.
//
// So the factors in fe25519.cpp are emitted from here, and this program refuses to emit
// anything until it has checked itself against mul() numerically:
//
//   1. transcribe mul()'s per-term factor rule from its own t0..t9 expressions
//   2. check that rule reproduces mul() on all ten limbs, over random inputs
//   3. merge the off-diagonals by summing, and check that against mul() the same way
//   4. only then emit the C++
//
// A wrong factor cannot pass step 2 or 3, so it cannot reach the library.
//
// BUILD AND RUN
//
//   g++ -O2 -std=c++17 tools/fe_square_gen.cpp \
//       -Iinclude -Isrc -o /tmp/fe_square_gen && /tmp/fe_square_gen
//
// It is a standalone tool, not part of the CMake build: nothing in the library depends on
// it at run time, and it is only needed when the squaring is changed.

#include "crypto/asyms/fe25519.hpp"

#include <cstdio>
#include <random>
#include <string>
#include <vector>

using certpp::crypto::Fe25519;

namespace {
    constexpr size_t L = Fe25519::LIMBS;   // 10

    /* The single-term factor rule, read off mul()'s t0..t9 expressions:
     *
     *   - f is doubled when i is odd AND the output limb k is even. Both halves of that
     *     condition are load-bearing and neither is guessable: t0/t2/t4/t6/t8 (even k)
     *     double f1..f9, while t1/t3/t5/t7/t9 (odd k) double nothing at all. "f is doubled
     *     when i is odd" is true of only half the rows and produces a square() that is
     *     wrong for every input.
     *   - g is scaled by 19 when the term wraps, i.e. i + j >= 10. A wrapping term always
     *     has j >= 1, so the "g1..g9 are pre-scaled, g0 is not" split in mul() is a
     *     consequence of where the wrap boundary is rather than a separate rule.
     *
     * k = (i + j) mod 10.
     */
    int termFactor(size_t i, size_t j) {
        const size_t k = (i + j) % L;
        const bool wrap = (i + j) >= L;
        const int two = ((i % 2 == 1) && (k % 2 == 0)) ? 2 : 1;
        const int nineteen = wrap ? 19 : 1;
        return two * nineteen;
    }

    /* Compare mul()'s limb sums, computed by transcribing its t0..t9 expressions, against
     * the same sums computed from termFactor(). Per-limb and before any carry pass, so a
     * factor error cannot hide behind a reduction that happens to repair it. */
    bool ruleMatchesMul(std::mt19937_64& rng) {
        std::uniform_int_distribution<int32_t> dist(-(1 << 20), (1 << 20));
        for (int trial = 0; trial < 200; ++trial) {
            Fe25519 a;
            for (size_t i = 0; i < L; ++i) a.limbs[i] = int32_t(dist(rng));

            std::vector<int64_t> byRule(L, 0);
            for (size_t i = 0; i < L; ++i) {
                for (size_t j = 0; j < L; ++j) {
                    byRule[(i + j) % L] += int64_t(termFactor(i, j)) * a.limbs[i] * a.limbs[j];
                }
            }

            const int64_t f0 = a.limbs[0], f1 = a.limbs[1], f2 = a.limbs[2];
            const int64_t f3 = a.limbs[3], f4 = a.limbs[4], f5 = a.limbs[5];
            const int64_t f6 = a.limbs[6], f7 = a.limbs[7], f8 = a.limbs[8];
            const int64_t f9 = a.limbs[9];
            const int64_t g0 = f0, g1 = f1, g2 = f2, g3 = f3, g4 = f4;
            const int64_t g5 = f5, g6 = f6, g7 = f7, g8 = f8, g9 = f9;
            const int64_t f1_2 = f1 * 2, f3_2 = f3 * 2, f5_2 = f5 * 2;
            const int64_t f7_2 = f7 * 2, f9_2 = f9 * 2;
            const int64_t g1_19 = g1 * 19, g2_19 = g2 * 19, g3_19 = g3 * 19;
            const int64_t g4_19 = g4 * 19, g5_19 = g5 * 19, g6_19 = g6 * 19;
            const int64_t g7_19 = g7 * 19, g8_19 = g8 * 19, g9_19 = g9 * 19;

            // Transcribed from Fe25519::mul's 2^25.5 branch, unchanged.
            const int64_t t0 = f0*g0 + f1_2*g9_19 + f2*g8_19 + f3_2*g7_19 + f4*g6_19
                             + f5_2*g5_19 + f6*g4_19 + f7_2*g3_19 + f8*g2_19 + f9_2*g1_19;
            const int64_t t1 = f0*g1 + f1*g0 + f2*g9_19 + f3*g8_19 + f4*g7_19 + f5*g6_19
                             + f6*g5_19 + f7*g4_19 + f8*g3_19 + f9*g2_19;
            const int64_t t2 = f0*g2 + f1_2*g1 + f2*g0 + f3_2*g9_19 + f4*g8_19 + f5_2*g7_19
                             + f6*g6_19 + f7_2*g5_19 + f8*g4_19 + f9_2*g3_19;
            const int64_t t3 = f0*g3 + f1*g2 + f2*g1 + f3*g0 + f4*g9_19 + f5*g8_19
                             + f6*g7_19 + f7*g6_19 + f8*g5_19 + f9*g4_19;
            const int64_t t4 = f0*g4 + f1_2*g3 + f2*g2 + f3_2*g1 + f4*g0 + f5_2*g9_19
                             + f6*g8_19 + f7_2*g7_19 + f8*g6_19 + f9_2*g5_19;
            const int64_t t5 = f0*g5 + f1*g4 + f2*g3 + f3*g2 + f4*g1 + f5*g0
                             + f6*g9_19 + f7*g8_19 + f8*g7_19 + f9*g6_19;
            const int64_t t6 = f0*g6 + f1_2*g5 + f2*g4 + f3_2*g3 + f4*g2 + f5_2*g1
                             + f6*g0 + f7_2*g9_19 + f8*g8_19 + f9_2*g7_19;
            const int64_t t7 = f0*g7 + f1*g6 + f2*g5 + f3*g4 + f4*g3 + f5*g2
                             + f6*g1 + f7*g0 + f8*g9_19 + f9*g8_19;
            const int64_t t8 = f0*g8 + f1_2*g7 + f2*g6 + f3_2*g5 + f4*g4 + f5_2*g3
                             + f6*g2 + f7_2*g1 + f8*g0 + f9_2*g9_19;
            const int64_t t9 = f0*g9 + f1*g8 + f2*g7 + f3*g6 + f4*g5 + f5*g4
                             + f6*g3 + f7*g2 + f8*g1 + f9*g0;
            const int64_t byMul[L] = { t0, t1, t2, t3, t4, t5, t6, t7, t8, t9 };

            for (size_t k = 0; k < L; ++k) {
                if (byMul[k] != byRule[k]) {
                    std::printf("FAIL rule vs mul(): trial %d limb %zu: "
                                "mul %lld, rule %lld\n",
                                trial, k, (long long)byMul[k], (long long)byRule[k]);
                    return false;
                }
            }
        }
        std::printf("  ok: the rule reproduces mul() on all %zu limbs x 200 random inputs\n", L);
        return true;
    }

    struct Term {
        size_t out;    // output limb
        int factor;
        size_t i, j;   // i <= j
    };

    /* Merge. A diagonal keeps its single factor. An off-diagonal is the SUM of the two
     * single-term factors -- the step the roadmap says two earlier passes got wrong. */
    std::vector<Term> merged() {
        std::vector<Term> out;
        for (size_t i = 0; i < L; ++i) {
            out.push_back({ (2 * i) % L, termFactor(i, i), i, i });
            for (size_t j = i + 1; j < L; ++j) {
                const size_t k = (i + j) % L;
                out.push_back({ k, termFactor(i, j) + termFactor(j, i), i, j });
            }
        }
        return out;
    }

    bool verifyMerged(std::mt19937_64& rng) {
        const std::vector<Term> terms = merged();
        std::uniform_int_distribution<int32_t> dist(-(1 << 20), (1 << 20));
        for (int trial = 0; trial < 20000; ++trial) {
            Fe25519 a;
            for (size_t i = 0; i < L; ++i) a.limbs[i] = int32_t(dist(rng));

            std::vector<int64_t> want(L, 0), got(L, 0);
            for (size_t i = 0; i < L; ++i) {
                for (size_t j = 0; j < L; ++j) {
                    want[(i + j) % L] += int64_t(termFactor(i, j)) * a.limbs[i] * a.limbs[j];
                }
            }
            for (const Term& t : terms) {
                got[t.out] += int64_t(t.factor) * a.limbs[t.i] * a.limbs[t.j];
            }
            for (size_t k = 0; k < L; ++k) {
                if (got[k] != want[k]) {
                    std::printf("FAIL merged vs mul(): trial %d limb %zu: "
                                "mul %lld, merged %lld\n",
                                trial, k, (long long)want[k], (long long)got[k]);
                    return false;
                }
            }
        }
        std::printf("  ok: the merged form reproduces mul() on all %zu limbs x 20000 random inputs\n", L);
        std::printf("  ok: %zu products, against mul()'s %zu\n", terms.size(), L * L);
        return true;
    }

    std::string emit() {
        const std::vector<Term> terms = merged();
        std::string s;
        char buf[128];
        s += "        const int64_t s0 = a.limbs[0], s1 = a.limbs[1], s2 = a.limbs[2];\n";
        s += "        const int64_t s3 = a.limbs[3], s4 = a.limbs[4], s5 = a.limbs[5];\n";
        s += "        const int64_t s6 = a.limbs[6], s7 = a.limbs[7], s8 = a.limbs[8];\n";
        s += "        const int64_t s9 = a.limbs[9];\n\n";
        for (size_t k = 0; k < L; ++k) {
            std::snprintf(buf, sizeof(buf), "        int64_t t%zu =", k);
            s += buf;
            bool first = true;
            for (const Term& t : terms) {
                if (t.out != k) continue;
                std::snprintf(buf, sizeof(buf), "%s %d*s%zu*s%zu",
                              first ? "" : " +", t.factor, t.i, t.j);
                s += buf;
                first = false;
            }
            s += ";\n";
        }
        return s;
    }
}

int main() {
    std::mt19937_64 rng(20261013);
    std::printf("Fe25519 squaring factor generator\n");
    if (!ruleMatchesMul(rng)) return 1;
    if (!verifyMerged(rng)) return 1;
    std::printf("\n--- the ten limb sums to paste into Fe25519::square ---\n\n");
    std::printf("%s", emit().c_str());
    return 0;
}
