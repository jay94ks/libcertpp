#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "crypto/hashers/streebogcore.hpp"
#include <cstring>

using namespace certpp;
using namespace certpp::crypto;

namespace {

    /* RFC 6986 section 6.3's byte permutation Tau, transcribed here rather than in the
     * implementation -- which derives Tau(8w + t) == w + 8t algebraically instead of storing
     * the table, and so needs that identity checked against the real Tau somewhere. */
    const uint8_t TAU[64] = {
        0,  8, 16, 24, 32, 40, 48, 56,
        1,  9, 17, 25, 33, 41, 49, 57,
        2, 10, 18, 26, 34, 42, 50, 58,
        3, 11, 19, 27, 35, 43, 51, 59,
        4, 12, 20, 28, 36, 44, 52, 60,
        5, 13, 21, 29, 37, 45, 53, 61,
        6, 14, 22, 30, 38, 46, 54, 62,
        7, 15, 23, 31, 39, 47, 55, 63
    };

    /* LPS written out exactly as RFC 6986 section 7 defines it: S, then P, then L, each as its
     * own pass, with l() summing matrix rows one bit at a time. Deliberately the slow, literal
     * reading of the spec, so it can disagree with the implementation's combined lookup table
     * if that table's derivation is wrong. */
    void literalLps(uint8_t state[64]) {
        uint8_t afterS[64];
        for (size_t i = 0; i < 64; ++i) {
            afterS[i] = StreebogCore::PI[state[i]];
        }

        // --> P(a) puts a_(Tau(j)) at position j, and this layout indexes by position directly.
        uint8_t afterP[64];
        for (size_t j = 0; j < 64; ++j) {
            afterP[j] = afterS[TAU[j]];
        }

        for (size_t w = 0; w < 8; ++w) {
            uint64_t word = 0;
            for (size_t j = 0; j < 8; ++j) {
                word |= uint64_t(afterP[w * 8 + j]) << (8 * j);
            }

            uint64_t result = 0;
            for (size_t i = 0; i < 64; ++i) {
                if ((word >> (63 - i)) & 1) {
                    result ^= StreebogCore::A[i];
                }
            }

            for (size_t j = 0; j < 8; ++j) {
                state[w * 8 + j] = uint8_t(result >> (8 * j));
            }
        }
    }

    /* A cheap deterministic generator, so the comparison below covers inputs no published
     * vector happens to produce. */
    uint32_t nextRandom(uint32_t& seed) {
        seed = seed * 1664525u + 1013904223u;
        return seed;
    }

} // namespace

/* Pi' must be a permutation of 0..255. A single mistyped entry would almost certainly break
 * this, and it is the one property of the substitution that can be checked without re-deriving
 * the whole table. */
TEST_CASE("Streebog's Pi' substitution is a bijection on V_8") {
    bool seen[256] = { false };

    for (size_t i = 0; i < 256; ++i) {
        const uint8_t value = StreebogCore::PI[i];
        CHECK_FALSE(seen[value]);
        seen[value] = true;
    }

    for (size_t i = 0; i < 256; ++i) {
        CHECK(seen[i]);
    }
}

/* The identity the combined lookup table is built on. transformLps() never consults Tau; it
 * reads state[w + 8t] for output word w's byte t, which is only correct because Tau is this
 * particular permutation. */
TEST_CASE("Streebog's Tau satisfies Tau(8w + t) == w + 8t") {
    bool seen[64] = { false };

    for (size_t w = 0; w < 8; ++w) {
        for (size_t t = 0; t < 8; ++t) {
            CHECK(size_t(TAU[w * 8 + t]) == w + 8 * t);
        }
    }

    for (size_t i = 0; i < 64; ++i) {
        CHECK_FALSE(seen[TAU[i]]);
        seen[TAU[i]] = true;
    }
}

/* The combined S/P/L table against the literal three-pass spec reading. The RFC's own vectors
 * only ever exercise the fast path, so without this there is nothing checking that the table's
 * derivation (and the Tau identity it relies on) is right rather than merely consistent. */
TEST_CASE("Streebog's combined LPS table agrees with the literal spec reading") {
    SUBCASE("the all-zero and all-ones states") {
        for (uint8_t fill : { uint8_t(0x00), uint8_t(0xFF), uint8_t(0x01), uint8_t(0x80) }) {
            CAPTURE(fill);

            uint8_t fast[64], slow[64];
            std::memset(fast, fill, sizeof(fast));
            std::memcpy(slow, fast, sizeof(slow));

            StreebogCore::transformLps(fast);
            literalLps(slow);

            CHECK(std::memcmp(fast, slow, 64) == 0);
        }
    }

    /* One byte set at a time: isolates every (position, value) pair's contribution, which is
     * exactly what an AX[t][v] entry indexed under the wrong t would get wrong. */
    SUBCASE("a single non-zero byte at each of the 64 positions") {
        for (size_t pos = 0; pos < 64; ++pos) {
            CAPTURE(pos);

            uint8_t fast[64], slow[64];
            std::memset(fast, 0, sizeof(fast));
            fast[pos] = uint8_t(0xA5);
            std::memcpy(slow, fast, sizeof(slow));

            StreebogCore::transformLps(fast);
            literalLps(slow);

            CHECK(std::memcmp(fast, slow, 64) == 0);
        }
    }

    SUBCASE("pseudorandom states") {
        uint32_t seed = 0x5EEDB065u;

        for (size_t trial = 0; trial < 64; ++trial) {
            CAPTURE(trial);

            uint8_t fast[64], slow[64];
            for (size_t i = 0; i < 64; ++i) {
                fast[i] = uint8_t(nextRandom(seed) >> 16);
            }
            std::memcpy(slow, fast, sizeof(slow));

            StreebogCore::transformLps(fast);
            literalLps(slow);

            CHECK(std::memcmp(fast, slow, 64) == 0);
        }
    }
}

/* The twelve iteration constants must all differ from each other and from zero -- the cheapest
 * check that would catch a duplicated or dropped block while transcribing them. */
TEST_CASE("Streebog's twelve iteration constants are distinct and non-zero") {
    const uint8_t zero[64] = { 0 };

    for (size_t i = 0; i < 12; ++i) {
        CAPTURE(i);
        CHECK(std::memcmp(StreebogCore::C[i], zero, 64) != 0);

        for (size_t j = i + 1; j < 12; ++j) {
            CAPTURE(j);
            CHECK(std::memcmp(StreebogCore::C[i], StreebogCore::C[j], 64) != 0);
        }
    }
}

/* The mod-2^512 accumulators, whose carries run from byte position 0 upwards. */
TEST_CASE("Streebog's mod-2^512 addition carries across the whole 512 bits") {
    SUBCASE("a small addend carries out of the lowest byte") {
        uint8_t acc[64] = { 0 };
        acc[0] = 0xFF;

        StreebogCore::addMod512(acc, uint64_t(1));
        CHECK(acc[0] == 0x00);
        CHECK(acc[1] == 0x01);
    }

    SUBCASE("a carry propagates all the way to the top byte") {
        uint8_t acc[64];
        std::memset(acc, 0xFF, sizeof(acc));
        acc[63] = 0x00;

        StreebogCore::addMod512(acc, uint64_t(1));
        CHECK(acc[0] == 0x00);
        CHECK(acc[62] == 0x00);
        CHECK(acc[63] == 0x01);
    }

    SUBCASE("the all-ones accumulator wraps to zero") {
        uint8_t acc[64];
        std::memset(acc, 0xFF, sizeof(acc));

        const uint8_t one[64] = { 1 };
        StreebogCore::addMod512(acc, one);

        const uint8_t zero[64] = { 0 };
        CHECK(std::memcmp(acc, zero, 64) == 0);
    }

    SUBCASE("adding two 512-bit values agrees byte by byte") {
        uint8_t acc[64], addend[64];
        for (size_t i = 0; i < 64; ++i) {
            acc[i] = uint8_t(0x10 + i);
            addend[i] = uint8_t(0x20 + i);
        }

        StreebogCore::addMod512(acc, addend);
        for (size_t i = 0; i < 64; ++i) {
            CAPTURE(i);
            CHECK(acc[i] == uint8_t(0x30 + 2 * i));
        }
    }

    /* 512 is what push() adds per block, so this is the exact increment N sees. */
    SUBCASE("adding 512 repeatedly matches a bit counter") {
        uint8_t acc[64] = { 0 };

        for (size_t block = 0; block < 300; ++block) {
            StreebogCore::addMod512(acc, uint64_t(512));
        }

        const uint64_t expected = 300ull * 512ull;
        for (size_t i = 0; i < 8; ++i) {
            CAPTURE(i);
            CHECK(acc[i] == uint8_t(expected >> (8 * i)));
        }
        for (size_t i = 8; i < 64; ++i) {
            CAPTURE(i);
            CHECK(acc[i] == 0);
        }
    }
}
