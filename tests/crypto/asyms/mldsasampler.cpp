// FIPS 204 7.3's pseudorandom sampling.
//
// These are deterministic functions of their seeds, so they are pinned against known answers
// rather than only against their own invariants. The expected values come from a Python
// reference written from the specification text and cross-checked against dilithium-py 1.4.0,
// which agreed on SampleInBall, the full ExpandA matrix and both ExpandS vectors for all three
// parameter sets. A structural check alone would not catch the things most likely to be wrong
// here -- the XOF choice, the sign-bit ordering, or ExpandA's transposed seed bytes -- because
// every one of them still yields a well-formed output.
//
// The fingerprint is order-sensitive, so a permutation of the coefficients fails it; individual
// coefficients are spelled out alongside so a failure says something more useful than "differs".

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include "crypto/asyms/mldsasampler.hpp"

#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    using Poly = MlDsaSampler::Poly;

    constexpr size_t N = MlDsaRing::N;

    /* Order-sensitive fingerprint, matching the one the reference used. */
    uint64_t fingerprint(const Poly& p) {
        uint64_t acc = 1469598103934665603ull;
        for (size_t i = 0; i < N; ++i) {
            acc ^= uint64_t(uint32_t(p.coeffs[i])) + 0x9E3779B97F4A7C15ull + (acc << 6) + (acc >> 2);
            acc *= 1099511628211ull;
        }
        return acc;
    }

    /* The seeds the reference used, built by formula rather than embedded as blobs. */
    std::vector<uint8_t> rampSeed(size_t length, uint8_t step, uint8_t offset) {
        std::vector<uint8_t> seed(length);
        for (size_t i = 0; i < length; ++i) {
            seed[i] = uint8_t(i * step + offset);
        }
        return seed;
    }
}

TEST_CASE("MlDsaSampler: CoeffFromThreeBytes masks the top bit and rejects at q") {
    int32_t out = -1;

    CHECK(MlDsaSampler::coeffFromThreeBytes(0, 0, 0, out));
    CHECK(out == 0);

    // The top bit of b2 is cleared, so 0x80 in the high byte is the same as 0x00. Masking is
    // not itself the filter, though -- the value still has to be below q.
    out = -1;
    CHECK(MlDsaSampler::coeffFromThreeBytes(0, 0, 0x80, out));
    CHECK(out == 0);

    // 2^23 - 1 survives the mask and is still above q.
    CHECK_FALSE(MlDsaSampler::coeffFromThreeBytes(0xFF, 0xFF, 0x7F, out));
    CHECK_FALSE(MlDsaSampler::coeffFromThreeBytes(0xFF, 0xFF, 0xFF, out));

    // Exactly at the boundary.
    const int32_t q = MlDsaRing::Q;
    const int32_t qm1 = q - 1;
    out = -1;
    CHECK(MlDsaSampler::coeffFromThreeBytes(
        uint8_t(qm1), uint8_t(qm1 >> 8), uint8_t(qm1 >> 16), out));
    CHECK(out == qm1);
    CHECK_FALSE(MlDsaSampler::coeffFromThreeBytes(
        uint8_t(q), uint8_t(q >> 8), uint8_t(q >> 16), out));

    // Setting the masked bit never changes the verdict.
    for (uint32_t z = 0; z < (1u << 23); z += 9973) {
        int32_t plain = 0;
        int32_t masked = 0;
        const bool a = MlDsaSampler::coeffFromThreeBytes(
            uint8_t(z), uint8_t(z >> 8), uint8_t(z >> 16), plain);
        const bool b = MlDsaSampler::coeffFromThreeBytes(
            uint8_t(z), uint8_t(z >> 8), uint8_t((z >> 16) | 0x80u), masked);

        REQUIRE(a == b);
        if (a) {
            REQUIRE(plain == masked);
            REQUIRE(plain == int32_t(z));
        }
    }
}

TEST_CASE("MlDsaSampler: CoeffFromHalfByte's two cases are not symmetric") {
    int32_t out = 0;

    // eta = 2: fifteen inputs onto five outputs, three each. The cut is at 15, not 10, and the
    // mod 5 is what spreads them -- reading it as "b < 5" would reject two thirds of valid
    // inputs and change every sampled polynomial.
    int counts2[5] = { 0, 0, 0, 0, 0 };
    for (uint8_t b = 0; b < 16; ++b) {
        if (MlDsaSampler::coeffFromHalfByte(b, 2, out)) {
            REQUIRE(b < 15);
            REQUIRE(out >= -2);
            REQUIRE(out <= 2);
            ++counts2[out + 2];
        }
        else {
            REQUIRE(b == 15);
        }
    }
    for (int i = 0; i < 5; ++i) {
        CHECK(counts2[i] == 3);
    }
    CHECK(MlDsaSampler::coeffFromHalfByte(0, 2, out));
    CHECK(out == 2);
    CHECK(MlDsaSampler::coeffFromHalfByte(4, 2, out));
    CHECK(out == -2);

    // eta = 4: nine inputs onto nine outputs, one each.
    int counts4[9] = { 0 };
    for (uint8_t b = 0; b < 16; ++b) {
        if (MlDsaSampler::coeffFromHalfByte(b, 4, out)) {
            REQUIRE(b < 9);
            REQUIRE(out >= -4);
            REQUIRE(out <= 4);
            ++counts4[out + 4];
        }
        else {
            REQUIRE(b >= 9);
        }
    }
    for (int i = 0; i < 9; ++i) {
        CHECK(counts4[i] == 1);
    }

    // No other eta exists.
    CHECK_FALSE(MlDsaSampler::coeffFromHalfByte(0, 3, out));
    CHECK_FALSE(MlDsaSampler::coeffFromHalfByte(0, 0, out));
}

TEST_CASE("MlDsaSampler: SampleInBall matches known answers and has weight tau") {
    struct Case {
        size_t tau;
        size_t seedLength;   // lambda/4
        uint64_t print;
        size_t firstPositions[3];
        int32_t firstValues[3];
    };

    const Case cases[] = {
        { 39, 32, 0xFEB33D05D96FDC75ull, { 4, 6, 9 },  { -1, 1, -1 } },
        { 49, 48, 0xCDF9345A74C28ACCull, { 2, 11, 20 }, { -1, -1, -1 } },
        { 60, 64, 0x5F65B33E6CE4854Cull, { 0, 1, 12 },  { 1, -1, -1 } },
    };

    for (const Case& c : cases) {
        const std::vector<uint8_t> seed = rampSeed(c.seedLength, 3, 2);

        Poly ball;
        REQUIRE(MlDsaSampler::sampleInBall(
            SReadOnlyByteSpan(seed.data(), seed.size()), c.tau, ball));

        CHECK(fingerprint(ball) == c.print);

        // Exactly tau nonzero coefficients, all +/-1 -- the defining property of B_tau.
        size_t nonzero = 0;
        std::vector<size_t> positions;
        for (size_t i = 0; i < N; ++i) {
            if (ball.coeffs[i] != 0) {
                REQUIRE((ball.coeffs[i] == 1 || ball.coeffs[i] == -1));
                positions.push_back(i);
                ++nonzero;
            }
        }
        CHECK(nonzero == c.tau);

        REQUIRE(positions.size() >= 3);
        for (size_t n = 0; n < 3; ++n) {
            CHECK(positions[n] == c.firstPositions[n]);
            CHECK(ball.coeffs[positions[n]] == c.firstValues[n]);
        }
    }

    // tau beyond 64 cannot work -- only 64 sign bits are squeezed.
    const std::vector<uint8_t> seed = rampSeed(32, 3, 2);
    Poly unused;
    CHECK_FALSE(MlDsaSampler::sampleInBall(
        SReadOnlyByteSpan(seed.data(), seed.size()), 65, unused));
    CHECK_FALSE(MlDsaSampler::sampleInBall(
        SReadOnlyByteSpan(seed.data(), seed.size()), 0, unused));
    CHECK_FALSE(MlDsaSampler::sampleInBall(SReadOnlyByteSpan(nullptr, 32), 39, unused));
}

TEST_CASE("MlDsaSampler: RejNTTPoly matches a known answer and stays below q") {
    const std::vector<uint8_t> seed = rampSeed(34, 7, 1);

    Poly a;
    REQUIRE(MlDsaSampler::rejNttPoly(SReadOnlyByteSpan(seed.data(), seed.size()), a));

    CHECK(fingerprint(a) == 0xCBE25E76833F4504ull);
    CHECK(a.coeffs[0] == 2684365);
    CHECK(a.coeffs[1] == 3645809);
    CHECK(a.coeffs[255] == 6809132);

    for (size_t i = 0; i < N; ++i) {
        REQUIRE(a.coeffs[i] >= 0);
        REQUIRE(a.coeffs[i] < MlDsaRing::Q);
    }

    // The seed length is fixed at 34 by the standard (rho plus two index bytes).
    CHECK_FALSE(MlDsaSampler::rejNttPoly(SReadOnlyByteSpan(seed.data(), 33), a));
    CHECK_FALSE(MlDsaSampler::rejNttPoly(SReadOnlyByteSpan(seed.data(), 35), a));
}

TEST_CASE("MlDsaSampler: RejBoundedPoly matches known answers for both eta") {
    std::vector<uint8_t> seed = rampSeed(64, 5, 3);
    seed.push_back(0);
    seed.push_back(0);

    struct Case { size_t eta; uint64_t print; int32_t first; int32_t second; int32_t last; };
    const Case cases[] = {
        { 2, 0xA95C743F01300E35ull, 1, -1, 0 },
        { 4, 0x92EE3F82AA12EB22ull, 1,  4, 4 },
    };

    for (const Case& c : cases) {
        Poly b;
        REQUIRE(MlDsaSampler::rejBoundedPoly(
            SReadOnlyByteSpan(seed.data(), seed.size()), c.eta, b));

        CHECK(fingerprint(b) == c.print);
        CHECK(b.coeffs[0] == c.first);
        CHECK(b.coeffs[1] == c.second);
        CHECK(b.coeffs[255] == c.last);

        for (size_t i = 0; i < N; ++i) {
            REQUIRE(b.coeffs[i] >= -int32_t(c.eta));
            REQUIRE(b.coeffs[i] <= int32_t(c.eta));
        }
    }

    Poly unused;
    CHECK_FALSE(MlDsaSampler::rejBoundedPoly(
        SReadOnlyByteSpan(seed.data(), 65), 2, unused));
    CHECK_FALSE(MlDsaSampler::rejBoundedPoly(
        SReadOnlyByteSpan(seed.data(), seed.size()), 3, unused));
}

// ExpandA's seed puts the COLUMN byte before the row byte (FIPS 204 Algorithm 32 line 3). Get
// that backwards and the matrix is transposed -- every key byte changes, and nothing about the
// scheme stops working on its own terms. This is the same trap as ML-KEM's SampleNTT indices.
TEST_CASE("MlDsaSampler: ExpandA seeds with the column byte first") {
    const std::vector<uint8_t> seed = rampSeed(32, 7, 1);
    const size_t k = 2;
    const size_t l = 3;

    std::vector<Poly> matrix(k * l);
    REQUIRE(MlDsaSampler::expandA(
        SReadOnlyByteSpan(seed.data(), seed.size()), k, l, matrix.data()));

    const uint64_t expected[2][3] = {
        { 0x139EFEC8F0EA76ADull, 0x811888034EF7D845ull, 0xC7C27462F0B619F9ull },
        { 0xD492853338BA22E7ull, 0xE0D7F0BFE5A41215ull, 0x5E1D8E7335A7B142ull },
    };
    const int32_t firsts[2][3] = {
        { 6195092, 1055228, 5906391 },
        { 1793134, 153960,  2978742 },
    };

    for (size_t r = 0; r < k; ++r) {
        for (size_t s = 0; s < l; ++s) {
            CHECK(fingerprint(matrix[r * l + s]) == expected[r][s]);
            CHECK(matrix[r * l + s].coeffs[0] == firsts[r][s]);
        }
    }

    // And prove the byte order directly rather than only through the fingerprints: A[1][2] is
    // seeded with s = 2 then r = 1, and the other order gives something else entirely.
    std::vector<uint8_t> manual(seed.begin(), seed.end());
    manual.push_back(2);    // s
    manual.push_back(1);    // r

    Poly direct;
    REQUIRE(MlDsaSampler::rejNttPoly(SReadOnlyByteSpan(manual.data(), manual.size()), direct));
    CHECK(fingerprint(direct) == fingerprint(matrix[1 * l + 2]));

    manual[32] = 1;         // swapped
    manual[33] = 2;

    Poly swapped;
    REQUIRE(MlDsaSampler::rejNttPoly(SReadOnlyByteSpan(manual.data(), manual.size()), swapped));
    CHECK(fingerprint(swapped) != fingerprint(matrix[1 * l + 2]));

    // Dimensions out of range are refused.
    CHECK_FALSE(MlDsaSampler::expandA(
        SReadOnlyByteSpan(seed.data(), seed.size()), 9, l, matrix.data()));
    CHECK_FALSE(MlDsaSampler::expandA(
        SReadOnlyByteSpan(seed.data(), seed.size()), k, 8, matrix.data()));
    CHECK_FALSE(MlDsaSampler::expandA(SReadOnlyByteSpan(seed.data(), 31), k, l, matrix.data()));
}

TEST_CASE("MlDsaSampler: ExpandS matches known answers, and s2 continues s1's index") {
    const std::vector<uint8_t> seed = rampSeed(64, 5, 3);
    const size_t k = 2;
    const size_t l = 3;

    std::vector<Poly> s1(l);
    std::vector<Poly> s2(k);
    REQUIRE(MlDsaSampler::expandS(
        SReadOnlyByteSpan(seed.data(), seed.size()), k, l, 2, s1.data(), s2.data()));

    const uint64_t expectedS1[3] = {
        0xA95C743F01300E35ull, 0x860AA84864E9CDA0ull, 0xDD711166DBA0F971ull
    };
    const uint64_t expectedS2[2] = { 0x0F549AE28C457AFAull, 0xE09F279DB0CBDB3Eull };

    for (size_t r = 0; r < l; ++r) {
        CHECK(fingerprint(s1[r]) == expectedS1[r]);
    }
    for (size_t r = 0; r < k; ++r) {
        CHECK(fingerprint(s2[r]) == expectedS2[r]);
    }

    CHECK(s1[0].coeffs[0] == 1);
    CHECK(s1[1].coeffs[0] == 0);
    CHECK(s2[0].coeffs[0] == 1);

    // s2[0] uses index l, not 0 -- the two vectors share rho but never a seed. If s2 restarted
    // its counter, s2[0] would equal s1[0], which is exactly the bug this checks for.
    CHECK(fingerprint(s2[0]) != fingerprint(s1[0]));

    // Every coefficient is within [-eta, eta].
    for (size_t r = 0; r < l; ++r) {
        for (size_t i = 0; i < N; ++i) {
            REQUIRE(s1[r].coeffs[i] >= -2);
            REQUIRE(s1[r].coeffs[i] <= 2);
        }
    }
}

TEST_CASE("MlDsaSampler: ExpandMask matches known answers for both gamma1") {
    const std::vector<uint8_t> seed = rampSeed(64, 5, 3);
    const size_t l = 2;

    struct Case { uint32_t gamma1; uint64_t prints[2]; int32_t firsts[2]; };
    const Case cases[] = {
        { 1u << 17, { 0x1CC150AFE3B2F113ull, 0x706A92882563911Eull }, { 1079, 47022 } },
        { 1u << 19, { 0x266600E5FB8083EBull, 0x6A5FE3633F05FC08ull }, { -129993, -346194 } },
    };

    for (const Case& c : cases) {
        std::vector<Poly> y(l);
        REQUIRE(MlDsaSampler::expandMask(
            SReadOnlyByteSpan(seed.data(), seed.size()), 7, l, c.gamma1, y.data()));

        for (size_t r = 0; r < l; ++r) {
            CHECK(fingerprint(y[r]) == c.prints[r]);
            CHECK(y[r].coeffs[0] == c.firsts[r]);

            // Coefficients land in [-gamma1 + 1, gamma1], and no rejection is involved: gamma1
            // is a power of two, so every bit pattern is a valid coefficient.
            for (size_t i = 0; i < N; ++i) {
                REQUIRE(y[r].coeffs[i] >= -int32_t(c.gamma1) + 1);
                REQUIRE(y[r].coeffs[i] <= int32_t(c.gamma1));
            }
        }
    }

    // mu shifts the per-polynomial seed, so a different mu gives different output.
    std::vector<Poly> a(l);
    std::vector<Poly> b(l);
    REQUIRE(MlDsaSampler::expandMask(
        SReadOnlyByteSpan(seed.data(), seed.size()), 7, l, 1u << 17, a.data()));
    REQUIRE(MlDsaSampler::expandMask(
        SReadOnlyByteSpan(seed.data(), seed.size()), 8, l, 1u << 17, b.data()));
    CHECK(fingerprint(a[0]) != fingerprint(b[0]));

    // And the shift is by one, so y[1] at mu == 7 is y[0] at mu == 8.
    CHECK(fingerprint(a[1]) == fingerprint(b[0]));

    // gamma1 must be a power of two; the standard's BitUnpack relies on it.
    std::vector<Poly> unused(l);
    CHECK_FALSE(MlDsaSampler::expandMask(
        SReadOnlyByteSpan(seed.data(), seed.size()), 0, l, 3, unused.data()));
    CHECK_FALSE(MlDsaSampler::expandMask(
        SReadOnlyByteSpan(seed.data(), seed.size()), 0, l, 0, unused.data()));
}

TEST_CASE("MlDsaSampler: the samplers are deterministic, and the XOFs are not interchangeable") {
    const std::vector<uint8_t> seed34 = rampSeed(34, 7, 1);

    Poly first, second;
    REQUIRE(MlDsaSampler::rejNttPoly(SReadOnlyByteSpan(seed34.data(), seed34.size()), first));
    REQUIRE(MlDsaSampler::rejNttPoly(SReadOnlyByteSpan(seed34.data(), seed34.size()), second));
    CHECK(fingerprint(first) == fingerprint(second));

    // RejNTTPoly uses SHAKE128 and RejBoundedPoly SHAKE256. They take different seed lengths,
    // so they cannot be confused by accident -- but a seed that happened to fit both would
    // produce completely different polynomials, which this records.
    std::vector<uint8_t> seed66 = rampSeed(64, 7, 1);
    seed66.push_back(0);
    seed66.push_back(0);

    Poly bounded;
    REQUIRE(MlDsaSampler::rejBoundedPoly(
        SReadOnlyByteSpan(seed66.data(), seed66.size()), 2, bounded));

    bool allSmall = true;
    for (size_t i = 0; i < N && allSmall; ++i) {
        allSmall = (bounded.coeffs[i] >= -2 && bounded.coeffs[i] <= 2);
    }
    CHECK(allSmall);
}
