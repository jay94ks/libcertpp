// FIPS 204 7.4's rounding and hint machinery.
//
// The property that actually matters here is the inversion: useHint(makeHint(z, r), r) must equal
// highBits(r + z) for every r and every z within gamma2. A signature carries one hint bit per
// coefficient instead of w1, and the verifier reconstructs the high bits from its own
// approximation plus those bits -- so if the inversion is off anywhere, signatures verify by
// luck. That identity is checked below over random pairs and, separately, over the boundary
// cases where it is most fragile.
//
// Everything here was validated in Python against the specification text first: all five
// operations agreed with dilithium-py 1.4.0 over 100,000 values per parameter set, and the
// inversion identity held over 200,000 random (r, z) pairs per set. That pass also corrected a
// wrong assumption -- see the carve-out test case.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include "crypto/asyms/mldsarounding.hpp"

using namespace certpp;
using namespace certpp::crypto;

namespace {
    using Poly = MlDsaRounding::Poly;

    constexpr int32_t Q = MlDsaRing::Q;
    constexpr int32_t D = MlDsaRounding::D;
    constexpr int32_t G44 = MlDsaRounding::GAMMA2_44;
    constexpr int32_t G65 = MlDsaRounding::GAMMA2_65_87;

    struct Lcg {
        uint64_t state;
        explicit Lcg(uint64_t seed) : state(seed) { }

        uint32_t next() {
            state = state * 6364136223846793005ull + 1442695040888963407ull;
            return uint32_t(state >> 33);
        }

        int32_t coefficient() {
            return int32_t(uint64_t(next()) % uint64_t(Q));
        }

        int32_t inRange(int32_t low, int32_t high) {
            return low + int32_t(uint64_t(next()) % uint64_t(high - low + 1));
        }
    };

    /* An independent mod-plus-minus, to compare the implementation against. */
    int32_t referenceModPm(int64_t value, int64_t modulus) {
        int64_t r = ((value % modulus) + modulus) % modulus;
        if (r > modulus / 2) {
            r -= modulus;
        }
        return int32_t(r);
    }
}

TEST_CASE("MlDsaRounding: the parameters are FIPS 204 Table 1's") {
    static_assert(MlDsaRounding::D == 13, "d is 13 for every parameter set");

    // gamma2 derived from q rather than written out, and the divisions are exact -- which is
    // what makes (q-1)/(2*gamma2) a whole number of buckets.
    CHECK(G44 == (Q - 1) / 88);
    CHECK(G65 == (Q - 1) / 32);
    CHECK((Q - 1) % (2 * G44) == 0);
    CHECK((Q - 1) % (2 * G65) == 0);

    // 44 buckets for ML-DSA-44, 16 for ML-DSA-65/87.
    CHECK(MlDsaRounding::highBitsRange(G44) == 44);
    CHECK(MlDsaRounding::highBitsRange(G65) == 16);
}

TEST_CASE("MlDsaRounding: modPm puts m/2 on the positive side") {
    // The boundary is the whole content of this operation: for an even modulus the range is
    // (-m/2, m/2], so m/2 stays positive and m/2 + 1 wraps negative. One off-by-one here
    // misfiles one coefficient value in every 2*gamma2.
    CHECK(MlDsaRounding::modPm(0, 16) == 0);
    CHECK(MlDsaRounding::modPm(8, 16) == 8);
    CHECK(MlDsaRounding::modPm(9, 16) == -7);
    CHECK(MlDsaRounding::modPm(15, 16) == -1);
    CHECK(MlDsaRounding::modPm(16, 16) == 0);
    CHECK(MlDsaRounding::modPm(-1, 16) == -1);
    CHECK(MlDsaRounding::modPm(-8, 16) == 8);

    const int32_t twoG = 2 * G44;
    CHECK(MlDsaRounding::modPm(G44, twoG) == G44);
    CHECK(MlDsaRounding::modPm(G44 + 1, twoG) == -(G44 - 1));

    Lcg rng(0x0D5A1);
    for (int trial = 0; trial < 20000; ++trial) {
        const int32_t value = rng.coefficient();
        for (int32_t modulus : { int32_t(1) << D, 2 * G44, 2 * G65 }) {
            const int32_t got = MlDsaRounding::modPm(value, modulus);
            REQUIRE(got == referenceModPm(value, modulus));
            REQUIRE(got > -modulus / 2);
            REQUIRE(got <= modulus / 2);
        }
    }
}

TEST_CASE("MlDsaRounding: power2Round splits exactly") {
    // The identity is exact, not modular: r == r1*2^d + r0 as integers.
    for (int32_t r : { 0, 1, 4095, 4096, 4097, 8191, 8192, Q - 2, Q - 1 }) {
        int32_t r1 = 0, r0 = 0;
        MlDsaRounding::power2Round(r, r1, r0);
        REQUIRE((int64_t(r1) << D) + int64_t(r0) == int64_t(r));
    }

    Lcg rng(0x20F0);
    int32_t maxHigh = 0;
    for (int trial = 0; trial < 60000; ++trial) {
        const int32_t r = rng.coefficient();

        int32_t r1 = 0, r0 = 0;
        MlDsaRounding::power2Round(r, r1, r0);

        REQUIRE((int64_t(r1) << D) + int64_t(r0) == int64_t(r));
        REQUIRE(r0 > -(int32_t(1) << (D - 1)));
        REQUIRE(r0 <= (int32_t(1) << (D - 1)));
        REQUIRE(r1 >= 0);
        REQUIRE(r1 < (int32_t(1) << (23 - D)));

        if (r1 > maxHigh) {
            maxHigh = r1;
        }
    }

    // FIPS 204 says t1's coefficients fit in 23 - d = 10 bits, which is what SimpleBitPack
    // relies on later.
    CHECK(maxHigh <= (int32_t(1) << (23 - D)) - 1);
}

TEST_CASE("MlDsaRounding: decompose satisfies its congruence and ranges") {
    Lcg rng(0xDEC0);

    for (int32_t gamma2 : { G44, G65 }) {
        const int32_t buckets = MlDsaRounding::highBitsRange(gamma2);

        for (int trial = 0; trial < 40000; ++trial) {
            const int32_t r = rng.coefficient();

            int32_t r1 = 0, r0 = 0;
            MlDsaRounding::decompose(r, gamma2, r1, r0);

            // Algorithm 36's own invariant, modulo q this time rather than exactly.
            REQUIRE((int64_t(r1) * 2 * gamma2 + int64_t(r0) - int64_t(r)) % Q == 0);
            REQUIRE(r1 >= 0);
            REQUIRE(r1 < buckets);
            REQUIRE(r0 > -gamma2 - 1);
            REQUIRE(r0 <= gamma2);

            // highBits/lowBits must agree with the split they are defined from.
            REQUIRE(MlDsaRounding::highBits(r, gamma2) == r1);
            REQUIRE(MlDsaRounding::lowBits(r, gamma2) == r0);
        }
    }
}

// This is the test that exists because the Python pass contradicted an assumption. FIPS 204
// Algorithm 36 branches on `r+ - r0 == q - 1`, and it is tempting to read that as "the single
// value r == q - 1". It is not: the condition holds across the whole top band of width gamma2.
// Simplifying it to a point comparison would put 95231 coefficients (ML-DSA-44) into the wrong
// bucket, and nothing but a vector from another implementation would catch it.
TEST_CASE("MlDsaRounding: decompose's (q-1) carve-out covers a band, not a point") {
    const int32_t gammas[] = { G44, G65 };

    for (int32_t gamma2 : gammas) {
        const int32_t buckets = MlDsaRounding::highBitsRange(gamma2);

        // Every r in [q - gamma2, q - 1] takes the branch, and every one of them gets r1 == 0.
        int32_t taken = 0;
        for (int32_t r = Q - gamma2; r <= Q - 1; ++r) {
            int32_t r1 = 0, r0 = 0;
            MlDsaRounding::decompose(r, gamma2, r1, r0);

            REQUIRE(r1 == 0);
            REQUIRE(r0 <= 0);
            ++taken;
        }
        CHECK(taken == gamma2);

        // The coefficient just below the band does *not* take it, and lands in the top bucket.
        int32_t r1 = 0, r0 = 0;
        MlDsaRounding::decompose(Q - gamma2 - 1, gamma2, r1, r0);
        CHECK(r1 == buckets - 1);

        // Without the branch r1 would be `buckets`, one past the top of its range -- which is
        // the concrete reason the carve-out exists at all.
        CHECK(r1 < buckets);
    }

    // Spelled out for the headline values, so a future reader does not have to recompute them.
    CHECK(G44 == 95232);
    CHECK(G65 == 261888);
}

TEST_CASE("MlDsaRounding: useHint inverts makeHint for every z within gamma2") {
    Lcg rng(0x8E147);

    for (int32_t gamma2 : { G44, G65 }) {
        for (int trial = 0; trial < 40000; ++trial) {
            const int32_t r = rng.coefficient();
            const int32_t z = rng.inRange(-gamma2, gamma2);

            const uint8_t hint = MlDsaRounding::makeHint(z, r, gamma2);

            int32_t sum = (r + z) % Q;
            if (sum < 0) {
                sum += Q;
            }

            REQUIRE(MlDsaRounding::useHint(hint, r, gamma2)
                    == MlDsaRounding::highBits(sum, gamma2));
        }
    }
}

// The inversion is most fragile where r sits exactly on a bucket boundary and z pushes it across,
// and at z = +/-gamma2 exactly -- the edge of the bound the signing loop enforces. Random
// sampling hits those with vanishing probability, so they are enumerated.
TEST_CASE("MlDsaRounding: the hint inversion holds at the bucket boundaries") {
    for (int32_t gamma2 : { G44, G65 }) {
        const int32_t buckets = MlDsaRounding::highBitsRange(gamma2);

        for (int32_t bucket = 0; bucket < buckets; ++bucket) {
            const int32_t centre = bucket * 2 * gamma2;

            for (int32_t offset : { -2, -1, 0, 1, 2 }) {
                const int32_t r = ((centre + offset) % Q + Q) % Q;

                for (int32_t z : { -gamma2, -gamma2 + 1, -1, 0, 1, gamma2 - 1, gamma2 }) {
                    const uint8_t hint = MlDsaRounding::makeHint(z, r, gamma2);

                    int32_t sum = (r + z) % Q;
                    if (sum < 0) {
                        sum += Q;
                    }

                    REQUIRE(MlDsaRounding::useHint(hint, r, gamma2)
                            == MlDsaRounding::highBits(sum, gamma2));
                }
            }
        }
    }

    // And across the carve-out band, where decompose() behaves differently from everywhere else.
    for (int32_t gamma2 : { G44, G65 }) {
        for (int32_t step = 0; step < 64; ++step) {
            const int32_t r = Q - 1 - step;

            for (int32_t z : { -gamma2, -1, 0, 1, gamma2 }) {
                const uint8_t hint = MlDsaRounding::makeHint(z, r, gamma2);

                int32_t sum = (r + z) % Q;
                if (sum < 0) {
                    sum += Q;
                }

                REQUIRE(MlDsaRounding::useHint(hint, r, gamma2)
                        == MlDsaRounding::highBits(sum, gamma2));
            }
        }
    }
}

TEST_CASE("MlDsaRounding: a zero hint leaves the high bits alone, and the tie goes down") {
    Lcg rng(0x717);

    for (int32_t gamma2 : { G44, G65 }) {
        for (int trial = 0; trial < 5000; ++trial) {
            const int32_t r = rng.coefficient();
            CHECK(MlDsaRounding::useHint(0, r, gamma2) == MlDsaRounding::highBits(r, gamma2));
        }

        // r0 == 0 counts as "not positive", so a set hint steps *down*. Splitting that tie the
        // other way would break exactly the coefficients sitting on a bucket boundary.
        const int32_t onBoundary = 2 * gamma2; // bucket 1 exactly, so r0 == 0
        int32_t r1 = 0, r0 = 0;
        MlDsaRounding::decompose(onBoundary, gamma2, r1, r0);
        REQUIRE(r0 == 0);
        REQUIRE(r1 == 1);
        CHECK(MlDsaRounding::useHint(1, onBoundary, gamma2) == 0);

        // And from bucket 0 it wraps to the top rather than going negative.
        MlDsaRounding::decompose(0, gamma2, r1, r0);
        REQUIRE(r1 == 0);
        REQUIRE(r0 == 0);
        CHECK(MlDsaRounding::useHint(1, 0, gamma2)
              == MlDsaRounding::highBitsRange(gamma2) - 1);
    }
}

TEST_CASE("MlDsaRounding: the polynomial forms match the scalar ones, and may alias") {
    Lcg rng(0x901A);

    Poly original;
    for (size_t i = 0; i < MlDsaRing::N; ++i) {
        original.coeffs[i] = rng.coefficient();
    }

    Poly high, low;
    MlDsaRounding::power2Round(original, high, low);
    for (size_t i = 0; i < MlDsaRing::N; ++i) {
        int32_t r1 = 0, r0 = 0;
        MlDsaRounding::power2Round(original.coeffs[i], r1, r0);
        REQUIRE(high.coeffs[i] == r1);
        REQUIRE(low.coeffs[i] == r0);
    }

    for (int32_t gamma2 : { G44, G65 }) {
        MlDsaRounding::decompose(original, gamma2, high, low);
        for (size_t i = 0; i < MlDsaRing::N; ++i) {
            int32_t r1 = 0, r0 = 0;
            MlDsaRounding::decompose(original.coeffs[i], gamma2, r1, r0);
            REQUIRE(high.coeffs[i] == r1);
            REQUIRE(low.coeffs[i] == r0);
        }
    }

    // The doc comment says high/low may alias the input; exercise it rather than trusting it.
    Poly aliased = original;
    Poly separateLow;
    MlDsaRounding::power2Round(aliased, aliased, separateLow);
    for (size_t i = 0; i < MlDsaRing::N; ++i) {
        int32_t r1 = 0, r0 = 0;
        MlDsaRounding::power2Round(original.coeffs[i], r1, r0);
        REQUIRE(aliased.coeffs[i] == r1);
        REQUIRE(separateLow.coeffs[i] == r0);
    }

    Poly aliasedLow = original;
    Poly separateHigh;
    MlDsaRounding::decompose(aliasedLow, G65, separateHigh, aliasedLow);
    for (size_t i = 0; i < MlDsaRing::N; ++i) {
        int32_t r1 = 0, r0 = 0;
        MlDsaRounding::decompose(original.coeffs[i], G65, r1, r0);
        REQUIRE(separateHigh.coeffs[i] == r1);
        REQUIRE(aliasedLow.coeffs[i] == r0);
    }
}
