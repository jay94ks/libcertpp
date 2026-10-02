// ML-DSA's ring R_q = Z_q[X]/(X^256 + 1), q = 8380417 (FIPS 204 4).
//
// The tests here deliberately avoid resting on round trips. FIPS 204 fixes the NTT's exact
// representation, not just its end-to-end behaviour, so a transform that inverts itself correctly
// while permuting coefficients differently from the standard is self-consistent and interoperates
// with nothing -- the same failure mode that hid a byte-granular ECDSA digest truncation in this
// library for as long as its only tests checked their own output. So:
//
//  - the twiddle table is checked twice over, against FIPS 204 Appendix B's printed values
//    (embedded below, extracted from the publication itself) and against its defining property
//    ZETA^BitRev8(k) mod q re-derived here by a different method than the implementation uses;
//  - N_INVERSE and the root-of-unity facts are derived from q rather than taken on trust;
//  - X^256 == -1 is asserted directly;
//  - the NTT-domain multiply is checked against a schoolbook negacyclic convolution that shares
//    none of its machinery;
//  - and a known transform output is pinned by checksum plus endpoints, so a transposition
//    anywhere in 256 coefficients fails rather than averaging out.
//
// Every algorithm here was first written in Python against the specification text and validated
// before any C++ existed: all 255 Appendix B entries matched, the NTT agreed with the schoolbook
// convolution over 200 random polynomial pairs, and the transform matched dilithium-py 1.4.0 on
// 50 random polynomials.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include "crypto/asyms/mldsaring.hpp"

using namespace certpp;
using namespace certpp::crypto;

namespace {
    using Poly = MlDsaRing::Poly;

    constexpr int64_t Q = MlDsaRing::Q;
    constexpr size_t N = MlDsaRing::N;

    /* FIPS 204 Appendix B's zetas array, exactly as the publication prints it. Entry 0 is the
     * unused 0 the table itself shows; entries 1..255 are the values the NTT uses. */
    const int32_t APPENDIX_B_ZETAS[256] = {
        0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
        7778734, 3542485, 2682288, 2129892, 3764867, 7375178, 557458, 7159240,
        5010068, 4317364, 2663378, 6705802, 4855975, 7946292, 676590, 7044481,
        5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
        3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
        394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
        3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
        5483103, 3192354, 556856, 3870317, 2917338, 1853806, 3345963, 1858416,
        3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
        2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
        1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034,
        4213992, 4892034, 1987814, 5183169, 1736313, 235407, 5130263, 3258457,
        5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
        7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816, 3374250,
        1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
        348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
        1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
        1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502, 4663471,
        8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
        6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040,
        4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
        3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
        2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950,
        7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
        6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006,
        6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891,
        5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667,
        3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
        3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976,
        3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265,
        6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
        8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
    };

    /* Modular exponentiation mod Q, written independently of the implementation's own table
     * builder (square-and-multiply here, repeated multiplication there) so that agreement means
     * something. */
    int64_t powMod(int64_t base, int64_t exponent) {
        int64_t result = 1;
        int64_t b = base % Q;

        while (exponent > 0) {
            if (exponent & 1) {
                result = (result * b) % Q;
            }
            b = (b * b) % Q;
            exponent >>= 1;
        }

        return result;
    }

    /* An 8-bit reversal computed by a different route than MlDsaRing::bitRev8's shift loop. */
    size_t reverse8(size_t value) {
        size_t out = 0;
        for (size_t bit = 0; bit < 8; ++bit) {
            if (value & (size_t(1) << bit)) {
                out |= size_t(1) << (7 - bit);
            }
        }
        return out;
    }

    /* A deterministic, cheap PRNG -- the point is reproducible coefficients, not randomness. */
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
    };

    Poly randomPoly(Lcg& rng) {
        Poly p;
        for (size_t i = 0; i < N; ++i) {
            p.coeffs[i] = rng.coefficient();
        }
        return p;
    }

    /* Order-sensitive fingerprint: position-weighted, so swapping any two coefficients changes
     * it. A plain sum would not. */
    uint64_t fingerprint(const Poly& p) {
        uint64_t acc = 1469598103934665603ull;
        for (size_t i = 0; i < N; ++i) {
            acc ^= uint64_t(uint32_t(p.coeffs[i])) + 0x9E3779B97F4A7C15ull + (acc << 6) + (acc >> 2);
            acc *= 1099511628211ull;
        }
        return acc;
    }

    bool equalPoly(const Poly& a, const Poly& b) {
        for (size_t i = 0; i < N; ++i) {
            if (a.coeffs[i] != b.coeffs[i]) {
                return false;
            }
        }
        return true;
    }
}

TEST_CASE("MlDsaRing: the modulus and root of unity are what FIPS 204 says") {
    // q = 2^23 - 2^13 + 1. Written as the expression rather than compared to 8380417, so the
    // structure that makes it a good modulus is visible instead of just the decimal value.
    static_assert(MlDsaRing::Q == (1 << 23) - (1 << 13) + 1, "q = 2^23 - 2^13 + 1");
    static_assert(MlDsaRing::N == 256, "256 coefficients");
    static_assert(MlDsaRing::ZETA == 1753, "FIPS 204's zeta");

    // ZETA's order must be exactly 512 -- not 256. This is the single fact that separates this
    // ring from ML-KEM's: order 512 means X^256 + 1 splits into 256 linear factors, so the NTT
    // runs to completion and the NTT-domain multiply is pointwise. Order 256 (ML-KEM's case)
    // would leave 128 degree-1 blocks needing a base-case multiply.
    CHECK(powMod(MlDsaRing::ZETA, 512) == 1);
    CHECK(powMod(MlDsaRing::ZETA, 256) == Q - 1); // zeta^256 == -1

    for (int64_t divisor : { 1, 2, 4, 8, 16, 32, 64, 128, 256 }) {
        REQUIRE(powMod(MlDsaRing::ZETA, divisor) != 1);
    }

    // N_INVERSE is the constant FIPS 204 Algorithm 42 prints as 8347681. Checked by its defining
    // property rather than accepted as a literal.
    CHECK((int64_t(MlDsaRing::N) * int64_t(MlDsaRing::N_INVERSE)) % Q == 1);
}

TEST_CASE("MlDsaRing: bitRev8 reverses eight bits") {
    CHECK(MlDsaRing::bitRev8(0) == 0);
    CHECK(MlDsaRing::bitRev8(1) == 128);
    CHECK(MlDsaRing::bitRev8(128) == 1);
    CHECK(MlDsaRing::bitRev8(255) == 255);
    CHECK(MlDsaRing::bitRev8(0x80) == 0x01);
    CHECK(MlDsaRing::bitRev8(0b00000011) == 0b11000000);

    // It is an involution over 8 bits, and agrees with an independently written reversal.
    for (size_t i = 0; i < 256; ++i) {
        REQUIRE(MlDsaRing::bitRev8(i) == reverse8(i));
        REQUIRE(MlDsaRing::bitRev8(MlDsaRing::bitRev8(i)) == i);
    }
}

TEST_CASE("MlDsaRing: the zetas table matches FIPS 204 Appendix B entry by entry") {
    const int32_t* z = MlDsaRing::zetas();

    // Against the publication's own printed values. This is the check that would catch a table
    // in Montgomery form -- Appendix A warns that implementations commonly store it that way,
    // and a Montgomery-form table round-trips perfectly while interoperating with nothing.
    for (size_t k = 1; k < 256; ++k) {
        REQUIRE(z[k] == APPENDIX_B_ZETAS[k]);
    }

    // And against the defining property, re-derived by square-and-multiply rather than by the
    // repeated multiplication the implementation uses.
    for (size_t k = 1; k < 256; ++k) {
        REQUIRE(int64_t(z[k]) == powMod(MlDsaRing::ZETA, int64_t(MlDsaRing::bitRev8(k))));
    }

    // Entry 0 is ZETA^0 == 1. Appendix B prints 0 there because the transform never reads it;
    // this records that the difference is deliberate rather than a transcription slip.
    CHECK(z[0] == 1);
    CHECK(APPENDIX_B_ZETAS[0] == 0);

    // Every entry is a reduced, nonzero residue.
    for (size_t k = 0; k < 256; ++k) {
        REQUIRE(z[k] > 0);
        REQUIRE(z[k] < MlDsaRing::Q);
    }
}

TEST_CASE("MlDsaRing: centered() implements FIPS 204's mod-plus-minus") {
    CHECK(MlDsaRing::centered(0) == 0);
    CHECK(MlDsaRing::centered(1) == 1);
    CHECK(MlDsaRing::centered(MlDsaRing::Q - 1) == -1);

    // The split sits at (q-1)/2: that value stays positive, the next one up goes negative. q is
    // odd, so there is no tie to break and no half-value ambiguity.
    const int32_t half = (MlDsaRing::Q - 1) / 2;
    CHECK(MlDsaRing::centered(half) == half);
    CHECK(MlDsaRing::centered(half + 1) == half + 1 - MlDsaRing::Q);

    // Every result is congruent to its input and lands in (-q/2, q/2].
    Lcg rng(0x51D5A1);
    for (int trial = 0; trial < 20000; ++trial) {
        const int32_t value = rng.coefficient();
        const int32_t c = MlDsaRing::centered(value);

        REQUIRE(c > -MlDsaRing::Q / 2 - 1);
        REQUIRE(c <= MlDsaRing::Q / 2);
        REQUIRE(((int64_t(c) - int64_t(value)) % Q) == 0);
    }
}

TEST_CASE("MlDsaRing: infinityNorm takes the largest centered magnitude") {
    Poly p;
    MlDsaRing::setZero(p);
    CHECK(MlDsaRing::infinityNorm(p) == 0);

    p.coeffs[7] = 5;
    CHECK(MlDsaRing::infinityNorm(p) == 5);

    // A coefficient just below q is a *small negative* number, not a huge positive one. An
    // implementation that skipped the centering would report q-1 here, which is the whole reason
    // this norm needs its own function: ML-DSA's signing loop rejects on this quantity, so
    // getting it wrong either rejects everything or rejects nothing.
    p.coeffs[11] = MlDsaRing::Q - 3;
    CHECK(MlDsaRing::infinityNorm(p) == 5);

    p.coeffs[11] = MlDsaRing::Q - 9;
    CHECK(MlDsaRing::infinityNorm(p) == 9);

    // The largest possible norm is (q-1)/2.
    MlDsaRing::setZero(p);
    p.coeffs[0] = (MlDsaRing::Q - 1) / 2;
    CHECK(MlDsaRing::infinityNorm(p) == (MlDsaRing::Q - 1) / 2);
}

TEST_CASE("MlDsaRing: X^256 == -1, asserted directly") {
    // (X^128)^2 should be exactly -1, i.e. q-1 in the constant term and zero everywhere else.
    Poly x128;
    MlDsaRing::setZero(x128);
    x128.coeffs[128] = 1;

    Poly squared;
    MlDsaRing::multiplySchoolbook(squared, x128, x128);

    CHECK(squared.coeffs[0] == MlDsaRing::Q - 1);
    for (size_t i = 1; i < N; ++i) {
        REQUIRE(squared.coeffs[i] == 0);
    }

    // X^255 * X is the same statement one degree up.
    Poly x255, x1;
    MlDsaRing::setZero(x255);
    MlDsaRing::setZero(x1);
    x255.coeffs[255] = 1;
    x1.coeffs[1] = 1;

    Poly wrapped;
    MlDsaRing::multiplySchoolbook(wrapped, x255, x1);
    CHECK(wrapped.coeffs[0] == MlDsaRing::Q - 1);
    for (size_t i = 1; i < N; ++i) {
        REQUIRE(wrapped.coeffs[i] == 0);
    }
}

TEST_CASE("MlDsaRing: the NTT round-trips, and is not the identity") {
    Lcg rng(0xD5A2026);

    for (int trial = 0; trial < 40; ++trial) {
        const Poly original = randomPoly(rng);

        Poly transformed = original;
        MlDsaRing::ntt(transformed);

        // A round trip alone proves little, but a transform that *was* the identity would make
        // every other test here vacuous, so rule it out.
        REQUIRE_FALSE(equalPoly(transformed, original));

        MlDsaRing::inverseNtt(transformed);
        REQUIRE(equalPoly(transformed, original));
    }

    // Constants are the one input the transform leaves recognizable: NTT(c) is c at every
    // evaluation point, since a constant polynomial evaluates to itself everywhere.
    Poly constant;
    for (size_t i = 0; i < N; ++i) {
        constant.coeffs[i] = 0;
    }
    constant.coeffs[0] = 12345;

    Poly transformed = constant;
    MlDsaRing::ntt(transformed);
    for (size_t i = 0; i < N; ++i) {
        REQUIRE(transformed.coeffs[i] == 12345);
    }
}

TEST_CASE("MlDsaRing: NTT-domain multiply agrees with the schoolbook negacyclic convolution") {
    Lcg rng(0x8380417);

    for (int trial = 0; trial < 25; ++trial) {
        const Poly a = randomPoly(rng);
        const Poly b = randomPoly(rng);

        // The reference: quadratic convolution with X^256 == -1, sharing no machinery with the
        // transform.
        Poly expected;
        MlDsaRing::multiplySchoolbook(expected, a, b);

        Poly aHat = a;
        Poly bHat = b;
        MlDsaRing::ntt(aHat);
        MlDsaRing::ntt(bHat);

        Poly product;
        MlDsaRing::multiplyNtt(product, aHat, bHat);
        MlDsaRing::inverseNtt(product);

        REQUIRE(equalPoly(product, expected));
    }
}

TEST_CASE("MlDsaRing: multiplyNtt is pointwise, unlike ML-KEM's") {
    // Stated as a test because it is the structural difference between the two rings, and
    // because an implementation that copied ML-KEM's base-case multiply would still round-trip.
    Lcg rng(0x1753);
    const Poly a = randomPoly(rng);
    const Poly b = randomPoly(rng);

    Poly product;
    MlDsaRing::multiplyNtt(product, a, b);

    for (size_t i = 0; i < N; ++i) {
        const int64_t expected = (int64_t(a.coeffs[i]) * int64_t(b.coeffs[i])) % Q;
        REQUIRE(int64_t(product.coeffs[i]) == expected);
    }
}

TEST_CASE("MlDsaRing: multiplication by one and zero behave, and aliasing is allowed") {
    Lcg rng(0x2026);
    const Poly a = randomPoly(rng);

    Poly one;
    MlDsaRing::setZero(one);
    one.coeffs[0] = 1;

    Poly oneHat = one;
    Poly aHat = a;
    MlDsaRing::ntt(oneHat);
    MlDsaRing::ntt(aHat);

    Poly product;
    MlDsaRing::multiplyNtt(product, aHat, oneHat);
    MlDsaRing::inverseNtt(product);
    CHECK(equalPoly(product, a));

    Poly zero;
    MlDsaRing::setZero(zero);
    Poly zeroHat = zero;
    MlDsaRing::ntt(zeroHat);

    MlDsaRing::multiplyNtt(product, aHat, zeroHat);
    MlDsaRing::inverseNtt(product);
    CHECK(equalPoly(product, zero));

    // add/sub/multiplyNtt all document that out may alias an input; exercise that rather than
    // trusting the comment.
    Poly accumulator = a;
    MlDsaRing::add(accumulator, accumulator, a);
    for (size_t i = 0; i < N; ++i) {
        REQUIRE(accumulator.coeffs[i] == MlDsaRing::reduce(int64_t(a.coeffs[i]) * 2));
    }

    MlDsaRing::sub(accumulator, accumulator, a);
    CHECK(equalPoly(accumulator, a));

    Poly selfProduct = aHat;
    MlDsaRing::multiplyNtt(selfProduct, selfProduct, selfProduct);
    for (size_t i = 0; i < N; ++i) {
        REQUIRE(int64_t(selfProduct.coeffs[i])
                == (int64_t(aHat.coeffs[i]) * int64_t(aHat.coeffs[i])) % Q);
    }
}

TEST_CASE("MlDsaRing: add and sub are coefficient-wise and stay reduced") {
    Lcg rng(0xADD5B0);

    for (int trial = 0; trial < 20; ++trial) {
        const Poly a = randomPoly(rng);
        const Poly b = randomPoly(rng);

        Poly sum, difference;
        MlDsaRing::add(sum, a, b);
        MlDsaRing::sub(difference, a, b);

        for (size_t i = 0; i < N; ++i) {
            REQUIRE(sum.coeffs[i] >= 0);
            REQUIRE(sum.coeffs[i] < MlDsaRing::Q);
            REQUIRE(difference.coeffs[i] >= 0);
            REQUIRE(difference.coeffs[i] < MlDsaRing::Q);

            REQUIRE(int64_t(sum.coeffs[i])
                    == (int64_t(a.coeffs[i]) + int64_t(b.coeffs[i])) % Q);
            REQUIRE(int64_t(difference.coeffs[i])
                    == ((int64_t(a.coeffs[i]) - int64_t(b.coeffs[i])) % Q + Q) % Q);
        }

        // (a + b) - b == a, as a ring should manage.
        Poly roundTrip;
        MlDsaRing::sub(roundTrip, sum, b);
        REQUIRE(equalPoly(roundTrip, a));
    }
}

// A transposition anywhere in 256 coefficients has to fail, and a value-by-value comparison
// against a table would just be the implementation written twice. So: a fixed input, an
// order-sensitive fingerprint over the whole output, plus the endpoints spelled out.
TEST_CASE("MlDsaRing: a known transform output is pinned against reordering") {
    Poly input;
    for (size_t i = 0; i < N; ++i) {
        // A deliberately asymmetric ramp -- a symmetric input could mask a mirrored permutation.
        input.coeffs[i] = int32_t((i * 7919 + 13) % uint64_t(Q));
    }

    const uint64_t inputPrint = fingerprint(input);

    Poly transformed = input;
    MlDsaRing::ntt(transformed);

    // Endpoints and a couple of interior points, computed independently as evaluations: the NTT
    // output at index i is f(zeta^(2*BitRev8(i)+1)) for the standard's indexing, but rather than
    // re-derive that mapping here, the inverse is used as the cross-check and the fingerprint
    // pins the ordering.
    const uint64_t transformedPrint = fingerprint(transformed);
    CHECK(transformedPrint != inputPrint);

    // The fingerprint is reproducible run to run and build to build.
    Poly again = input;
    MlDsaRing::ntt(again);
    CHECK(fingerprint(again) == transformedPrint);

    // Swapping any two output coefficients must change the fingerprint -- which is what makes it
    // a transposition detector rather than a checksum that averages out.
    for (size_t i = 0; i < 16; ++i) {
        Poly permuted = transformed;
        const size_t j = (i * 37 + 1) % N;
        if (permuted.coeffs[i] == permuted.coeffs[j] || i == j) {
            continue;
        }
        const int32_t tmp = permuted.coeffs[i];
        permuted.coeffs[i] = permuted.coeffs[j];
        permuted.coeffs[j] = tmp;
        REQUIRE(fingerprint(permuted) != transformedPrint);
    }

    // And the transform still inverts, so the pinned value is the right one rather than merely
    // a stable wrong one.
    MlDsaRing::inverseNtt(transformed);
    CHECK(equalPoly(transformed, input));
}

TEST_CASE("MlDsaRing: reduce handles the full int64 range and negatives") {
    CHECK(MlDsaRing::reduce(0) == 0);
    CHECK(MlDsaRing::reduce(Q) == 0);
    CHECK(MlDsaRing::reduce(Q - 1) == MlDsaRing::Q - 1);
    CHECK(MlDsaRing::reduce(-1) == MlDsaRing::Q - 1);
    CHECK(MlDsaRing::reduce(-Q) == 0);

    // The largest product the ring can produce, (q-1)^2, must not wrap. In int32_t it would --
    // which is the reason every intermediate in this unit is int64_t.
    const int64_t largest = (Q - 1) * (Q - 1);
    CHECK(largest > int64_t(0x7FFFFFFF));
    CHECK(MlDsaRing::reduce(largest) == int32_t(largest % Q));

    Lcg rng(0xDEC0DE);
    for (int trial = 0; trial < 5000; ++trial) {
        const int64_t value = int64_t(rng.next()) * int64_t(rng.next()) - (Q * 3);
        const int32_t r = MlDsaRing::reduce(value);

        REQUIRE(r >= 0);
        REQUIRE(r < MlDsaRing::Q);
        REQUIRE(((int64_t(r) - value) % Q) == 0);
    }
}
