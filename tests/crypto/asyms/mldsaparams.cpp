// ML-DSA's parameter sets, checked against FIPS 204 Tables 1 and 2.
//
// The point of this file is that every length MlDsaParams reports is *derived* from the
// tabulated parameters rather than written down, so the derivation has to be pinned against the
// standard's own published sizes. A mistyped length would stay internally consistent -- an
// implementation using the wrong sk length throughout still round-trips with itself -- and would
// surface only against an external vector, or here.
//
// Nearly everything below is a static_assert rather than a CHECK: the figures are constexpr, so
// a mismatch should fail the build rather than a test run.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include "crypto/asyms/mldsaparams.hpp"
#include "crypto/asyms/mldsarounding.hpp"
#include "crypto/asyms/mldsasampler.hpp"

using namespace certpp;
using namespace certpp::crypto;

namespace {
    constexpr MlDsaParams P44 = MlDsaParams::mlDsa44();
    constexpr MlDsaParams P65 = MlDsaParams::mlDsa65();
    constexpr MlDsaParams P87 = MlDsaParams::mlDsa87();
}

// ---- FIPS 204 Table 1 -----------------------------------------------------------------------
static_assert(P44.tau == 39 && P65.tau == 49 && P87.tau == 60, "Table 1: tau");
static_assert(P44.lambda == 128 && P65.lambda == 192 && P87.lambda == 256, "Table 1: lambda");
static_assert(P44.k == 4 && P44.l == 4, "Table 1: ML-DSA-44 is (4,4)");
static_assert(P65.k == 6 && P65.l == 5, "Table 1: ML-DSA-65 is (6,5)");
static_assert(P87.k == 8 && P87.l == 7, "Table 1: ML-DSA-87 is (8,7)");
static_assert(P44.omega == 80 && P65.omega == 55 && P87.omega == 75, "Table 1: omega");

// gamma1 is 2^17 for ML-DSA-44 and 2^19 for *both* of the others, so it cannot distinguish 65
// from 87.
static_assert(P44.gamma1 == (1u << 17), "Table 1: ML-DSA-44 gamma1");
static_assert(P65.gamma1 == (1u << 19), "Table 1: ML-DSA-65 gamma1");
static_assert(P87.gamma1 == (1u << 19), "Table 1: ML-DSA-87 gamma1");
static_assert(P65.gamma1 == P87.gamma1, "gamma1 is shared between 65 and 87");

// eta is NOT monotone in security level: 2, 4, 2. Reading it as rising would give ML-DSA-87 the
// wrong private-key range and the wrong sk length, so it is asserted explicitly in both
// directions.
static_assert(P44.eta == 2, "Table 1: ML-DSA-44 eta");
static_assert(P65.eta == 4, "Table 1: ML-DSA-65 eta");
static_assert(P87.eta == 2, "Table 1: ML-DSA-87 eta -- 2, not 4");
static_assert(P87.eta < P65.eta, "eta decreases from ML-DSA-65 to ML-DSA-87");

// gamma2 is (q-1)/88 for ML-DSA-44 and (q-1)/32 for the others; both divisions are exact, which
// is what makes (q-1)/(2*gamma2) a whole number of buckets.
static_assert(P44.gamma2 == (MlDsaRing::Q - 1) / 88, "Table 1: ML-DSA-44 gamma2");
static_assert(P65.gamma2 == (MlDsaRing::Q - 1) / 32, "Table 1: ML-DSA-65 gamma2");
static_assert(P87.gamma2 == (MlDsaRing::Q - 1) / 32, "Table 1: ML-DSA-87 gamma2");
static_assert((MlDsaRing::Q - 1) % (2 * P44.gamma2) == 0, "gamma2 divides q-1 exactly");
static_assert((MlDsaRing::Q - 1) % (2 * P65.gamma2) == 0, "gamma2 divides q-1 exactly");

// beta = tau * eta.
static_assert(P44.beta == P44.tau * P44.eta && P44.beta == 78, "Table 1: ML-DSA-44 beta");
static_assert(P65.beta == P65.tau * P65.eta && P65.beta == 196, "Table 1: ML-DSA-65 beta");
static_assert(P87.beta == P87.tau * P87.eta && P87.beta == 120, "Table 1: ML-DSA-87 beta");

// ---- FIPS 204 Table 2: the sizes every length must derive to -------------------------------
static_assert(P44.publicKeyBytes() == 1312, "Table 2: ML-DSA-44 public key");
static_assert(P65.publicKeyBytes() == 1952, "Table 2: ML-DSA-65 public key");
static_assert(P87.publicKeyBytes() == 2592, "Table 2: ML-DSA-87 public key");

static_assert(P44.privateKeyBytes() == 2560, "Table 2: ML-DSA-44 private key");
static_assert(P65.privateKeyBytes() == 4032, "Table 2: ML-DSA-65 private key");
static_assert(P87.privateKeyBytes() == 4896, "Table 2: ML-DSA-87 private key");

static_assert(P44.signatureBytes() == 2420, "Table 2: ML-DSA-44 signature");
static_assert(P65.signatureBytes() == 3309, "Table 2: ML-DSA-65 signature");
static_assert(P87.signatureBytes() == 4627, "Table 2: ML-DSA-87 signature");

// 4627, not 4595 -- the latter was the initial public draft's figure and still circulates.
static_assert(MlDsaParams::maxSignatureBytes() == 4627, "largest signature is 4627 bytes");
static_assert(MlDsaParams::maxPrivateKeyBytes() == 4896, "largest private key");
static_assert(MlDsaParams::maxPublicKeyBytes() == 2592, "largest public key");

// ---- the derived widths the packing depends on ----------------------------------------------
static_assert(MlDsaParams::t1BitWidth() == 10, "t1 is bitlen(q-1) - d = 10 bits");
static_assert(P44.etaBitWidth() == 3 && P65.etaBitWidth() == 4 && P87.etaBitWidth() == 3,
              "bitlen(2*eta)");
static_assert(P44.gamma1BitWidth() == 17 && P65.gamma1BitWidth() == 19, "bitlen(gamma1 - 1)");
static_assert(P44.commitmentBytes() == 32, "c-tilde is lambda/4 bytes");
static_assert(P65.commitmentBytes() == 48, "c-tilde is lambda/4 bytes");
static_assert(P87.commitmentBytes() == 64, "c-tilde is lambda/4 bytes");

static_assert(P44.k <= MlDsaParams::MAX_K && P87.k <= MlDsaParams::MAX_K, "MAX_K bounds k");
static_assert(P87.k == MlDsaParams::MAX_K, "MAX_K is ML-DSA-87's k");
static_assert(P87.l == MlDsaParams::MAX_L, "MAX_L is ML-DSA-87's l");

TEST_CASE("MlDsaParams: the three sets are accepted and nothing else is") {
    CHECK(P44.isValid());
    CHECK(P65.isValid());
    CHECK(P87.isValid());

    CHECK(P44.equals(MlDsaParams::mlDsa44()));
    CHECK_FALSE(P44.equals(P65));
    CHECK_FALSE(P65.equals(P87));

    // A set that differs in one field is not one of the three, however plausible. This one is
    // ML-DSA-87 with the eta a reader would expect it to have.
    MlDsaParams plausible = P87;
    plausible.eta = 4;
    CHECK_FALSE(plausible.isValid());

    // And a k past MAX_K, which is the one that would overflow a fixed-capacity buffer.
    MlDsaParams oversized = P87;
    oversized.k = 9;
    CHECK_FALSE(oversized.isValid());
}

TEST_CASE("MlDsaParams: highBitsRange matches the rounding unit's own answer") {
    CHECK(P44.highBitsRange() == 44);
    CHECK(P65.highBitsRange() == 16);
    CHECK(P87.highBitsRange() == 16);

    // The same quantity the rounding unit computes from gamma2 alone -- two independent paths to
    // one number, so a disagreement surfaces here rather than in a signature that fails to
    // verify.
    CHECK(P44.highBitsRange() == size_t(MlDsaRounding::highBitsRange(P44.gamma2)));
    CHECK(P65.highBitsRange() == size_t(MlDsaRounding::highBitsRange(P65.gamma2)));
    CHECK(P87.highBitsRange() == size_t(MlDsaRounding::highBitsRange(P87.gamma2)));

    // gamma2 is also exactly the constants the rounding unit names.
    CHECK(P44.gamma2 == MlDsaRounding::GAMMA2_44);
    CHECK(P65.gamma2 == MlDsaRounding::GAMMA2_65_87);
    CHECK(P87.gamma2 == MlDsaRounding::GAMMA2_65_87);
}

// The sizes are derived, so this re-derives them a second way -- by summing the parts a key or
// signature is actually made of -- rather than restating the formula. Two different routes to
// Table 2's numbers.
TEST_CASE("MlDsaParams: the sizes add up from the parts they are made of") {
    const MlDsaParams sets[] = { P44, P65, P87 };

    for (const MlDsaParams& p : sets) {
        // pk = rho || k * SimpleBitPack(t1, 2^10 - 1)
        const size_t rho = 32;
        const size_t t1Packed = 32 * MlDsaParams::t1BitWidth();
        CHECK(p.publicKeyBytes() == rho + p.k * t1Packed);

        // sk = rho || K || tr || l * BitPack(s1) || k * BitPack(s2) || k * BitPack(t0)
        const size_t kSeed = 32;
        const size_t tr = 64;
        const size_t sPacked = 32 * p.etaBitWidth();
        const size_t t0Packed = 32 * 13;
        CHECK(p.privateKeyBytes()
              == rho + kSeed + tr + p.l * sPacked + p.k * sPacked + p.k * t0Packed);

        // sig = c-tilde || l * BitPack(z, gamma1-1, gamma1) || HintBitPack (omega + k)
        const size_t zPacked = 32 * (1 + p.gamma1BitWidth());
        CHECK(p.signatureBytes()
              == p.commitmentBytes() + p.l * zPacked + (p.omega + p.k));

        // Every fixed buffer in the implementation is sized from these, so none may exceed the
        // maxima.
        REQUIRE(p.signatureBytes() <= MlDsaParams::maxSignatureBytes());
        REQUIRE(p.privateKeyBytes() <= MlDsaParams::maxPrivateKeyBytes());
        REQUIRE(p.publicKeyBytes() <= MlDsaParams::maxPublicKeyBytes());
        REQUIRE(p.k <= MlDsaParams::MAX_K);
        REQUIRE(p.l <= MlDsaParams::MAX_L);
    }
}

TEST_CASE("MlDsaParams: the sampler and codec limits cover every set") {
    const MlDsaParams sets[] = { P44, P65, P87 };

    for (const MlDsaParams& p : sets) {
        // The samplers' own maxima must bound the table, or a parameter set would overrun them.
        REQUIRE(p.k <= MlDsaSampler::MAX_K);
        REQUIRE(p.l <= MlDsaSampler::MAX_L);
        REQUIRE(p.tau <= MlDsaSampler::MAX_TAU);

        // tau <= 64 is what lets SampleInBall take its sign bits from 8 squeezed bytes.
        REQUIRE(p.tau <= 64);

        // eta is one of the two CoeffFromHalfByte handles.
        REQUIRE((p.eta == 2 || p.eta == 4));

        // omega fits in the single byte HintBitPack writes as a running total.
        REQUIRE(p.omega <= 255);
    }
}
