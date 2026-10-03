// Fe25519: GF(2^255 - 19) in fixed-width constant-time form.
//
// Validated against CBigNum, which is the right oracle here: it is heavily tested, it shares no
// code with this unit, and its arbitrary-precision arithmetic is exact. The whole point of
// Fe25519 is to do the same arithmetic without CBigNum's data-dependent limb count, so agreeing
// with it on every operation is exactly the property wanted.
//
// The specific errors this guards against are the ones that survive a round trip. The radix is
// 2^25.5, so a partial product where both limb indices are odd lands one bit high; getting that
// wrong is wrong on every input, but an implementation that was consistently wrong in both
// directions would still round-trip. And toBytes()'s conditional subtraction of p only matters
// for values in [p, 2^255), which decode back to the same element either way -- so only a check
// against canonical bytes finds it.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>
#include "crypto/asyms/fe25519.hpp"

#include <vector>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    /* p = 2^255 - 19, built rather than transcribed. */
    const CBigNum& fieldPrime() {
        static const CBigNum p =
            CBigNum(uint64_t(1)).shl(255).sub(CBigNum(uint64_t(19)));
        return p;
    }

    struct Lcg {
        uint64_t state;
        explicit Lcg(uint64_t seed) : state(seed) { }

        uint32_t next() {
            state = state * 6364136223846793005ull + 1442695040888963407ull;
            return uint32_t(state >> 33);
        }
    };

    /* A random field element, as both representations. */
    void randomElement(Lcg& rng, CBigNum& asBig, Fe25519& asFe) {
        uint8_t bytes[32];
        for (size_t i = 0; i < 32; ++i) {
            bytes[i] = uint8_t(rng.next());
        }
        bytes[31] = uint8_t(bytes[31] & 0x7Fu);   // keep it below 2^255

        asFe.fromBytes(bytes);
        asBig = CBigNum::fromLittleEndian(SReadOnlyByteSpan(bytes, 32));
        asBig.mod(fieldPrime());
    }

    CBigNum toBig(const Fe25519& fe) {
        uint8_t bytes[32];
        fe.toBytes(bytes);
        return CBigNum::fromLittleEndian(SReadOnlyByteSpan(bytes, 32));
    }

    Fe25519 fromBig(const CBigNum& value) {
        CBigNum reduced(value);
        reduced.mod(fieldPrime());

        uint8_t bytes[32] = { 0 };
        REQUIRE(reduced.toLittleEndian(SByteSpan(bytes, 32)));

        Fe25519 fe;
        fe.fromBytes(bytes);
        return fe;
    }

    /* The interesting values: zero, one, p-1, and the boundary either side of p. */
    std::vector<CBigNum> edgeValues() {
        const CBigNum& p = fieldPrime();

        std::vector<CBigNum> out;
        out.push_back(CBigNum(uint64_t(0)));
        out.push_back(CBigNum(uint64_t(1)));
        out.push_back(CBigNum(uint64_t(2)));
        out.push_back(CBigNum(uint64_t(19)));
        out.push_back(CBigNum(uint64_t(38)));

        CBigNum pm1(p);
        pm1.sub(CBigNum(uint64_t(1)));
        out.push_back(pm1);

        CBigNum pm2(p);
        pm2.sub(CBigNum(uint64_t(2)));
        out.push_back(pm2);

        out.push_back(CBigNum(uint64_t(1)).shl(254));
        out.push_back(CBigNum(uint64_t(1)).shl(128));

        CBigNum half(p);
        half.sub(CBigNum(uint64_t(1)));
        half.shr(1);
        out.push_back(half);

        return out;
    }
}

TEST_CASE("Fe25519: the limb layout is radix 2^25.5 over 255 bits") {
    static_assert(Fe25519::LIMBS == 10, "ten limbs");
    static_assert(Fe25519::BYTES == 32, "32-byte encoding");

    // Alternating 26 and 25 bits, summing to exactly 255 -- which is what makes the top limb
    // line up with 2^255 and the wrap a clean factor of 19.
    int total = 0;
    for (size_t i = 0; i < Fe25519::LIMBS; ++i) {
        const int width = Fe25519::widthOf(i);
        REQUIRE((width == 26 || width == 25));
        REQUIRE(width == ((i % 2 == 0) ? 26 : 25));
        total += width;
    }
    CHECK(total == 255);

    // The int64 bound the multiply depends on: 10 partial products, each at most (2^26-1)^2,
    // each possibly scaled by 2 and by 19. Checked here so a future change to the radix cannot
    // silently overflow.
    const int64_t worst = (int64_t(1) << 26) - 1;
    const int64_t bound = 10 * worst * worst * 38;
    CHECK(bound > 0);                              // no overflow computing it
    CHECK(bound < (int64_t(1) << 62));             // comfortably inside int64
}

TEST_CASE("Fe25519: encoding round-trips and produces canonical bytes") {
    Lcg rng(0xFE25519);

    for (int trial = 0; trial < 5000; ++trial) {
        CBigNum expected;
        Fe25519 fe;
        randomElement(rng, expected, fe);

        CHECK(toBig(fe) == expected);
    }

    // The case a missing conditional subtraction gets wrong: a value in [p, 2^255), which
    // decodes to the same element either way but must encode as its reduced representative.
    const CBigNum& p = fieldPrime();
    for (uint64_t extra = 0; extra < 24; ++extra) {
        CBigNum unreduced(p);
        unreduced.add(CBigNum(extra));

        // Only those still below 2^255 are representable in 32 bytes with the top bit clear.
        if (unreduced >= CBigNum(uint64_t(1)).shl(255)) {
            continue;
        }

        uint8_t bytes[32] = { 0 };
        REQUIRE(unreduced.toLittleEndian(SByteSpan(bytes, 32)));

        Fe25519 fe;
        fe.fromBytes(bytes);

        // Must come back as `extra`, not as p + extra.
        CHECK(toBig(fe) == CBigNum(extra));
    }

    // fromBytes masks bit 255 rather than rejecting it (RFC 7748 5).
    uint8_t high[32] = { 0 };
    high[0] = 7;
    high[31] = 0x80;
    Fe25519 masked;
    masked.fromBytes(high);
    CHECK(toBig(masked) == CBigNum(uint64_t(7)));

    Fe25519 zero;
    zero.setZero();
    CHECK(zero.isZero());
    CHECK(toBig(zero) == CBigNum(uint64_t(0)));

    Fe25519 one;
    one.setOne();
    CHECK_FALSE(one.isZero());
    CHECK(toBig(one) == CBigNum(uint64_t(1)));
}

TEST_CASE("Fe25519: add, sub and mul agree with CBigNum") {
    Lcg rng(0x25519);
    const CBigNum& p = fieldPrime();

    for (int trial = 0; trial < 3000; ++trial) {
        CBigNum bigA, bigB;
        Fe25519 feA, feB;
        randomElement(rng, bigA, feA);
        randomElement(rng, bigB, feB);

        Fe25519 result;

        Fe25519::add(result, feA, feB);
        CBigNum expectedAdd(bigA);
        expectedAdd.add(bigB);
        expectedAdd.mod(p);
        REQUIRE(toBig(result) == expectedAdd);

        Fe25519::sub(result, feA, feB);
        CBigNum expectedSub(bigA);
        expectedSub.modSub(bigB, p);
        REQUIRE(toBig(result) == expectedSub);

        Fe25519::mul(result, feA, feB);
        CBigNum expectedMul(bigA);
        expectedMul.mulMod(bigB, p);
        REQUIRE(toBig(result) == expectedMul);

        Fe25519::square(result, feA);
        CBigNum expectedSquare(bigA);
        expectedSquare.mulMod(bigA, p);
        REQUIRE(toBig(result) == expectedSquare);

        Fe25519::mulA24(result, feA);
        CBigNum expectedA24(bigA);
        expectedA24.mulMod(CBigNum(uint64_t(121665)), p);
        REQUIRE(toBig(result) == expectedA24);
    }
}

// Every pair of edge values, where the carry chain and the 19x wrap are most strained. Random
// sampling essentially never lands on p-1 or on a value that makes a limb go negative at the
// top, so these are enumerated.
TEST_CASE("Fe25519: the edges, exhaustively paired") {
    const std::vector<CBigNum> edges = edgeValues();
    const CBigNum& p = fieldPrime();

    for (const CBigNum& a : edges) {
        for (const CBigNum& b : edges) {
            const Fe25519 feA = fromBig(a);
            const Fe25519 feB = fromBig(b);
            Fe25519 result;

            Fe25519::add(result, feA, feB);
            CBigNum expected(a);
            expected.add(b);
            expected.mod(p);
            REQUIRE(toBig(result) == expected);

            // Subtraction is the one that drives limbs negative, which is why signed limbs
            // exist -- a - b for a < b has to work without a borrow branch.
            Fe25519::sub(result, feA, feB);
            CBigNum expectedSub(a);
            expectedSub.modSub(b, p);
            REQUIRE(toBig(result) == expectedSub);

            Fe25519::mul(result, feA, feB);
            CBigNum expectedMul(a);
            expectedMul.mulMod(b, p);
            REQUIRE(toBig(result) == expectedMul);
        }
    }
}

TEST_CASE("Fe25519: inversion is the fixed a^(p-2) chain") {
    Lcg rng(0xC0FFEE);
    const CBigNum& p = fieldPrime();

    for (int trial = 0; trial < 300; ++trial) {
        CBigNum big;
        Fe25519 fe;
        randomElement(rng, big, fe);

        if (big.isZero()) {
            continue;
        }

        Fe25519 inverse;
        Fe25519::invert(inverse, fe);

        // x * x^-1 == 1 is the defining property; checked that way rather than against a
        // reference inverse, so a wrong addition chain cannot agree by construction.
        Fe25519 product;
        Fe25519::mul(product, fe, inverse);

        Fe25519 one;
        one.setOne();
        REQUIRE(toBig(product) == CBigNum(uint64_t(1)));

        // And it must equal CBigNum's own modular inverse.
        CBigNum expected;
        REQUIRE(CBigNum::modInverse(big, p, expected));
        REQUIRE(toBig(inverse) == expected);
    }

    // Zero has no inverse. Returning zero keeps the operation branch-free, and the one caller
    // that matters treats a zero denominator as the all-zero shared secret RFC 7748 6.1 already
    // requires be rejected.
    Fe25519 zero;
    zero.setZero();
    Fe25519 inverseOfZero;
    Fe25519::invert(inverseOfZero, zero);
    CHECK(inverseOfZero.isZero());

    // One inverts to one.
    Fe25519 one;
    one.setOne();
    Fe25519 inverseOfOne;
    Fe25519::invert(inverseOfOne, one);
    CHECK(toBig(inverseOfOne) == CBigNum(uint64_t(1)));
}

// condSwap is what replaces CBigNum::condSwap, whose own documentation admits it is a plain
// branch. In a Montgomery ladder the condition is a bit of the private scalar, so a branch there
// leaks the key one bit per iteration.
TEST_CASE("Fe25519: condSwap exchanges under a mask without branching") {
    Lcg rng(0x5EED5);

    for (int trial = 0; trial < 200; ++trial) {
        CBigNum bigA, bigB;
        Fe25519 a, b;
        randomElement(rng, bigA, a);
        randomElement(rng, bigB, b);

        const Fe25519 originalA = a;
        const Fe25519 originalB = b;

        // Mask zero leaves them alone.
        Fe25519::condSwap(0, a, b);
        for (size_t i = 0; i < Fe25519::LIMBS; ++i) {
            REQUIRE(a.limbs[i] == originalA.limbs[i]);
            REQUIRE(b.limbs[i] == originalB.limbs[i]);
        }

        // All ones swaps them.
        Fe25519::condSwap(0xFFFFFFFFu, a, b);
        for (size_t i = 0; i < Fe25519::LIMBS; ++i) {
            REQUIRE(a.limbs[i] == originalB.limbs[i]);
            REQUIRE(b.limbs[i] == originalA.limbs[i]);
        }

        // And swapping twice is the identity.
        Fe25519::condSwap(0xFFFFFFFFu, a, b);
        for (size_t i = 0; i < Fe25519::LIMBS; ++i) {
            REQUIRE(a.limbs[i] == originalA.limbs[i]);
        }
    }
}

TEST_CASE("Fe25519: aliasing is allowed on every binary operation") {
    Lcg rng(0xA11A5);
    const CBigNum& p = fieldPrime();

    for (int trial = 0; trial < 200; ++trial) {
        CBigNum bigA, bigB;
        Fe25519 a, b;
        randomElement(rng, bigA, a);
        randomElement(rng, bigB, b);

        // out == a
        Fe25519 target = a;
        Fe25519::mul(target, target, b);
        CBigNum expected(bigA);
        expected.mulMod(bigB, p);
        REQUIRE(toBig(target) == expected);

        // out == b
        target = b;
        Fe25519::sub(target, a, target);
        CBigNum expectedSub(bigA);
        expectedSub.modSub(bigB, p);
        REQUIRE(toBig(target) == expectedSub);

        // out == a == b
        target = a;
        Fe25519::mul(target, target, target);
        CBigNum expectedSquare(bigA);
        expectedSquare.mulMod(bigA, p);
        REQUIRE(toBig(target) == expectedSquare);

        // invert in place
        if (!bigA.isZero()) {
            target = a;
            Fe25519::invert(target, target);
            CBigNum expectedInverse;
            REQUIRE(CBigNum::modInverse(bigA, p, expectedInverse));
            REQUIRE(toBig(target) == expectedInverse);
        }
    }
}
