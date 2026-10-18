#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "../../../src/crypto/asyms/fe448.hpp"

#include <certpp/utils/bignum.hpp>
#include <doctest/doctest.h>

using namespace certpp;
using namespace certpp::crypto;

namespace {

    const CBigNum& prime448() {
        static const CBigNum p = CBigNum(uint64_t(1)).shl(448)
            .sub(CBigNum(uint64_t(1)).shl(224))
            .sub(CBigNum(uint64_t(1)));
        return p;
    }

    Fe448 fromBigNum(const CBigNum& value) {
        uint8_t bytes[Fe448::BYTES] = {};
        CHECK(value.toLittleEndian(SByteSpan(bytes, sizeof(bytes))));
        Fe448 out;
        CHECK(out.fromBytes(bytes));
        return out;
    }

    CBigNum toBigNum(const Fe448& value) {
        uint8_t bytes[Fe448::BYTES];
        value.toBytes(bytes);
        return CBigNum::fromLittleEndian(SReadOnlyByteSpan(bytes, sizeof(bytes)));
    }

    uint64_t nextWord(uint64_t& state) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    }

    CBigNum randomField(uint64_t& state) {
        uint8_t bytes[Fe448::BYTES];
        for (size_t i = 0; i < sizeof(bytes); i += 8) {
            const uint64_t word = nextWord(state);
            for (size_t j = 0; j < 8; ++j) {
                bytes[i + j] = uint8_t(word >> (8 * j));
            }
        }
        return CBigNum::fromLittleEndian(SReadOnlyByteSpan(bytes, sizeof(bytes))).mod(prime448());
    }

} // namespace

TEST_CASE("Fe448: canonical encoding boundaries") {
    uint8_t bytes[Fe448::BYTES] = {};
    Fe448 value;
    CHECK(value.fromBytes(bytes));
    CHECK(value.isZero());

    CBigNum pMinusOne(prime448());
    pMinusOne.sub(CBigNum(uint64_t(1)));
    REQUIRE(pMinusOne.toLittleEndian(SByteSpan(bytes, sizeof(bytes))));
    CHECK(value.fromBytes(bytes));
    CHECK(toBigNum(value) == pMinusOne);

    REQUIRE(prime448().toLittleEndian(SByteSpan(bytes, sizeof(bytes))));
    CHECK_FALSE(value.fromBytes(bytes));
}

TEST_CASE("Fe448: arithmetic agrees with exact CBigNum reduction") {
    uint64_t state = 0x72d34af15b9c08e1ull;
    const CBigNum& p = prime448();
    for (size_t trial = 0; trial < 1000; ++trial) {
        const CBigNum aBig = randomField(state);
        const CBigNum bBig = randomField(state);
        const Fe448 a = fromBigNum(aBig);
        const Fe448 b = fromBigNum(bBig);
        Fe448 actual;

        Fe448::add(actual, a, b);
        CBigNum expected(aBig);
        expected.add(bBig).mod(p);
        CHECK(toBigNum(actual) == expected);

        Fe448::sub(actual, a, b);
        expected = aBig;
        expected.modSub(bBig, p);
        CHECK(toBigNum(actual) == expected);

        Fe448::mul(actual, a, b);
        expected = aBig;
        expected.mulMod(bBig, p);
        CHECK(toBigNum(actual) == expected);

        Fe448::square(actual, a);
        expected = aBig;
        expected.mulMod(aBig, p);
        CHECK(toBigNum(actual) == expected);

        Fe448::mulSmall(actual, a, 39081);
        expected = aBig;
        expected.mulMod(CBigNum(uint64_t(39081)), p);
        CHECK(toBigNum(actual) == expected);
    }
}

TEST_CASE("Fe448: inversion and square-root ratio agree with exact arithmetic") {
    uint64_t state = 0xb16f49a57c0328d5ull;
    const CBigNum& p = prime448();
    for (size_t trial = 0; trial < 24; ++trial) {
        CBigNum aBig = randomField(state);
        CBigNum vBig = randomField(state);
        if (aBig.isZero()) aBig = CBigNum(uint64_t(1));
        if (vBig.isZero()) vBig = CBigNum(uint64_t(1));
        const Fe448 a = fromBigNum(aBig);
        const Fe448 v = fromBigNum(vBig);

        Fe448 inverse;
        Fe448::invert(inverse, a);
        Fe448 product;
        Fe448::mul(product, inverse, a);
        CBigNum one(uint64_t(1));
        CHECK(toBigNum(product) == one);

        Fe448 rootSeed = fromBigNum(randomField(state));
        Fe448 u;
        Fe448::square(u, rootSeed);
        Fe448::mul(u, u, v);
        Fe448 root;
        REQUIRE(Fe448::squareRootRatio(root, u, v));
        Fe448 check;
        Fe448::square(check, root);
        Fe448::mul(check, check, v);
        CHECK(check.isEqual(u));

        CBigNum nonResidue(uint64_t(2));
        CBigNum exponent(p);
        exponent.sub(CBigNum(uint64_t(1))).shr(1);
        while (CBigNum::modExp(nonResidue, exponent, p) == one) {
            nonResidue.add(CBigNum(uint64_t(1)));
        }
        Fe448 badU;
        Fe448::mul(badU, u, fromBigNum(nonResidue));
        CHECK_FALSE(Fe448::squareRootRatio(root, badU, v));
    }
}
