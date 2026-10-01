#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    const EEc2KnownCurves ALL_CURVES[] = {
        ECURVE2_B163, ECURVE2_K163,
        ECURVE2_B233, ECURVE2_K233,
        ECURVE2_B283, ECURVE2_K283,
        ECURVE2_B409, ECURVE2_K409,
        ECURVE2_B571, ECURVE2_K571,
    };
}

TEST_CASE("SEc2Point: default-constructed point is the point at infinity") {
    SEc2Point pt;
    CHECK(pt.infinity);
}

TEST_CASE("CEc2Curve: knownCurves() rejects invalid identifiers") {
    CEc2Curve curve;
    CHECK_FALSE(CEc2Curve::knownCurves(ECURVE2_UNKNOWN, curve));
    CHECK_FALSE(CEc2Curve::knownCurves(ECURVE2_MAX, curve));
}

TEST_CASE("CEc2Curve: the base point G lies on every known curve") {
    for (auto id : ALL_CURVES) {
        CEc2Curve curve;
        REQUIRE(CEc2Curve::knownCurves(id, curve));
        CHECK(curve.isOnCurve(curve.g));
    }
}

TEST_CASE("CEc2Curve: fieldByteLen matches each field's degree") {
    CEc2Curve b163, b233, b283, b409, b571;
    REQUIRE(CEc2Curve::knownCurves(ECURVE2_B163, b163));
    REQUIRE(CEc2Curve::knownCurves(ECURVE2_B233, b233));
    REQUIRE(CEc2Curve::knownCurves(ECURVE2_B283, b283));
    REQUIRE(CEc2Curve::knownCurves(ECURVE2_B409, b409));
    REQUIRE(CEc2Curve::knownCurves(ECURVE2_B571, b571));

    CHECK(b163.fieldByteLen() == 21); // ceil(163/8)
    CHECK(b233.fieldByteLen() == 30); // ceil(233/8)
    CHECK(b283.fieldByteLen() == 36); // ceil(283/8)
    CHECK(b409.fieldByteLen() == 52); // ceil(409/8)
    CHECK(b571.fieldByteLen() == 72); // ceil(571/8)
}

TEST_CASE("CEc2Curve: adding the point at infinity is the identity operation, for every known curve") {
    for (auto id : ALL_CURVES) {
        CEc2Curve curve;
        REQUIRE(CEc2Curve::knownCurves(id, curve));

        SEc2Point infinity;
        CHECK(curve.add(curve.g, infinity).equals(curve.g));
        CHECK(curve.add(infinity, curve.g).equals(curve.g));
    }
}

TEST_CASE("CEc2Curve: doubling G matches adding G to itself, for every known curve") {
    for (auto id : ALL_CURVES) {
        CEc2Curve curve;
        REQUIRE(CEc2Curve::knownCurves(id, curve));

        SEc2Point doubled = curve.doublePoint(curve.g);
        SEc2Point added = curve.add(curve.g, curve.g);

        CHECK(doubled.equals(added));
        CHECK(curve.isOnCurve(doubled));
    }
}

TEST_CASE("CEc2Curve: scalarMul(G, 2) matches doubling G, for every known curve") {
    for (auto id : ALL_CURVES) {
        CEc2Curve curve;
        REQUIRE(CEc2Curve::knownCurves(id, curve));

        SEc2Point viaScalar = curve.scalarMul(curve.g, CBigNum(uint64_t(2)));
        SEc2Point viaDouble = curve.doublePoint(curve.g);

        CHECK(viaScalar.equals(viaDouble));
    }
}

TEST_CASE("CEc2Curve: a point plus its negation is the point at infinity, for every known curve") {
    // A binary curve's negation is (x, x+y), not (x, p-y) like a prime-field curve.
    for (auto id : ALL_CURVES) {
        CEc2Curve curve;
        REQUIRE(CEc2Curve::knownCurves(id, curve));

        CGf2m negY(curve.g.x);
        negY.add(curve.g.y);
        SEc2Point negG(curve.g.x, negY);
        REQUIRE(curve.isOnCurve(negG));

        SEc2Point sum = curve.add(curve.g, negG);
        CHECK(sum.infinity);
    }
}

TEST_CASE("CEc2Curve: scalarMul(G, n) is the point at infinity, for every known curve (fundamental group order check)") {
    for (auto id : ALL_CURVES) {
        CEc2Curve curve;
        REQUIRE(CEc2Curve::knownCurves(id, curve));

        SEc2Point result = curve.scalarMul(curve.g, curve.n);
        CHECK(result.infinity);
    }
}

TEST_CASE("CEc2Curve: SEC1 uncompressed point encoding round-trips, for every known curve") {
    for (auto id : ALL_CURVES) {
        CEc2Curve curve;
        REQUIRE(CEc2Curve::knownCurves(id, curve));

        TArray<uint8_t> encoded;
        REQUIRE(curve.encodePoint(curve.g, encoded));
        REQUIRE(encoded.size() == 1 + 2 * curve.fieldByteLen());
        CHECK(encoded[0] == 0x04);

        SEc2Point decoded;
        REQUIRE(curve.decodePoint(SReadOnlyByteSpan(encoded.begin(), encoded.size()), decoded));
        CHECK(decoded.equals(curve.g));
    }
}

TEST_CASE("CEc2Curve: the point at infinity encodes as a single 0x00 byte, but decodePoint rejects it") {
    CEc2Curve curve;
    REQUIRE(CEc2Curve::knownCurves(ECURVE2_B163, curve));
    SEc2Point infinity;

    TArray<uint8_t> encoded;
    REQUIRE(curve.encodePoint(infinity, encoded));
    REQUIRE(encoded.size() == 1);
    CHECK(encoded[0] == 0x00);

    // The point at infinity is never a valid public key -- decodePoint() rejects it outright
    // (see ecdsa2.cpp's createPublicKey()/createPrivateKey(), the only callers) rather than
    // round-tripping it, unlike encodePoint() which still needs to represent it for completeness.
    SEc2Point decoded;
    CHECK_FALSE(curve.decodePoint(SReadOnlyByteSpan(encoded.begin(), encoded.size()), decoded));
}

TEST_CASE("CEc2Curve: decodePoint rejects a point not on the curve") {
    CEc2Curve curve;
    REQUIRE(CEc2Curve::knownCurves(ECURVE2_B163, curve));

    TArray<uint8_t> encoded;
    REQUIRE(curve.encodePoint(curve.g, encoded));
    encoded[encoded.size() - 1] ^= 0xFF; // tamper with Y

    SEc2Point decoded;
    CHECK_FALSE(curve.decodePoint(SReadOnlyByteSpan(encoded.begin(), encoded.size()), decoded));
}

TEST_CASE("CEc2Curve: decodePoint rejects an on-curve point outside the main order-n subgroup") {
    // These binary curves have cofactor 2 (B-163) rather than 1, so "on the curve" and "in the
    // order-n subgroup" are NOT the same condition -- unlike CEcCurve's prime-field curves. The
    // point (0, sqrt(b)) is always on the curve (y^2 + 0 == 0 + 0 + b reduces to y^2 == b, and
    // squaring is a bijection over GF(2^m), so a square root always exists) and always has order
    // exactly 2 (it's its own negation: -(x,y) == (x, x+y), so at x == 0 that's (0, y) itself).
    // Since this library's subgroup order n is always an odd prime, gcd(2, n) == 1, so this
    // order-2 point can never be a multiple of G -- it's a genuine small-subgroup confinement
    // candidate (the same vulnerability class as CVE-2026-26007), not a contrived non-point.
    CEc2Curve curve;
    REQUIRE(CEc2Curve::knownCurves(ECURVE2_B163, curve));

    CGf2m x(*curve.field, 0);
    CGf2m y = curve.b;
    for (size_t i = 0; i + 1 < curve.field->m; ++i) {
        y.square();
    }

    SEc2Point smallSubgroupPoint(x, y);
    REQUIRE(curve.isOnCurve(smallSubgroupPoint));
    REQUIRE_FALSE(curve.scalarMul(smallSubgroupPoint, curve.n).infinity); // confirms it's NOT order n

    TArray<uint8_t> encoded;
    REQUIRE(curve.encodePoint(smallSubgroupPoint, encoded));

    SEc2Point decoded;
    CHECK_FALSE(curve.decodePoint(SReadOnlyByteSpan(encoded.begin(), encoded.size()), decoded));
}
