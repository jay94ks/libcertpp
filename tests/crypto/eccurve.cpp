#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;
using namespace certpp::crypto;

namespace {
    // NIST P-256 / secp256r1 domain parameters -- used here purely as a real, well-known curve
    // to exercise CEcCurve/SEcPoint directly (independently of the P256 algorithm class, which
    // has its own copy of these same constants).
    const CEcCurve& testCurve() {
        static const CEcCurve curve(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
        );

        return curve;
    }
}

TEST_CASE("CEcCurve: fieldByteLen matches the field prime's bit length") {
    CHECK(testCurve().fieldByteLen() == 32); // 256 bits
}

TEST_CASE("SEcPoint: default-constructed point is the point at infinity") {
    SEcPoint pt;
    CHECK(pt.infinity);
}

TEST_CASE("CEcCurve: the base point G lies on the curve") {
    CHECK(testCurve().isOnCurve(testCurve().g));
}

TEST_CASE("CEcCurve: adding the point at infinity is the identity operation") {
    const CEcCurve& curve = testCurve();
    SEcPoint infinity;

    CHECK(curve.add(curve.g, infinity).equals(curve.g));
    CHECK(curve.add(infinity, curve.g).equals(curve.g));
}

TEST_CASE("CEcCurve: doubling G matches adding G to itself") {
    const CEcCurve& curve = testCurve();

    SEcPoint doubled = curve.doublePoint(curve.g);
    SEcPoint added = curve.add(curve.g, curve.g);

    CHECK(doubled.equals(added));
    CHECK(curve.isOnCurve(doubled));
}

TEST_CASE("CEcCurve: scalarMul(G, 2) matches doubling G") {
    const CEcCurve& curve = testCurve();

    SEcPoint viaScalar = curve.scalarMul(curve.g, CBigNum(uint64_t(2)));
    SEcPoint viaDouble = curve.doublePoint(curve.g);

    CHECK(viaScalar.equals(viaDouble));
}

TEST_CASE("CEcCurve: a point plus its negation is the point at infinity") {
    const CEcCurve& curve = testCurve();

    CBigNum negY(curve.p);
    negY.sub(curve.g.y);
    SEcPoint negG(curve.g.x, negY);
    REQUIRE(curve.isOnCurve(negG));

    SEcPoint sum = curve.add(curve.g, negG);
    CHECK(sum.infinity);
}

TEST_CASE("CEcCurve: scalarMul(G, n) is the point at infinity (fundamental group order check)") {
    const CEcCurve& curve = testCurve();
    SEcPoint result = curve.scalarMul(curve.g, curve.n);
    CHECK(result.infinity);
}

TEST_CASE("CEcCurve: SEC1 uncompressed point encoding round-trips") {
    const CEcCurve& curve = testCurve();

    TArray<uint8_t> encoded;
    REQUIRE(curve.encodePoint(curve.g, encoded));
    REQUIRE(encoded.size() == 65); // 0x04 || X(32) || Y(32)
    CHECK(encoded[0] == 0x04);

    SEcPoint decoded;
    REQUIRE(curve.decodePoint(SReadOnlyByteSpan(encoded.begin(), encoded.size()), decoded));
    CHECK(decoded.equals(curve.g));
}

TEST_CASE("CEcCurve: the point at infinity encodes as a single 0x00 byte, but decodePoint rejects it") {
    const CEcCurve& curve = testCurve();
    SEcPoint infinity;

    TArray<uint8_t> encoded;
    REQUIRE(curve.encodePoint(infinity, encoded));
    REQUIRE(encoded.size() == 1);
    CHECK(encoded[0] == 0x00);

    // The point at infinity is never a valid public key -- decodePoint() rejects it outright
    // (see ecdsa.cpp's createPublicKey()/createPrivateKey(), the only callers) rather than
    // round-tripping it, unlike encodePoint() which still needs to represent it for completeness.
    SEcPoint decoded;
    CHECK_FALSE(curve.decodePoint(SReadOnlyByteSpan(encoded.begin(), encoded.size()), decoded));
}

TEST_CASE("CEcCurve: decodePoint rejects a point not on the curve") {
    const CEcCurve& curve = testCurve();

    TArray<uint8_t> encoded;
    REQUIRE(curve.encodePoint(curve.g, encoded));
    encoded[encoded.size() - 1] ^= 0xFF; // tamper with Y

    SEcPoint decoded;
    CHECK_FALSE(curve.decodePoint(SReadOnlyByteSpan(encoded.begin(), encoded.size()), decoded));
}

TEST_CASE("CEcCurve: decodePoint rejects a non-canonical coordinate (x or y >= p)") {
    // Without an explicit field-range check, isOnCurve()'s mod-p arithmetic would accept x == p
    // (reduces to 0) exactly as readily as x == 0 -- letting a point be smuggled in under a
    // non-canonical byte encoding that's numerically out of [0, p) but equivalent mod p.
    const CEcCurve& curve = testCurve();
    size_t flen = curve.fieldByteLen();

    TArray<uint8_t> encoded;
    REQUIRE(curve.encodePoint(curve.g, encoded));

    TArray<uint8_t> tampered = encoded;
    REQUIRE(curve.p.toBigEndian(SByteSpan(tampered.begin() + 1, flen))); // x := p (== 0 mod p)

    SEcPoint decoded;
    CHECK_FALSE(curve.decodePoint(SReadOnlyByteSpan(tampered.begin(), tampered.size()), decoded));
}
