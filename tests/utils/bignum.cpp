#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;

TEST_CASE("CBigNum: default-constructed value is zero") {
    CBigNum n;
    CHECK(n.isZero());
    CHECK(n.bitLength() == 0);
}

TEST_CASE("CBigNum: big-endian round trip") {
    const uint8_t bytes[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    CBigNum n = CBigNum::fromBigEndian(SReadOnlyByteSpan(bytes, sizeof(bytes)));

    TArray<uint8_t> out;
    n.toBigEndian(out);

    REQUIRE(out.size() == sizeof(bytes));
    for (size_t i = 0; i < sizeof(bytes); ++i) {
        CHECK(out[i] == bytes[i]);
    }
}

TEST_CASE("CBigNum: big-endian minimal encoding strips leading zero bytes") {
    const uint8_t bytes[] = { 0x00, 0x00, 0x00, 0x2A };
    CBigNum n = CBigNum::fromBigEndian(SReadOnlyByteSpan(bytes, sizeof(bytes)));

    TArray<uint8_t> out;
    n.toBigEndian(out);

    REQUIRE(out.size() == 1);
    CHECK(out[0] == 0x2A);
}

TEST_CASE("CBigNum: zero encodes as a single 0x00 byte") {
    CBigNum n;

    TArray<uint8_t> out;
    n.toBigEndian(out);

    REQUIRE(out.size() == 1);
    CHECK(out[0] == 0);
}

TEST_CASE("CBigNum: fixed-width big-endian encoding pads and rejects overflow") {
    CBigNum n(uint64_t(0x2A));

    uint8_t buf4[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    CHECK(n.toBigEndian(SByteSpan(buf4, sizeof(buf4))));
    CHECK(buf4[0] == 0);
    CHECK(buf4[1] == 0);
    CHECK(buf4[2] == 0);
    CHECK(buf4[3] == 0x2A);

    uint8_t tooSmall[1];
    CBigNum big(uint64_t(0x1FF));
    CHECK_FALSE(big.toBigEndian(SByteSpan(tooSmall, sizeof(tooSmall))));
}

TEST_CASE("CBigNum: comparisons") {
    CBigNum a(uint64_t(100));
    CBigNum b(uint64_t(200));
    CBigNum c(uint64_t(100));

    CHECK(a < b);
    CHECK(b > a);
    CHECK(a == c);
    CHECK(a != b);
    CHECK(a <= c);
    CHECK(a >= c);
}

TEST_CASE("CBigNum: bit length, testBit and setBit") {
    CBigNum n(uint64_t(0));
    CHECK(n.bitLength() == 0);

    n.setBit(0);
    CHECK(n.bitLength() == 1);
    CHECK(n.testBit(0));
    CHECK_FALSE(n.testBit(1));

    n.setBit(40);
    CHECK(n.bitLength() == 41);
    CHECK(n.testBit(40));
}

TEST_CASE("CBigNum: isEven") {
    CHECK(CBigNum(uint64_t(0)).isEven());
    CHECK(CBigNum(uint64_t(2)).isEven());
    CHECK_FALSE(CBigNum(uint64_t(3)).isEven());
}

TEST_CASE("CBigNum: add across a limb boundary") {
    CBigNum a(uint64_t(0xFFFFFFFFu));
    CBigNum b(uint64_t(1));
    CBigNum sum = a.add(b);

    TArray<uint8_t> out;
    sum.toBigEndian(out);

    REQUIRE(out.size() == 5);
    CHECK(out[0] == 0x01);
    CHECK(out[1] == 0);
    CHECK(out[2] == 0);
    CHECK(out[3] == 0);
    CHECK(out[4] == 0);
}

TEST_CASE("CBigNum: sub is the inverse of add") {
    CBigNum a(uint64_t(123456789));
    CBigNum b(uint64_t(987654321));

    CBigNum sum(a);
    sum.add(b);

    CBigNum back(sum);
    back.sub(a);

    CHECK(back == b);
}

TEST_CASE("CBigNum: mul across limb boundaries") {
    CBigNum a(uint64_t(0xFFFFFFFFu));
    CBigNum product = a.mul(a);

    // 0xFFFFFFFF^2 = 0xFFFFFFFE00000001
    CBigNum expected(uint64_t(0xFFFFFFFE00000001ull));
    CHECK(product == expected);
}

TEST_CASE("CBigNum: divMod") {
    CBigNum dividend(uint64_t(100));
    CBigNum divisor(uint64_t(7));

    CBigNum q, r;
    dividend.divMod(divisor, q, r);

    CHECK(q == CBigNum(uint64_t(14)));
    CHECK(r == CBigNum(uint64_t(2)));
}

TEST_CASE("CBigNum: mod") {
    CBigNum n(uint64_t(1000));
    CHECK(n.mod(CBigNum(uint64_t(360))) == CBigNum(uint64_t(280)));
}

TEST_CASE("CBigNum: shl/shr") {
    CBigNum one(uint64_t(1));

    CBigNum shifted(one);
    shifted.shl(40);
    CHECK(shifted.bitLength() == 41);

    CBigNum shiftedBack(shifted);
    shiftedBack.shr(40);
    CHECK(shiftedBack == one);

    CBigNum shiftedTooFar(shifted);
    shiftedTooFar.shr(41);
    CHECK(shiftedTooFar.isZero());
}

TEST_CASE("CBigNum: gcd") {
    CHECK(CBigNum::gcd(CBigNum(uint64_t(48)), CBigNum(uint64_t(18))) == CBigNum(uint64_t(6)));
    CHECK(CBigNum::gcd(CBigNum(uint64_t(17)), CBigNum(uint64_t(5))) == CBigNum(uint64_t(1)));
}

TEST_CASE("CBigNum: modExp") {
    CHECK(CBigNum::modExp(CBigNum(uint64_t(5)), CBigNum(uint64_t(3)), CBigNum(uint64_t(13)))
        == CBigNum(uint64_t(8))); // 5^3 mod 13 = 125 mod 13 = 8

    CHECK(CBigNum::modExp(CBigNum(uint64_t(2)), CBigNum(uint64_t(10)), CBigNum(uint64_t(1000)))
        == CBigNum(uint64_t(24))); // 2^10 mod 1000 = 1024 mod 1000 = 24
}

TEST_CASE("CBigNum: modInverse") {
    CBigNum inv;
    REQUIRE(CBigNum::modInverse(CBigNum(uint64_t(3)), CBigNum(uint64_t(11)), inv));
    CHECK(inv == CBigNum(uint64_t(4))); // 3*4 = 12 = 1 mod 11

    CBigNum notInvertible;
    CHECK_FALSE(CBigNum::modInverse(CBigNum(uint64_t(2)), CBigNum(uint64_t(4)), notInvertible));
}

TEST_CASE("CBigNum: isProbablePrime") {
    CHECK(CBigNum(uint64_t(2)).isProbablePrime());
    CHECK(CBigNum(uint64_t(97)).isProbablePrime());
    CHECK(CBigNum(uint64_t(104729)).isProbablePrime()); // the 10000th prime

    CHECK_FALSE(CBigNum(uint64_t(1)).isProbablePrime());
    CHECK_FALSE(CBigNum(uint64_t(100)).isProbablePrime());
    CHECK_FALSE(CBigNum(uint64_t(561)).isProbablePrime()); // Carmichael number
}

TEST_CASE("CBigNum: generatePrime produces a probable prime of the requested bit length") {
    CBigNum p;
    REQUIRE(CBigNum::generatePrime(64, p));

    CHECK(p.bitLength() == 64);
    CHECK_FALSE(p.isEven());
    CHECK(p.isProbablePrime());
}

namespace {
    // An independent multiply, built only from add()/shl()/testBit() -- none of which mul()
    // itself calls -- used to cross-check mul() below without assuming anything about its
    // internal implementation (portable schoolbook loop, or the hardware-accelerated
    // MULX/ADCX path from CERTPP_DISABLE_HWACCEL_SIMD's build option).
    CBigNum referenceMul(const CBigNum& a, const CBigNum& b) {
        CBigNum result;
        for (size_t i = 0; i < b.bitLength(); ++i) {
            if (b.testBit(i)) {
                CBigNum shifted(a);
                shifted.shl(i);
                result.add(shifted);
            }
        }
        return result;
    }
}

TEST_CASE("CBigNum: mul() cross-checked against an independent reference multiply, many random operand pairs") {
    // Covers a range of bit lengths straddling the 32-bit limb boundary and the 64-bit-pair
    // boundary the hardware-accelerated path (bignum.cpp's mulAccelerated()) groups limbs by,
    // including odd limb counts on both sides.
    const size_t bitLengths[] = { 1, 7, 32, 33, 63, 64, 65, 127, 160, 256, 384, 521, 571, 1024, 2048 };

    for (size_t aBits : bitLengths) {
        for (size_t bBits : bitLengths) {
            for (int trial = 0; trial < 3; ++trial) {
                CBigNum a, b;
                REQUIRE(CBigNum::random(aBits, a));
                REQUIRE(CBigNum::random(bBits, b));

                CBigNum expected = referenceMul(a, b);
                CBigNum actual = a.mul(b);

                CHECK(actual == expected);
            }
        }
    }
}

// secureClear()'s observable contract. That the freed limbs were actually overwritten is not
// assertable from here -- there is no way to read a heap block after it is released, and a test
// that allocated a fresh value and looked for the old pattern would depend on the allocator
// reusing the same block, which it is under no obligation to do. The wipe rests on
// CSecure::zero, which tests/utils/secure.cpp covers directly.
TEST_CASE("CBigNum: secureClear() zeroes the value and leaves it usable") {
    CBigNum value = CBigNum::fromBigEndian(SReadOnlyByteSpan(
        reinterpret_cast<const uint8_t*>("\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE\x01\x02\x03\x04"), 12));
    REQUIRE_FALSE(value.isZero());

    value.secureClear();

    CHECK(value.isZero());
    CHECK(value.bitLength() == 0);
    CHECK(value == CBigNum(uint64_t(0)));

    // Still a usable object afterwards, not a husk: clearing resets the value rather than
    // invalidating it, so the same variable can be reused.
    value = CBigNum(uint64_t(42));
    CHECK(value == CBigNum(uint64_t(42)));

    value.add(CBigNum(uint64_t(8)));
    CHECK(value == CBigNum(uint64_t(50)));

    // Clearing an already-zero value, and clearing twice, are both fine.
    CBigNum zero;
    zero.secureClear();
    CHECK(zero.isZero());
    zero.secureClear();
    CHECK(zero.isZero());

    // A value large enough to span several limbs, and one that was reduced to fewer limbs than it
    // once held -- secureClear() wipes the whole allocation rather than just the live limbs.
    CBigNum wide;
    REQUIRE(CBigNum::random(2048, wide));
    wide.mod(CBigNum(uint64_t(7)));
    wide.secureClear();
    CHECK(wide.isZero());
}
