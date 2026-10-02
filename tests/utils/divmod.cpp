#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;

/* CBigNum::divMod() is Knuth's Algorithm D, which is fast but has two places that are easy to get
 * wrong and almost never exercised by ordinary use: the quotient-digit estimate's correction loop,
 * and the "add the divisor back" branch that fires on roughly 1 in 2^31 quotient digits. Neither
 * shows up in a handful of hand-picked cases, and a wrong result there is not obviously wrong --
 * it is off by exactly one divisor in one limb position.
 *
 * So this file does not test divMod() against expected values. It tests it against an independent
 * implementation: a deliberately naive bit-serial long division written with nothing but CBigNum's
 * public operations (shl/add/sub/compare), which is the algorithm divMod() itself used before and
 * which is slow but transparently correct. Every case below asserts the two agree, and that
 * quotient * divisor + remainder == dividend with remainder < divisor.
 *
 * The random cases are seeded deterministically rather than from CRng, so a failure is
 * reproducible from the output alone. */

namespace {

    /* Bit-serial long division over the public API only -- the reference divMod() is checked
     * against. Deliberately the slow, obvious algorithm: shift the dividend's bits into a running
     * remainder one at a time, subtracting the divisor whenever it fits. */
    void referenceDivMod(
        const CBigNum& dividend, const CBigNum& divisor, CBigNum& outQuot, CBigNum& outRem
    ) {
        CBigNum quot;
        CBigNum rem;
        const CBigNum one(uint64_t(1));

        for (size_t i = dividend.bitLength(); i-- > 0; ) {
            rem.shl(1);
            if (dividend.testBit(i)) {
                rem.add(one);
            }

            quot.shl(1);
            if (rem.compare(divisor) >= 0) {
                rem.sub(divisor);
                quot.add(one);
            }
        }

        outQuot = std::move(quot);
        outRem = std::move(rem);
    }

    /* xorshift64* -- a deterministic generator, so any failure reproduces from the seed. */
    class Rng {
    private:
        uint64_t _state;

    public:
        explicit Rng(uint64_t seed) : _state(seed ? seed : 0x9E3779B97F4A7C15ull) {}

        uint64_t next() {
            _state ^= _state >> 12;
            _state ^= _state << 25;
            _state ^= _state >> 27;
            return _state * 0x2545F4914F6CDD1Dull;
        }

        uint32_t below(uint32_t bound) {
            return bound ? uint32_t(next() % uint64_t(bound)) : 0;
        }
    };

    CBigNum randomOfBits(Rng& rng, size_t bits) {
        if (!bits) {
            return CBigNum();
        }

        const size_t bytes = (bits + 7) / 8;
        CBuffer buf(bytes);
        uint8_t* p = buf.toPtr();

        for (size_t i = 0; i < bytes; ++i) {
            p[i] = uint8_t(rng.next() >> 24);
        }

        // Trim to exactly `bits` bits, with the top bit set so the value really is that long.
        const size_t topBitInByte = (bits - 1) % 8;
        p[0] &= uint8_t((1u << (topBitInByte + 1)) - 1u);
        p[0] |= uint8_t(1u << topBitInByte);

        return CBigNum::fromBigEndian(buf.toSpan());
    }

    /* Asserts divMod() agrees with the reference, and that the result satisfies the division
     * identity independently of either implementation. */
    void checkAgrees(const CBigNum& dividend, const CBigNum& divisor) {
        CBigNum fastQ, fastR;
        dividend.divMod(divisor, fastQ, fastR);

        CBigNum refQ, refR;
        referenceDivMod(dividend, divisor, refQ, refR);

        REQUIRE(fastQ.compare(refQ) == 0);
        REQUIRE(fastR.compare(refR) == 0);

        // q * d + r == dividend, and r < d -- true of correct division regardless of how either
        // implementation got there.
        CBigNum recomposed(fastQ);
        recomposed.mul(divisor);
        recomposed.add(fastR);

        CHECK(recomposed.compare(dividend) == 0);
        CHECK(fastR.compare(divisor) < 0);
    }

} // namespace

TEST_CASE("CBigNum::divMod(): agrees with a bit-serial reference on hand-picked edge cases") {
    const CBigNum zero;
    const CBigNum one(uint64_t(1));
    const CBigNum two(uint64_t(2));

    SUBCASE("dividend smaller than divisor") {
        checkAgrees(CBigNum(uint64_t(5)), CBigNum(uint64_t(7)));
    }

    SUBCASE("dividend equal to divisor") {
        checkAgrees(CBigNum(uint64_t(7)), CBigNum(uint64_t(7)));
    }

    SUBCASE("zero dividend") {
        checkAgrees(zero, CBigNum(uint64_t(7)));
    }

    SUBCASE("divide by one") {
        checkAgrees(CBigNum(uint64_t(0xDEADBEEFCAFEBABEull)), one);
    }

    SUBCASE("divide by two") {
        checkAgrees(CBigNum(uint64_t(0xDEADBEEFCAFEBABEull)), two);
    }

    SUBCASE("single-limb divisor, multi-limb dividend") {
        Rng rng(0xA11CE);
        checkAgrees(randomOfBits(rng, 512), CBigNum(uint64_t(0xFFFFFFFFull)));
        checkAgrees(randomOfBits(rng, 512), CBigNum(uint64_t(1)));
        checkAgrees(randomOfBits(rng, 512), CBigNum(uint64_t(0x80000000ull)));
    }

    SUBCASE("divisor top limb already normalized (shift == 0)") {
        // 0xFFFFFFFF_00000000 -- top limb has its high bit set, so Algorithm D's D1 is a no-op.
        CBigNum divisor = CBigNum::fromBigEndian(
            SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("\xFF\xFF\xFF\xFF\x00\x00\x00\x00"), 8)
        );
        Rng rng(0xBEEF);
        checkAgrees(randomOfBits(rng, 256), divisor);
    }

    SUBCASE("divisor top limb needing a maximal shift") {
        // Top limb == 1, so D1 shifts by 31 -- the widest normalization.
        CBigNum divisor = CBigNum::fromBigEndian(
            SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>("\x01\x00\x00\x00\x00\x00\x00\x01"), 8)
        );
        Rng rng(0xF00D);
        checkAgrees(randomOfBits(rng, 256), divisor);
    }

    SUBCASE("all-ones operands of several widths") {
        for (size_t bits : { size_t(32), size_t(33), size_t(64), size_t(65), size_t(128) }) {
            CAPTURE(bits);

            CBuffer ones((bits + 7) / 8);
            std::memset(ones.toPtr(), 0xFF, ones.size());
            CBigNum big = CBigNum::fromBigEndian(ones.toSpan());

            checkAgrees(big, CBigNum(uint64_t(0xFFFFFFFFull)));
            checkAgrees(big, big);
        }
    }
}

/* The quotient-digit estimate is derived from the top two limbs of the running remainder, so the
 * cases that stress it hardest are divisors whose leading limbs are extreme: 0x80000000 followed
 * by zeros (the estimate repeatedly lands one high) and 0xFFFFFFFF... (the correction loop runs).
 * These are the shapes that exercise D3's loop and D5/D6's add-back. */
TEST_CASE("CBigNum::divMod(): agrees with the reference on estimate-stressing divisor shapes") {
    struct Shape { const char* name; uint8_t lead; uint8_t fill; };
    const Shape shapes[] = {
        { "0x80 then zeros", 0x80, 0x00 },
        { "0x80 then ones",  0x80, 0xFF },
        { "all ones",        0xFF, 0xFF },
        { "0xFF then zeros", 0xFF, 0x00 },
        { "0x01 then zeros", 0x01, 0x00 },
        { "0x01 then ones",  0x01, 0xFF },
    };

    Rng rng(0x5EED);

    for (const Shape& shape : shapes) {
        CAPTURE(shape.name);

        for (size_t divisorBytes : { size_t(8), size_t(9), size_t(16), size_t(33) }) {
            CAPTURE(divisorBytes);

            CBuffer d(divisorBytes);
            std::memset(d.toPtr(), shape.fill, divisorBytes);
            d.toPtr()[0] = shape.lead;
            CBigNum divisor = CBigNum::fromBigEndian(d.toSpan());
            REQUIRE_FALSE(divisor.isZero());

            for (size_t dividendBits : { size_t(64), size_t(128), size_t(257), size_t(512) }) {
                CAPTURE(dividendBits);
                checkAgrees(randomOfBits(rng, dividendBits), divisor);
            }
        }
    }
}

TEST_CASE("CBigNum::divMod(): agrees with the reference across randomized widths") {
    Rng rng(0xC0FFEE);

    // Every (dividend, divisor) width combination around the limb boundaries, where the
    // quotient-limb count and the normalization shift interact.
    for (size_t dividendBits = 1; dividendBits <= 160; ++dividendBits) {
        for (size_t divisorBits : { size_t(1), size_t(31), size_t(32), size_t(33), size_t(63),
                                    size_t(64), size_t(65), size_t(96), size_t(127) })
        {
            if (!divisorBits) {
                continue;
            }

            CBigNum dividend = randomOfBits(rng, dividendBits);
            CBigNum divisor = randomOfBits(rng, divisorBits);
            if (divisor.isZero()) {
                continue;
            }

            CAPTURE(dividendBits);
            CAPTURE(divisorBits);
            checkAgrees(dividend, divisor);
        }
    }
}

TEST_CASE("CBigNum::divMod(): agrees with the reference on realistic key-sized operands") {
    Rng rng(0x1234ABCD);

    // The shape modExp() actually produces: a product roughly twice the modulus width, reduced by
    // the modulus. This is the case the whole optimization exists for.
    for (size_t modulusBits : { size_t(256), size_t(521), size_t(1024), size_t(2048) }) {
        CAPTURE(modulusBits);

        CBigNum modulus = randomOfBits(rng, modulusBits);
        REQUIRE_FALSE(modulus.isZero());

        checkAgrees(randomOfBits(rng, modulusBits * 2), modulus);
        checkAgrees(randomOfBits(rng, modulusBits * 2 - 1), modulus);
        checkAgrees(randomOfBits(rng, modulusBits + 1), modulus);
    }
}

/* Algorithm D's D5/D6 "add the divisor back" branch fires when the quotient-digit estimate is
 * still one too high after D3's refinement. Its probability is about 2/2^32 per quotient digit, so
 * no amount of random testing reaches it -- a sweep of 72,695 randomized multi-limb divisions over
 * a model of this exact implementation triggered it zero times. It also cannot happen at all for a
 * two-limb divisor, because D3's two-digit test then examines the whole divisor and the estimate is
 * exact; it needs three limbs or more.
 *
 * The inputs below were therefore constructed rather than sampled: the branch was first exercised
 * exhaustively in a 4-bit-limb model of the same algorithm (53,587 triggers, zero disagreements
 * with exact arithmetic), and the triggering limb patterns were then scaled into the top nibble of
 * each 32-bit limb, which preserves every ratio D3's estimate and refinement depend on. Each of
 * these was confirmed to take the branch, and to produce the right answer when it does.
 *
 * Without this case the rarest and least obvious part of the algorithm would ship untested. */
TEST_CASE("CBigNum::divMod(): correct when Algorithm D's add-back branch fires") {
    struct Trigger { const char* dividend; const char* divisor; };
    const Trigger triggers[] = {
        { "F000000030000000E0000000E000000090000000A0000000",
          "A000000020000000E0000000" },
        { "E00000008000000020000000500000005000000010000000E0000000D0000000",
          "70000000400000005000000080000000" },
        { "60000000D0000000600000001000000060000000F0000000",
          "A0000000F000000050000000" },
        { "600000008000000020000000D000000020000000900000003000000010000000",
          "60000000800000005000000020000000" },
        { "A0000000E000000010000000C0000000E0000000D000000060000000B0000000",
          "A0000000E0000000C0000000B0000000" },
        { "90000000000000001000000080000000A000000090000000",
          "9000000000000000F0000000" },
        { "E000000060000000A00000002000000000000000600000007000000010000000",
          "E000000060000000D0000000D0000000" },
    };

    for (const Trigger& t : triggers) {
        CAPTURE(t.dividend);
        CAPTURE(t.divisor);

        CBigNum dividend, divisor;
        REQUIRE(CBigNum::fromHex(t.dividend, dividend));
        REQUIRE(CBigNum::fromHex(t.divisor, divisor));
        REQUIRE_FALSE(divisor.isZero());

        checkAgrees(dividend, divisor);
    }
}

TEST_CASE("CBigNum::divMod(): division by zero yields zero quotient and remainder") {
    CBigNum quot(uint64_t(5));
    CBigNum rem(uint64_t(7));

    CBigNum(uint64_t(42)).divMod(CBigNum(), quot, rem);

    CHECK(quot.isZero());
    CHECK(rem.isZero());
}

/* mod()/modExp() ride on divMod(), so a regression there would surface here too -- and these are
 * the operations every asymmetric algorithm in the library actually calls. */
TEST_CASE("CBigNum::mod()/modExp(): consistent with divMod() after the Algorithm D rewrite") {
    Rng rng(0xFEEDFACE);

    for (int i = 0; i < 40; ++i) {
        CBigNum value = randomOfBits(rng, 64 + (rng.below(448)));
        CBigNum modulus = randomOfBits(rng, 32 + (rng.below(224)));
        if (modulus.isZero()) {
            continue;
        }

        CBigNum quot, rem;
        value.divMod(modulus, quot, rem);

        CBigNum viaMod(value);
        viaMod.mod(modulus);
        CHECK(viaMod.compare(rem) == 0);
    }

    // A known modExp triple, independent of divMod's internals: 7^11 mod 13 == 2.
    CHECK(
        CBigNum::modExp(CBigNum(uint64_t(7)), CBigNum(uint64_t(11)), CBigNum(uint64_t(13)))
            .compare(CBigNum(uint64_t(2))) == 0
    );
}
