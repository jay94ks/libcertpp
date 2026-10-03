#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <certpp.hpp>

using namespace certpp;
using namespace certpp::crypto;

/* CMontgomery replaces a long division with precomputed constants and two limb-wise
 * multiply-accumulate passes, which puts it in the same category as CBigNum::divMod(): fast, and
 * with a handful of places that are easy to get wrong while still producing plausible-looking
 * answers. The two classics are (1) skipping the final conditional subtraction, so a result in
 * [m, 2m) escapes unreduced -- which only shows on about half of all inputs and never on a
 * hand-picked small case -- and (2) losing a carry out of the top limb in the reduction pass.
 *
 * So, exactly like tests/utils/divmod.cpp, this file does not test against expected values. It
 * tests every CMontgomery operation against the CBigNum operation it is the fast path for
 * (mulMod/mod/modSub/modNeg/modExp), which are themselves covered by divmod.cpp against an
 * independent bit-serial reference and by every RFC/FIPS/ACVP vector in tests/crypto/. Agreement
 * with the slow path over this many inputs is the actual evidence that the fast path is sound.
 *
 * The moduli are not arbitrary: every field prime and group order this library ships (the 29
 * CEcCurve parameter sets' p and n, plus edwards448's p and L) is exercised, alongside random odd
 * moduli from 32 to 1024 bits. The random cases are seeded deterministically rather than from
 * CRng, so a failure is reproducible from the output alone. */

namespace {

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

    CBigNum randomOddOfBits(Rng& rng, size_t bits) {
        CBigNum value = randomOfBits(rng, bits);
        value.setBit(0);
        return value;
    }

    /* edwards448's field prime, 2^448 - 2^224 - 1 (derived exactly as src/crypto/asyms/ed448.cpp
     * derives it, rather than transcribing a 112-hex-digit literal). */
    CBigNum ed448Prime() {
        return CBigNum(uint64_t(1)).shl(448)
            .sub(CBigNum(uint64_t(1)).shl(224))
            .sub(CBigNum(uint64_t(1)));
    }

    /* edwards448's base point order L = 2^446 - 0x8335DC...BB0D (RFC 7748). */
    CBigNum ed448Order() {
        CBigNum addend;
        CBigNum::fromHex("8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D", addend);
        return CBigNum(uint64_t(1)).shl(446).sub(addend);
    }

    /* Every modulus this library actually ships: each of the 29 CEcCurve parameter sets' field
     * prime p and subgroup order n, plus edwards448's p and L. */
    TArray<CBigNum> shippedModuli() {
        TArray<CBigNum> out;

        for (int i = ECURVE_P192; i < ECURVE_MAX; ++i) {
            CEcCurve curve;
            REQUIRE(CEcCurve::knownCurves(EEcKnownCurves(i), curve));

            out.add(curve.p);
            out.add(curve.n);
        }

        out.add(ed448Prime());
        out.add(ed448Order());
        return out;
    }

    /* Asserts every CMontgomery operation agrees with the CBigNum operation it replaces, both in
     * the ordinary domain (mulMod) and in the Montgomery domain (toMont/mul/fromMod round trip),
     * for one (a, b, m) triple. */
    void checkAgrees(const CMontgomery& mont, const CBigNum& a, const CBigNum& b) {
        const CBigNum& m = mont.modulus();
        REQUIRE(mont.isValid());

        // --> toMont()/fromMont() must round-trip back to the ordinary residue. A dropped
        // conversion on either side shows up here before it can be mistaken for an arithmetic bug.
        CBigNum aRef(a);
        aRef.mod(m);

        const CBigNum aMont = mont.toMont(a);
        REQUIRE(aMont.compare(m) < 0);
        CHECK(mont.fromMont(aMont).compare(aRef) == 0);

        CBigNum bRef(b);
        bRef.mod(m);

        const CBigNum bMont = mont.toMont(b);
        REQUIRE(bMont.compare(m) < 0);
        CHECK(mont.fromMont(bMont).compare(bRef) == 0);

        // --> Montgomery-domain multiply: fromMont(mul(aR, bR)) == a*b mod m.
        CBigNum refMul(a);
        refMul.mulMod(b, m);

        CBigNum gotMont(aMont);
        mont.mul(gotMont, bMont);
        REQUIRE(gotMont.compare(m) < 0); // the final conditional subtraction really happened
        CHECK(mont.fromMont(gotMont).compare(refMul) == 0);

        // --> Ordinary-domain multiply: a straight drop-in for CBigNum::mulMod().
        CBigNum gotMul(a);
        mont.mulMod(gotMul, b);
        CHECK(gotMul.compare(refMul) == 0);
        CHECK(gotMul.compare(m) < 0);

        // --> Squaring, which aliases both operands onto the same object.
        CBigNum refSqr(a);
        refSqr.mulMod(a, m);

        CBigNum gotSqr(aMont);
        mont.mul(gotSqr, gotSqr);
        CHECK(mont.fromMont(gotSqr).compare(refSqr) == 0);

        // --> add/sub/dbl/neg are domain-agnostic (a -> a*R is linear), so each is checked twice:
        // against the CBigNum reference on ordinary values, and through the Montgomery domain.
        CBigNum refAdd(aRef);
        refAdd.add(bRef);
        refAdd.mod(m);

        CBigNum gotAdd(a);
        mont.add(gotAdd, b);
        CHECK(gotAdd.compare(refAdd) == 0);
        CHECK(gotAdd.compare(m) < 0);

        CBigNum gotAddMont(aMont);
        mont.add(gotAddMont, bMont);
        CHECK(mont.fromMont(gotAddMont).compare(refAdd) == 0);

        CBigNum refSub(a);
        refSub.modSub(b, m);

        CBigNum gotSub(a);
        mont.sub(gotSub, b);
        CHECK(gotSub.compare(refSub) == 0);
        CHECK(gotSub.compare(m) < 0);

        CBigNum gotSubMont(aMont);
        mont.sub(gotSubMont, bMont);
        CHECK(mont.fromMont(gotSubMont).compare(refSub) == 0);

        CBigNum refDbl(aRef);
        refDbl.add(aRef);
        refDbl.mod(m);

        CBigNum gotDbl(a);
        mont.dbl(gotDbl);
        CHECK(gotDbl.compare(refDbl) == 0);

        CBigNum refNeg(a);
        refNeg.modNeg(m);

        CBigNum gotNeg(a);
        mont.neg(gotNeg);
        CHECK(gotNeg.compare(refNeg) == 0);
    }

    /* The hand-picked edge cases the brief calls out, for one modulus: 0, 1, m-1, m, m+1, and
     * values far larger than the modulus. These are where an off-by-one in the final reduction or
     * a missing "reduce the operand first" step lives. */
    void checkEdgeCases(const CMontgomery& mont) {
        const CBigNum& m = mont.modulus();

        const CBigNum zero;
        const CBigNum one(uint64_t(1));

        CBigNum mMinusOne(m);
        mMinusOne.sub(one);

        CBigNum mPlusOne(m);
        mPlusOne.add(one);

        // --> m^2 - 1 and m*m+m: both far above the modulus, and the second is an exact multiple
        // of m plus m, i.e. where "reduce, then reduce again" and "reduce once" differ if the
        // reduction is sloppy.
        CBigNum big(m);
        big.mul(m);
        big.sub(one);

        CBigNum multiple(m);
        multiple.mul(m);
        multiple.add(m);

        const CBigNum operands[] = { zero, one, mMinusOne, m, mPlusOne, big, multiple };
        const size_t count = sizeof(operands) / sizeof(operands[0]);

        for (size_t i = 0; i < count; ++i) {
            for (size_t j = 0; j < count; ++j) {
                CAPTURE(i);
                CAPTURE(j);
                checkAgrees(mont, operands[i], operands[j]);
            }
        }

        // --> one() is the Montgomery form of 1, so it has to behave as the identity in the
        // Montgomery domain and convert back to 1 (or to 0 when m == 1).
        CBigNum refOne(one);
        refOne.mod(m);
        CHECK(mont.fromMont(mont.one()).compare(refOne) == 0);

        CBigNum identity(mont.toMont(mMinusOne));
        mont.mul(identity, mont.one());
        CHECK(mont.fromMont(identity).compare(mMinusOne) == 0);
    }

} // namespace

TEST_CASE("CMontgomery: rejects a modulus it cannot work with") {
    // --> Montgomery reduction needs gcd(R, m) == 1 with R a power of two, i.e. an odd modulus.
    // An even or zero one has no n', and the context has to say so rather than compute nonsense.
    CHECK_FALSE(CMontgomery().isValid());
    CHECK_FALSE(CMontgomery(CBigNum()).isValid());
    CHECK_FALSE(CMontgomery(CBigNum(uint64_t(2))).isValid());
    CHECK_FALSE(CMontgomery(CBigNum(uint64_t(0xFFFFFFFFFFFFFFFEull))).isValid());

    CHECK(CMontgomery(CBigNum(uint64_t(1))).isValid());
    CHECK(CMontgomery(CBigNum(uint64_t(3))).isValid());
    CHECK(CMontgomery(CBigNum(uint64_t(0xFFFFFFFFFFFFFFFFull))).isValid());
}

TEST_CASE("CMontgomery: agrees with CBigNum on hand-picked edge cases, per shipped modulus") {
    const TArray<CBigNum> moduli = shippedModuli();

    for (size_t i = 0; i < moduli.size(); ++i) {
        CAPTURE(i);

        const CMontgomery mont(moduli[i]);
        REQUIRE(mont.isValid());
        checkEdgeCases(mont);
    }
}

TEST_CASE("CMontgomery: agrees with CBigNum on tiny moduli") {
    // --> Single-limb moduli exercise the s == 1 path, where the reduction pass's inner loop does
    // not run at all and the carry handling is all that is left of it.
    for (uint64_t m = 1; m <= 33; m += 2) {
        CAPTURE(m);

        const CBigNum modulus(m);
        const CMontgomery mont(modulus);
        REQUIRE(mont.isValid());
        checkEdgeCases(mont);

        // --> Exhaustive over [0, 2m+2], so every operand class (below, equal to, and above the
        // modulus, including an exact multiple of it) is covered without being hand-picked.
        for (uint64_t a = 0; a <= 2 * m + 2; ++a) {
            for (uint64_t b = 0; b <= 2 * m + 2; ++b) {
                checkAgrees(mont, CBigNum(a), CBigNum(b));
            }
        }
    }
}

TEST_CASE("CMontgomery: agrees with CBigNum on random operands, per shipped modulus") {
    const TArray<CBigNum> moduli = shippedModuli();
    Rng rng(0xC0FFEE1234567890ull);

    for (size_t i = 0; i < moduli.size(); ++i) {
        CAPTURE(i);

        const CMontgomery mont(moduli[i]);
        REQUIRE(mont.isValid());

        const size_t bits = moduli[i].bitLength();

        for (size_t round = 0; round < 40; ++round) {
            CAPTURE(round);

            // --> Both operands in range, then deliberately out of range: twice the modulus's bit
            // length, which is the width an unreduced product of two field elements has.
            checkAgrees(mont, randomOfBits(rng, bits - 1), randomOfBits(rng, bits - 1));
            checkAgrees(mont, randomOfBits(rng, bits), randomOfBits(rng, bits));
            checkAgrees(mont, randomOfBits(rng, 2 * bits), randomOfBits(rng, bits / 2));
            checkAgrees(mont, randomOfBits(rng, bits / 2), randomOfBits(rng, 2 * bits));
        }
    }
}

TEST_CASE("CMontgomery: agrees with CBigNum on random odd moduli across bit widths") {
    // --> Nothing here is prime, and the widths span one limb to 32 of them -- CMontgomery is not
    // a field-specific type, so the only thing it may assume about the modulus is that it is odd.
    const size_t widths[] = { 32, 33, 63, 64, 65, 96, 127, 128, 192, 256, 384, 521, 1024 };
    const size_t widthCount = sizeof(widths) / sizeof(widths[0]);

    Rng rng(0x5EED0F1CEBABE001ull);

    for (size_t w = 0; w < widthCount; ++w) {
        CAPTURE(widths[w]);

        for (size_t trial = 0; trial < 6; ++trial) {
            CAPTURE(trial);

            const CBigNum m = randomOddOfBits(rng, widths[w]);
            const CMontgomery mont(m);
            REQUIRE(mont.isValid());

            checkEdgeCases(mont);

            for (size_t round = 0; round < 20; ++round) {
                CAPTURE(round);

                checkAgrees(mont, randomOfBits(rng, widths[w]), randomOfBits(rng, widths[w]));
                checkAgrees(
                    mont, randomOfBits(rng, 2 * widths[w] + 5), randomOfBits(rng, widths[w] - 1)
                );
            }
        }
    }
}

TEST_CASE("CMontgomery::modExp(): agrees with CBigNum::modExp()") {
    Rng rng(0xA5A5A5A5DEADBEEFull);

    SUBCASE("hand-picked exponents on a shipped prime") {
        CEcCurve curve;
        REQUIRE(CEcCurve::knownCurves(ECURVE_P256, curve));

        const CMontgomery mont(curve.p);
        REQUIRE(mont.isValid());

        CBigNum pMinusOne(curve.p);
        pMinusOne.sub(CBigNum(uint64_t(1)));

        const CBigNum bases[] = {
            CBigNum(), CBigNum(uint64_t(1)), CBigNum(uint64_t(2)), pMinusOne, curve.p, curve.n
        };
        const CBigNum exponents[] = {
            CBigNum(), CBigNum(uint64_t(1)), CBigNum(uint64_t(2)), CBigNum(uint64_t(65537)),
            pMinusOne
        };

        for (size_t i = 0; i < sizeof(bases) / sizeof(bases[0]); ++i) {
            for (size_t j = 0; j < sizeof(exponents) / sizeof(exponents[0]); ++j) {
                CAPTURE(i);
                CAPTURE(j);

                const CBigNum ref = CBigNum::modExp(bases[i], exponents[j], curve.p);
                CHECK(mont.modExp(bases[i], exponents[j]).compare(ref) == 0);
            }
        }
    }

    SUBCASE("random operands on random odd moduli") {
        const size_t widths[] = { 32, 65, 128, 256 };

        for (size_t w = 0; w < sizeof(widths) / sizeof(widths[0]); ++w) {
            CAPTURE(widths[w]);

            const CBigNum m = randomOddOfBits(rng, widths[w]);
            const CMontgomery mont(m);
            REQUIRE(mont.isValid());

            for (size_t round = 0; round < 8; ++round) {
                CAPTURE(round);

                const CBigNum base = randomOfBits(rng, widths[w] + 7);
                const CBigNum exponent = randomOfBits(rng, 64);

                const CBigNum ref = CBigNum::modExp(base, exponent, m);
                CHECK(mont.modExp(base, exponent).compare(ref) == 0);
            }
        }
    }
}

TEST_CASE("CMontgomery: a long chain of operations stays in step with CBigNum") {
    // --> Every check above starts from freshly reduced operands, which would hide an error that
    // only accumulates: a result that is correct mod m but left unreduced feeds the next operation
    // an out-of-domain input, and the two paths drift apart a few steps later rather than
    // immediately. This runs a few thousand chained operations against the slow path to catch that.
    const TArray<CBigNum> moduli = shippedModuli();
    Rng rng(0x1BADB0021BADB002ull);

    for (size_t i = 0; i < moduli.size(); ++i) {
        CAPTURE(i);

        const CBigNum& m = moduli[i];
        const CMontgomery mont(m);
        REQUIRE(mont.isValid());

        CBigNum ref = randomOfBits(rng, m.bitLength() - 1);
        CBigNum got = mont.toMont(ref);

        for (size_t step = 0; step < 200; ++step) {
            const CBigNum operand = randomOfBits(rng, m.bitLength() - 1);
            const CBigNum operandMont = mont.toMont(operand);

            switch (step % 4) {
            case 0:
                ref.mulMod(operand, m);
                mont.mul(got, operandMont);
                break;

            case 1:
                ref.add(operand);
                ref.mod(m);
                mont.add(got, operandMont);
                break;

            case 2:
                ref.modSub(operand, m);
                mont.sub(got, operandMont);
                break;

            default:
                ref.mulMod(ref, m);
                mont.mul(got, got);
                break;
            }

            REQUIRE(got.compare(m) < 0);
        }

        CHECK(mont.fromMont(got).compare(ref) == 0);
    }
}
