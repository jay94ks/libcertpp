#include "fe25519.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

        /* Bit offset of limb i: 0, 26, 51, 77, 102, 128, 153, 179, 204, 230. */
        constexpr int OFFSET[Fe25519::LIMBS] = { 0, 26, 51, 77, 102, 128, 153, 179, 204, 230 };

        /* One carry pass over signed limbs, finishing with limb 9's overflow folded back into
         * limb 0 as a factor of 19 (because 2^255 == 19 mod p). The shift is arithmetic, which
         * is what lets a negative limb -- the ordinary result of sub() -- propagate correctly
         * without a borrow branch.
         *
         * --> Left as a loop deliberately. An unrolled version with literal shift amounts was
         * written and measured, on the theory that widthOf(i)'s modulo was costing something
         * across the ~50,000 calls a ladder makes: it made no difference at all, within a run-to-
         * run spread of about 11%. widthOf() is constexpr and the bound is fixed, so the compiler
         * was already doing it. The loop stays because it is shorter and says the same thing. */
        void carryPass(int64_t* t) {
            int64_t carry = 0;

            for (size_t i = 0; i < Fe25519::LIMBS; ++i) {
                t[i] += carry;
                carry = t[i] >> Fe25519::widthOf(i);
                t[i] -= carry << Fe25519::widthOf(i);
            }

            t[0] += carry * 19;

            // Limb 0 may now exceed its width; one short pass settles it.
            carry = t[0] >> 26;
            t[0] -= carry << 26;
            t[1] += carry;
        }

        void store(Fe25519& out, const int64_t* t) {
            for (size_t i = 0; i < Fe25519::LIMBS; ++i) {
                out.limbs[i] = int32_t(t[i]);
            }
        }

        void load(int64_t* t, const Fe25519& in) {
            for (size_t i = 0; i < Fe25519::LIMBS; ++i) {
                t[i] = in.limbs[i];
            }
        }

        /* out250 = a^(2^250 - 1) and out11 = a^11.
         *
         * The long run of one-bits that the two fixed exponents this file needs both start with:
         * the inversion's p - 2 == 2^255 - 21, and the square root's (p + 3) / 8 == 2^252 - 2.
         * 249 squarings and 11 multiplications, in the same order for every input, so neither the
         * value nor any property of it affects the control flow.
         *
         * Shared rather than written out twice. It is a forty-line addition chain, and a square
         * root that got it wrong in exactly the same way as the inverse would still agree with
         * itself on every self-consistency check -- one copy, checked against CBigNum, is one
         * thing to be sure of rather than two. a^11 comes back alongside because the inversion's
         * tail needs it and the chain computes it on the way regardless. */
        void powTwo250Minus1(Fe25519& out250, Fe25519& out11, const Fe25519& a) {
            Fe25519 z2, z9, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, work;

            Fe25519::square(z2, a);                             // 2
            Fe25519::square(work, z2);                          // 4
            Fe25519::square(work, work);                        // 8
            Fe25519::mul(z9, work, a);                          // 9
            Fe25519::mul(out11, z9, z2);                        // 11

            Fe25519::square(work, out11);                       // 22
            Fe25519::mul(z2_5_0, work, z9);                     // 2^5 - 2^0

            Fe25519::square(work, z2_5_0);
            for (int i = 1; i < 5; ++i) {
                Fe25519::square(work, work);
            }
            Fe25519::mul(z2_10_0, work, z2_5_0);                // 2^10 - 2^0

            Fe25519::square(work, z2_10_0);
            for (int i = 1; i < 10; ++i) {
                Fe25519::square(work, work);
            }
            Fe25519::mul(z2_20_0, work, z2_10_0);               // 2^20 - 2^0

            Fe25519::square(work, z2_20_0);
            for (int i = 1; i < 20; ++i) {
                Fe25519::square(work, work);
            }
            Fe25519::mul(work, work, z2_20_0);                  // 2^40 - 2^0

            Fe25519::square(work, work);
            for (int i = 1; i < 10; ++i) {
                Fe25519::square(work, work);
            }
            Fe25519::mul(z2_50_0, work, z2_10_0);               // 2^50 - 2^0

            Fe25519::square(work, z2_50_0);
            for (int i = 1; i < 50; ++i) {
                Fe25519::square(work, work);
            }
            Fe25519::mul(z2_100_0, work, z2_50_0);              // 2^100 - 2^0

            Fe25519::square(work, z2_100_0);
            for (int i = 1; i < 100; ++i) {
                Fe25519::square(work, work);
            }
            Fe25519::mul(work, work, z2_100_0);                 // 2^200 - 2^0

            Fe25519::square(work, work);
            for (int i = 1; i < 50; ++i) {
                Fe25519::square(work, work);
            }
            Fe25519::mul(out250, work, z2_50_0);                // 2^250 - 2^0
        }

        /* sqrt(-1) mod p, the constant the second square-root candidate is multiplied by.
         *
         * Derived rather than transcribed as a 255-bit literal, the same choice ed25519.cpp makes
         * for the curve's d and base point: 2 is a quadratic non-residue mod p, so 2^((p-1)/4) is
         * a square root of -1. (p - 1) / 4 == 2^253 - 5, which is the run of ones above shifted
         * up three places (2^253 - 8) times 2^3 -- three squarings and one multiply by the cube.
         *
         * Computed once on first use and kept for the life of the process, like ed25519.cpp's own
         * derived constants. */
        const Fe25519& sqrtMinusOne() {
            static const Fe25519 value = [] {
                Fe25519 one, two;
                one.setOne();
                Fe25519::add(two, one, one);

                Fe25519 chain, unused11;
                powTwo250Minus1(chain, unused11, two);          // 2^(2^250 - 1)

                Fe25519 result;
                Fe25519::square(result, chain);
                Fe25519::square(result, result);
                Fe25519::square(result, result);                // 2^(2^253 - 8)

                Fe25519 cube;
                Fe25519::square(cube, two);
                Fe25519::mul(cube, cube, two);                  // 2^3

                Fe25519::mul(result, result, cube);             // 2^(2^253 - 5)
                return result;
            }();

            return value;
        }

    } // namespace

    /* Zero. */
    void Fe25519::setZero() {
        std::memset(limbs, 0, sizeof(limbs));
    }

    /* One. */
    void Fe25519::setOne() {
        std::memset(limbs, 0, sizeof(limbs));
        limbs[0] = 1;
    }

    /* Decodes a little-endian 32-byte value, masking bit 255. */
    void Fe25519::fromBytes(const uint8_t in[BYTES]) {
        // RFC 7748 5: the top bit of a u-coordinate is masked, not rejected.
        uint8_t masked[BYTES];
        std::memcpy(masked, in, BYTES);
        masked[31] = uint8_t(masked[31] & 0x7Fu);

        // Sliced bit by bit, so the alternating 26/25 widths need no per-limb byte arithmetic.
        // Not the fastest way to unpack, but this runs once per scalar multiplication rather
        // than once per ladder step.
        auto bitAt = [&](size_t bit) -> uint32_t {
            return uint32_t((masked[bit >> 3] >> (bit & 7u)) & 1u);
        };

        for (size_t i = 0; i < LIMBS; ++i) {
            const int width = widthOf(i);
            int32_t value = 0;

            for (int b = 0; b < width; ++b) {
                value |= int32_t(bitAt(size_t(OFFSET[i] + b))) << b;
            }

            limbs[i] = value;
        }
    }

    /* Encodes as a little-endian 32-byte value, fully reduced into [0, p). */
    void Fe25519::toBytes(uint8_t out[BYTES]) const {
        int64_t t[LIMBS];
        load(t, *this);

        carryPass(t);
        carryPass(t);

        // --> The conditional subtraction of p, as an arithmetic cascade. q ends up 1 when the
        // value is at or above p and 0 otherwise, without ever comparing it. Adding 19*q and
        // then discarding the 2^255 bit is the subtraction. Skipping this yields a
        // representative in [p, 2^255) for some inputs, which still decodes back to the same
        // field element -- so no round-trip test would notice, and only a check against the
        // canonical bytes catches it.
        int64_t q = (19 * t[9] + (int64_t(1) << 24)) >> 25;
        for (size_t i = 0; i < LIMBS; ++i) {
            q = (t[i] + q) >> widthOf(i);
        }

        t[0] += 19 * q;

        int64_t carry = 0;
        for (size_t i = 0; i < LIMBS; ++i) {
            t[i] += carry;
            carry = t[i] >> widthOf(i);
            t[i] -= carry << widthOf(i);
        }
        // `carry` here is the 2^255 bit, and dropping it completes the subtraction.

        std::memset(out, 0, BYTES);

        for (size_t i = 0; i < LIMBS; ++i) {
            const int width = widthOf(i);

            for (int b = 0; b < width; ++b) {
                const size_t bit = size_t(OFFSET[i] + b);
                const uint8_t value = uint8_t((t[i] >> b) & 1);
                out[bit >> 3] = uint8_t(out[bit >> 3] | (value << (bit & 7u)));
            }
        }
    }

    /* out = a + b. */
    void Fe25519::add(Fe25519& out, const Fe25519& a, const Fe25519& b) {
        int64_t t[LIMBS];
        for (size_t i = 0; i < LIMBS; ++i) {
            t[i] = int64_t(a.limbs[i]) + int64_t(b.limbs[i]);
        }

        carryPass(t);
        store(out, t);
    }

    /* out = a - b. */
    void Fe25519::sub(Fe25519& out, const Fe25519& a, const Fe25519& b) {
        int64_t t[LIMBS];
        for (size_t i = 0; i < LIMBS; ++i) {
            // Signed limbs, so this just goes negative and the carry pass sorts it out -- no
            // borrow, and no branch on which operand is larger.
            t[i] = int64_t(a.limbs[i]) - int64_t(b.limbs[i]);
        }

        carryPass(t);
        store(out, t);
    }

    /* out = a * b. */
    void Fe25519::mul(Fe25519& out, const Fe25519& a, const Fe25519& b) {
        // Generated from the rule validated against exact arithmetic: a doubling when
        // both limb indices are odd, and a factor of 19 when the product lands at 2^255
        // or above. Pre-scaling the operands folds both constants out of the inner
        // expressions, leaving pure multiply-accumulate with no branches at all -- which
        // is what the 10x10 loop this replaces could not give the compiler.
        const int64_t f0 = a.limbs[0];
        const int64_t f1 = a.limbs[1];
        const int64_t f2 = a.limbs[2];
        const int64_t f3 = a.limbs[3];
        const int64_t f4 = a.limbs[4];
        const int64_t f5 = a.limbs[5];
        const int64_t f6 = a.limbs[6];
        const int64_t f7 = a.limbs[7];
        const int64_t f8 = a.limbs[8];
        const int64_t f9 = a.limbs[9];
        const int64_t g0 = b.limbs[0];
        const int64_t g1 = b.limbs[1];
        const int64_t g2 = b.limbs[2];
        const int64_t g3 = b.limbs[3];
        const int64_t g4 = b.limbs[4];
        const int64_t g5 = b.limbs[5];
        const int64_t g6 = b.limbs[6];
        const int64_t g7 = b.limbs[7];
        const int64_t g8 = b.limbs[8];
        const int64_t g9 = b.limbs[9];

        // The odd limbs doubled, and every limb times 19, computed once each rather than
        // per partial product.
        const int64_t f1_2 = f1 * 2;
        const int64_t f3_2 = f3 * 2;
        const int64_t f5_2 = f5 * 2;
        const int64_t f7_2 = f7 * 2;
        const int64_t f9_2 = f9 * 2;
        const int64_t g1_19 = g1 * 19;
        const int64_t g2_19 = g2 * 19;
        const int64_t g3_19 = g3 * 19;
        const int64_t g4_19 = g4 * 19;
        const int64_t g5_19 = g5 * 19;
        const int64_t g6_19 = g6 * 19;
        const int64_t g7_19 = g7 * 19;
        const int64_t g8_19 = g8 * 19;
        const int64_t g9_19 = g9 * 19;

        int64_t t0 = f0 * g0 + f1_2 * g9_19 + f2 * g8_19
                     + f3_2 * g7_19 + f4 * g6_19 + f5_2 * g5_19
                     + f6 * g4_19 + f7_2 * g3_19 + f8 * g2_19
                     + f9_2 * g1_19;
        int64_t t1 = f0 * g1 + f1 * g0 + f2 * g9_19
                     + f3 * g8_19 + f4 * g7_19 + f5 * g6_19
                     + f6 * g5_19 + f7 * g4_19 + f8 * g3_19
                     + f9 * g2_19;
        int64_t t2 = f0 * g2 + f1_2 * g1 + f2 * g0
                     + f3_2 * g9_19 + f4 * g8_19 + f5_2 * g7_19
                     + f6 * g6_19 + f7_2 * g5_19 + f8 * g4_19
                     + f9_2 * g3_19;
        int64_t t3 = f0 * g3 + f1 * g2 + f2 * g1
                     + f3 * g0 + f4 * g9_19 + f5 * g8_19
                     + f6 * g7_19 + f7 * g6_19 + f8 * g5_19
                     + f9 * g4_19;
        int64_t t4 = f0 * g4 + f1_2 * g3 + f2 * g2
                     + f3_2 * g1 + f4 * g0 + f5_2 * g9_19
                     + f6 * g8_19 + f7_2 * g7_19 + f8 * g6_19
                     + f9_2 * g5_19;
        int64_t t5 = f0 * g5 + f1 * g4 + f2 * g3
                     + f3 * g2 + f4 * g1 + f5 * g0
                     + f6 * g9_19 + f7 * g8_19 + f8 * g7_19
                     + f9 * g6_19;
        int64_t t6 = f0 * g6 + f1_2 * g5 + f2 * g4
                     + f3_2 * g3 + f4 * g2 + f5_2 * g1
                     + f6 * g0 + f7_2 * g9_19 + f8 * g8_19
                     + f9_2 * g7_19;
        int64_t t7 = f0 * g7 + f1 * g6 + f2 * g5
                     + f3 * g4 + f4 * g3 + f5 * g2
                     + f6 * g1 + f7 * g0 + f8 * g9_19
                     + f9 * g8_19;
        int64_t t8 = f0 * g8 + f1_2 * g7 + f2 * g6
                     + f3_2 * g5 + f4 * g4 + f5_2 * g3
                     + f6 * g2 + f7_2 * g1 + f8 * g0
                     + f9_2 * g9_19;
        int64_t t9 = f0 * g9 + f1 * g8 + f2 * g7
                     + f3 * g6 + f4 * g5 + f5 * g4
                     + f6 * g3 + f7 * g2 + f8 * g1
                     + f9 * g0;

        int64_t t[LIMBS] = { t0, t1, t2, t3, t4, t5, t6, t7, t8, t9 };

        // Two passes: the first brings limbs into range, the second settles the 19x
        // fold-back out of limb 0.
        carryPass(t);
        carryPass(t);
        store(out, t);
    }

    /* out = a^2. */
    void Fe25519::square(Fe25519& out, const Fe25519& a) {
        // --> Deliberately still mul(a, a) rather than a dedicated squaring. A squaring routine
        // halves the partial products, because every off-diagonal term appears twice and can be
        // doubled once -- worth perhaps 30% of the ladder. It is also a second 100-term
        // expression to get right, with its own doubling rules interacting with the radix's,
        // and the ladder calls square() four times per iteration where a wrong one would still
        // agree with itself. Left until the unrolled mul below has been measured, so the gain
        // can be attributed rather than assumed.
        mul(out, a, a);
    }

    /* out = a * 121665. */
    void Fe25519::mulA24(Fe25519& out, const Fe25519& a) {
        int64_t t[LIMBS];

        for (size_t i = 0; i < LIMBS; ++i) {
            t[i] = int64_t(a.limbs[i]) * 121665;
        }

        carryPass(t);
        carryPass(t);
        store(out, t);
    }

    /* out = -a. */
    void Fe25519::neg(Fe25519& out, const Fe25519& a) {
        Fe25519 zero;
        zero.setZero();
        sub(out, zero, a);
    }

    /* out = a^-1, via the fixed a^(p-2) chain. */
    void Fe25519::invert(Fe25519& out, const Fe25519& a) {
        // p - 2 is 250 one-bits followed by 01101, so the exponentiation is a fixed sequence of
        // 254 squarings and 11 multiplications. It runs identically for every input -- including
        // zero, which simply yields zero -- so neither the value nor any property of it affects
        // the control flow.
        Fe25519 work, z11;
        powTwo250Minus1(work, z11, a);                  // 2^250 - 2^0

        square(work, work);
        square(work, work);
        square(work, work);
        square(work, work);
        square(work, work);
        mul(out, work, z11);                            // 2^255 - 21 == p - 2
    }

    /* out = a square root of a, if a has one. */
    bool Fe25519::squareRoot(Fe25519& out, const Fe25519& a) {
        // (p + 3) / 8 == 2^252 - 2, which is the shared chain's 2^250 - 1 squared (2^251 - 2),
        // times a (2^251 - 1), squared again.
        Fe25519 chain, unused11;
        powTwo250Minus1(chain, unused11, a);            // 2^250 - 1

        Fe25519 candidate;
        square(candidate, chain);                       // 2^251 - 2
        mul(candidate, candidate, a);                   // 2^251 - 1
        square(candidate, candidate);                   // 2^252 - 2 == (p + 3) / 8

        // --> Both candidates are squared back and compared, rather than one being trusted. The
        // exponentiation alone cannot tell a residue from a non-residue: for a non-residue it
        // returns a perfectly ordinary-looking element that is a root of nothing. Skipping the
        // check would hand Ed25519's point decoding an x that does not satisfy the curve
        // equation, i.e. accept a malformed public key.
        Fe25519 check;
        square(check, candidate);
        if (check.isEqual(a)) {
            out = candidate;
            return true;
        }

        mul(candidate, candidate, sqrtMinusOne());

        square(check, candidate);
        if (check.isEqual(a)) {
            out = candidate;
            return true;
        }

        return false;
    }

    /* Swaps a and b under a mask, without branching. */
    void Fe25519::condSwap(uint32_t mask, Fe25519& a, Fe25519& b) {
        // --> In a Montgomery ladder the condition is a bit of the private scalar, so this has
        // to be arithmetic rather than an `if`. Every limb is read and written on both paths.
        const int32_t m = int32_t(mask);

        for (size_t i = 0; i < LIMBS; ++i) {
            const int32_t difference = (a.limbs[i] ^ b.limbs[i]) & m;
            a.limbs[i] = a.limbs[i] ^ difference;
            b.limbs[i] = b.limbs[i] ^ difference;
        }
    }

    /* Whether this element is zero. */
    bool Fe25519::isZero() const {
        uint8_t encoded[BYTES];
        toBytes(encoded);

        // Every byte is read; the verdict is one bit, which is all the caller needs and all that
        // can be observed.
        uint8_t accumulator = 0;
        for (size_t i = 0; i < BYTES; ++i) {
            accumulator = uint8_t(accumulator | encoded[i]);
        }

        return accumulator == 0;
    }

    /* Whether this element equals another. */
    bool Fe25519::isEqual(const Fe25519& other) const {
        // By difference, not by limbs: the representation is redundant, so two limb arrays can
        // differ and still stand for the same element.
        Fe25519 difference;
        sub(difference, *this, other);
        return difference.isZero();
    }

    /* The low bit of the canonical representative. */
    bool Fe25519::isOdd() const {
        uint8_t encoded[BYTES];
        toBytes(encoded);

        return (encoded[0] & 1u) != 0;
    }

} // namespace crypto
} // namespace certpp
