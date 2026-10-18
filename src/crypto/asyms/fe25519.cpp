#include "fe25519.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

#if defined(CERTPP_FE25519_RADIX51)

        /* Bit offset of limb i: 0, 51, 102, 153, 204. */
        constexpr int OFFSET[Fe25519::LIMBS] = { 0, 51, 102, 153, 204 };

        constexpr int64_t MASK51 = (int64_t(1) << 51) - 1;

        /* One carry pass over five signed 51-bit limbs, ending with limb 4's overflow folded back
         * into limb 0 as a factor of 19, because 2^255 == 19 mod p.
         *
         * The shifts are arithmetic, which is what lets a negative limb -- the ordinary result of
         * sub() -- propagate correctly without a borrow branch. That is the same property the
         * 2^25.5 path relies on, and the reason both layouts keep signed limbs rather than
         * adding a multiple of p before every subtraction.
         *
         * Left as a loop for the same reason as the 2^25.5 version: unrolling it was measured and
         * changed nothing inside the run-to-run spread. */
        void carryPass(int64_t* t) {
            int64_t carry = 0;

            for (size_t i = 0; i < Fe25519::LIMBS; ++i) {
                t[i] += carry;
                carry = t[i] >> Fe25519::widthOf(i);
                t[i] -= carry << Fe25519::widthOf(i);
            }

            t[0] += carry * 19;

            // Limb 0 may now exceed its width; one short pass settles it.
            carry = t[0] >> 51;
            t[0] -= carry << 51;
            t[1] += carry;
        }

        void store(Fe25519& out, const int64_t* t) {
            for (size_t i = 0; i < Fe25519::LIMBS; ++i) {
                out.limbs[i] = t[i];
            }
        }

        void load(int64_t* t, const Fe25519& in) {
            for (size_t i = 0; i < Fe25519::LIMBS; ++i) {
                t[i] = in.limbs[i];
            }
        }

        void storeReduced128(Fe25519& out, unsigned __int128* t) {
            constexpr uint64_t mask = (uint64_t(1) << 51) - 1;
            uint64_t reduced[Fe25519::LIMBS];

            unsigned __int128 carry = t[0] >> 51;
            reduced[0] = uint64_t(t[0]) & mask;
            t[1] += carry;
            carry = t[1] >> 51;
            reduced[1] = uint64_t(t[1]) & mask;
            t[2] += carry;
            carry = t[2] >> 51;
            reduced[2] = uint64_t(t[2]) & mask;
            t[3] += carry;
            carry = t[3] >> 51;
            reduced[3] = uint64_t(t[3]) & mask;
            t[4] += carry;
            carry = t[4] >> 51;
            reduced[4] = uint64_t(t[4]) & mask;

            unsigned __int128 low = (unsigned __int128)(reduced[0]) + carry * 19;
            reduced[0] = uint64_t(low) & mask;
            carry = low >> 51;
            low = (unsigned __int128)(reduced[1]) + carry;
            reduced[1] = uint64_t(low) & mask;
            reduced[2] += uint64_t(low >> 51);

            for (size_t i = 0; i < Fe25519::LIMBS; ++i) {
                out.limbs[i] = reduced[i];
            }
        }

        /* Reduces five folded product accumulators while retaining two independent carry chains.
         *
         * A strictly limb-0-to-limb-4 carry makes every accumulator wait for the previous one,
         * even though multiplication produced all five independently. Here the even and odd
         * chains advance separately until the final two short carries. The result is deliberately
         * only carry-bounded: limbs 1 and 3 may exceed 2^51 by a small carry, which is within the
         * documented loose-input bounds and avoids another serial pass in every ladder operation.
         */
        inline void storeProductReduced(
            Fe25519& out,
            unsigned __int128 h0,
            unsigned __int128 h1,
            unsigned __int128 h2,
            unsigned __int128 h3,
            unsigned __int128 h4
        ) {
            constexpr uint64_t mask = (uint64_t(1) << 51) - 1;

            h3 += uint64_t(h2 >> 51);
            uint64_t r2 = uint64_t(h2) & mask;

            h1 += uint64_t(h0 >> 51);
            uint64_t r0 = uint64_t(h0) & mask;

            h4 += uint64_t(h3 >> 51);
            uint64_t r3 = uint64_t(h3) & mask;

            r2 += uint64_t(h1 >> 51);
            uint64_t r1 = uint64_t(h1) & mask;

            r0 += uint64_t(h4 >> 51) * 19;
            const uint64_t r4 = uint64_t(h4) & mask;

            r3 += r2 >> 51;
            r2 &= mask;

            r1 += r0 >> 51;
            r0 &= mask;

            out.limbs[0] = r0;
            out.limbs[1] = r1;
            out.limbs[2] = r2;
            out.limbs[3] = r3;
            out.limbs[4] = r4;
        }

        /* The 5x5 product, accumulated as explicit (hi, lo) pairs rather than __int128 values.
         *
         * --> This is the second version of this function, and the first one was correct and not
         * faster, which is worth saying plainly. Written with a __int128 accumulator array, it
         * passed every test and produced exactly the Ed25519 signing time the 2^25.5 layout did.
         * The reason is in the generated code, not the arithmetic: `t[k] >> 51` on a __int128 is
         * a double-precision shift, which x86-64 has no single instruction for, so every one
         * lowers to shrd+sar. Eight of those per round over three rounds is 48 instructions of
         * shifting to fold 25 products, and the whole function came out at 495 instructions for
         * 25 multiplies -- 195 of them moves, 80 shift halves, 25 imuls doing the actual work.
         *
         * So: each accumulator is a pair of 64-bit words and every carry is a 64-bit shift. The
         * products are still native 64x64->128; only the arithmetic around them changes.
         */
        struct Acc {
            uint64_t lo;
            uint64_t hi;
        };

        /* Adds one native 64x64->128 product into an accumulator.
         *
         * A single product, taken apart once. >> 64 on a __int128 is a register copy of the high
         * word, not a shift, so this is still one instruction's worth of multiply work plus two
         * moves -- not the two separate multiplies an earlier version of this did by computing
         * the low half a second time as a plain 64-bit product.
         */
        inline void accumulate(Acc& into, uint64_t a, uint64_t b) {
            const unsigned __int128 product = (unsigned __int128)a * b;

            const uint64_t s = into.lo + (uint64_t)product;
            into.hi += (uint64_t)(product >> 64) + (s < (uint64_t)product ? 1ull : 0ull);
            into.lo = s;
        }

        /* into += 19 * src, for a src that the carry chain has already reduced to 51 bits.
         *
         * The product 19 * src is two words wide in general and three words wide at the very top,
         * which is why the low half is taken as a 64-bit product and only its carry -- never the
         * full 128-bit value -- is added to the scaled high half.
         */
        inline void foldIn(Acc& into, const Acc& src) {
            const unsigned __int128 low = (unsigned __int128)src.lo * 19ull;
            const unsigned __int128 high = (unsigned __int128)src.hi * 19ull + (low >> 64);

            const uint64_t s = into.lo + (uint64_t)low;
            into.hi += (uint64_t)high + (s < (uint64_t)low ? 1ull : 0ull);
            into.lo = s;
        }

        /* Folds the ten 51-bit accumulators a 5x5 product lands in down to the five limbs an
         * element actually has.
         *
         * The product reaches bit 459 and an element holds 255 of them, so everything from limb 5
         * up has to come back down by 2^255 == 19 mod p. It comes down four limbs at a time, one
         * factor of 19 per limb -- NOT as 19 times the whole upper half, because 19 * (t8 * 2^153)
         * overflows the __int128 these are held in. Folding a limb at a time is what P4's two
         * failed attempts did not do.
         *
         * Three rounds because each shrinks the carry by about 2^51: the first leaves the top
         * limb near 2^59, the second near 2^8, the third exact. That is an argument, not a proof;
         * the proof is tests/crypto/asyms/fe25519.cpp checking every operation against CBigNum,
         * which is the check that would catch this being wrong rather than merely wrong-looking.
         */
        void reduce9(Acc* t, int64_t* out) {
            // --> t[0..9], not t[0..8]. The carry chain has to normalize t[8] as well, or the
            // 19x fold below reads its un-reduced pair -- up to 2^105 with the high word holding
            // bits 64..105 -- and treats it as if it were a 51-bit limb. An earlier version ran
            // the chain only to k = 7 and was right on every product below 2^408 and wrong on
            // every one above it: 2^254 * 2^254, (p-1)^2 and (2^251+9)^2.
            for (int round = 0; round < 3; ++round) {
                // Carry limb k upward. The carry out of a 128-bit accumulator shifted right by 51
                // is (hi << 13) | (lo >> 51) in the low word and hi >> 51 in the high one --
                // both halves, which an earlier version of this dropped by zeroing hi and so
                // lost the upper half of every limb. Two shifts and an or, against the shrd+sar
                // pair the __int128 version needed, but with nothing written to memory.
                for (int k = 0; k < 9; ++k) {
                    const uint64_t carryLo = (t[k].lo >> 51) | (t[k].hi << 13);
                    const uint64_t carryHi = t[k].hi >> 51;
                    t[k].lo &= (uint64_t)MASK51;
                    t[k].hi = 0;

                    const uint64_t s = t[k + 1].lo + carryLo;
                    t[k + 1].hi += carryHi + (s < carryLo ? 1ull : 0ull);
                    t[k + 1].lo = s;
                }

                // Everything from limb 5 up is above 2^255, so it folds back by 19 -- limb by
                // limb, one per destination, because 19 times the whole upper half would not fit
                // in 64 bits. Limb k folds into limb k - 5.
                for (int k = 5; k < 10; ++k) {
                    foldIn(t[k - 5], t[k]);
                    t[k].lo = 0;
                    t[k].hi = 0;
                }
            }

            for (int k = 0; k < 5; ++k) {
                out[k] = int64_t(t[k].lo);
            }
        }

#else

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

#endif // CERTPP_FE25519_RADIX51

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

        // Sliced bit by bit, so the mixed limb widths need no per-limb byte arithmetic. Not the
        // fastest way to unpack, but this runs once per scalar multiplication rather than once
        // per ladder step.
        auto bitAt = [&](size_t bit) -> uint64_t {
            return uint64_t((masked[bit >> 3] >> (bit & 7u)) & 1u);
        };

        for (size_t i = 0; i < LIMBS; ++i) {
            const int width = widthOf(i);

            // --> int64_t on both layouts. The 2^25.5 limbs fit an int32_t and always did; a
            // 51-bit limb does not, and truncating one would decode a field element to a
            // different one.
            int64_t value = 0;

            for (int b = 0; b < width; ++b) {
                value |= int64_t(bitAt(size_t(OFFSET[i] + b))) << b;
            }

            limbs[i] = Limb(value);
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
#if defined(CERTPP_FE25519_RADIX51)
        // --> The same subtraction in the 51-bit layout, derived rather than recalled.
        //
        // After the two carry passes above every limb is in [0, 2^51) and limb 4 holds weight
        // 2^204, so the value x is in [0, 2^255). Reducing it means x - p = (x + 19) - 2^255,
        // and both halves of that are one carry cascade:
        //
        //   u = x + 19, carried limb by limb, with the bit that leaves limb 4 being the 2^255
        //       that has to go. Call that bit c. c is 1 exactly when x + 19 >= 2^255, i.e.
        //       exactly when x >= p.
        //   So u represents x + 19 - c*2^255 = x - c*p, which is the answer when c is 1 and
        //       is not the answer when c is 0 -- and when c is 0 nothing overflowed, so u is
        //       x + 19 rather than x, and the select has to pick the untouched limbs.
        //
        // The select is a mask rather than a branch, so the encoded bytes do not depend on a
        // comparison anywhere. An earlier version of this used ref10's (19*v[4] + 2^50) >> 51
        // form and adjusted the top limb by q - 2^51; it produced non-canonical bytes for values
        // at or above p, which tests/crypto/asyms/fe25519.cpp's encoding test caught against
        // CBigNum.
        int64_t u[LIMBS];

        u[0] = t[0] + 19;
        int64_t c = u[0] >> 51;
        u[0] -= c << 51;

        for (size_t i = 1; i < LIMBS; ++i) {
            u[i] = t[i] + c;
            c = u[i] >> 51;
            u[i] -= c << 51;
        }
        // c is now the 2^255 bit of (x + 19): 1 when x >= p, 0 otherwise.

        const int64_t select = -c; // 0 or all-ones
        for (size_t i = 0; i < LIMBS; ++i) {
            t[i] = (u[i] & select) | (t[i] & ~select);
        }
#else
        int64_t q = (19 * t[9] + (int64_t(1) << 24)) >> 25;
        for (size_t i = 0; i < LIMBS; ++i) {
            q = (t[i] + q) >> widthOf(i);
        }

        t[0] += 19 * q;
#endif // CERTPP_FE25519_RADIX51

        int64_t carry = 0;
        for (size_t i = 0; i < LIMBS; ++i) {
            t[i] += carry;
            carry = t[i] >> widthOf(i);
            t[i] -= carry << widthOf(i);
        }
        // `carry` here is the 2^255 bit, and dropping it completes the subtraction. On the
        // 51-bit path the equivalent adjustment already happened above, where limb 4 takes
        // q - 2^51 rather than q; this pass then has nothing left to carry.

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
#if defined(CERTPP_FE25519_RADIX51)
        // Keep every limb non-negative in the unsigned radix-51 representation. Adding 2p is
        // congruent to zero and gives enough headroom for any two carry-reduced inputs.
        constexpr uint64_t B = uint64_t(1) << 51;
        unsigned __int128 t[LIMBS] = {
            (unsigned __int128)(a.limbs[0]) + (2 * B - 38) - b.limbs[0],
            (unsigned __int128)(a.limbs[1]) + (2 * B - 2) - b.limbs[1],
            (unsigned __int128)(a.limbs[2]) + (2 * B - 2) - b.limbs[2],
            (unsigned __int128)(a.limbs[3]) + (2 * B - 2) - b.limbs[3],
            (unsigned __int128)(a.limbs[4]) + (2 * B - 2) - b.limbs[4],
        };
        storeReduced128(out, t);
#else
        int64_t t[LIMBS];
        for (size_t i = 0; i < LIMBS; ++i) {
            // Signed limbs, so this just goes negative and the carry pass sorts it out -- no
            // borrow, and no branch on which operand is larger.
            t[i] = int64_t(a.limbs[i]) - int64_t(b.limbs[i]);
        }

        carryPass(t);
        store(out, t);
#endif
    }

    /* out = a * b. */
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((always_inline))
#endif
    void Fe25519::mul(Fe25519& out, const Fe25519& a, const Fe25519& b) {
#if defined(CERTPP_FE25519_RADIX51)
        // Fold terms above 2^255 directly with 2^255 == 19. Unsigned 128-bit products accept the
        // single doubled-range result produced by addLoose()/subLoose(), allowing point formulas
        // to omit carry passes before an immediate multiply.
        const unsigned __int128 f0 = a.limbs[0], f1 = a.limbs[1], f2 = a.limbs[2];
        const unsigned __int128 f3 = a.limbs[3], f4 = a.limbs[4];
        const uint64_t g0 = b.limbs[0], g1 = b.limbs[1], g2 = b.limbs[2];
        const uint64_t g3 = b.limbs[3], g4 = b.limbs[4];
        const uint64_t g1_19 = g1 * 19, g2_19 = g2 * 19;
        const uint64_t g3_19 = g3 * 19, g4_19 = g4 * 19;

        const unsigned __int128 h0 = f0*g0 + f1*g4_19 + f2*g3_19 + f3*g2_19 + f4*g1_19;
        const unsigned __int128 h1 = f0*g1 + f1*g0 + f2*g4_19 + f3*g3_19 + f4*g2_19;
        const unsigned __int128 h2 = f0*g2 + f1*g1 + f2*g0 + f3*g4_19 + f4*g3_19;
        const unsigned __int128 h3 = f0*g3 + f1*g2 + f2*g1 + f3*g0 + f4*g4_19;
        const unsigned __int128 h4 = f0*g4 + f1*g3 + f2*g2 + f3*g1 + f4*g0;

        storeProductReduced(out, h0, h1, h2, h3, h4);
#else
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
#endif // CERTPP_FE25519_RADIX51
    }

    /* out = a^2. */
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((always_inline))
#endif
    void Fe25519::square(Fe25519& out, const Fe25519& a) {
#if defined(CERTPP_FE25519_RADIX51)
        // Ten products, scheduled so doubling and the 19-fold happen on 64-bit operands before
        // multiplication. This keeps the five wide accumulators independent and avoids carrying
        // several temporary 128-bit products through the expression tree.
        uint64_t g0 = a.limbs[0], g1 = a.limbs[1], g2 = a.limbs[2];
        uint64_t g3 = a.limbs[3], g4 = a.limbs[4];
        unsigned __int128 h0 = (unsigned __int128)g0 * g0;
        g0 *= 2;
        unsigned __int128 h1 = (unsigned __int128)g0 * g1;
        unsigned __int128 h2 = (unsigned __int128)g0 * g2;
        unsigned __int128 h3 = (unsigned __int128)g0 * g3;
        unsigned __int128 h4 = (unsigned __int128)g0 * g4;

        g0 = g4;
        g4 *= 19;
        h3 += (unsigned __int128)g0 * g4;
        h2 += (unsigned __int128)g1 * g1;
        g1 *= 2;
        h3 += (unsigned __int128)g1 * g2;
        h4 += (unsigned __int128)g1 * g3;
        h0 += (unsigned __int128)g1 * g4;

        g0 = g3;
        g3 *= 19;
        h1 += (unsigned __int128)g0 * g3;
        h2 += (unsigned __int128)(g0 * 2) * g4;
        h4 += (unsigned __int128)g2 * g2;
        g2 *= 2;
        h0 += (unsigned __int128)g2 * g3;
        h1 += (unsigned __int128)g2 * g4;

        storeProductReduced(out, h0, h1, h2, h3, h4);
#else
        // --> A dedicated squaring: 55 products against mul()'s 100, because each of the 45
        // off-diagonal pairs appears twice and is computed once.
        //
        // The merged factors are GENERATED, not written by hand, and this is the whole point.
        // Two earlier attempts at deriving them by hand were both wrong, and
        // docs/history/09-field-and-aead.md
        // names the reason: the 2^25.5 radix applies its corrections *asymmetrically*, so the
        // matrix is symmetric in value but not in correction and the merged factor for a pair
        // is the SUM of the two single-term factors rather than twice one of them. Deriving
        // that sum by hand is exactly what produces a square() that agrees with itself and
        // with nothing else -- the failure mode this class exists to prevent.
        //
        // So the factors below come from `tools/fe_square_gen.cpp`, which reads mul()'s own
        // per-term rule (f doubled when the index is odd AND the output limb is even; g
        // scaled by 19 when the term wraps, i.e. i + j >= 10), checks that rule reproduces
        // mul() on all ten limbs over 200 random inputs, checks the merged form the same way
        // over 20,000, and only then emits these expressions. Regenerate with that tool
        // rather than editing here.
        //
        // Worked examples of the three distinct factors, so the shape is checkable by eye:
        //   1*s0*s0  diagonal, even index, no wrap          -> 1
        //   38*s5*s5 diagonal, odd index, 2*5 = 10 wraps   -> 2 * 19
        //   76*s1*s9 both odd, so 2 + 2 from the two sides -> (2 + 2) * 19
        //   38*s2*s8 both even, so 1 + 1                   -> (1 + 1) * 19
        const int64_t s0 = a.limbs[0], s1 = a.limbs[1], s2 = a.limbs[2];
        const int64_t s3 = a.limbs[3], s4 = a.limbs[4], s5 = a.limbs[5];
        const int64_t s6 = a.limbs[6], s7 = a.limbs[7], s8 = a.limbs[8];
        const int64_t s9 = a.limbs[9];

        const int64_t s0_2 = s0 * 2;
        const int64_t s1_2 = s1 * 2;
        const int64_t s2_2 = s2 * 2;
        const int64_t s3_2 = s3 * 2;
        const int64_t s4_2 = s4 * 2;
        const int64_t s5_2 = s5 * 2;
        const int64_t s5_19 = s5 * 19;
        const int64_t s6_2 = s6 * 2;
        const int64_t s6_19 = s6 * 19;
        const int64_t s7_2 = s7 * 2;
        const int64_t s7_19 = s7 * 19;
        const int64_t s7_38 = s7 * 38;
        const int64_t s8_2 = s8 * 2;
        const int64_t s8_19 = s8 * 19;
        const int64_t s9_2 = s9 * 2;
        const int64_t s9_19 = s9 * 19;
        const int64_t s9_38 = s9 * 38;

        int64_t t0 = s0*s0 + s1_2*s9_38 + s2_2*s8_19 + s3_2*s7_38 + s4_2*s6_19 + s5_2*s5_19;
        int64_t t1 = s0_2*s1 + s2_2*s9_19 + s3_2*s8_19 + s4_2*s7_19 + s5_2*s6_19;
        int64_t t2 = s0_2*s2 + s1_2*s1 + s3_2*s9_38 + s4_2*s8_19 + s5_2*s7_38 + s6*s6_19;
        int64_t t3 = s0_2*s3 + s1_2*s2 + s4_2*s9_19 + s5_2*s8_19 + s6_2*s7_19;
        int64_t t4 = s0_2*s4 + s1_2*s3_2 + s2*s2 + s5_2*s9_38 + s6_2*s8_19 + s7_2*s7_19;
        int64_t t5 = s0_2*s5 + s1_2*s4 + s2_2*s3 + s6_2*s9_19 + s7_2*s8_19;
        int64_t t6 = s0_2*s6 + s1_2*s5_2 + s2_2*s4 + s3_2*s3 + s7_2*s9_38 + s8*s8_19;
        int64_t t7 = s0_2*s7 + s1_2*s6 + s2_2*s5 + s3_2*s4 + s8_2*s9_19;
        int64_t t8 = s0_2*s8 + s1_2*s7_2 + s2_2*s6 + s3_2*s5_2 + s4*s4 + s9_2*s9_19;
        int64_t t9 = s0_2*s9 + s1_2*s8 + s2_2*s7 + s3_2*s6 + s4_2*s5;

        int64_t t[LIMBS] = { t0, t1, t2, t3, t4, t5, t6, t7, t8, t9 };

        // Same two passes mul() uses: the first brings limbs into range, the second settles
        // the 19x fold-back out of limb 0.
        carryPass(t);
        carryPass(t);
        store(out, t);
#endif // CERTPP_FE25519_RADIX51
    }

    /* out = a * 121665. */
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((always_inline))
#endif
    void Fe25519::mulA24(Fe25519& out, const Fe25519& a) {
#if defined(CERTPP_FE25519_RADIX51)
        // Each product needs 128 bits: 121665 * (2^51 - 1) is 2^68. Feed the five independent
        // products into the same two-chain reduction as general multiplication.
        const unsigned __int128 h0 = (unsigned __int128)a.limbs[0] * 121665;
        const unsigned __int128 h1 = (unsigned __int128)a.limbs[1] * 121665;
        const unsigned __int128 h2 = (unsigned __int128)a.limbs[2] * 121665;
        const unsigned __int128 h3 = (unsigned __int128)a.limbs[3] * 121665;
        const unsigned __int128 h4 = (unsigned __int128)a.limbs[4] * 121665;

        storeProductReduced(out, h0, h1, h2, h3, h4);
#else
        int64_t t[LIMBS];

        for (size_t i = 0; i < LIMBS; ++i) {
            t[i] = int64_t(a.limbs[i]) * 121665;
        }

        carryPass(t);
        carryPass(t);
        store(out, t);
#endif // CERTPP_FE25519_RADIX51
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

    /* out = sqrt(u / v), using one fixed exponentiation rather than invert(v) + sqrt(). */
    bool Fe25519::squareRootRatio(
        Fe25519& out, const Fe25519& u, const Fe25519& v
    ) {
        // RFC 8032 5.1.3: x = u*v^3*(u*v^7)^((p-5)/8), where (p-5)/8 = 2^252-3.
        Fe25519 v2, v3, v7;
        square(v2, v);
        mul(v3, v2, v);
        square(v7, v3);
        mul(v7, v7, v);

        Fe25519 uv7;
        mul(uv7, u, v7);

        Fe25519 chain, unused11;
        powTwo250Minus1(chain, unused11, uv7);          // (u*v^7)^(2^250 - 1)
        square(chain, chain);
        square(chain, chain);
        mul(chain, chain, uv7);                         // (u*v^7)^(2^252 - 3)

        Fe25519 candidate;
        mul(candidate, chain, v3);
        mul(candidate, candidate, u);

        Fe25519 check;
        square(check, candidate);
        mul(check, check, v);
        if (check.isEqual(u)) {
            out = candidate;
            return true;
        }

        Fe25519 negativeU;
        neg(negativeU, u);
        if (!check.isEqual(negativeU)) {
            return false;
        }

        mul(candidate, candidate, sqrtMinusOne());
        square(check, candidate);
        mul(check, check, v);
        if (!check.isEqual(u)) {
            return false;
        }

        out = candidate;
        return true;
    }

    namespace {

#if defined(__GNUC__) || defined(__clang__)
        __attribute__((always_inline, flatten))
#endif
        inline void x25519LadderBody(
            const uint8_t scalar[Fe25519::BYTES],
            const uint8_t u[Fe25519::BYTES],
            uint8_t out[Fe25519::BYTES]
        ) {
            Fe25519 x1, x2, z2, x3, z3;
            x1.fromBytes(u);
            x2.setOne();
            z2.setZero();
            x3 = x1;
            z3.setOne();

            uint32_t swap = 0;
            for (size_t bitIndex = 255; bitIndex-- > 0; ) {
                const uint32_t bit =
                    uint32_t((scalar[bitIndex >> 3] >> (bitIndex & 7u)) & 1u);
                swap ^= bit;
                const uint32_t mask = uint32_t(0) - swap;
                Fe25519::condSwap(mask, x2, x3);
                Fe25519::condSwap(mask, z2, z3);
                swap = bit;

                // Reuse coordinates once their old values are dead. Four temporaries are enough
                // for the same operation order and give the flattened accelerated loop shorter
                // live ranges than ten distinct field elements.
                Fe25519 t0, t1, t2, t3;
                Fe25519::subLoose(t0, x2, z2);       // B
                Fe25519::addLoose(x2, x2, z2);       // A
                Fe25519::square(t1, x2);             // AA
                Fe25519::square(z2, t0);             // BB
                Fe25519::subLoose(t2, t1, z2);       // E
                Fe25519::subLoose(t3, x3, z3);       // D
                Fe25519::addLoose(x3, x3, z3);       // C
                Fe25519::mul(z3, t3, x2);            // DA
                Fe25519::mul(t3, x3, t0);            // CB

                Fe25519::addLoose(t0, z3, t3);
                Fe25519::square(x3, t0);
                Fe25519::subLoose(t0, z3, t3);
                Fe25519::square(t0, t0);
                Fe25519::mul(z3, t0, x1);
                Fe25519::mul(x2, t1, z2);
                Fe25519::mulA24(t0, t2);
                Fe25519::addLoose(t0, t0, t1);
                Fe25519::mul(z2, t2, t0);
            }

            const uint32_t mask = uint32_t(0) - swap;
            Fe25519::condSwap(mask, x2, x3);
            Fe25519::condSwap(mask, z2, z3);

            Fe25519 inverse;
            Fe25519::invert(inverse, z2);
            Fe25519::mul(x2, x2, inverse);
            x2.toBytes(out);
        }

#if defined(CERTPP_ARCH_HAS_MULX) && defined(CERTPP_FE25519_RADIX51)
        /* AVX2 widens the two conditional swaps, while BMI2 removes MUL's fixed rdx:rax
         * destination from the 5x51 products. ADX lets the compiler schedule the corresponding
         * carry additions independently. The decision is cached and depends only on public CPU
         * capabilities, never on the scalar or point. */
        enum class EX25519Acceleration {
            None,
            Generic,
            TigerLake,
        };

        EX25519Acceleration x25519Acceleration() {
            static const EX25519Acceleration detected = [] {
                __builtin_cpu_init();
#if !defined(CERTPP_DISABLE_HWACCEL_AVX512)
                if (__builtin_cpu_is("tigerlake") != 0) {
                    return EX25519Acceleration::TigerLake;
                }
#endif
                if (__builtin_cpu_supports("avx2") != 0 &&
                    __builtin_cpu_supports("bmi2") != 0 &&
                    __builtin_cpu_supports("adx") != 0) {
                    return EX25519Acceleration::Generic;
                }
                return EX25519Acceleration::None;
            }();
            return detected;
        }

        __attribute__((target("avx2,bmi2,adx"), flatten))
        void x25519LadderAccelerated(
            const uint8_t scalar[Fe25519::BYTES],
            const uint8_t u[Fe25519::BYTES],
            uint8_t out[Fe25519::BYTES]
        ) {
            x25519LadderBody(scalar, u, out);
        }

#if !defined(CERTPP_DISABLE_HWACCEL_AVX512)
        /* Tiger Lake's function-level architecture setting adds its scheduling model and full
         * register set. Keeping this as a separate exact-model dispatch avoids imposing that ISA
         * on other AVX2/BMI2/ADX processors, which continue through the generic function above. */
        __attribute__((target("arch=tigerlake"), flatten))
        void x25519LadderTigerLake(
            const uint8_t scalar[Fe25519::BYTES],
            const uint8_t u[Fe25519::BYTES],
            uint8_t out[Fe25519::BYTES]
        ) {
            x25519LadderBody(scalar, u, out);
        }
#endif
#endif

    } // namespace

    void Fe25519::x25519Ladder(
        const uint8_t scalar[BYTES], const uint8_t u[BYTES], uint8_t out[BYTES]
    ) {
#if defined(CERTPP_ARCH_HAS_MULX) && defined(CERTPP_FE25519_RADIX51)
        const EX25519Acceleration acceleration = x25519Acceleration();
#if !defined(CERTPP_DISABLE_HWACCEL_AVX512)
        if (acceleration == EX25519Acceleration::TigerLake) {
            x25519LadderTigerLake(scalar, u, out);
            return;
        }
#endif
        if (acceleration == EX25519Acceleration::Generic) {
            x25519LadderAccelerated(scalar, u, out);
            return;
        }
#endif
        x25519LadderBody(scalar, u, out);
    }

    /* Swaps a and b under a mask, without branching. */
    void Fe25519::condSwap(uint32_t mask, Fe25519& a, Fe25519& b) {
        // --> In a Montgomery ladder the condition is a bit of the private scalar, so this has
        // to be arithmetic rather than an `if`. Every limb is read and written on both paths.
        //
        // The mask is a 32-bit one by the documented contract (0 or 0xFFFFFFFF, anything else
        // mixing the two element-wise), so it is sign-extended to the limb width rather than
        // zero-extended. Zero-extending would be the subtle wrong answer: on the 51-bit layout
        // 0xFFFFFFFF widened that way is 0x00000000FFFFFFFF, which swaps the low half of every
        // limb and leaves the rest -- a swap that half-happens. An unconditional mask means the
        // two layouts need different code here, which is why this is not shared.
        const Limb m = Limb(static_cast<int64_t>(static_cast<int32_t>(mask)));

        for (size_t i = 0; i < LIMBS; ++i) {
            const Limb difference = (a.limbs[i] ^ b.limbs[i]) & m;
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
