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
         * without a borrow branch. */
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
        int64_t left[LIMBS];
        int64_t right[LIMBS];
        load(left, a);
        load(right, b);

        int64_t t[LIMBS] = { 0 };

        // --> Two factors apply to each partial product, and the first is the one that makes a
        // naive version wrong on *every* input rather than some:
        //
        //  - a doubling when both limb indices are odd, because OFFSET[i] + OFFSET[j] is one bit
        //    above OFFSET[i+j] in that case -- two half-bit offsets adding to a whole one, which
        //    is the price of a non-integer radix;
        //  - a factor of 19 when i + j >= 10, since the product then sits at 2^255 or above and
        //    2^255 == 19 mod p.
        //
        // Both were validated against exact arithmetic before this was written.
        for (size_t i = 0; i < LIMBS; ++i) {
            for (size_t j = 0; j < LIMBS; ++j) {
                int64_t product = left[i] * right[j];

                if ((i % 2 == 1) && (j % 2 == 1)) {
                    product *= 2;
                }

                const size_t k = i + j;
                if (k < LIMBS) {
                    t[k] += product;
                }
                else {
                    t[k - LIMBS] += product * 19;
                }
            }
        }

        // Two passes: the first brings limbs into range, the second settles the 19x fold-back.
        carryPass(t);
        carryPass(t);
        store(out, t);
    }

    /* out = a^2. */
    void Fe25519::square(Fe25519& out, const Fe25519& a) {
        // Same operation; a dedicated squaring would halve the multiplies, which is worth doing
        // only if profiling says so. Correctness first, and one code path to audit.
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

    /* out = a^-1, via the fixed a^(p-2) chain. */
    void Fe25519::invert(Fe25519& out, const Fe25519& a) {
        // p - 2 is 250 one-bits followed by 01101, so the exponentiation is a fixed sequence of
        // 254 squarings and 11 multiplications. It runs identically for every input -- including
        // zero, which simply yields zero -- so neither the value nor any property of it affects
        // the control flow.
        Fe25519 z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, work;

        square(z2, a);                                  // 2
        square(work, z2);                               // 4
        square(work, work);                             // 8
        mul(z9, work, a);                               // 9
        mul(z11, z9, z2);                               // 11

        square(work, z11);                              // 22
        mul(z2_5_0, work, z9);                          // 2^5 - 2^0

        square(work, z2_5_0);
        for (int i = 1; i < 5; ++i) {
            square(work, work);
        }
        mul(z2_10_0, work, z2_5_0);                     // 2^10 - 2^0

        square(work, z2_10_0);
        for (int i = 1; i < 10; ++i) {
            square(work, work);
        }
        mul(z2_20_0, work, z2_10_0);                    // 2^20 - 2^0

        square(work, z2_20_0);
        for (int i = 1; i < 20; ++i) {
            square(work, work);
        }
        mul(work, work, z2_20_0);                       // 2^40 - 2^0

        square(work, work);
        for (int i = 1; i < 10; ++i) {
            square(work, work);
        }
        mul(z2_50_0, work, z2_10_0);                    // 2^50 - 2^0

        square(work, z2_50_0);
        for (int i = 1; i < 50; ++i) {
            square(work, work);
        }
        mul(z2_100_0, work, z2_50_0);                   // 2^100 - 2^0

        square(work, z2_100_0);
        for (int i = 1; i < 100; ++i) {
            square(work, work);
        }
        mul(work, work, z2_100_0);                      // 2^200 - 2^0

        square(work, work);
        for (int i = 1; i < 50; ++i) {
            square(work, work);
        }
        mul(work, work, z2_50_0);                       // 2^250 - 2^0

        square(work, work);
        square(work, work);
        square(work, work);
        square(work, work);
        square(work, work);
        mul(out, work, z11);                            // 2^255 - 21 == p - 2
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

} // namespace crypto
} // namespace certpp
