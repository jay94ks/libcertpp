#ifndef __SRC_CRYPTO_ASYMS_MLDSAROUNDING_HPP__
#define __SRC_CRYPTO_ASYMS_MLDSAROUNDING_HPP__

#include <certpp/common.hpp>
#include "mldsaring.hpp"

namespace certpp {
namespace crypto {

    /**
     * FIPS 204 7.4's rounding and hint machinery: the coefficient-level operations that let
     * ML-DSA transmit a signature without the full high-order part of w, and recover it at the
     * verifier. Private to the ML-DSA implementation, so no type prefix.
     *
     * The hint mechanism is the reason any of this exists. A signature carries `h`, one bit per
     * coefficient, rather than w1 itself; the verifier reconstructs HighBits(w - c*s2 + c*t0)
     * from its own approximation plus those bits. That only works if `useHint()` inverts
     * `makeHint()` *exactly*, and only while the perturbation stays within gamma2 -- a bound the
     * signing loop is responsible for enforcing before it calls makeHint(). Both halves were
     * checked against an independent implementation over 100,000 values per parameter set, and
     * the inversion identity over 200,000 random (r, z) pairs, before this was written.
     *
     * Two traps are worth naming here rather than leaving in the commit history.
     *
     * **`decompose()`'s (q-1) carve-out is not a special case for r == q-1.** FIPS 204
     * Algorithm 36 branches on `r+ - r0 == q - 1`, and that condition holds for the whole top
     * band of width gamma2 -- 95232 values (1.14% of q) at gamma2 = (q-1)/88, and 261888 (3.1%)
     * at (q-1)/32. Rewriting it as `r == q - 1`, which looks equivalent and is the obvious
     * simplification, is wrong for 95231 inputs in the first case. The condition is implemented
     * exactly as the standard states it.
     *
     * **`mod±` here is not `MlDsaRing::centered()`.** That one reduces modulo q, which is odd,
     * so its split sits at (q-1)/2. These reduce modulo 2^d and 2*gamma2, both even, where the
     * representative range is (-m/2, m/2] and m/2 itself stays positive. Same definition
     * (FIPS 204 2.3), different modulus, different edge -- so this unit has its own modPm()
     * rather than reaching for the ring's.
     */
    class MlDsaRounding {
    public:
        /** The dropped-bit count d, 13 for every ML-DSA parameter set (FIPS 204 Table 1). */
        static constexpr int32_t D = 13;

        /** gamma2 for ML-DSA-44: (q-1)/88. */
        static constexpr int32_t GAMMA2_44 = (MlDsaRing::Q - 1) / 88;

        /** gamma2 for ML-DSA-65 and ML-DSA-87: (q-1)/32. */
        static constexpr int32_t GAMMA2_65_87 = (MlDsaRing::Q - 1) / 32;

        /** The ring element these operate over, coefficient by coefficient. */
        using Poly = MlDsaRing::Poly;

    public:
        /**
         * FIPS 204 2.3's `mod±`: the representative of value congruent modulo modulus that lies
         * in (-modulus/2, modulus/2].
         *
         * Only used with even moduli here (2^d and 2*gamma2), where modulus/2 is itself the
         * positive endpoint. See this class's doc comment for why MlDsaRing::centered() is not
         * the same operation.
         * @param value Any int32_t; negative inputs are handled.
         * @param modulus A positive, even modulus.
         * @return The congruent representative in (-modulus/2, modulus/2].
         */
        static int32_t modPm(int32_t value, int32_t modulus);

        /**
         * Power2Round (FIPS 204 Algorithm 35): splits a coefficient into a high part and a
         * d-bit centered low part, such that r == r1*2^d + r0 exactly.
         *
         * This is how a public key is shrunk: t is split and only t1 is published, with t0
         * recovered during verification via the hints.
         * @param r A coefficient; reduced into [0, q) first.
         * @param r1 Receives the high part, in [0, 2^(23-d)).
         * @param r0 Receives the low part, in (-2^(d-1), 2^(d-1)].
         */
        static void power2Round(int32_t r, int32_t& r1, int32_t& r0);

        /**
         * Decompose (FIPS 204 Algorithm 36): splits a coefficient around 2*gamma2, so that
         * r == r1*2*gamma2 + r0 (mod q) with r1 in [0, (q-1)/(2*gamma2)).
         *
         * Note the carve-out described in this class's doc comment -- it is a band, not a point.
         * @param r A coefficient; reduced into [0, q) first.
         * @param gamma2 GAMMA2_44 or GAMMA2_65_87.
         * @param r1 Receives the high part.
         * @param r0 Receives the low part, in (-gamma2, gamma2].
         */
        static void decompose(int32_t r, int32_t gamma2, int32_t& r1, int32_t& r0);

        /**
         * HighBits (FIPS 204 Algorithm 37): Decompose's high part.
         * @param r A coefficient.
         * @param gamma2 GAMMA2_44 or GAMMA2_65_87.
         * @return r1.
         */
        static int32_t highBits(int32_t r, int32_t gamma2);

        /**
         * LowBits (FIPS 204 Algorithm 38): Decompose's low part.
         * @param r A coefficient.
         * @param gamma2 GAMMA2_44 or GAMMA2_65_87.
         * @return r0.
         */
        static int32_t lowBits(int32_t r, int32_t gamma2);

        /**
         * MakeHint (FIPS 204 Algorithm 39): reports whether adding z to r would change r's high
         * bits, which is the single bit the signature carries for that coefficient.
         * @param z The perturbation; the caller must have bounded it by gamma2, or useHint()
         * cannot invert this (see this class's doc comment).
         * @param r A coefficient.
         * @param gamma2 GAMMA2_44 or GAMMA2_65_87.
         * @return 1 if the high bits differ, 0 otherwise.
         */
        static uint8_t makeHint(int32_t z, int32_t r, int32_t gamma2);

        /**
         * UseHint (FIPS 204 Algorithm 40): recovers HighBits(r + z) from r and the hint bit,
         * without knowing z.
         * @param hint 0 or 1, as makeHint() produced.
         * @param r A coefficient.
         * @param gamma2 GAMMA2_44 or GAMMA2_65_87.
         * @return The recovered high part, in [0, (q-1)/(2*gamma2)).
         */
        static int32_t useHint(uint8_t hint, int32_t r, int32_t gamma2);

        /**
         * Applies power2Round() to every coefficient of a polynomial.
         * @param poly The polynomial to split.
         * @param high Receives the high parts; may alias poly.
         * @param low Receives the low parts; may alias poly.
         */
        static void power2Round(const Poly& poly, Poly& high, Poly& low);

        /**
         * Applies decompose() to every coefficient of a polynomial.
         * @param poly The polynomial to split.
         * @param gamma2 GAMMA2_44 or GAMMA2_65_87.
         * @param high Receives the high parts; may alias poly.
         * @param low Receives the low parts; may alias poly.
         */
        static void decompose(const Poly& poly, int32_t gamma2, Poly& high, Poly& low);

        /**
         * The number of distinct high-bit values for a given gamma2, i.e. (q-1)/(2*gamma2):
         * 44 for ML-DSA-44 and 16 for ML-DSA-65/87. This is the modulus useHint() wraps within,
         * and the range HighBits() lands in.
         * @param gamma2 GAMMA2_44 or GAMMA2_65_87.
         * @return The count.
         */
        static int32_t highBitsRange(int32_t gamma2);
    };

} // namespace crypto
} // namespace certpp

#endif
