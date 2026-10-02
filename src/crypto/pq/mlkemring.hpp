#ifndef __SRC_CRYPTO_PQ_MLKEMRING_HPP__
#define __SRC_CRYPTO_PQ_MLKEMRING_HPP__

#include <certpp/common.hpp>

namespace certpp {
namespace crypto {

    /**
     * Arithmetic in ML-KEM's polynomial ring R_q = Z_q[X]/(X^256 + 1), q = 3329 (FIPS 203 2.4.4)
     * -- the primitive both K-PKE and ML-KEM proper are built on. Private to the PQ
     * implementation: nothing here is part of the public API, so (per
     * docs/coding-conventions.md) it takes no type prefix.
     *
     * Two things about this ring drive everything below. It is *negacyclic*: X^256 == -1, so a
     * product that overflows degree 255 wraps round with its sign flipped rather than simply
     * wrapping. And q was chosen so that 17 is a primitive 256th root of unity, which is what
     * makes a Number-Theoretic Transform possible -- multiplication becomes pointwise work in the
     * NTT domain instead of the 65536 coefficient products a schoolbook multiply would need.
     *
     * FIPS 203 fixes the NTT's *exact* representation, not merely its end-to-end behaviour,
     * because the wire format exposes NTT-domain values directly (an encapsulation key is a
     * ByteEncode of NTT-domain coefficients). A transform that round-trips correctly but
     * permutes the coefficients differently from the standard is therefore self-consistent and
     * completely non-interoperable -- the same failure mode that let this library ship a
     * byte-granular ECDSA digest truncation for as long as its only tests verified their own
     * output. Hence the deliberate choices here: the twiddle tables are asserted against their
     * defining property rather than trusted as transcribed constants (see
     * tests/crypto/pq/mlkemring.cpp, which re-derives every entry from 17^BitRev7(i)), and the
     * NTT is checked against a schoolbook negacyclic multiply rather than only against its own
     * inverse.
     *
     * Coefficients are kept fully reduced in [0, Q) at every public entry and exit point, and
     * intermediates run in int32_t, where a product of two coefficients (< 3329^2, about 1.1e7)
     * has four orders of magnitude of headroom. Reduction is a plain `% Q` against a
     * compile-time constant, which the compiler turns into a reciprocal multiply -- as fast as a
     * hand-written Barrett step and considerably easier to audit, and it sidesteps the "is this
     * value currently in Montgomery form?" class of bug entirely. If profiling ever justifies
     * Montgomery representation, it can be introduced behind these same signatures.
     */
    class MlKemRing {
    public:
        static constexpr size_t N = 256;      // --> coefficients per polynomial
        static constexpr int32_t Q = 3329;    // --> the prime modulus
        static constexpr int32_t ZETA = 17;   // --> a primitive 256th root of unity mod Q

        /**
         * One element of R_q: 256 coefficients, each held reduced in [0, Q). Also used to carry
         * NTT-domain values, which are 128 degree-1 blocks rather than a polynomial -- the layout
         * is identical, so the distinction is the caller's to track (as it is in FIPS 203 itself).
         */
        struct Poly {
            int16_t coeffs[N];
        };

    public:
        /**
         * Reverses the low 7 bits of i -- the index permutation FIPS 203's twiddle tables are
         * built on (zetas[i] = ZETA^BitRev7(i)).
         * @param index Value to reverse; only its low 7 bits are considered.
         * @return The 7-bit reversal of index.
         */
        static size_t bitRev7(size_t index);

        /**
         * Returns the NTT layer twiddle factors: zetas[i] = ZETA^BitRev7(i) mod Q, i in [0, 128).
         * @return Pointer to 128 entries, valid for the process lifetime.
         */
        static const int16_t* zetas();

        /**
         * Returns the base-case multiply twiddles: gammas[i] = ZETA^(2*BitRev7(i) + 1) mod Q,
         * i in [0, 128) -- the per-block constants FIPS 203 Algorithm 12 multiplies by.
         * @return Pointer to 128 entries, valid for the process lifetime.
         */
        static const int16_t* gammas();

        /**
         * Reduces a value to [0, Q).
         * @param value Any int32_t; negative inputs are handled.
         * @return value mod Q, in [0, Q).
         */
        static int16_t reduce(int32_t value);

        /**
         * Sets every coefficient to zero.
         * @param out Polynomial to clear.
         */
        static void setZero(Poly& out);

        /**
         * Coefficient-wise addition in R_q.
         * @param out Receives a + b; may alias either input.
         * @param a First operand.
         * @param b Second operand.
         */
        static void add(Poly& out, const Poly& a, const Poly& b);

        /**
         * Coefficient-wise subtraction in R_q.
         * @param out Receives a - b; may alias either input.
         * @param a Minuend.
         * @param b Subtrahend.
         */
        static void sub(Poly& out, const Poly& a, const Poly& b);

        /**
         * Applies the forward NTT in place (FIPS 203 Algorithm 9), taking a polynomial to its
         * 128 degree-1 NTT-domain blocks.
         * @param poly Polynomial to transform in place.
         */
        static void ntt(Poly& poly);

        /**
         * Applies the inverse NTT in place (FIPS 203 Algorithm 10), including the final
         * multiplication by 128^-1 mod Q.
         * @param poly NTT-domain value to transform in place.
         */
        static void inverseNtt(Poly& poly);

        /**
         * Multiplies two NTT-domain values (FIPS 203 Algorithm 11), block by block via the
         * degree-1 base case of Algorithm 12.
         * @param out Receives the product; may alias either input.
         * @param a First NTT-domain operand.
         * @param b Second NTT-domain operand.
         */
        static void multiplyNtt(Poly& out, const Poly& a, const Poly& b);

        /**
         * Multiplies in R_q directly, by the definition rather than via the NTT: schoolbook
         * convolution with X^256 == -1 wraparound. Quadratic, so it exists to check ntt() and
         * multiplyNtt() against an implementation that shares none of their machinery -- not for
         * use on any hot path.
         * @param out Receives a * b in R_q; must not alias either input.
         * @param a First operand.
         * @param b Second operand.
         */
        static void multiplySchoolbook(Poly& out, const Poly& a, const Poly& b);
    };

} // namespace crypto
} // namespace certpp

#endif
