#ifndef __SRC_CRYPTO_PQ_MLDSARING_HPP__
#define __SRC_CRYPTO_PQ_MLDSARING_HPP__

#include <certpp/common.hpp>

namespace certpp {
namespace crypto {

    /**
     * Arithmetic in ML-DSA's polynomial ring R_q = Z_q[X]/(X^256 + 1), q = 8380417 (FIPS 204 4)
     * -- the primitive everything in ML-DSA is built on. Private to the PQ implementation:
     * nothing here is part of the public API, so (per docs/coding-conventions.md) it takes no
     * type prefix.
     *
     * This is *not* ML-KEM's ring with different numbers, and the differences are the whole
     * reason it is a separate unit rather than a parameterization of MlKemRing:
     *
     * - q = 2^23 - 2^13 + 1 rather than 3329, so a coefficient needs 23 bits and int32_t
     *   storage, and a product of two coefficients reaches about 7.0e13 -- which overflows
     *   int32_t by four orders of magnitude, so every intermediate here runs in int64_t. In
     *   ML-KEM's ring a product fits in int32_t with room to spare; carrying that habit over
     *   would be a silent-wraparound bug rather than a performance choice.
     * - ZETA = 1753 has order exactly **512** mod q, not 256, so X^256 + 1 splits all the way
     *   into 256 linear factors and the NTT is **complete**: 8 layers, 256 independent points.
     *   ML-KEM's transform stops one layer short, leaving 128 degree-1 blocks and needing a
     *   base-case multiply with its own twiddle table. Here multiplyNtt() is plain pointwise
     *   multiplication and there is no second table at all.
     * - The index permutation is BitRev8, over 8 bits, where ML-KEM's is BitRev7.
     *
     * Coefficients are kept fully reduced in [0, Q) at every entry and exit point. Reduction is
     * a plain `% Q` against a compile-time constant, which the compiler turns into a reciprocal
     * multiply; this is the same choice MlKemRing documents, for the same two reasons -- it is
     * about as fast as a hand-written Barrett step and far easier to audit, and it sidesteps the
     * "is this value currently in Montgomery form?" class of bug outright. FIPS 204 Appendix A
     * warns specifically that implementations usually keep the zetas array in Montgomery form,
     * which makes a representation mismatch there exactly the kind of self-consistent-but-wrong
     * failure this library has been bitten by before. Nothing here is in Montgomery form; if
     * profiling ever justifies it, it can go behind these same signatures.
     *
     * The twiddle table is assertable against the standard in two independent ways, and the
     * tests use both: FIPS 204 Appendix B prints all 255 entries, and they are also defined as
     * ZETA^BitRev8(k) mod q, which the test re-derives rather than trusting the table as
     * transcribed. The NTT is likewise checked against a schoolbook negacyclic multiply rather
     * than only against its own inverse -- a transform that round-trips but permutes its
     * coefficients differently from the standard is self-consistent and interoperates with
     * nothing.
     */
    class MlDsaRing {
    public:
        /** Coefficients per polynomial. */
        static constexpr size_t N = 256;

        /** The prime modulus, q = 2^23 - 2^13 + 1 (FIPS 204 4). */
        static constexpr int32_t Q = 8380417;

        /**
         * A primitive 512th root of unity mod Q (FIPS 204 4). Its order being 512 rather than
         * 256 is what makes the NTT complete -- see this class's own doc comment.
         */
        static constexpr int32_t ZETA = 1753;

        /**
         * 256^-1 mod Q, the scaling the inverse NTT finishes with. This is the constant FIPS 204
         * Algorithm 42 writes as 8347681; the test derives it from Q rather than trusting it.
         */
        static constexpr int32_t N_INVERSE = 8347681;

        /** One element of R_q: 256 coefficients, each reduced into [0, Q). */
        struct Poly {
            int32_t coeffs[N];
        };

    public:
        /**
         * Reverses the low 8 bits of k -- the index permutation FIPS 204's twiddle table is built
         * on (zetas[k] = ZETA^BitRev8(k)).
         * @param index Value to reverse; only its low 8 bits are considered.
         * @return The 8-bit reversal of index.
         */
        static size_t bitRev8(size_t index);

        /**
         * Returns the NTT layer twiddle factors: zetas[k] = ZETA^BitRev8(k) mod Q, k in [0, 256).
         * Entry 0 is 1 and unused by the transform, matching how Appendix B tabulates it.
         * @return Pointer to 256 entries, valid for the process lifetime.
         */
        static const int32_t* zetas();

        /**
         * Reduces a value to [0, Q).
         * @param value Any int64_t; negative inputs are handled.
         * @return value mod Q, in [0, Q).
         */
        static int32_t reduce(int64_t value);

        /**
         * Reduces a coefficient to its *centered* representative, FIPS 204's `mod±` (2.3): the
         * unique value congruent to it in (-Q/2, Q/2].
         *
         * This is the representation the infinity norm is defined over, and it is a different
         * convention from the [0, Q) one everything else here uses -- which is why it is a named
         * operation rather than something sprinkled inline.
         * @param value A coefficient in [0, Q).
         * @return The congruent value in (-Q/2, Q/2].
         */
        static int32_t centered(int32_t value);

        /**
         * The infinity norm ||poly||_inf (FIPS 204 2.3): the largest absolute value among the
         * coefficients' centered representatives.
         *
         * ML-DSA's signing loop rejects on exactly this quantity, so it is part of the ring's
         * interface rather than a caller's business.
         * @param poly Polynomial whose coefficients are in [0, Q).
         * @return The norm, in [0, Q/2].
         */
        static int32_t infinityNorm(const Poly& poly);

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
         * Applies the forward NTT in place (FIPS 204 Algorithm 41), taking a polynomial to its
         * 256 NTT-domain point values.
         * @param poly Polynomial to transform in place.
         */
        static void ntt(Poly& poly);

        /**
         * Applies the inverse NTT in place (FIPS 204 Algorithm 42), including the final
         * multiplication by N_INVERSE.
         * @param poly NTT-domain value to transform in place.
         */
        static void inverseNtt(Poly& poly);

        /**
         * Multiplies two NTT-domain values coefficient by coefficient (FIPS 204 Algorithm 45).
         *
         * Pointwise, with no per-block twiddle: the transform is complete, so each coefficient is
         * an independent evaluation point. ML-KEM's equivalent cannot be written this way.
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
