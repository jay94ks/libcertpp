#ifndef __SRC_CRYPTO_ASYMS_MLDSASAMPLER_HPP__
#define __SRC_CRYPTO_ASYMS_MLDSASAMPLER_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include "mldsaring.hpp"

namespace certpp {
namespace crypto {

    /**
     * FIPS 204 7.3's pseudorandom sampling: the three rejection samplers and the Expand*
     * procedures that drive them. Private to the ML-DSA implementation, so no type prefix.
     *
     * All three samplers consume an amount of XOF stream that depends on their seed -- that is
     * what "rejection sampling" means here -- so they read through `SHAKE128::squeeze()` /
     * `SHAKE256::squeeze()` rather than asking `finish()` for a fixed length. This is why
     * incremental squeezing was a hard prerequisite rather than a convenience.
     *
     * Which XOF goes where is not interchangeable: `rejNttPoly()` and `expandA()` use SHAKE128
     * (the standard's `G`), while `sampleInBall()`, `rejBoundedPoly()`, `expandS()` and
     * `expandMask()` use SHAKE256 (`H`). Swapping them produces a scheme that works perfectly
     * with itself and interoperates with nothing.
     *
     * **`expandA()`'s seed order is transposed.** FIPS 204 Algorithm 32 builds the seed as
     * `rho || IntegerToBytes(s, 1) || IntegerToBytes(r, 1)` for entry `A[r][s]` -- the *column*
     * byte before the row byte. This is the same trap ML-KEM's `SampleNTT(rho || j || i)` has,
     * and it has the same consequence: get it backwards and the matrix is transposed, every key
     * byte changes, and nothing about the scheme stops working on its own terms.
     *
     * Every integer written into a seed goes in little-endian (FIPS 204 Algorithm 11), so
     * `IntegerToBytes(r, 2)` is `{r & 0xFF, r >> 8}`.
     *
     * FIPS 204 Appendix C sets iteration limits for the indeterminate loops here -- 481 for
     * RejBoundedPoly, 298 for RejNTTPoly, 121 for SampleInBall, for a failure probability below
     * 2^-256 -- and says an implementation *should not* bound them at all, but that any bound
     * must be at least those. These are unbounded, which is the recommended behaviour and
     * removes the question of what to do on exhaustion.
     */
    class MlDsaSampler {
    public:
        /** The ring element the samplers produce. */
        using Poly = MlDsaRing::Poly;

        /** The largest module rank k any parameter set uses (ML-DSA-87). */
        static constexpr size_t MAX_K = 8;

        /** The largest vector dimension l any parameter set uses (ML-DSA-87). */
        static constexpr size_t MAX_L = 7;

        /** The largest Hamming weight tau any parameter set uses; 8 sign bytes bound it at 64. */
        static constexpr size_t MAX_TAU = 64;

    public:
        /**
         * CoeffFromThreeBytes (FIPS 204 Algorithm 14): three bytes to a value in [0, q), or a
         * rejection.
         *
         * The top bit of the third byte is cleared before the value is assembled, so the input
         * is 23 bits rather than 24 -- a candidate of 2^23 - 1 is still above q and rejected.
         * @param b0 Low byte.
         * @param b1 Middle byte.
         * @param b2 High byte; only its low 7 bits are used.
         * @param out Receives the coefficient when accepted.
         * @return true if the candidate was below q.
         */
        static bool coeffFromThreeBytes(uint8_t b0, uint8_t b1, uint8_t b2, int32_t& out);

        /**
         * CoeffFromHalfByte (FIPS 204 Algorithm 15): a nibble to a value in [-eta, eta], or a
         * rejection.
         *
         * The two cases are not symmetric. At eta = 2 the nibble maps through `2 - (b mod 5)`
         * for b < 15, so fifteen inputs cover five outputs three times each; at eta = 4 it is
         * `4 - b` for b < 9, nine inputs covering nine outputs once each. Only eta 2 and 4
         * exist.
         * @param nibble A value in [0, 15].
         * @param eta 2 or 4.
         * @param out Receives the coefficient when accepted.
         * @return true if the nibble was accepted.
         */
        static bool coeffFromHalfByte(uint8_t nibble, size_t eta, int32_t& out);

        /**
         * SampleInBall (FIPS 204 Algorithm 29): a polynomial with exactly tau coefficients in
         * {-1, +1} and the rest zero, via a Fisher-Yates shuffle over a SHAKE256 stream.
         *
         * The first 8 squeezed bytes are the sign bits, read little-endian within each byte;
         * every byte after that is a candidate position, resampled while it exceeds the current
         * index. Both halves come from the same stream in that order, so a reader that took the
         * signs from elsewhere would still produce a valid-looking ball and the wrong one.
         * @param seed The seed; ML-DSA passes c-tilde, which is lambda/4 bytes.
         * @param tau The Hamming weight; at most MAX_TAU.
         * @param out Receives the polynomial.
         * @return true on success; false if tau is out of range, the seed is empty, or the XOF
         * failed.
         */
        static bool sampleInBall(const SReadOnlyByteSpan& seed, size_t tau, Poly& out);

        /**
         * RejNTTPoly (FIPS 204 Algorithm 30): a uniform NTT-domain polynomial over Z_q, taking
         * three SHAKE128 bytes per candidate.
         * @param seed Exactly 34 bytes (rho plus two index bytes).
         * @param out Receives 256 coefficients in [0, q).
         * @return true on success; false if the seed is the wrong size or the XOF failed.
         */
        static bool rejNttPoly(const SReadOnlyByteSpan& seed, Poly& out);

        /**
         * RejBoundedPoly (FIPS 204 Algorithm 31): coefficients in [-eta, eta], taking one
         * SHAKE256 byte per *two* candidates -- the low nibble first, then the high one.
         * @param seed Exactly 66 bytes (rho plus two index bytes).
         * @param eta 2 or 4.
         * @param out Receives 256 coefficients in [-eta, eta].
         * @return true on success; false if the seed is the wrong size, eta is not 2 or 4, or
         * the XOF failed.
         */
        static bool rejBoundedPoly(const SReadOnlyByteSpan& seed, size_t eta, Poly& out);

        /**
         * ExpandA (FIPS 204 Algorithm 32): the k x l matrix A-hat, in NTT form.
         *
         * See this class's doc comment for the transposed seed order, which is the one thing
         * here that is easy to get wrong and impossible to notice without an external vector.
         * @param seed Exactly 32 bytes.
         * @param k Row count, at most MAX_K.
         * @param l Column count, at most MAX_L.
         * @param out Receives k*l polynomials in row-major order, so A[r][s] is out[r*l + s].
         * @return true on success.
         */
        static bool expandA(const SReadOnlyByteSpan& seed, size_t k, size_t l, Poly* out);

        /**
         * ExpandS (FIPS 204 Algorithm 33): the secret vectors s1 (length l) and s2 (length k),
         * both with coefficients in [-eta, eta].
         *
         * s1 is seeded with the index r and s2 with r + l, so the two vectors never share a
         * seed even though they come from one rho.
         * @param seed Exactly 64 bytes.
         * @param k Length of s2, at most MAX_K.
         * @param l Length of s1, at most MAX_L.
         * @param eta 2 or 4.
         * @param s1 Receives l polynomials.
         * @param s2 Receives k polynomials.
         * @return true on success.
         */
        static bool expandS(
            const SReadOnlyByteSpan& seed, size_t k, size_t l, size_t eta, Poly* s1, Poly* s2
        );

        /**
         * ExpandMask (FIPS 204 Algorithm 34): the masking vector y, length l, with coefficients
         * in [-gamma1 + 1, gamma1].
         *
         * Unlike the three above this is not rejection sampling -- gamma1 is a power of two, so
         * a fixed 32*(1 + bitlen(gamma1 - 1)) bytes per polynomial unpack directly through
         * BitUnpack with nothing discarded.
         * @param seed Exactly 64 bytes.
         * @param mu The counter folded into each polynomial's seed as mu + r.
         * @param l Vector length, at most MAX_L.
         * @param gamma1 A power of two; 2^17 or 2^19.
         * @param out Receives l polynomials.
         * @return true on success.
         */
        static bool expandMask(
            const SReadOnlyByteSpan& seed, uint32_t mu, size_t l, uint32_t gamma1, Poly* out
        );
    };

} // namespace crypto
} // namespace certpp

#endif
