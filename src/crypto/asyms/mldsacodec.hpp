#ifndef __SRC_CRYPTO_ASYMS_MLDSACODEC_HPP__
#define __SRC_CRYPTO_ASYMS_MLDSACODEC_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include "mldsaring.hpp"

namespace certpp {
namespace crypto {

    /**
     * FIPS 204 7.1-7.2's bit packing and hint encoding: the wire format ML-DSA's keys and
     * signatures are made of. Private to the ML-DSA implementation, so no type prefix.
     *
     * Four of these are straightforward -- `simpleBitPack`/`simpleBitUnpack` for coefficients in
     * [0, b], `bitPack`/`bitUnpack` for [-a, b], the latter pair encoding `b - w_i` so a signed
     * range fits an unsigned field. Bits run little-endian within each byte, which is also
     * ML-KEM's convention.
     *
     * **Decoding does not imply the range.** FIPS 204 says so itself, right under Algorithm 17:
     * for some (a, b) there exist byte strings that decode to coefficients outside [0, b] or
     * [-a, b], and that is a concern for input from an untrusted source. It depends on whether
     * the range's size is a power of two, and for ML-DSA's actual uses it splits like this:
     *
     * - `t1` (b = 2^10 - 1), `t0` (a = 2^12 - 1, b = 2^12) and `z` (a = gamma1 - 1, b = gamma1)
     *   are **safe** -- the range exactly fills its bit width, so every encoding is valid.
     * - `s1`/`s2` (a = b = eta) are **not**: at eta = 2 three bits decode down to -5, and at
     *   eta = 4 four bits decode down to -11. A decapsulation of a private key from outside has
     *   to range-check them, which is why FIPS 204's skDecode does.
     * - `w1` (b = (q-1)/(2*gamma2) - 1 = 43 or 15) is unsafe at 43 (six bits reach 63), but it
     *   is only ever encoded, never decoded -- it feeds the hash and never arrives from a peer.
     *
     * This is the same shape of hazard as ML-KEM's ByteDecode_12, and it is called out here
     * rather than left for the caller to notice.
     *
     * `hintBitUnpack` is the sharpest trap in the standard. It must reject on three distinct
     * conditions, and an implementation that enforces fewer accepts malleable signatures --
     * which is exactly what ACVP's 36 "modified signature - hint" cases are testing. They are
     * listed on the function itself.
     */
    class MlDsaCodec {
    public:
        /** The ring element these pack and unpack. */
        using Poly = MlDsaRing::Poly;

        /** The largest k (module rank) any ML-DSA parameter set uses, for fixed-size buffers. */
        static constexpr size_t MAX_K = 8;

    public:
        /**
         * The number of bits in b's binary representation (FIPS 204's `bitlen`).
         * @param value The value to measure.
         * @return 0 for 0, otherwise floor(log2(value)) + 1.
         */
        static size_t bitLength(uint32_t value);

        /**
         * SimpleBitPack (FIPS 204 Algorithm 16): packs coefficients known to lie in [0, b].
         * @param poly The polynomial; every coefficient must be in [0, b].
         * @param b The inclusive upper bound.
         * @param out Receives exactly 32 * bitLength(b) bytes.
         * @return true on success; false if out is the wrong size or a coefficient is out of
         * range.
         */
        static bool simpleBitPack(const Poly& poly, uint32_t b, const SByteSpan& out);

        /**
         * SimpleBitUnpack (FIPS 204 Algorithm 18).
         *
         * Does *not* guarantee the result lies in [0, b] -- see this class's doc comment. The
         * caller range-checks when the input is untrusted and b + 1 is not a power of two.
         * @param in Exactly 32 * bitLength(b) bytes.
         * @param b The bound the encoder used.
         * @param out Receives the decoded coefficients.
         * @return true on success; false if in is the wrong size.
         */
        static bool simpleBitUnpack(const SReadOnlyByteSpan& in, uint32_t b, Poly& out);

        /**
         * BitPack (FIPS 204 Algorithm 17): packs coefficients in [-a, b], by encoding b - w_i.
         * @param poly The polynomial; every coefficient must be in [-a, b].
         * @param a The inclusive lower bound's magnitude.
         * @param b The inclusive upper bound.
         * @param out Receives exactly 32 * bitLength(a + b) bytes.
         * @return true on success; false if out is the wrong size or a coefficient is out of
         * range.
         */
        static bool bitPack(const Poly& poly, uint32_t a, uint32_t b, const SByteSpan& out);

        /**
         * BitUnpack (FIPS 204 Algorithm 19).
         *
         * Does *not* guarantee the result lies in [-a, b] -- see this class's doc comment; for
         * `s1`/`s2` at eta = 2 or 4 it genuinely cannot, and the caller must check.
         * @param in Exactly 32 * bitLength(a + b) bytes.
         * @param a The lower bound's magnitude the encoder used.
         * @param b The upper bound the encoder used.
         * @param out Receives the decoded coefficients.
         * @return true on success; false if in is the wrong size.
         */
        static bool bitUnpack(const SReadOnlyByteSpan& in, uint32_t a, uint32_t b, Poly& out);

        /**
         * Reports whether every coefficient lies in [low, high], for the decodes that cannot
         * guarantee it themselves.
         * @param poly The polynomial to check.
         * @param low Inclusive lower bound.
         * @param high Inclusive upper bound.
         * @return true if every coefficient is within the bounds.
         */
        static bool inRange(const Poly& poly, int32_t low, int32_t high);

        /**
         * HintBitPack (FIPS 204 Algorithm 20): encodes k polynomials with binary coefficients,
         * at most omega of them set in total, into omega + k bytes.
         *
         * The last k bytes are a running total of how many positions have been written after
         * each polynomial; the first omega hold the positions themselves.
         * @param hints k polynomials whose coefficients are 0 or 1.
         * @param k The module rank.
         * @param omega The total hint budget for the parameter set.
         * @param out Receives exactly omega + k bytes.
         * @return true on success; false on a size mismatch, a non-binary coefficient, or more
         * than omega set coefficients in total.
         */
        static bool hintBitPack(
            const Poly* hints, size_t k, size_t omega, const SByteSpan& out
        );

        /**
         * HintBitUnpack (FIPS 204 Algorithm 21), the sharpest decode trap in the standard.
         *
         * Rejects on three *distinct* conditions, all of which must be implemented or malformed
         * signatures are accepted as valid:
         *
         * 1. a cumulative index that moves backwards or exceeds omega;
         * 2. positions that are not strictly increasing **within one polynomial** -- note the
         *    comparison resets at each polynomial boundary, so positions may legitimately
         *    decrease from the end of `h[i]` to the start of `h[i+1]`, and an implementation
         *    that checks monotonicity across the whole array rejects valid signatures;
         * 3. any non-zero byte left over in the first omega after the last position read.
         *
         * Each one exists to make the encoding injective: without them several byte strings
         * decode to the same hint vector, and a signature can be modified without invalidating
         * it. ACVP's "modified signature - hint" cases hit exactly these.
         * @param in Exactly omega + k bytes.
         * @param k The module rank.
         * @param omega The total hint budget for the parameter set.
         * @param out Receives k polynomials with 0/1 coefficients; untouched on rejection.
         * @return true if the encoding was well formed; false otherwise.
         */
        static bool hintBitUnpack(
            const SReadOnlyByteSpan& in, size_t k, size_t omega, Poly* out
        );
    };

} // namespace crypto
} // namespace certpp

#endif
