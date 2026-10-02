#ifndef __SRC_CRYPTO_PQ_MLKEMSAMPLER_HPP__
#define __SRC_CRYPTO_PQ_MLKEMSAMPLER_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include "mlkemring.hpp"

namespace certpp {
namespace crypto {

    /**
     * ML-KEM's two samplers: `SampleNTT` (FIPS 203 Algorithm 7), which rejection-samples a
     * uniform NTT-domain polynomial from a SHAKE128 stream, and `SamplePolyCBD` (Algorithm 8),
     * which turns PRF output into the small-coefficient "noise" the Module-LWE assumption needs.
     * Private to the PQ implementation, so no type prefix.
     *
     * `sampleNtt()` is the reason `SHAKE128::squeeze()` had to exist. It consumes the XOF three
     * bytes at a time and keeps going until 256 coefficients have been *accepted*, so the amount
     * of stream it needs is not known in advance -- measured at roughly 474 to 498 bytes, i.e.
     * about three SHAKE128 rate blocks, varying with the seed. A fixed-length `finish()` cannot
     * express that.
     *
     * Both are deterministic functions of their input, which is what makes them testable at all:
     * the same seed and indices must always give the same polynomial, and the byte order in which
     * the seed, the indices and the stream are consumed is part of ML-KEM's wire format rather
     * than an implementation detail.
     */
    class MlKemSampler {
    public:
        /**
         * Rejection-samples a uniform polynomial in the NTT domain from SHAKE128(seed || i || j)
         * (FIPS 203 Algorithm 7).
         *
         * Note the index order: the two bytes are appended as `i` then `j` in this signature's
         * terms, and FIPS 203's matrix expansion calls this as `SampleNTT(rho || j || i)` -- the
         * indices are transposed relative to the natural loop order, which the standard's own
         * margin note calls out. The caller is responsible for passing them the way the algorithm
         * it is implementing requires; this function simply appends what it is given, in order.
         * @param seed A 32-byte seed (FIPS 203's rho).
         * @param firstIndex The byte appended at offset 32.
         * @param secondIndex The byte appended at offset 33.
         * @param out Receives 256 coefficients, each in [0, Q).
         * @return true on success; false if seed is not 32 bytes or the XOF failed.
         */
        static bool sampleNtt(
            const SReadOnlyByteSpan& seed, uint8_t firstIndex, uint8_t secondIndex,
            MlKemRing::Poly& out
        );

        /**
         * Samples a polynomial from the centered binomial distribution with parameter eta
         * (FIPS 203 Algorithm 8): each coefficient is the difference of two sums of eta bits, so
         * it lands in [-eta, eta] before being reduced into [0, Q).
         * @param eta The distribution parameter; ML-KEM uses 2 or 3.
         * @param prfOutput Exactly 64*eta bytes of PRF output.
         * @param out Receives 256 coefficients, each in [0, Q).
         * @return true on success; false if eta is out of range or prfOutput is the wrong size.
         */
        static bool samplePolyCbd(
            size_t eta, const SReadOnlyByteSpan& prfOutput, MlKemRing::Poly& out
        );
    };

} // namespace crypto
} // namespace certpp

#endif
