#include <certpp/crypto/pq/mlkem.hpp>
#include "mlkemring.hpp"
#include <certpp/crypto/hashers/shake128.hpp>
#include <cstring>

namespace certpp {
namespace crypto {

    /* Rejection-samples a uniform NTT-domain polynomial from SHAKE128(seed || i || j). */
    bool CMlKemSampler::sampleNtt(
        const SReadOnlyByteSpan& seed, uint8_t firstIndex, uint8_t secondIndex,
        SMlKemPoly& out
    ) {
        if (seed.size != 32 || !seed.data) {
            return false;
        }

        uint8_t prefix[34];
        std::memcpy(prefix, seed.data, 32);
        prefix[32] = firstIndex;
        prefix[33] = secondIndex;

        SHAKE128 xof;
        if (xof.push(SReadOnlyByteSpan(prefix, sizeof(prefix))) != sizeof(prefix)) {
            return false;
        }

        // --> Three bytes at a time yield two 12-bit candidates, and each is kept only if it is
        // below Q -- so how much of the stream this consumes depends on the seed (about 474-498
        // bytes in practice, three-ish SHAKE128 rate blocks). That is why squeeze() exists: there
        // is no length to ask finish() for. A bound here would be a correctness bug, not a
        // safeguard, so the loop runs until 256 coefficients are accepted.
        size_t accepted = 0;
        while (accepted < SMlKemPoly::COEFFICIENTS) {
            uint8_t chunk[3];
            if (!xof.squeeze(SByteSpan(chunk, sizeof(chunk)))) {
                return false;
            }

            const uint32_t d1 = uint32_t(chunk[0]) | (uint32_t(chunk[1] & 0x0Fu) << 8);
            const uint32_t d2 = (uint32_t(chunk[1]) >> 4) | (uint32_t(chunk[2]) << 4);

            // Order matters: d1 is offered before d2, and skipping a rejected d1 must not skip
            // the d2 that shares its three bytes.
            if (d1 < uint32_t(SMlKemPoly::MODULUS)) {
                out.coeffs[accepted] = int16_t(d1);
                ++accepted;
            }

            if (d2 < uint32_t(SMlKemPoly::MODULUS) && accepted < SMlKemPoly::COEFFICIENTS) {
                out.coeffs[accepted] = int16_t(d2);
                ++accepted;
            }
        }

        return true;
    }

    /* Samples from the centered binomial distribution with parameter eta. */
    bool CMlKemSampler::samplePolyCbd(
        size_t eta, const SReadOnlyByteSpan& prfOutput, SMlKemPoly& out
    ) {
        if (eta < 1 || eta > 3) {
            return false;
        }

        const size_t needed = 64 * eta;
        if (prfOutput.size != needed || !prfOutput.data) {
            return false;
        }

        const uint8_t* src = prfOutput.data;

        // --> Bits are read little-endian within each byte, the same convention ByteEncode uses.
        // Coefficient i consumes bits [2*i*eta, 2*i*eta + 2*eta): the first eta are summed into x,
        // the next eta into y, and the coefficient is x - y -- so it lies in [-eta, eta] and is
        // centered on zero, which is the whole point of the distribution.
        for (size_t i = 0; i < SMlKemPoly::COEFFICIENTS; ++i) {
            const size_t base = 2 * i * eta;

            int32_t x = 0;
            int32_t y = 0;

            for (size_t j = 0; j < eta; ++j) {
                const size_t xBit = base + j;
                const size_t yBit = base + eta + j;

                x += int32_t((src[xBit >> 3] >> (xBit & 7u)) & 1u);
                y += int32_t((src[yBit >> 3] >> (yBit & 7u)) & 1u);
            }

            out.coeffs[i] = MlKemRing::reduce(x - y);
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
