#include <certpp/crypto/kems/mlkem.hpp>
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
            // SHAKE128's 168-byte rate is divisible by three. Reading one complete rate block
            // keeps exactly the same candidate order while replacing roughly 160 three-byte
            // virtual calls per polynomial with the three sponge-block reads the sampler
            // actually needs.
            uint8_t chunk[168];
            if (!xof.squeeze(SByteSpan(chunk, sizeof(chunk)))) {
                return false;
            }

            for (size_t offset = 0;
                 offset < sizeof(chunk) && accepted < SMlKemPoly::COEFFICIENTS;
                 offset += 3)
            {
                const uint32_t d1 = uint32_t(chunk[offset])
                    | (uint32_t(chunk[offset + 1] & 0x0Fu) << 8);
                const uint32_t d2 = (uint32_t(chunk[offset + 1]) >> 4)
                    | (uint32_t(chunk[offset + 2]) << 4);

                // Order matters: d1 is offered before d2, and skipping a rejected d1 must not
                // skip the d2 that shares its three bytes.
                if (d1 < uint32_t(SMlKemPoly::MODULUS)) {
                    out.coeffs[accepted] = int16_t(d1);
                    ++accepted;
                }

                if (d2 < uint32_t(SMlKemPoly::MODULUS)
                    && accepted < SMlKemPoly::COEFFICIENTS)
                {
                    out.coeffs[accepted] = int16_t(d2);
                    ++accepted;
                }
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

        // Bits are little-endian within each byte. The masks add each eta-bit lane in parallel,
        // then each output extracts the two adjacent population counts. This is the same CBD
        // mapping as the bit-by-bit definition, with fixed work and no general modular division.
        if (eta == 2) {
            for (size_t i = 0; i < SMlKemPoly::COEFFICIENTS / 8; ++i) {
                const uint32_t t = uint32_t(src[4 * i])
                    | (uint32_t(src[4 * i + 1]) << 8)
                    | (uint32_t(src[4 * i + 2]) << 16)
                    | (uint32_t(src[4 * i + 3]) << 24);
                uint32_t lanes = t & 0x55555555u;
                lanes += (t >> 1) & 0x55555555u;

                for (size_t j = 0; j < 8; ++j) {
                    const int32_t difference = int32_t((lanes >> (4 * j)) & 0x3u)
                        - int32_t((lanes >> (4 * j + 2)) & 0x3u);
                    out.coeffs[8 * i + j] = int16_t(
                        difference + int32_t(uint32_t(difference) >> 31) * MlKemRing::Q);
                }
            }
        }
        else if (eta == 3) {
            for (size_t i = 0; i < SMlKemPoly::COEFFICIENTS / 4; ++i) {
                const uint32_t t = uint32_t(src[3 * i])
                    | (uint32_t(src[3 * i + 1]) << 8)
                    | (uint32_t(src[3 * i + 2]) << 16);
                uint32_t lanes = t & 0x00249249u;
                lanes += (t >> 1) & 0x00249249u;
                lanes += (t >> 2) & 0x00249249u;

                for (size_t j = 0; j < 4; ++j) {
                    const int32_t difference = int32_t((lanes >> (6 * j)) & 0x7u)
                        - int32_t((lanes >> (6 * j + 3)) & 0x7u);
                    out.coeffs[4 * i + j] = int16_t(
                        difference + int32_t(uint32_t(difference) >> 31) * MlKemRing::Q);
                }
            }
        }
        else {
            for (size_t i = 0; i < SMlKemPoly::COEFFICIENTS / 4; ++i) {
                const uint32_t t = src[i];
                for (size_t j = 0; j < 4; ++j) {
                    const int32_t difference = int32_t((t >> (2 * j)) & 1u)
                        - int32_t((t >> (2 * j + 1)) & 1u);
                    out.coeffs[4 * i + j] = int16_t(
                        difference + int32_t(uint32_t(difference) >> 31) * MlKemRing::Q);
                }
            }
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
