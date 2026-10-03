#include "mldsasampler.hpp"
#include "mldsacodec.hpp"
#include <certpp/crypto/hashers/shake128.hpp>
#include <certpp/crypto/hashers/shake256.hpp>
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

        /* IntegerToBytes (FIPS 204 Algorithm 11): little-endian, `length` bytes. */
        void integerToBytes(uint32_t value, uint8_t* out, size_t length) {
            for (size_t i = 0; i < length; ++i) {
                out[i] = uint8_t((value >> (8 * i)) & 0xFFu);
            }
        }

    } // namespace

    /* CoeffFromThreeBytes (FIPS 204 Algorithm 14). */
    bool MlDsaSampler::coeffFromThreeBytes(uint8_t b0, uint8_t b1, uint8_t b2, int32_t& out) {
        // --> The top bit of b2 is cleared, so the candidate is 23 bits. That still leaves
        // values in [q, 2^23) to reject -- masking is not itself the filter, which is easy to
        // misread from the algorithm's two separate steps.
        const uint32_t z = (uint32_t(b2 & 0x7Fu) << 16) | (uint32_t(b1) << 8) | uint32_t(b0);

        if (z >= uint32_t(MlDsaRing::Q)) {
            return false;
        }

        out = int32_t(z);
        return true;
    }

    /* CoeffFromHalfByte (FIPS 204 Algorithm 15). */
    bool MlDsaSampler::coeffFromHalfByte(uint8_t nibble, size_t eta, int32_t& out) {
        if (eta == 2) {
            if (nibble >= 15) {
                return false;
            }

            // Fifteen inputs onto five outputs, three each -- which is why the cut is at 15 and
            // not 10, and why the mod 5 is there at all.
            out = 2 - int32_t(nibble % 5);
            return true;
        }

        if (eta == 4) {
            if (nibble >= 9) {
                return false;
            }

            out = 4 - int32_t(nibble);
            return true;
        }

        return false; // no other eta exists
    }

    /* SampleInBall (FIPS 204 Algorithm 29). */
    bool MlDsaSampler::sampleInBall(const SReadOnlyByteSpan& seed, size_t tau, Poly& out) {
        if (!seed.data || seed.size == 0 || tau == 0 || tau > MAX_TAU) {
            return false;
        }

        SHAKE256 xof;
        if (xof.push(seed) != seed.size) {
            return false;
        }

        // The first 8 bytes are the sign bits -- 64 of them, which is exactly why tau is capped
        // at 64. BytesToBits is little-endian within each byte, so bit i lives at
        // signs[i / 8] >> (i % 8).
        uint8_t signs[8];
        if (!xof.squeeze(SByteSpan(signs, sizeof(signs)))) {
            return false;
        }

        std::memset(out.coeffs, 0, sizeof(out.coeffs));

        for (size_t i = MlDsaRing::N - tau; i < MlDsaRing::N; ++i) {
            // Rejection-sample a position in [0, i]. Unbounded, per FIPS 204 Appendix C's
            // recommendation; the expected number of draws is barely above one.
            uint8_t j = 0;
            do {
                if (!xof.squeeze(SByteSpan(&j, 1))) {
                    return false;
                }
            } while (size_t(j) > i);

            const size_t signIndex = i + tau - MlDsaRing::N;
            const uint8_t bit = uint8_t((signs[signIndex >> 3] >> (signIndex & 7u)) & 1u);

            // Fisher-Yates: whatever was at j moves to i, and j takes the new signed one. Doing
            // this in the other order loses a coefficient whenever j == i.
            out.coeffs[i] = out.coeffs[j];
            out.coeffs[j] = bit ? -1 : 1;
        }

        return true;
    }

    /* RejNTTPoly (FIPS 204 Algorithm 30). */
    bool MlDsaSampler::rejNttPoly(const SReadOnlyByteSpan& seed, Poly& out) {
        if (!seed.data || seed.size != 34) {
            return false;
        }

        // SHAKE128 here, not SHAKE256 -- this is the standard's G. See the class doc comment.
        SHAKE128 xof;
        if (xof.push(seed) != seed.size) {
            return false;
        }

        size_t accepted = 0;

        while (accepted < MlDsaRing::N) {
            uint8_t chunk[3];
            if (!xof.squeeze(SByteSpan(chunk, sizeof(chunk)))) {
                return false;
            }

            int32_t coefficient = 0;
            if (coeffFromThreeBytes(chunk[0], chunk[1], chunk[2], coefficient)) {
                out.coeffs[accepted] = coefficient;
                ++accepted;
            }
        }

        return true;
    }

    /* RejBoundedPoly (FIPS 204 Algorithm 31). */
    bool MlDsaSampler::rejBoundedPoly(const SReadOnlyByteSpan& seed, size_t eta, Poly& out) {
        if (!seed.data || seed.size != 66 || (eta != 2 && eta != 4)) {
            return false;
        }

        SHAKE256 xof;
        if (xof.push(seed) != seed.size) {
            return false;
        }

        size_t accepted = 0;

        while (accepted < MlDsaRing::N) {
            uint8_t byte = 0;
            if (!xof.squeeze(SByteSpan(&byte, 1))) {
                return false;
            }

            // Order matters: the low nibble is offered first, then the high one. A rejected low
            // nibble must not consume the high one's turn, and the last accepted coefficient
            // must not overrun -- hence the second bounds check rather than a single loop test.
            int32_t low = 0;
            if (coeffFromHalfByte(uint8_t(byte & 0x0Fu), eta, low)) {
                out.coeffs[accepted] = low;
                ++accepted;
            }

            int32_t high = 0;
            if (accepted < MlDsaRing::N
                && coeffFromHalfByte(uint8_t(byte >> 4), eta, high))
            {
                out.coeffs[accepted] = high;
                ++accepted;
            }
        }

        return true;
    }

    /* ExpandA (FIPS 204 Algorithm 32). */
    bool MlDsaSampler::expandA(const SReadOnlyByteSpan& seed, size_t k, size_t l, Poly* out) {
        if (!seed.data || seed.size != 32 || !out) {
            return false;
        }
        if (k == 0 || k > MAX_K || l == 0 || l > MAX_L) {
            return false;
        }

        uint8_t expanded[34];
        std::memcpy(expanded, seed.data, 32);

        for (size_t r = 0; r < k; ++r) {
            for (size_t s = 0; s < l; ++s) {
                // --> Column byte first, then row. FIPS 204 Algorithm 32 line 3, and the margin
                // note beside it, are explicit; writing them the natural way round transposes
                // the matrix and changes every byte of the key without breaking anything that
                // only ever talks to itself.
                expanded[32] = uint8_t(s);
                expanded[33] = uint8_t(r);

                if (!rejNttPoly(SReadOnlyByteSpan(expanded, sizeof(expanded)), out[r * l + s])) {
                    return false;
                }
            }
        }

        return true;
    }

    /* ExpandS (FIPS 204 Algorithm 33). */
    bool MlDsaSampler::expandS(
        const SReadOnlyByteSpan& seed, size_t k, size_t l, size_t eta, Poly* s1, Poly* s2
    ) {
        if (!seed.data || seed.size != 64 || !s1 || !s2) {
            return false;
        }
        if (k == 0 || k > MAX_K || l == 0 || l > MAX_L) {
            return false;
        }

        uint8_t expanded[66];
        std::memcpy(expanded, seed.data, 64);

        for (size_t r = 0; r < l; ++r) {
            integerToBytes(uint32_t(r), expanded + 64, 2);

            if (!rejBoundedPoly(SReadOnlyByteSpan(expanded, sizeof(expanded)), eta, s1[r])) {
                return false;
            }
        }

        for (size_t r = 0; r < k; ++r) {
            // s2's index continues from where s1's left off, so the two vectors never share a
            // seed despite coming from one rho.
            integerToBytes(uint32_t(r + l), expanded + 64, 2);

            if (!rejBoundedPoly(SReadOnlyByteSpan(expanded, sizeof(expanded)), eta, s2[r])) {
                return false;
            }
        }

        return true;
    }

    /* ExpandMask (FIPS 204 Algorithm 34). */
    bool MlDsaSampler::expandMask(
        const SReadOnlyByteSpan& seed, uint32_t mu, size_t l, uint32_t gamma1, Poly* out
    ) {
        if (!seed.data || seed.size != 64 || !out || l == 0 || l > MAX_L) {
            return false;
        }
        if (gamma1 == 0 || (gamma1 & (gamma1 - 1)) != 0) {
            return false; // the standard relies on gamma1 being a power of two
        }

        const size_t width = 1 + MlDsaCodec::bitLength(gamma1 - 1);
        const size_t bytesPerPoly = 32 * width;

        // 2^19 is the largest gamma1, giving width 20 and 640 bytes.
        uint8_t block[32 * 20];
        if (bytesPerPoly > sizeof(block)) {
            return false;
        }

        uint8_t expanded[66];
        std::memcpy(expanded, seed.data, 64);

        for (size_t r = 0; r < l; ++r) {
            integerToBytes(mu + uint32_t(r), expanded + 64, 2);

            // Not rejection sampling: gamma1 is a power of two, so every bit pattern is a valid
            // coefficient and a fixed-length squeeze unpacks directly.
            SHAKE256 xof;
            if (xof.push(SReadOnlyByteSpan(expanded, sizeof(expanded))) != sizeof(expanded)) {
                return false;
            }
            if (!xof.squeeze(SByteSpan(block, bytesPerPoly))) {
                return false;
            }

            if (!MlDsaCodec::bitUnpack(
                    SReadOnlyByteSpan(block, bytesPerPoly), gamma1 - 1, gamma1, out[r]))
            {
                return false;
            }
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
