#include "mldsacodec.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

        /* Writes `width` bits of `value` at `bitOffset`, little-endian within each byte -- the
         * same convention BitsToBytes (FIPS 204 Algorithm 12) defines. */
        void writeBits(uint8_t* out, size_t bitOffset, uint32_t value, size_t width) {
            for (size_t bit = 0; bit < width; ++bit) {
                const size_t position = bitOffset + bit;

                if ((value >> bit) & 1u) {
                    out[position >> 3] = uint8_t(out[position >> 3] | (1u << (position & 7u)));
                }
            }
        }

        /* Reads `width` bits from `bitOffset`, matching writeBits. */
        uint32_t readBits(const uint8_t* in, size_t bitOffset, size_t width) {
            uint32_t value = 0;

            for (size_t bit = 0; bit < width; ++bit) {
                const size_t position = bitOffset + bit;

                if ((in[position >> 3] >> (position & 7u)) & 1u) {
                    value |= uint32_t(1) << bit;
                }
            }

            return value;
        }

    } // namespace

    /* FIPS 204's bitlen. */
    size_t MlDsaCodec::bitLength(uint32_t value) {
        size_t bits = 0;

        while (value != 0) {
            ++bits;
            value >>= 1;
        }

        return bits;
    }

    /* SimpleBitPack (FIPS 204 Algorithm 16). */
    bool MlDsaCodec::simpleBitPack(const Poly& poly, uint32_t b, const SByteSpan& out) {
        const size_t width = bitLength(b);
        const size_t needed = 32 * width;

        if (width == 0 || out.size != needed || !out.data) {
            return false;
        }

        for (size_t i = 0; i < MlDsaRing::N; ++i) {
            if (poly.coeffs[i] < 0 || uint32_t(poly.coeffs[i]) > b) {
                return false;
            }
        }

        std::memset(out.data, 0, needed);

        for (size_t i = 0; i < MlDsaRing::N; ++i) {
            writeBits(out.data, i * width, uint32_t(poly.coeffs[i]), width);
        }

        return true;
    }

    /* SimpleBitUnpack (FIPS 204 Algorithm 18). */
    bool MlDsaCodec::simpleBitUnpack(const SReadOnlyByteSpan& in, uint32_t b, Poly& out) {
        const size_t width = bitLength(b);

        if (width == 0 || in.size != 32 * width || !in.data) {
            return false;
        }

        // --> No range check here, deliberately: FIPS 204 defines this as a pure bit-field read,
        // and for b = 43 it genuinely can produce 63. The caller decides whether that matters,
        // because for t1 (b = 2^10 - 1) it cannot happen at all. See the class doc comment.
        for (size_t i = 0; i < MlDsaRing::N; ++i) {
            out.coeffs[i] = int32_t(readBits(in.data, i * width, width));
        }

        return true;
    }

    /* BitPack (FIPS 204 Algorithm 17). */
    bool MlDsaCodec::bitPack(const Poly& poly, uint32_t a, uint32_t b, const SByteSpan& out) {
        const size_t width = bitLength(a + b);
        const size_t needed = 32 * width;

        if (width == 0 || out.size != needed || !out.data) {
            return false;
        }

        for (size_t i = 0; i < MlDsaRing::N; ++i) {
            if (poly.coeffs[i] < -int64_t(a) || poly.coeffs[i] > int64_t(b)) {
                return false;
            }
        }

        std::memset(out.data, 0, needed);

        // --> b - w_i, which maps [-a, b] onto [0, a + b] and is what lets an unsigned bit field
        // carry a signed range. Note the direction: the encoding is *descending* in w_i, so a
        // decoder that forgets the subtraction produces a mirrored polynomial that still packs
        // and unpacks consistently with itself.
        for (size_t i = 0; i < MlDsaRing::N; ++i) {
            const uint32_t shifted = uint32_t(int64_t(b) - int64_t(poly.coeffs[i]));
            writeBits(out.data, i * width, shifted, width);
        }

        return true;
    }

    /* BitUnpack (FIPS 204 Algorithm 19). */
    bool MlDsaCodec::bitUnpack(
        const SReadOnlyByteSpan& in, uint32_t a, uint32_t b, Poly& out
    ) {
        const size_t width = bitLength(a + b);

        if (width == 0 || in.size != 32 * width || !in.data) {
            return false;
        }

        for (size_t i = 0; i < MlDsaRing::N; ++i) {
            const uint32_t field = readBits(in.data, i * width, width);
            out.coeffs[i] = int32_t(int64_t(b) - int64_t(field));
        }

        return true;
    }

    /* True if every coefficient is within [low, high]. */
    bool MlDsaCodec::inRange(const Poly& poly, int32_t low, int32_t high) {
        for (size_t i = 0; i < MlDsaRing::N; ++i) {
            if (poly.coeffs[i] < low || poly.coeffs[i] > high) {
                return false;
            }
        }

        return true;
    }

    /* HintBitPack (FIPS 204 Algorithm 20). */
    bool MlDsaCodec::hintBitPack(
        const Poly* hints, size_t k, size_t omega, const SByteSpan& out
    ) {
        if (!hints || k == 0 || k > MAX_K || omega == 0 || omega > 255) {
            return false;
        }
        if (out.size != omega + k || !out.data) {
            return false;
        }

        std::memset(out.data, 0, out.size);

        size_t index = 0;

        for (size_t i = 0; i < k; ++i) {
            for (size_t j = 0; j < MlDsaRing::N; ++j) {
                const int32_t coefficient = hints[i].coeffs[j];

                if (coefficient == 0) {
                    continue;
                }
                if (coefficient != 1) {
                    return false; // a hint is binary by definition
                }
                if (index >= omega) {
                    return false; // more set coefficients than the budget allows
                }

                out.data[index] = uint8_t(j);
                ++index;
            }

            // The running total after this polynomial. Positions ascend within each one, which
            // is what makes the encoding recoverable from these k checkpoints alone.
            out.data[omega + i] = uint8_t(index);
        }

        return true;
    }

    /* HintBitUnpack (FIPS 204 Algorithm 21), with all three rejection conditions. */
    bool MlDsaCodec::hintBitUnpack(
        const SReadOnlyByteSpan& in, size_t k, size_t omega, Poly* out
    ) {
        if (!out || k == 0 || k > MAX_K || omega == 0 || omega > 255) {
            return false;
        }
        if (in.size != omega + k || !in.data) {
            return false;
        }

        // Built into locals and only committed on success, so a rejection leaves the caller's
        // polynomials untouched rather than half-written -- the caller is about to treat a
        // false return as "this signature is invalid", and a partially filled hint vector lying
        // around is the kind of thing that later gets used by accident.
        Poly scratch[MAX_K];
        for (size_t i = 0; i < k; ++i) {
            std::memset(scratch[i].coeffs, 0, sizeof(scratch[i].coeffs));
        }

        size_t index = 0;

        for (size_t i = 0; i < k; ++i) {
            const size_t limit = in.data[omega + i];

            // (1) The running total must not move backwards, nor past the budget. Backwards
            // would mean this polynomial claims fewer positions than the previous one already
            // consumed; past omega would read outside the position area.
            if (limit < index || limit > omega) {
                return false;
            }

            const size_t first = index;

            while (index < limit) {
                // (2) Strictly increasing *within this polynomial*. The comparison starts afresh
                // at `first`, so a position may legitimately drop from the end of h[i] to the
                // start of h[i+1]; checking monotonicity across the whole array instead would
                // reject valid signatures. Equal positions are rejected too, not just
                // decreasing ones -- otherwise the same coefficient could be named twice and
                // two encodings would mean one hint.
                if (index > first && in.data[index - 1] >= in.data[index]) {
                    return false;
                }

                scratch[i].coeffs[in.data[index]] = 1;
                ++index;
            }
        }

        // (3) Everything past the last position read must be zero. Without this, any value could
        // be stuffed into the unused tail and the signature would still verify -- the encoding
        // would stop being injective, which is precisely what makes a signature malleable.
        for (size_t i = index; i < omega; ++i) {
            if (in.data[i] != 0) {
                return false;
            }
        }

        for (size_t i = 0; i < k; ++i) {
            std::memcpy(out[i].coeffs, scratch[i].coeffs, sizeof(scratch[i].coeffs));
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
