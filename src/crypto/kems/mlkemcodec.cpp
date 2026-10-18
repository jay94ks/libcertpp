#include "mlkemcodec.hpp"

namespace certpp {
namespace crypto {

    /* Packs 256 d-bit coefficients into 32*d bytes. */
    bool MlKemCodec::byteEncode(size_t d, const SMlKemPoly& poly, const SByteSpan& out) {
        if (d < 1 || d > 12) {
            return false;
        }

        const size_t needed = 32 * d;
        if (out.size != needed || !out.data) {
            return false;
        }

        uint8_t* dst = out.data;
        size_t dstIndex = 0;
        uint32_t pending = 0;
        size_t pendingBits = 0;

        // Coefficients are a contiguous little-endian bit stream. A small reservoir preserves
        // that definition directly while emitting a byte at a time; it avoids testing and
        // conditionally setting every individual bit in this serialization hot path.
        for (size_t i = 0; i < SMlKemPoly::COEFFICIENTS; ++i) {
            const uint32_t value = uint32_t(poly.coeffs[i]);
            pending |= value << pendingBits;
            pendingBits += d;

            while (pendingBits >= 8) {
                dst[dstIndex++] = uint8_t(pending);
                pending >>= 8;
                pendingBits -= 8;
            }
        }

        return dstIndex == needed && pendingBits == 0;
    }

    /* Unpacks 32*d bytes into 256 coefficients. */
    bool MlKemCodec::byteDecode(size_t d, const SReadOnlyByteSpan& in, SMlKemPoly& out) {
        if (d < 1 || d > 12) {
            return false;
        }

        const size_t needed = 32 * d;
        if (in.size != needed || !in.data) {
            return false;
        }

        const uint8_t* src = in.data;
        size_t srcIndex = 0;
        uint32_t pending = 0;
        size_t pendingBits = 0;
        const uint32_t mask = (uint32_t(1) << d) - 1;
        for (size_t i = 0; i < SMlKemPoly::COEFFICIENTS; ++i) {
            while (pendingBits < d) {
                pending |= uint32_t(src[srcIndex++]) << pendingBits;
                pendingBits += 8;
            }
            const uint32_t value = pending & mask;
            pending >>= d;
            pendingBits -= d;

            // --> d == 12 is the one width that reduces mod Q rather than mod 2^d, which is what
            // makes this decode lossy: a 12-bit segment in 3329..4095 folds into range instead of
            // being rejected here. Callers that must not accept such an encoding check
            // isCanonical12() first; see this class's own doc comment.
            if (d == 12) {
                const uint32_t reduced = value - uint32_t(SMlKemPoly::MODULUS);
                out.coeffs[i] = int16_t(
                    reduced + (reduced >> 31) * uint32_t(SMlKemPoly::MODULUS));
            } else {
                out.coeffs[i] = int16_t(value);
            }
        }

        return srcIndex == needed && pendingBits == 0;
    }

    /* True iff every 12-bit segment is below Q. */
    bool MlKemCodec::isCanonical12(const SReadOnlyByteSpan& in) {
        if (in.size != 384 || !in.data) {
            return false;
        }

        const uint8_t* src = in.data;
        for (size_t i = 0; i < SMlKemPoly::COEFFICIENTS / 2; ++i) {
            const uint32_t packed = uint32_t(src[3 * i])
                | (uint32_t(src[3 * i + 1]) << 8)
                | (uint32_t(src[3 * i + 2]) << 16);
            const uint32_t first = packed & 0xFFFu;
            const uint32_t second = packed >> 12;
            if (first >= uint32_t(SMlKemPoly::MODULUS)
                || second >= uint32_t(SMlKemPoly::MODULUS))
            {
                return false;
            }
        }

        return true;
    }

    /* Rounds each coefficient down to d bits, in place. */
    bool MlKemCodec::compress(size_t d, SMlKemPoly& poly) {
        if (d < 1 || d > 11) {
            return false;
        }

        const int64_t twoToD = int64_t(1) << d;
        const int64_t q = int64_t(SMlKemPoly::MODULUS);

        for (size_t i = 0; i < SMlKemPoly::COEFFICIENTS; ++i) {
            const int64_t x = int64_t(poly.coeffs[i]);

            // --> round(x * 2^d / q) with ties upward, done in integers: (2*x*2^d + q) / (2*q).
            // Written this way rather than as (x*2^d + q/2)/q because q is odd, so q/2 truncates
            // and the tie rule would be left to luck. Both forms were checked against the exact
            // rational definition for every x in [0, q) and every d ML-KEM uses, and they do
            // agree -- but only one of them is correct by construction.
            const int64_t rounded = (2 * x * twoToD + q) / (2 * q);

            poly.coeffs[i] = int16_t(rounded & (twoToD - 1));
        }

        return true;
    }

    /* Expands each d-bit coefficient back into [0, Q), in place. */
    bool MlKemCodec::decompress(size_t d, SMlKemPoly& poly) {
        if (d < 1 || d > 11) {
            return false;
        }

        const int64_t q = int64_t(SMlKemPoly::MODULUS);

        for (size_t i = 0; i < SMlKemPoly::COEFFICIENTS; ++i) {
            const int64_t y = int64_t(poly.coeffs[i]);

            // round(y * q / 2^d), ties upward -- exact, since the denominator is a power of two.
            const int64_t rounded = (y * q + (int64_t(1) << (d - 1))) >> d;

            // y < 2^d makes the rounded result strictly smaller than Q.
            poly.coeffs[i] = int16_t(rounded);
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
