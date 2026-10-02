#include "mlkemcodec.hpp"

namespace certpp {
namespace crypto {

    /* Packs 256 d-bit coefficients into 32*d bytes. */
    bool MlKemCodec::byteEncode(size_t d, const MlKemRing::Poly& poly, const SByteSpan& out) {
        if (d < 1 || d > 12) {
            return false;
        }

        const size_t needed = 32 * d;
        if (out.size != needed || !out.data) {
            return false;
        }

        uint8_t* dst = out.data;
        for (size_t i = 0; i < needed; ++i) {
            dst[i] = 0;
        }

        // --> Bit index i*d + j is coefficient i's bit j, and bit b of the stream lives in
        // dst[b / 8] at position b % 8 -- little-endian within the byte. Coefficients run
        // contiguously, so for d of 10/11/12 one coefficient spans two or three bytes; writing
        // bit by bit keeps that straddling correct without any special cases.
        for (size_t i = 0; i < MlKemRing::N; ++i) {
            const uint32_t value = uint32_t(poly.coeffs[i]);

            for (size_t j = 0; j < d; ++j) {
                if ((value >> j) & 1u) {
                    const size_t bit = i * d + j;
                    dst[bit >> 3] = uint8_t(dst[bit >> 3] | (1u << (bit & 7u)));
                }
            }
        }

        return true;
    }

    /* Unpacks 32*d bytes into 256 coefficients. */
    bool MlKemCodec::byteDecode(size_t d, const SReadOnlyByteSpan& in, MlKemRing::Poly& out) {
        if (d < 1 || d > 12) {
            return false;
        }

        const size_t needed = 32 * d;
        if (in.size != needed || !in.data) {
            return false;
        }

        const uint8_t* src = in.data;

        for (size_t i = 0; i < MlKemRing::N; ++i) {
            uint32_t value = 0;

            for (size_t j = 0; j < d; ++j) {
                const size_t bit = i * d + j;
                const uint32_t set = (src[bit >> 3] >> (bit & 7u)) & 1u;
                value |= set << j;
            }

            // --> d == 12 is the one width that reduces mod Q rather than mod 2^d, which is what
            // makes this decode lossy: a 12-bit segment in 3329..4095 folds into range instead of
            // being rejected here. Callers that must not accept such an encoding check
            // isCanonical12() first; see this class's own doc comment.
            if (d == 12) {
                out.coeffs[i] = MlKemRing::reduce(int32_t(value));
            } else {
                out.coeffs[i] = int16_t(value);
            }
        }

        return true;
    }

    /* True iff every 12-bit segment is below Q. */
    bool MlKemCodec::isCanonical12(const SReadOnlyByteSpan& in) {
        if (in.size != 384 || !in.data) {
            return false;
        }

        const uint8_t* src = in.data;

        for (size_t i = 0; i < MlKemRing::N; ++i) {
            uint32_t value = 0;

            for (size_t j = 0; j < 12; ++j) {
                const size_t bit = i * 12 + j;
                value |= ((src[bit >> 3] >> (bit & 7u)) & 1u) << j;
            }

            if (value >= uint32_t(MlKemRing::Q)) {
                return false;
            }
        }

        return true;
    }

    /* Rounds each coefficient down to d bits, in place. */
    bool MlKemCodec::compress(size_t d, MlKemRing::Poly& poly) {
        if (d < 1 || d > 11) {
            return false;
        }

        const int64_t twoToD = int64_t(1) << d;
        const int64_t q = int64_t(MlKemRing::Q);

        for (size_t i = 0; i < MlKemRing::N; ++i) {
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
    bool MlKemCodec::decompress(size_t d, MlKemRing::Poly& poly) {
        if (d < 1 || d > 11) {
            return false;
        }

        const int64_t q = int64_t(MlKemRing::Q);

        for (size_t i = 0; i < MlKemRing::N; ++i) {
            const int64_t y = int64_t(poly.coeffs[i]);

            // round(y * q / 2^d), ties upward -- exact, since the denominator is a power of two.
            const int64_t rounded = (y * q + (int64_t(1) << (d - 1))) >> d;

            poly.coeffs[i] = MlKemRing::reduce(int32_t(rounded));
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
