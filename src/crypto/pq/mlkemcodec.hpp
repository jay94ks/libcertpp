#ifndef __SRC_CRYPTO_PQ_MLKEMCODEC_HPP__
#define __SRC_CRYPTO_PQ_MLKEMCODEC_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include "mlkemring.hpp"

namespace certpp {
namespace crypto {

    /**
     * ML-KEM's wire encoding: the bit-packing of FIPS 203 Algorithms 5/6 (ByteEncode/ByteDecode)
     * and the lossy coefficient rounding of Algorithms 3/4 (Compress/Decompress). Private to the
     * PQ implementation, so no type prefix (see docs/coding-conventions.md).
     *
     * This is the layer that decides what an ML-KEM key or ciphertext actually looks like as
     * bytes, so a mistake here is purely an interoperability failure -- everything still round
     * trips through this library's own encoder and decoder while agreeing with nothing else. Two
     * details carry most of that risk:
     *
     * - Bits are packed **little-endian within each byte**, and coefficients are *contiguous*
     *   with no per-coefficient byte alignment. For d = 10, 11 and 12 a coefficient therefore
     *   straddles byte boundaries, which is exactly where a plausible-looking big-endian or
     *   byte-aligned variant would diverge.
     * - `byteDecode()` at d = 12 reduces each 12-bit segment **mod q**, so it is deliberately
     *   *not* injective: segments in 3329..4095 exist but cannot have come from `byteEncode()`.
     *   That asymmetry is not a wart to be smoothed over -- ML-KEM's own encapsulation-key
     *   validity check is precisely the test that an encapsulation key decodes without any
     *   segment exceeding q-1.
     */
    class MlKemCodec {
    public:
        /**
         * Packs 256 d-bit coefficients into exactly 32*d bytes (FIPS 203 Algorithm 5).
         * @param d Bits per coefficient; 1 to 12.
         * @param poly Coefficients to pack. Each must already be less than 2^d (or less than Q
         * when d is 12); values above that are silently truncated to their low d bits.
         * @param out Destination, which must be exactly 32*d bytes.
         * @return true on success; false if d is out of range or out is the wrong size.
         */
        static bool byteEncode(size_t d, const MlKemRing::Poly& poly, const SByteSpan& out);

        /**
         * Unpacks 32*d bytes into 256 coefficients (FIPS 203 Algorithm 6). For d < 12 each value
         * is taken mod 2^d, i.e. exactly the d bits read; for d = 12 it is additionally reduced
         * mod Q, which is what makes the decode lossy and the validity check meaningful.
         * @param d Bits per coefficient; 1 to 12.
         * @param in Source, which must be exactly 32*d bytes.
         * @param out Receives the unpacked coefficients.
         * @return true on success; false if d is out of range or in is the wrong size.
         */
        static bool byteDecode(size_t d, const SReadOnlyByteSpan& in, MlKemRing::Poly& out);

        /**
         * Reports whether every 12-bit segment of a d=12 encoding is a valid field element, i.e.
         * strictly less than Q -- the "modulus check" ML-KEM applies to an encapsulation key
         * before trusting it, since byteDecode(12, ...) would otherwise silently fold an
         * out-of-range segment into range.
         * @param in A 384-byte d=12 encoding.
         * @return true if in is 384 bytes and every segment is below Q; false otherwise.
         */
        static bool isCanonical12(const SReadOnlyByteSpan& in);

        /**
         * Rounds each coefficient from [0, Q) down to d bits in place (FIPS 203 Algorithm 3):
         * round(coefficient * 2^d / Q) mod 2^d, ties upward. Afterwards the polynomial holds
         * d-bit values rather than field elements -- it is being used as a container for the
         * compressed representation, exactly as FIPS 203 does.
         * @param d Target bits per coefficient; 1 to 11.
         * @param poly Polynomial to compress in place.
         * @return true on success; false if d is out of range.
         */
        static bool compress(size_t d, MlKemRing::Poly& poly);

        /**
         * Expands each d-bit coefficient back into [0, Q) in place (FIPS 203 Algorithm 4):
         * round(coefficient * Q / 2^d), ties upward. The inverse of compress() only
         * approximately -- the rounding error is what ML-KEM's decryption-failure analysis
         * budgets for -- so this is not a lossless round trip and is not meant to be.
         * @param d Bits per coefficient the values currently hold; 1 to 11.
         * @param poly Polynomial to decompress in place.
         * @return true on success; false if d is out of range.
         */
        static bool decompress(size_t d, MlKemRing::Poly& poly);
    };

} // namespace crypto
} // namespace certpp

#endif
