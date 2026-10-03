#ifndef __SRC_CRYPTO_HASHERS_STREEBOGCORE_HPP__
#define __SRC_CRYPTO_HASHERS_STREEBOGCORE_HPP__

#include <certpp/common.hpp>

namespace certpp {
namespace crypto {

    /**
     * The GOST R 34.11-2012 (Streebog, RFC 6986) compression function g_N and the two
     * mod-2^512 accumulators its calculation procedure needs, shared by Streebog256 and
     * Streebog512. The two digest lengths differ only in their initializing value
     * (0^512 vs (00000001)^64) and in whether the final state is emitted whole or cut down
     * to MSB_256, so -- exactly like Sha2_64Core for SHA-384/SHA-512 -- this owns the one
     * piece genuinely shared between them while each digest keeps its own context, padding
     * and output handling.
     *
     * Byte order, which is the single easiest thing to get wrong here: RFC 6986 numbers a
     * V_512 vector's bytes from the right starting at zero, and writes vectors in hex
     * most-significant-byte-first, so its printed message/hash strings read backwards
     * relative to a byte stream. (Its own example 2 is the proof: the hex decodes to
     * readable CP1251 Russian text only when read right to left, and its example 1 is the
     * ASCII string "0123...012".) Every 64-byte buffer here is therefore indexed by the
     * spec's own byte position -- index 0 is a_0, the least significant byte of the vector
     * and the *first* byte of a message block -- which makes message bytes stream straight
     * into a block at increasing indices, makes the digest come out in the order every
     * published Streebog digest uses, and makes MSB_256 the *upper* half (indices 32..63).
     */
    class StreebogCore {
    public:
        /**
         * Pi', the nonlinear bijection of V_8 (RFC 6986 section 6.2).
         */
        static const uint8_t PI[256];

        /**
         * The 64 rows of the matrix A specifying the linear transformation l (RFC 6986
         * section 6.4). Row 0 is the one selected by l's input's most significant bit.
         */
        static const uint64_t A[64];

        /**
         * The twelve iteration constants C[1]..C[12] (RFC 6986 section 6.5), in this
         * class's byte-position-0-first layout.
         */
        static const uint8_t C[12][64];

    public:
        /**
         * Applies the linear transformation l to one 64-bit word, straight off the A
         * matrix. Used to build the combined S/P/L lookup table once at first use, and
         * exposed so a test can re-derive that table's contents independently.
         *
         * @param value The word to transform; its bit 63 selects A[0].
         * @return l(value).
         */
        static uint64_t transformL(uint64_t value);

        /**
         * Applies LPS -- the substitution S, the byte permutation P and the linear
         * transformation L, in that order -- to a 512-bit state in place, via a combined
         * 8x256-entry lookup table derived from PI and A on first use.
         *
         * @param state The 64-byte state to transform in place.
         */
        static void transformLps(uint8_t state[64]);

        /**
         * Runs the round function g_N(h, m) = E(LPS(h ^ N), m) ^ h ^ m (RFC 6986
         * section 8) over one 512-bit message block, updating h in place.
         *
         * @param h The 64-byte running hash state, updated in place.
         * @param n The 64-byte message-length counter N.
         * @param m The 64-byte message block to compress.
         */
        static void compress(uint8_t h[64], const uint8_t n[64], const uint8_t m[64]);

        /**
         * Adds one 512-bit value into another, modulo 2^512 -- the [+] of RFC 6986's
         * Z_(2^512), used for the EPSILON checksum.
         *
         * @param acc The 64-byte accumulator, updated in place.
         * @param addend The 64-byte value to add.
         */
        static void addMod512(uint8_t acc[64], const uint8_t addend[64]);

        /**
         * Adds a small value into a 512-bit accumulator, modulo 2^512 -- used for the
         * bit-length counter N, which only ever grows by at most 512 at a time.
         *
         * @param acc The 64-byte accumulator, updated in place.
         * @param addend The value to add.
         */
        static void addMod512(uint8_t acc[64], uint64_t addend);
    };

} // namespace crypto
} // namespace certpp

#endif
