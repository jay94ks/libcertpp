#ifndef __SRC_CRYPTO_HASHERS_KECCAKCORE_HPP__
#define __SRC_CRYPTO_HASHERS_KECCAKCORE_HPP__

#include <certpp/common.hpp>

namespace certpp {
namespace crypto {

    /**
     * The Keccak-f[1600] permutation (FIPS 202 3.2) plus the byte-oriented sponge-absorption
     * step built on it -- the one piece shared between every fixed-1600-bit-state Keccak/SHA-3
     * XOF this library implements (SHAKE128, SHAKE256): the permutation itself, and absorbing a
     * block into the state, don't depend on the sponge's rate/capacity split (that's purely a
     * buffering/padding concern each XOF's own push()/finish() still owns) -- only on the fixed
     * 1600-bit state width, which is the same for every member of the Keccak-f family regardless
     * of which SHA-3/SHAKE variant it backs.
     */
    class KeccakCore {
    public:
        static constexpr size_t STATE_BYTES = 200; // 1600 bits

    private:
        static inline uint64_t rotl64(uint64_t v, int n) {
            return n == 0 ? v : (v << n) | (v >> (64 - n));
        }

        /**
         * Applies the Keccak-f[1600] permutation (24 rounds of theta/rho/pi/chi/iota) to a
         * 1600-bit state, given as 25 64-bit lanes, lane(x, y) at a[x + 5*y].
         */
        static void f1600(uint64_t a[25]);

    public:
        /**
         * Byte-orients the state for absorption/squeezing: Keccak lanes are little-endian 64-bit
         * words regardless of host endianness, so this reads/writes byte-by-byte rather than
         * reinterpret-casting (which would be wrong on a big-endian host).
         */
        static void permute(uint8_t state[STATE_BYTES]);

        /**
         * XORs src into the first len bytes of the state (len must not exceed STATE_BYTES --
         * callers pass their own rate, which is always well under that), then permutes.
         */
        static void absorbBlock(uint8_t state[STATE_BYTES], const uint8_t* src, size_t len);
    };

} // namespace crypto
} // namespace certpp

#endif
