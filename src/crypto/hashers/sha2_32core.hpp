#ifndef __SRC_CRYPTO_HASHERS_SHA2_32CORE_HPP__
#define __SRC_CRYPTO_HASHERS_SHA2_32CORE_HPP__

#include <certpp/common.hpp>

namespace certpp {
namespace crypto {

    /**
     * Runs the SHA-256/SHA-224 compression function (FIPS 180-4) over one 64-byte block,
     * updating the 8-word (32-bit) state in place. SHA-224 and SHA-256 are identical except for
     * their initial hash values and truncated output length, so this is the one piece actually
     * shared between them; each still owns its own context/padding/output-length handling.
     */
    class Sha2_32Core {
    private:
        static inline uint32_t rotr(uint32_t value, uint32_t count) {
            return (value >> count) | (value << (32 - count));
        }

/* Hardware-accelerated compression (Intel SHA Extensions), gated by both the
 * CERTPP_DISABLE_HWACCEL_SHA build option and the target architecture -- see sha2_32core.cpp's
 * identical guard (which this must match exactly) for the full rationale. */
#if !defined(CERTPP_DISABLE_HWACCEL_SHA) && (defined(_M_X64) || defined(__x86_64__))
        /**
         * Whether this CPU actually has the SHA extensions -- see sha2_32core.cpp for the
         * detection logic.
         */
        static bool hasSha();

        /**
         * Runs the compression function over one 64-byte block via the SHA extensions, updating
         * state in place.
         */
#if defined(__GNUC__) && !defined(_MSC_VER)
        __attribute__((target("sha,sse4.1")))
#endif
        static void transformAccelerated(uint32_t state[8], const uint8_t block[64]);
#endif

        /**
         * Runs the compression function over one 64-byte block, updating state in place (the
         * portable fallback).
         */
        static void transformPortable(uint32_t state[8], const uint8_t block[64]);

    public:
        /**
         * Runs the compression function over one 64-byte block, updating state in place --
         * dispatches to the SHA extensions when the build supports them and this CPU actually
         * has them, otherwise the portable loop.
         * @param state The 8-word running hash state, updated in place.
         * @param block The 64-byte input block to compress.
         */
        static inline void transform(uint32_t state[8], const uint8_t block[64]) {
#if !defined(CERTPP_DISABLE_HWACCEL_SHA) && (defined(_M_X64) || defined(__x86_64__))
            if (hasSha()) {
                transformAccelerated(state, block);
                return;
            }
#endif
            transformPortable(state, block);
        }
    };

} // namespace crypto
} // namespace certpp

#endif
