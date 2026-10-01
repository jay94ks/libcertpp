#ifndef __INCLUDE_CERTPP_CRYPTO_HASHERS_SHA1_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HASHERS_SHA1_HPP__

#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * SHA-1 cryptographic hash function (FIPS 180-4). Cryptographically broken -- only useful
     * for interoperating with legacy certificates/fingerprints that still reference it, never
     * for new signatures.
     */
    class CERTPP_API SHA1 : public IHasher {
    private:
        /**
         * Internal state for SHA-1 computation.
         */
        struct Context {
            uint32_t state[5];     // --> h0..h4.
            uint8_t buffer[64];    // --> Unprocessed input, buffered until a full block is available.
            size_t bufferLen;      // --> Number of valid bytes currently in buffer (0-63).
            uint64_t totalLen;     // --> Total number of input bytes pushed so far.
        };

    private:
        Context _ctx;

        /**
         * Rotates value left by count bits (0 < count < 32).
         */
        static inline uint32_t rotl(uint32_t value, uint32_t count) {
            return (value << count) | (value >> (32 - count));
        }

/* Hardware-accelerated compression (Intel SHA Extensions), gated by both the
 * CERTPP_DISABLE_HWACCEL_SHA build option and the target architecture -- see sha1.cpp's own
 * identical guard (which this must match exactly) for the full rationale. */
#if !defined(CERTPP_DISABLE_HWACCEL_SHA) && (defined(_M_X64) || defined(__x86_64__))
        /**
         * Whether this CPU actually has the SHA extensions -- see sha1.cpp for the detection
         * logic.
         */
        static bool hasSha();

        /**
         * Runs the SHA-1 compression function over one 64-byte block via the SHA extensions,
         * updating state in place.
         */
#if defined(__GNUC__) && !defined(_MSC_VER)
        __attribute__((target("sha,sse4.1")))
#endif
        static void transformAccelerated(uint32_t state[5], const uint8_t block[64]);
#endif

        /**
         * Runs the SHA-1 compression function over one 64-byte block, updating state in place
         * (the portable fallback).
         */
        static void transformPortable(uint32_t state[5], const uint8_t block[64]);

        /**
         * Runs the SHA-1 compression function over one 64-byte block, updating state in place --
         * dispatches to the SHA extensions when the build supports them and this CPU actually
         * has them, otherwise the portable loop.
         */
        static inline void transform(uint32_t state[5], const uint8_t block[64]) {
#if !defined(CERTPP_DISABLE_HWACCEL_SHA) && (defined(_M_X64) || defined(__x86_64__))
            if (hasSha()) {
                transformAccelerated(state, block);
                return;
            }
#endif
            transformPortable(state, block);
        }

    public:
        /**
         * Constructs a SHA-1 hasher, ready to accept input.
         */
        SHA1() : IHasher(20) {
            reset();
        }

        /**
         * Resets the SHA-1 context to its initial state.
         */
        void reset() override;

        /**
         * Pushes data into the SHA-1 context for hashing.
         * @param buf The input data to be hashed.
         * @return The number of bytes processed.
         */
        size_t push(const SReadOnlyByteSpan& buf) override;

        /**
         * Finalizes the SHA-1 hash computation and writes the result to the output buffer.
         * @param out The output buffer to store the hash result (at least byteWidth() bytes).
         * @return True if the hash was successfully finalized, false otherwise.
         */
        bool finish(SByteSpan& out) override;
    };

} // namespace crypto
} // namespace certpp

#endif
