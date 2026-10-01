#ifndef __INCLUDE_CERTPP_CRYPTO_HASHERS_MD5_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HASHERS_MD5_HPP__

#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * MD5 cryptographic hash function (RFC 1321). Cryptographically broken -- only useful for
     * interoperating with legacy certificates/fingerprints that still reference it, never for
     * new signatures.
     */
    class CERTPP_API MD5 : public IHasher {
    private:
        /**
         * Internal state for MD5 computation.
         */
        struct Context {
            uint32_t state[4];     // --> A, B, C, D.
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

        /**
         * Runs the MD5 compression function over one 64-byte block, updating state in place.
         */
        static void transform(uint32_t state[4], const uint8_t block[64]);

    public:
        /**
         * Constructs an MD5 hasher, ready to accept input.
         */
        MD5() : IHasher(16) {
            reset();
        }

        /**
         * Resets the MD5 context to its initial state.
         */
        void reset() override;

        /**
         * Pushes data into the MD5 context for hashing.
         * @param buf The input data to be hashed.
         * @return The number of bytes processed.
         */
        size_t push(const SReadOnlyByteSpan& buf) override;

        /**
         * Finalizes the MD5 hash computation and writes the result to the output buffer.
         * @param out The output buffer to store the hash result (at least byteWidth() bytes).
         * @return True if the hash was successfully finalized, false otherwise.
         */
        bool finish(SByteSpan& out) override;
    };

} // namespace crypto
} // namespace certpp

#endif
