#ifndef __INCLUDE_CERTPP_CRYPTO_HASHERS_SHA224_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HASHERS_SHA224_HPP__

#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * SHA-224 cryptographic hash function (FIPS 180-4) -- SHA-256's compression function with a
     * different initial state, truncated to 28 bytes of output.
     */
    class CERTPP_API SHA224 : public IHasher {
    private:
        /**
         * Internal state for SHA-224 computation.
         */
        struct Context {
            uint32_t state[8];     // --> h0..h7.
            uint8_t buffer[64];    // --> Unprocessed input, buffered until a full block is available.
            size_t bufferLen;      // --> Number of valid bytes currently in buffer (0-63).
            uint64_t totalLen;     // --> Total number of input bytes pushed so far.
        };

    private:
        Context _ctx;

    public:
        /**
         * Constructs a SHA-224 hasher, ready to accept input.
         */
        SHA224() : IHasher(28) {
            reset();
        }

        /**
         * Resets the SHA-224 context to its initial state.
         */
        void reset() override;

        /**
         * Pushes data into the SHA-224 context for hashing.
         * @param buf The input data to be hashed.
         * @return The number of bytes processed.
         */
        size_t push(const SReadOnlyByteSpan& buf) override;

        /**
         * Finalizes the SHA-224 hash computation and writes the result to the output buffer.
         * @param out The output buffer to store the hash result (at least byteWidth() bytes).
         * @return True if the hash was successfully finalized, false otherwise.
         */
        bool finish(const SByteSpan& out) override;
    };

} // namespace crypto
} // namespace certpp

#endif
