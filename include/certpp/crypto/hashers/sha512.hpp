#ifndef __INCLUDE_CERTPP_CRYPTO_HASHERS_SHA512_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HASHERS_SHA512_HPP__

#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * SHA-512 cryptographic hash function (FIPS 180-4).
     */
    class CERTPP_API SHA512 : public IHasher {
    private:
        /**
         * Internal state for SHA-512 computation.
         */
        struct Context {
            uint64_t state[8];     // --> h0..h7.
            uint8_t buffer[128];   // --> Unprocessed input, buffered until a full block is available.
            size_t bufferLen;      // --> Number of valid bytes currently in buffer (0-127).
            uint64_t totalLen;     // --> Total number of input bytes pushed so far.
        };

    private:
        Context _ctx;

    public:
        /**
         * Constructs a SHA-512 hasher, ready to accept input.
         */
        SHA512() : IHasher(64) {
            reset();
        }

        /**
         * Resets the SHA-512 context to its initial state.
         */
        void reset() override;

        /**
         * Pushes data into the SHA-512 context for hashing.
         * @param buf The input data to be hashed.
         * @return The number of bytes processed.
         */
        size_t push(const SReadOnlyByteSpan& buf) override;

        /**
         * Finalizes the SHA-512 hash computation and writes the result to the output buffer.
         * @param out The output buffer to store the hash result (at least byteWidth() bytes).
         * @return True if the hash was successfully finalized, false otherwise.
         */
        bool finish(const SByteSpan& out) override;
    };

} // namespace crypto
} // namespace certpp

#endif
