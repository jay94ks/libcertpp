#ifndef __INCLUDE_CERTPP_CRYPTO_HASHERS_SHA384_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HASHERS_SHA384_HPP__

#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * SHA-384 cryptographic hash function (FIPS 180-4). Identical to SHA-512 except for its
     * initial hash values and its truncated (48-byte) output.
     */
    class CERTPP_API SHA384 : public IHasher {
    private:
        /**
         * Internal state for SHA-384 computation.
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
         * Constructs a SHA-384 hasher, ready to accept input.
         */
        SHA384() : IHasher(48) {
            reset();
        }

        /**
         * Resets the SHA-384 context to its initial state.
         */
        void reset() override;

        /**
         * Pushes data into the SHA-384 context for hashing.
         * @param buf The input data to be hashed.
         * @return The number of bytes processed.
         */
        size_t push(const SReadOnlyByteSpan& buf) override;

        /**
         * Finalizes the SHA-384 hash computation and writes the result to the output buffer.
         * @param out The output buffer to store the hash result (at least byteWidth() bytes).
         * @return True if the hash was successfully finalized, false otherwise.
         */
        bool finish(SByteSpan& out) override;
    };

} // namespace crypto
} // namespace certpp

#endif
