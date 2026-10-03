#ifndef __INCLUDE_CERTPP_CRYPTO_HASHERS_STREEBOG512_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HASHERS_STREEBOG512_HPP__

#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * GOST R 34.11-2012 ("Streebog") with a 512-bit hash code (RFC 6986), the hash GOST R
     * 34.10-2012 pairs with its 512-bit parameter sets.
     *
     * The digest is emitted with RFC 6986's byte position 0 first -- the order every
     * published Streebog digest uses, which is the reverse of the order the RFC prints the
     * same vector in. See src/crypto/hashers/streebogcore.hpp for why.
     */
    class CERTPP_API Streebog512 : public IHasher {
    private:
        /**
         * Internal state for a Streebog computation.
         */
        struct Context {
            uint8_t h[64];        // --> The running hash state.
            uint8_t n[64];        // --> N, the number of message bits compressed so far.
            uint8_t sigma[64];    // --> EPSILON, the sum mod 2^512 of every compressed block.
            uint8_t buffer[64];   // --> Unprocessed input, buffered until a full block is available.
            size_t bufferLen;     // --> Number of valid bytes currently in buffer (0-63).
        };

    private:
        Context _ctx;

    public:
        /**
         * Constructs a Streebog-512 hasher, ready to accept input.
         */
        Streebog512() : IHasher(64) {
            reset();
        }

        /**
         * Resets the context to its initial state (IV = 0^512).
         */
        void reset() override;

        /**
         * Pushes data into the context for hashing.
         * @param buf The input data to be hashed.
         * @return The number of bytes processed.
         */
        size_t push(const SReadOnlyByteSpan& buf) override;

        /**
         * Finalizes the hash computation and writes the result to the output buffer.
         * @param out The output buffer to store the hash result (at least byteWidth() bytes).
         * @return True if the hash was successfully finalized, false otherwise.
         */
        bool finish(const SByteSpan& out) override;
    };

} // namespace crypto
} // namespace certpp

#endif
