#ifndef __INCLUDE_CERTPP_CRYPTO_HASHERS_STREEBOG256_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HASHERS_STREEBOG256_HPP__

#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * GOST R 34.11-2012 ("Streebog") with a 256-bit hash code (RFC 6986), the hash GOST R
     * 34.10-2012 pairs with its 256-bit parameter sets.
     *
     * This is *not* a truncation of Streebog-512 applied after the fact: RFC 6986 section 6.1
     * gives the 256-bit function its own initializing value, (00000001)^64 rather than 0^512,
     * so the two produce unrelated states from the very first block. The final MSB_256 cut is
     * only the last step of a differently-seeded computation.
     *
     * The digest is emitted with RFC 6986's byte position 0 first -- the order every published
     * Streebog digest uses, which is the reverse of the order the RFC prints the same vector
     * in, and which puts MSB_256 in the *upper* half of the final state. See
     * src/crypto/hashers/streebogcore.hpp for why.
     */
    class CERTPP_API Streebog256 : public IHasher {
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
         * Constructs a Streebog-256 hasher, ready to accept input.
         */
        Streebog256() : IHasher(32) {
            reset();
        }

        /**
         * Resets the context to its initial state (IV = (00000001)^64).
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
