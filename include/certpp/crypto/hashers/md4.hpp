#ifndef __INCLUDE_CERTPP_CRYPTO_HASHERS_MD4_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HASHERS_MD4_HPP__

#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * MD4 cryptographic hash function (RFC 1320). Cryptographically broken -- only useful for
     * interoperating with legacy protocols that still reference it, never for new signatures.
     *
     * It is weaker than MD5, not merely as weak: collisions are findable by hand in well under a
     * second, and MD4 is even non-collision-resistant against the far cheaper attacks MD5 resists.
     * The one reason it is here is that NTLM/EAP-MSCHAPv2 define the NT hash as MD4 of the
     * UTF-16LE password, so a client that must speak those protocols has no alternative.
     */
    class CERTPP_API MD4 : public IHasher {
    private:
        /**
         * Internal state for MD4 computation.
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
         * Runs the MD4 compression function over one 64-byte block, updating state in place.
         */
        static void transform(uint32_t state[4], const uint8_t block[64]);

    public:
        /**
         * Constructs an MD4 hasher, ready to accept input.
         */
        MD4() : IHasher(16) {
            reset();
        }

        /**
         * Resets the MD4 context to its initial state.
         */
        void reset() override;

        /**
         * Pushes data into the MD4 context for hashing.
         * @param buf The input data to be hashed.
         * @return The number of bytes processed.
         */
        size_t push(const SReadOnlyByteSpan& buf) override;

        /**
         * Finalizes the MD4 hash computation and writes the result to the output buffer.
         * @param out The output buffer to store the hash result (at least byteWidth() bytes).
         * @return True if the hash was successfully finalized, false otherwise.
         */
        bool finish(const SByteSpan& out) override;
    };

} // namespace crypto
} // namespace certpp

#endif
