#ifndef __INCLUDE_CERTPP_CRYPTO_HASHERS_SHAKE256_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HASHERS_SHAKE256_HPP__

#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * SHAKE256, the 256-bit-security extendable-output function from the Keccak/SHA-3 family
     * (FIPS 202). Unlike this library's other IHasher implementations, SHAKE is a genuine XOF:
     * its output length isn't fixed by the algorithm, so it's fixed by the constructor argument
     * instead (matching IHasher::byteWidth()'s existing "one fixed size per instance" contract).
     * Needed by Ed448 (RFC 8032), which uses SHAKE256(x, 114) everywhere Ed25519 uses SHA-512.
     */
    class CERTPP_API SHAKE256 : public IHasher {
    private:
        /**
         * Internal state for SHAKE256 computation.
         */
        struct Context {
            uint8_t state[200];  // --> The 1600-bit Keccak sponge state, byte-oriented.
            uint8_t buffer[136]; // --> Unabsorbed input, buffered until a full rate-sized block is available.
            size_t bufferLen;    // --> Number of valid bytes currently in buffer (0-135).
            bool squeezing;      // --> True once finish()'s padding/permutation has run (push() rejects further input).
        };

    private:
        Context _ctx;

        static constexpr size_t RATE = 136; // 1088 bits -- SHAKE256's rate (capacity = 512 bits)

    public:
        /**
         * Constructs a SHAKE256 hasher, ready to accept input.
         * @param outputBytes The number of output bytes finish() will produce.
         */
        explicit SHAKE256(size_t outputBytes = 32) : IHasher(outputBytes) {
            reset();
        }

        /**
         * Resets the SHAKE256 context to its initial state.
         */
        void reset() override;

        /**
         * Pushes data into the SHAKE256 context for absorption.
         * @param buf The input data to be hashed.
         * @return The number of bytes processed.
         */
        size_t push(const SReadOnlyByteSpan& buf) override;

        /**
         * Finalizes absorption (applying the SHAKE domain-separated padding) and squeezes
         * byteWidth() bytes of output.
         * @param out The output buffer to store the result (at least byteWidth() bytes).
         * @return True if the output was successfully produced, false otherwise.
         */
        bool finish(SByteSpan& out) override;
    };

} // namespace crypto
} // namespace certpp

#endif
