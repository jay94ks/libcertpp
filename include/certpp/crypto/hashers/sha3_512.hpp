#ifndef __INCLUDE_CERTPP_CRYPTO_HASHERS_SHA3_512_HPP__
#define __INCLUDE_CERTPP_CRYPTO_HASHERS_SHA3_512_HPP__

#include <certpp/crypto/hasher.hpp>

namespace certpp {
namespace crypto {

    /**
     * SHA3-512 (FIPS 202 6.1), the 512-bit fixed-output member of the Keccak/SHA-3 family --
     * from scratch, like every other hasher here.
     *
     * Despite the name it is not a variant of SHA-2: SHA-3 is the same sponge construction as the
     * SHAKE XOFs (absorb into a 1600-bit state through the Keccak-f[1600] permutation, then
     * squeeze), and shares both the permutation and the buffering/padding with them -- see
     * src/crypto/hashers/keccakcore.hpp and sha3core.hpp. It differs from SHAKE in exactly two
     * respects: its rate is 72 bytes (200 - 2*64, the capacity being twice the output
     * length), and its domain-separation byte is 0x06 rather than SHAKE's 0x1F -- so a correct
     * Keccak permutation with the wrong domain byte yields a plausible digest of the right length
     * that matches nothing.
     *
     * Unlike SHAKE, the output length is fixed by the algorithm, so byteWidth() is always 64
     * and the constructor takes no argument. finish() is a query, as in the SHA-2 family: it
     * leaves the sponge untouched, so it may be called repeatedly and push() still works
     * afterwards.
     *
     * Added because ML-KEM needs it as FIPS 203's G function (see docs/pqc-review.md), but it
     * is an ordinary member of the EHashers family (EHASH_SHA3_512) and usable anywhere a hasher
     * is.
     */
    class CERTPP_API SHA3_512 : public IHasher {
    private:
        /**
         * Internal sponge state for SHA3-512.
         */
        struct Context {
            uint8_t state[200];  // --> The 1600-bit Keccak sponge state, byte-oriented.
            uint8_t buffer[72]; // --> Unabsorbed input, below one rate block.
            size_t bufferLen;    // --> Valid bytes currently in buffer (0-71).
        };

    private:
        Context _ctx;

        static constexpr size_t DIGEST_BYTES = 64;
        static constexpr size_t RATE = 72;

    public:
        /**
         * Constructs a SHA3-512 hasher, ready to accept input.
         */
        SHA3_512() : IHasher(DIGEST_BYTES) {
            reset();
        }

        /**
         * Resets the context to its initial state.
         */
        void reset() override;

        /**
         * Pushes data into the context for absorption.
         * @param buf The input data to be hashed.
         * @return The number of bytes processed.
         */
        size_t push(const SReadOnlyByteSpan& buf) override;

        /**
         * Applies SHA-3's domain-separated padding and writes the 64-byte digest. Leaves the
         * sponge unchanged, so it may be called more than once and absorption may continue.
         * @param out The output buffer (at least byteWidth() bytes).
         * @return True if the digest was written, false otherwise.
         */
        bool finish(const SByteSpan& out) override;
    };

} // namespace crypto
} // namespace certpp

#endif
