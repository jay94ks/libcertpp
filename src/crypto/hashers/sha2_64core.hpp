#ifndef __SRC_CRYPTO_HASHERS_SHA2_64CORE_HPP__
#define __SRC_CRYPTO_HASHERS_SHA2_64CORE_HPP__

#include <certpp/common.hpp>

namespace certpp {
namespace crypto {

    /**
     * Runs the SHA-384/SHA-512 compression function (FIPS 180-4) over one 128-byte block,
     * updating the 8-word (64-bit) state in place. SHA-384 and SHA-512 are identical except for
     * their initial hash values and truncated output length, so this is the one piece actually
     * shared between them; each still owns its own context/padding/output-length handling.
     */
    class Sha2_64Core {
    private:
        static inline uint64_t rotr(uint64_t value, uint64_t count) {
            return (value >> count) | (value << (64 - count));
        }

    public:
        /**
         * @param state The 8-word running hash state, updated in place.
         * @param block The 128-byte input block to compress.
         */
        static void transform(uint64_t state[8], const uint8_t block[128]);
    };

} // namespace crypto
} // namespace certpp

#endif
