#ifndef __SRC_CRYPTO_HASHERS_SHA2_64CORE_HPP__
#define __SRC_CRYPTO_HASHERS_SHA2_64CORE_HPP__

#include <certpp/common.hpp>
#include <cstring>

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

        /* Reads one 64-bit big-endian word.
         *
         * SHA-384/SHA-512 take their message words MSB-first, and both x86-64 and AArch64 have a
         * single instruction for that conversion -- BSWAP, REV -- which the builtins below name.
         * The loop is the fallback for a compiler with neither.
         *
         * This replaced a byte-at-a-time loop that cost 8.7% of the whole compression function,
         * measured. The packing is only 5% of it, so this is the small part made perfect rather
         * than the bottleneck addressed; the bottleneck is the rounds, which are serial. */
        static inline uint64_t loadBe64(const uint8_t* src) {
            uint64_t value = 0;
            std::memcpy(&value, src, sizeof(value));

#if defined(__GNUC__) || defined(__clang__)
            return __builtin_bswap64(value);
#elif defined(_MSC_VER)
            return _byteswap_uint64(value);
#else
            // A compiler with neither builtin still has to produce a correct answer. This is the
            // loop the two builtins replace, kept for exactly this case and nowhere else -- an
            // earlier version of this called __builtin_bswap64() again here, which would not have
            // compiled on the compilers it was meant to cover.
            for (size_t i = sizeof(value); i-- > 0;) {
                value = (value << 8) | src[i];
            }
            return value;
#endif
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
