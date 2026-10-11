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
         * A compiler with neither gets loadBe64Portable().
         *
         * The builtins are not decoration. GCC 13 turns the portable loop into twenty-two
         * instructions against the builtin's two (`movq`; `bswap`), so this cannot be written
         * once and left to the optimiser. Clang does recognise the loop and compiles either form
         * to three instructions, which is why this is spelled out rather than relying on the
         * portable form everywhere.
         *
         * This replaced a byte-at-a-time loop that cost 8.7% of the whole compression function,
         * measured. The packing is only 5% of it, so this is the small part made perfect rather
         * than the bottleneck addressed; the bottleneck is the rounds, which are serial. */
        static inline uint64_t loadBe64(const uint8_t* src) {
#if defined(__GNUC__) || defined(__clang__)
            uint64_t value;
            std::memcpy(&value, src, sizeof(value));
            return __builtin_bswap64(value);
#elif defined(_MSC_VER)
            uint64_t value;
            std::memcpy(&value, src, sizeof(value));
            return _byteswap_uint64(value);
#else
            return loadBe64Portable(src);
#endif
        }

    public:
        /**
         * Reads one 64-bit big-endian word, assuming no compiler has a byte-swap intrinsic. This
         * is the fallback loadBe64() uses where none is available.
         *
         * It is public, and always compiled, for one reason: as a branch inside an `#if` this
         * code is built by none of the four configurations this library ships, so none of them
         * can test it. Being a function makes it compiled everywhere, which lets
         * tests/crypto/hashers/sha512.cpp hold it against an independently written reference
         * even on a build that never calls it. The branch it replaced was wrong -- it
         * byte-reversed the input instead of assembling it big-endian, on every input tried --
         * and no number of green tests would have said so.
         *
         * @param src Eight readable bytes, most significant first.
         * @return Those eight bytes as a 64-bit value.
         */
        static inline uint64_t loadBe64Portable(const uint8_t* src) {
            uint64_t value = 0;
            for (size_t i = 0; i < sizeof(value); ++i) {
                value = (value << 8) | src[i];
            }
            return value;
        }

        /**
         * @param state The 8-word running hash state, updated in place.
         * @param block The 128-byte input block to compress.
         */
        static void transform(uint64_t state[8], const uint8_t block[128]);
    };

} // namespace crypto
} // namespace certpp

#endif
