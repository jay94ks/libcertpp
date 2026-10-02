#ifndef __SRC_CRYPTO_HASHERS_SHA3CORE_HPP__
#define __SRC_CRYPTO_HASHERS_SHA3CORE_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include "keccakcore.hpp"

namespace certpp {
namespace crypto {

    /**
     * The sponge buffering, padding and squeezing shared by every fixed-output SHA-3 digest
     * (FIPS 202 6.1) -- private, so no type prefix. Sits on `KeccakCore` exactly as the SHAKE XOFs
     * do, and is shared between SHA3-256 and SHA3-512 the way `Sha2_32Core` is shared between
     * SHA-224 and SHA-256: as free-standing operations over raw arrays, so each public hasher can
     * declare its own context in its own header without depending on anything under `src/`.
     *
     * SHA-3 differs from SHAKE in only two respects: the rate is 200 - 2*digestWidth (the capacity
     * being twice the output length), and the domain-separation byte is 0x06 rather than SHAKE's
     * 0x1F. Everything else -- the permutation, the absorption, the 0x80 multi-rate terminator --
     * is identical, which is why there is no second Keccak implementation here.
     *
     * `digest()` is deliberately a *query*: it pads and squeezes a copy and leaves the caller's
     * state and buffer untouched, so it can be called repeatedly and absorption can continue
     * afterwards. That matches the SHA-2 family's behaviour, which these two are drop-in
     * replacements for, rather than the XOFs' one-way transition into squeezing.
     */
    class Sha3Core {
    public:
        static constexpr size_t MAX_RATE = 144; // --> SHA3-224's rate, the largest SHA-3 uses

        /**
         * Returns the sponge rate for a digest of the given width: 200 - 2*width bytes.
         * @param digestWidth Digest size in bytes.
         * @return The rate in bytes.
         */
        static size_t rateFor(size_t digestWidth);

        /**
         * Absorbs input, buffering whatever does not complete a rate block.
         * @param state The 200-byte sponge state, updated in place.
         * @param buffer Partial-block buffer of at least rate bytes.
         * @param bufferLen Valid bytes in buffer; updated in place.
         * @param rate The sponge rate in bytes.
         * @param buf Input to absorb.
         * @return The number of input bytes consumed.
         */
        static size_t absorb(
            uint8_t* state, uint8_t* buffer, size_t& bufferLen, size_t rate,
            const SReadOnlyByteSpan& buf
        );

        /**
         * Pads and squeezes digestWidth bytes without disturbing state or buffer.
         * @param state The current sponge state.
         * @param buffer The partial-block buffer.
         * @param bufferLen Valid bytes in buffer.
         * @param rate The sponge rate in bytes.
         * @param out Destination for the digest.
         * @param digestWidth Bytes to write; must not exceed rate.
         */
        static void digest(
            const uint8_t* state, const uint8_t* buffer, size_t bufferLen, size_t rate,
            uint8_t* out, size_t digestWidth
        );
    };

} // namespace crypto
} // namespace certpp

#endif
