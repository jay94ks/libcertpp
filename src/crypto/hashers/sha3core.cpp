#include "sha3core.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    /* Returns 200 - 2*digestWidth, SHA-3's rate for that output length. */
    size_t Sha3Core::rateFor(size_t digestWidth) {
        return KeccakCore::STATE_BYTES - 2 * digestWidth;
    }

    /* Absorbs input a rate block at a time. */
    size_t Sha3Core::absorb(
        uint8_t* state, uint8_t* buffer, size_t& bufferLen, size_t rate,
        const SReadOnlyByteSpan& buf
    ) {
        if (buf.empty()) {
            return 0;
        }

        size_t consumed = 0;

        // Top up a partial block first, if one is buffered.
        if (bufferLen > 0) {
            const size_t need = rate - bufferLen;
            const size_t take = need < buf.size ? need : buf.size;

            std::memcpy(buffer + bufferLen, buf.data, take);
            bufferLen += take;
            consumed += take;

            if (bufferLen == rate) {
                KeccakCore::absorbBlock(state, buffer, rate);
                bufferLen = 0;
            }
        }

        // Absorb further whole blocks straight from the caller's buffer.
        while (buf.size - consumed >= rate) {
            KeccakCore::absorbBlock(state, buf.data + consumed, rate);
            consumed += rate;
        }

        // Buffer the remainder, which is now less than one block.
        const size_t remaining = buf.size - consumed;
        if (remaining > 0) {
            std::memcpy(buffer + bufferLen, buf.data + consumed, remaining);
            bufferLen += remaining;
            consumed += remaining;
        }

        return consumed;
    }

    /* Pads and squeezes, leaving the caller's state and buffer untouched. */
    void Sha3Core::digest(
        const uint8_t* state, const uint8_t* buffer, size_t bufferLen, size_t rate,
        uint8_t* out, size_t digestWidth
    ) {
        // --> Everything below runs on a snapshot, which is what makes this a query: the caller's
        // sponge is never advanced, so the digest can be taken twice and absorption can continue
        // afterwards. The SHA-2 hashers finalize a temporary context for exactly this reason.
        uint8_t snapshot[KeccakCore::STATE_BYTES];
        std::memcpy(snapshot, state, sizeof(snapshot));

        // --> SHA-3's domain-separated multi-rate padding: 0x06 (where SHAKE uses 0x1F), zero
        // fill, then 0x80 into the block's last byte -- merged into a single byte when the
        // buffered content leaves exactly one free. That 0x06-versus-0x1F byte is the only thing
        // separating a SHA-3 digest from a SHAKE output of the same length, so it is the single
        // byte here most worth getting right.
        uint8_t block[MAX_RATE] = { 0 };
        std::memcpy(block, buffer, bufferLen);
        block[bufferLen] = uint8_t(block[bufferLen] ^ 0x06u);
        block[rate - 1] = uint8_t(block[rate - 1] ^ 0x80u);

        KeccakCore::absorbBlock(snapshot, block, rate);

        // No SHA-3 digest is wider than its own rate, so a single copy suffices -- there is never
        // a second squeeze block to permute for.
        std::memcpy(out, snapshot, digestWidth);
    }

} // namespace crypto
} // namespace certpp
