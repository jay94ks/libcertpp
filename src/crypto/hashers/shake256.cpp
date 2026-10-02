#include <certpp/crypto/hashers/shake256.hpp>
#include "keccakcore.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    void SHAKE256::reset() {
        std::memset(_ctx.state, 0, sizeof(_ctx.state));
        std::memset(_ctx.buffer, 0, sizeof(_ctx.buffer));
        _ctx.bufferLen = 0;
        _ctx.squeezing = false;
        _ctx.squeezePos = 0;
    }

    size_t SHAKE256::push(const SReadOnlyByteSpan& buf) {
        if (_ctx.squeezing || buf.empty()) {
            return 0;
        }

        size_t total = buf.size;
        size_t consumed = 0;

        // Top up a partial buffered block first, if there is one.
        if (_ctx.bufferLen > 0) {
            size_t need = RATE - _ctx.bufferLen;
            size_t take = need < total ? need : total;

            std::memcpy(_ctx.buffer + _ctx.bufferLen, buf.data, take);
            _ctx.bufferLen += take;
            consumed += take;

            if (_ctx.bufferLen == RATE) {
                KeccakCore::absorbBlock(_ctx.state, _ctx.buffer, RATE);
                _ctx.bufferLen = 0;
            }
        }

        // Absorb any further full blocks directly from the caller's buffer.
        while (total - consumed >= RATE) {
            KeccakCore::absorbBlock(_ctx.state, buf.data + consumed, RATE);
            consumed += RATE;
        }

        // Buffer whatever's left (less than one full block).
        size_t remaining = total - consumed;
        if (remaining > 0) {
            std::memcpy(_ctx.buffer + _ctx.bufferLen, buf.data + consumed, remaining);
            _ctx.bufferLen += remaining;
            consumed += remaining;
        }

        return consumed;
    }

    /* Applies SHAKE's domain-separated multi-rate padding and absorbs the final block, switching
     * the sponge from absorbing to squeezing. Idempotent: both finish() and squeeze() call it, and
     * whichever runs first does the work. */
    void SHAKE256::finalizeAbsorption() {
        if (_ctx.squeezing) {
            return;
        }

        // Append 0x1F, zero-fill, then OR 0x80 into the last byte of the rate-sized block --
        // merged into one byte if the buffered content leaves exactly one byte free.
        uint8_t block[RATE] = { 0 };
        std::memcpy(block, _ctx.buffer, _ctx.bufferLen);
        block[_ctx.bufferLen] ^= 0x1F;
        block[RATE - 1] ^= 0x80;

        KeccakCore::absorbBlock(_ctx.state, block, RATE);
        _ctx.squeezing = true;
        _ctx.bufferLen = 0;
        _ctx.squeezePos = 0;
    }

    bool SHAKE256::finish(SByteSpan& out) {
        if (out.size < byteWidth()) {
            return false;
        }

        finalizeAbsorption();

        size_t produced = 0;
        size_t needed = byteWidth();

        // --> Squeeze from a copy, never the live state: every other hasher here finalizes a
        // temporary so finish() can be called twice and hand back the same bytes, and any output
        // longer than one rate block permutes the state between blocks. Squeezing in place would
        // leave the state advanced, so a second finish() -- which skips the already-applied
        // padding -- would return the *continuation* of the output stream rather than repeating
        // it. At or below RATE no permutation runs, which is why the shipped output lengths
        // (32/64, and Ed448's 114) never exposed this.
        uint8_t state[KeccakCore::STATE_BYTES];
        std::memcpy(state, _ctx.state, sizeof(state));

        while (produced < needed) {
            size_t chunk = needed - produced;
            if (chunk > RATE) {
                chunk = RATE;
            }

            std::memcpy(out.data + produced, state, chunk);
            produced += chunk;

            if (produced < needed) {
                KeccakCore::permute(state);
            }
        }

        return true;
    }

    /* Squeezes the next out.size bytes of the output stream, advancing the sponge. */
    bool SHAKE256::squeeze(const SByteSpan& out) {
        // --> Ordered this way on purpose: TSpan::empty() is true for a null pointer *or* a zero
        // size, so testing it first would quietly report success for a caller asking for bytes
        // with nowhere to put them.
        if (out.size == 0) {
            return true; // nothing requested
        }

        if (!out.data) {
            return false; // bytes requested, no buffer to write them to
        }

        finalizeAbsorption();

        size_t produced = 0;
        while (produced < out.size) {
            // --> The first rate block is readable straight out of the state: absorbBlock()
            // already permuted. Only a block boundary *after* that costs another permutation,
            // which is why the cursor is checked before the copy rather than after it.
            if (_ctx.squeezePos == RATE) {
                KeccakCore::permute(_ctx.state);
                _ctx.squeezePos = 0;
            }

            size_t available = RATE - _ctx.squeezePos;
            size_t take = out.size - produced;
            if (take > available) {
                take = available;
            }

            std::memcpy(out.data + produced, _ctx.state + _ctx.squeezePos, take);
            _ctx.squeezePos += take;
            produced += take;
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
