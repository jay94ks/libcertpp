#include <certpp/crypto/hashers/shake128.hpp>
#include "keccakcore.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    void SHAKE128::reset() {
        std::memset(_ctx.state, 0, sizeof(_ctx.state));
        std::memset(_ctx.buffer, 0, sizeof(_ctx.buffer));
        _ctx.bufferLen = 0;
        _ctx.squeezing = false;
    }

    size_t SHAKE128::push(const SReadOnlyByteSpan& buf) {
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

    bool SHAKE128::finish(SByteSpan& out) {
        if (out.size < byteWidth()) {
            return false;
        }

        if (!_ctx.squeezing) {
            // SHAKE's domain-separated multi-rate padding: append 0x1F, zero-fill, then OR
            // 0x80 into the last byte of the rate-sized block -- merged into one byte if the
            // buffered content leaves exactly one byte free.
            uint8_t block[RATE] = { 0 };
            std::memcpy(block, _ctx.buffer, _ctx.bufferLen);
            block[_ctx.bufferLen] ^= 0x1F;
            block[RATE - 1] ^= 0x80;

            KeccakCore::absorbBlock(_ctx.state, block, RATE);
            _ctx.squeezing = true;
            _ctx.bufferLen = 0;
        }

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

} // namespace crypto
} // namespace certpp
