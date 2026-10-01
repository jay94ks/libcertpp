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

    bool SHAKE256::finish(SByteSpan& out) {
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

        while (produced < needed) {
            size_t chunk = needed - produced;
            if (chunk > RATE) {
                chunk = RATE;
            }

            std::memcpy(out.data + produced, _ctx.state, chunk);
            produced += chunk;

            if (produced < needed) {
                KeccakCore::permute(_ctx.state);
            }
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
