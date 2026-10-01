#include <certpp/crypto/hashers/sha256.hpp>
#include "sha2_32core.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    /* Resets the SHA-256 context to its initial state. */
    void SHA256::reset() {
        _ctx.state[0] = 0x6a09e667;
        _ctx.state[1] = 0xbb67ae85;
        _ctx.state[2] = 0x3c6ef372;
        _ctx.state[3] = 0xa54ff53a;
        _ctx.state[4] = 0x510e527f;
        _ctx.state[5] = 0x9b05688c;
        _ctx.state[6] = 0x1f83d9ab;
        _ctx.state[7] = 0x5be0cd19;

        _ctx.bufferLen = 0;
        _ctx.totalLen = 0;
    }

    /* Pushes data into the SHA-256 context for hashing. */
    size_t SHA256::push(const SReadOnlyByteSpan& buf) {
        if (buf.empty()) {
            return 0;
        }

        const uint8_t* data = buf.data;
        size_t remaining = buf.size;
        _ctx.totalLen += remaining;

        if (_ctx.bufferLen > 0) {
            size_t need = 64 - _ctx.bufferLen;
            size_t take = remaining < need ? remaining : need;

            std::memcpy(_ctx.buffer + _ctx.bufferLen, data, take);
            _ctx.bufferLen += take;
            data += take;
            remaining -= take;

            if (_ctx.bufferLen == 64) {
                Sha2_32Core::transform(_ctx.state, _ctx.buffer);
                _ctx.bufferLen = 0;
            }
        }

        while (remaining >= 64) {
            Sha2_32Core::transform(_ctx.state, data);
            data += 64;
            remaining -= 64;
        }

        if (remaining > 0) {
            std::memcpy(_ctx.buffer, data, remaining);
            _ctx.bufferLen = remaining;
        }

        return buf.size;
    }

    /* Finalizes the SHA-256 hash computation and writes the result to the output buffer. */
    bool SHA256::finish(SByteSpan& out) {
        if (out.size < byteWidth()) {
            return false;
        }

        // --> Finalize a local copy, so finish() can be called more than once without
        // corrupting the live context.
        SHA256 temp;
        temp._ctx = _ctx;

        uint8_t pad[64] = { 0x80 };
        size_t padLen = (temp._ctx.bufferLen < 56) ? (56 - temp._ctx.bufferLen) : (120 - temp._ctx.bufferLen);

        uint64_t bitLen = temp._ctx.totalLen * 8;
        uint8_t lengthField[8];
        for (size_t i = 0; i < 8; ++i) {
            // --> SHA-256 appends the bit length big-endian.
            lengthField[i] = uint8_t(bitLen >> (8 * (7 - i)));
        }

        temp.push(SReadOnlyByteSpan(pad, padLen));
        temp.push(SReadOnlyByteSpan(lengthField, sizeof(lengthField)));

        for (size_t i = 0; i < 8; ++i) {
            // --> SHA-256 outputs each 32-bit word big-endian, matching its input packing.
            out.data[i * 4 + 0] = uint8_t(temp._ctx.state[i] >> 24);
            out.data[i * 4 + 1] = uint8_t(temp._ctx.state[i] >> 16);
            out.data[i * 4 + 2] = uint8_t(temp._ctx.state[i] >> 8);
            out.data[i * 4 + 3] = uint8_t(temp._ctx.state[i]);
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
