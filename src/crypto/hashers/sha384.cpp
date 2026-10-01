#include <certpp/crypto/hashers/sha384.hpp>
#include "sha2_64core.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    /* Resets the SHA-384 context to its initial state. */
    void SHA384::reset() {
        _ctx.state[0] = 0xcbbb9d5dc1059ed8ull;
        _ctx.state[1] = 0x629a292a367cd507ull;
        _ctx.state[2] = 0x9159015a3070dd17ull;
        _ctx.state[3] = 0x152fecd8f70e5939ull;
        _ctx.state[4] = 0x67332667ffc00b31ull;
        _ctx.state[5] = 0x8eb44a8768581511ull;
        _ctx.state[6] = 0xdb0c2e0d64f98fa7ull;
        _ctx.state[7] = 0x47b5481dbefa4fa4ull;

        _ctx.bufferLen = 0;
        _ctx.totalLen = 0;
    }

    /* Pushes data into the SHA-384 context for hashing. */
    size_t SHA384::push(const SReadOnlyByteSpan& buf) {
        if (buf.empty()) {
            return 0;
        }

        const uint8_t* data = buf.data;
        size_t remaining = buf.size;
        _ctx.totalLen += remaining;

        if (_ctx.bufferLen > 0) {
            size_t need = 128 - _ctx.bufferLen;
            size_t take = remaining < need ? remaining : need;

            std::memcpy(_ctx.buffer + _ctx.bufferLen, data, take);
            _ctx.bufferLen += take;
            data += take;
            remaining -= take;

            if (_ctx.bufferLen == 128) {
                Sha2_64Core::transform(_ctx.state, _ctx.buffer);
                _ctx.bufferLen = 0;
            }
        }

        while (remaining >= 128) {
            Sha2_64Core::transform(_ctx.state, data);
            data += 128;
            remaining -= 128;
        }

        if (remaining > 0) {
            std::memcpy(_ctx.buffer, data, remaining);
            _ctx.bufferLen = remaining;
        }

        return buf.size;
    }

    /* Finalizes the SHA-384 hash computation and writes the result to the output buffer. */
    bool SHA384::finish(SByteSpan& out) {
        if (out.size < byteWidth()) {
            return false;
        }

        // --> Finalize a local copy, so finish() can be called more than once without
        // corrupting the live context.
        SHA384 temp;
        temp._ctx = _ctx;

        uint8_t pad[128] = { 0x80 };
        size_t padLen = (temp._ctx.bufferLen < 112) ? (112 - temp._ctx.bufferLen) : (240 - temp._ctx.bufferLen);

        // --> The message-length field is 128 bits; the high 64 bits are always zero for any
        // realistic input (would require 2^64 bytes of input to matter).
        uint64_t bitLen = temp._ctx.totalLen * 8;
        uint8_t lengthField[16] = { 0 };
        for (size_t i = 0; i < 8; ++i) {
            lengthField[8 + i] = uint8_t(bitLen >> (8 * (7 - i)));
        }

        temp.push(SReadOnlyByteSpan(pad, padLen));
        temp.push(SReadOnlyByteSpan(lengthField, sizeof(lengthField)));

        // --> SHA-384 truncates SHA-512's 8-word state to its first 6 words (48 bytes).
        for (size_t i = 0; i < 6; ++i) {
            // --> Each 64-bit word is output big-endian, matching the input packing.
            for (size_t j = 0; j < 8; ++j) {
                out.data[i * 8 + j] = uint8_t(temp._ctx.state[i] >> (8 * (7 - j)));
            }
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
