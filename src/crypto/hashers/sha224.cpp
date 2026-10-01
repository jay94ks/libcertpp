#include <certpp/crypto/hashers/sha224.hpp>
#include "sha2_32core.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    /* Resets the SHA-224 context to its initial state (FIPS 180-4 5.3.2 -- distinct from
     * SHA-256's own initial state, despite sharing the same compression function). */
    void SHA224::reset() {
        _ctx.state[0] = 0xc1059ed8;
        _ctx.state[1] = 0x367cd507;
        _ctx.state[2] = 0x3070dd17;
        _ctx.state[3] = 0xf70e5939;
        _ctx.state[4] = 0xffc00b31;
        _ctx.state[5] = 0x68581511;
        _ctx.state[6] = 0x64f98fa7;
        _ctx.state[7] = 0xbefa4fa4;

        _ctx.bufferLen = 0;
        _ctx.totalLen = 0;
    }

    /* Pushes data into the SHA-224 context for hashing. */
    size_t SHA224::push(const SReadOnlyByteSpan& buf) {
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

    /* Finalizes the SHA-224 hash computation and writes the result to the output buffer. */
    bool SHA224::finish(SByteSpan& out) {
        if (out.size < byteWidth()) {
            return false;
        }

        // --> Finalize a local copy, so finish() can be called more than once without
        // corrupting the live context.
        SHA224 temp;
        temp._ctx = _ctx;

        uint8_t pad[64] = { 0x80 };
        size_t padLen = (temp._ctx.bufferLen < 56) ? (56 - temp._ctx.bufferLen) : (120 - temp._ctx.bufferLen);

        uint64_t bitLen = temp._ctx.totalLen * 8;
        uint8_t lengthField[8];
        for (size_t i = 0; i < 8; ++i) {
            // --> SHA-224 appends the bit length big-endian.
            lengthField[i] = uint8_t(bitLen >> (8 * (7 - i)));
        }

        temp.push(SReadOnlyByteSpan(pad, padLen));
        temp.push(SReadOnlyByteSpan(lengthField, sizeof(lengthField)));

        // --> SHA-224 truncates SHA-256's 8-word state to its first 7 words (28 bytes).
        for (size_t i = 0; i < 7; ++i) {
            // --> Each 32-bit word is output big-endian, matching the input packing.
            out.data[i * 4 + 0] = uint8_t(temp._ctx.state[i] >> 24);
            out.data[i * 4 + 1] = uint8_t(temp._ctx.state[i] >> 16);
            out.data[i * 4 + 2] = uint8_t(temp._ctx.state[i] >> 8);
            out.data[i * 4 + 3] = uint8_t(temp._ctx.state[i]);
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
