#include <certpp/crypto/hashers/md5.hpp>
#include <cstring>

namespace certpp {
namespace crypto {

    /* Runs the MD5 compression function over one 64-byte block, updating state in place. */
    void MD5::transform(uint32_t state[4], const uint8_t block[64]) {
        /* Per-round left-rotate amounts, 4 groups of 4, repeated across the 4 rounds of 16 steps each. */
        static constexpr uint32_t SHIFTS[64] = {
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
        };

        /* Round constants: floor(abs(sin(i + 1)) * 2^32), for i in [0, 64). */
        static constexpr uint32_t K[64] = {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
        };

        uint32_t m[16];
        for (size_t i = 0; i < 16; ++i) {
            // --> MD5 packs message words little-endian, unlike the SHA family.
            m[i] = uint32_t(block[i * 4])
                | (uint32_t(block[i * 4 + 1]) << 8)
                | (uint32_t(block[i * 4 + 2]) << 16)
                | (uint32_t(block[i * 4 + 3]) << 24);
        }

        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

        for (uint32_t i = 0; i < 64; ++i) {
            uint32_t f;
            uint32_t g;

            if (i < 16) {
                f = (b & c) | (~b & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | (~d & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | ~d);
                g = (7 * i) % 16;
            }

            f = f + a + K[i] + m[g];
            a = d;
            d = c;
            c = b;
            b = b + rotl(f, SHIFTS[i]);
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    }

    /* Resets the MD5 context to its initial state. */
    void MD5::reset() {
        _ctx.state[0] = 0x67452301;
        _ctx.state[1] = 0xefcdab89;
        _ctx.state[2] = 0x98badcfe;
        _ctx.state[3] = 0x10325476;

        _ctx.bufferLen = 0;
        _ctx.totalLen = 0;
    }

    /* Pushes data into the MD5 context for hashing. */
    size_t MD5::push(const SReadOnlyByteSpan& buf) {
        if (buf.empty()) {
            return 0;
        }

        const uint8_t* data = buf.data;
        size_t remaining = buf.size;
        _ctx.totalLen += remaining;

        // --> Top up a partial block from a previous push() before consuming any full blocks.
        if (_ctx.bufferLen > 0) {
            size_t need = 64 - _ctx.bufferLen;
            size_t take = remaining < need ? remaining : need;

            std::memcpy(_ctx.buffer + _ctx.bufferLen, data, take);
            _ctx.bufferLen += take;
            data += take;
            remaining -= take;

            if (_ctx.bufferLen == 64) {
                transform(_ctx.state, _ctx.buffer);
                _ctx.bufferLen = 0;
            }
        }

        // --> Consume full blocks directly from the caller's buffer.
        while (remaining >= 64) {
            transform(_ctx.state, data);
            data += 64;
            remaining -= 64;
        }

        // --> Buffer whatever's left (less than one block).
        if (remaining > 0) {
            std::memcpy(_ctx.buffer, data, remaining);
            _ctx.bufferLen = remaining;
        }

        return buf.size;
    }

    /* Finalizes the MD5 hash computation and writes the result to the output buffer. */
    bool MD5::finish(const SByteSpan& out) {
        if (out.size < byteWidth()) {
            return false;
        }

        // --> Finalize a local copy, so finish() can be called more than once without
        // corrupting the live context.
        MD5 temp;
        temp._ctx = _ctx;

        uint8_t pad[64] = { 0x80 };
        size_t padLen = (temp._ctx.bufferLen < 56) ? (56 - temp._ctx.bufferLen) : (120 - temp._ctx.bufferLen);

        uint64_t bitLen = temp._ctx.totalLen * 8;
        uint8_t lengthField[8];
        for (size_t i = 0; i < 8; ++i) {
            // --> MD5 appends the bit length little-endian, unlike the SHA family.
            lengthField[i] = uint8_t(bitLen >> (8 * i));
        }

        // --> Reuses push() on the local copy to run the padding/length field through the same
        // buffering logic (and thus the same transform() calls) as ordinary input.
        temp.push(SReadOnlyByteSpan(pad, padLen));
        temp.push(SReadOnlyByteSpan(lengthField, sizeof(lengthField)));

        for (size_t i = 0; i < 4; ++i) {
            // --> MD5 outputs each 32-bit word little-endian, matching its input packing.
            out.data[i * 4 + 0] = uint8_t(temp._ctx.state[i]);
            out.data[i * 4 + 1] = uint8_t(temp._ctx.state[i] >> 8);
            out.data[i * 4 + 2] = uint8_t(temp._ctx.state[i] >> 16);
            out.data[i * 4 + 3] = uint8_t(temp._ctx.state[i] >> 24);
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
