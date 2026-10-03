#include <certpp/crypto/hashers/md4.hpp>
#include <cstring>

namespace certpp {
namespace crypto {

    /* Runs the MD4 compression function over one 64-byte block, updating state in place. */
    void MD4::transform(uint32_t state[4], const uint8_t block[64]) {
        /* Which message word each of the 48 steps uses. MD4 is the odd one out here: MD5 derives
         * its word index arithmetically ((5i + 1) % 16 and friends), but MD4's rounds 2 and 3 use
         * fixed permutations that no formula produces -- round 2 reads the message in column order
         * (0, 4, 8, 12, 1, ...) and round 3 in the order RFC 1320 3.4 spells out step by step,
         * which is the 4-bit index with its two halves swapped and each half's bits reversed. */
        static constexpr uint32_t ORDER[48] = {
            0, 1, 2, 3,  4, 5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
            0, 4, 8, 12, 1, 5,  9, 13,  2,  6, 10, 14,  3,  7, 11, 15,
            0, 8, 4, 12, 2, 10, 6, 14,  1,  9,  5, 13,  3, 11,  7, 15,
        };

        /* Per-round left-rotate amounts: 3/7/11/19, then 3/5/9/13, then 3/9/11/15, each repeated
         * four times across its round of 16 steps. */
        static constexpr uint32_t SHIFTS[48] = {
            3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19,
            3, 5,  9, 13, 3, 5,  9, 13, 3, 5,  9, 13, 3, 5,  9, 13,
            3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15,
        };

        uint32_t m[16];
        for (size_t i = 0; i < 16; ++i) {
            // --> MD4 packs message words little-endian, as MD5 does and unlike the SHA family.
            m[i] = uint32_t(block[i * 4])
                | (uint32_t(block[i * 4 + 1]) << 8)
                | (uint32_t(block[i * 4 + 2]) << 16)
                | (uint32_t(block[i * 4 + 3]) << 24);
        }

        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

        // --> Three rounds of 16 steps, not MD5's four; the round constant is added from round 2
        // onwards only, where MD5 has a distinct constant per step.
        for (uint32_t i = 0; i < 48; ++i) {
            uint32_t f;
            uint32_t k;

            if (i < 16) {
                f = (b & c) | (~b & d);                 // F, selection -- same as MD5's round 1
                k = 0;
            } else if (i < 32) {
                f = (b & c) | (b & d) | (c & d);        // G, majority -- MD5 uses a selection here
                k = 0x5a827999;                         // floor(sqrt(2) * 2^30)
            } else {
                f = b ^ c ^ d;                          // H, parity
                k = 0x6ed9eba1;                         // floor(sqrt(3) * 2^30)
            }

            // --> MD4 rotates the *result* into place rather than adding it to b as MD5 does:
            // the new value replaces a, and the registers then shift round by one.
            const uint32_t t = rotl(a + f + m[ORDER[i]] + k, SHIFTS[i]);
            a = d;
            d = c;
            c = b;
            b = t;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    }

    /* Resets the MD4 context to its initial state. */
    void MD4::reset() {
        _ctx.state[0] = 0x67452301;
        _ctx.state[1] = 0xefcdab89;
        _ctx.state[2] = 0x98badcfe;
        _ctx.state[3] = 0x10325476;

        _ctx.bufferLen = 0;
        _ctx.totalLen = 0;
    }

    /* Pushes data into the MD4 context for hashing. */
    size_t MD4::push(const SReadOnlyByteSpan& buf) {
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

    /* Finalizes the MD4 hash computation and writes the result to the output buffer. */
    bool MD4::finish(const SByteSpan& out) {
        if (out.size < byteWidth()) {
            return false;
        }

        // --> Finalize a local copy, so finish() can be called more than once without
        // corrupting the live context.
        MD4 temp;
        temp._ctx = _ctx;

        uint8_t pad[64] = { 0x80 };
        size_t padLen = (temp._ctx.bufferLen < 56) ? (56 - temp._ctx.bufferLen) : (120 - temp._ctx.bufferLen);

        uint64_t bitLen = temp._ctx.totalLen * 8;
        uint8_t lengthField[8];
        for (size_t i = 0; i < 8; ++i) {
            // --> MD4 appends the bit length little-endian, unlike the SHA family.
            lengthField[i] = uint8_t(bitLen >> (8 * i));
        }

        // --> Reuses push() on the local copy to run the padding/length field through the same
        // buffering logic (and thus the same transform() calls) as ordinary input.
        temp.push(SReadOnlyByteSpan(pad, padLen));
        temp.push(SReadOnlyByteSpan(lengthField, sizeof(lengthField)));

        for (size_t i = 0; i < 4; ++i) {
            // --> MD4 outputs each 32-bit word little-endian, matching its input packing.
            out.data[i * 4 + 0] = uint8_t(temp._ctx.state[i]);
            out.data[i * 4 + 1] = uint8_t(temp._ctx.state[i] >> 8);
            out.data[i * 4 + 2] = uint8_t(temp._ctx.state[i] >> 16);
            out.data[i * 4 + 3] = uint8_t(temp._ctx.state[i] >> 24);
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
