#include <certpp/crypto/hashers/streebog256.hpp>
#include "streebogcore.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    /* Resets the context to its initial state (IV = (00000001)^64). */
    void Streebog256::reset() {
        // --> RFC 6986 section 6.1: the 256-bit function's IV is (00000001)^64, i.e. every one
        // of the 64 bytes is 0x01 -- not the 512-bit function's 0^512. This is the whole
        // difference between the two digests; getting it wrong produces a self-consistent but
        // wrong 256-bit hash that no other implementation agrees with.
        std::memset(_ctx.h, 0x01, sizeof(_ctx.h));
        std::memset(_ctx.n, 0, sizeof(_ctx.n));
        std::memset(_ctx.sigma, 0, sizeof(_ctx.sigma));

        _ctx.bufferLen = 0;
    }

    /* Pushes data into the context for hashing. */
    size_t Streebog256::push(const SReadOnlyByteSpan& buf) {
        if (buf.empty()) {
            return 0;
        }

        const uint8_t* data = buf.data;
        size_t remaining = buf.size;

        if (_ctx.bufferLen > 0) {
            size_t need = 64 - _ctx.bufferLen;
            size_t take = remaining < need ? remaining : need;

            std::memcpy(_ctx.buffer + _ctx.bufferLen, data, take);
            _ctx.bufferLen += take;
            data += take;
            remaining -= take;

            if (_ctx.bufferLen == 64) {
                StreebogCore::compress(_ctx.h, _ctx.n, _ctx.buffer);
                StreebogCore::addMod512(_ctx.n, uint64_t(512));
                StreebogCore::addMod512(_ctx.sigma, _ctx.buffer);
                _ctx.bufferLen = 0;
            }
        }

        while (remaining >= 64) {
            StreebogCore::compress(_ctx.h, _ctx.n, data);
            StreebogCore::addMod512(_ctx.n, uint64_t(512));
            StreebogCore::addMod512(_ctx.sigma, data);
            data += 64;
            remaining -= 64;
        }

        if (remaining > 0) {
            std::memcpy(_ctx.buffer, data, remaining);
            _ctx.bufferLen = remaining;
        }

        return buf.size;
    }

    /* Finalizes the hash computation and writes the result to the output buffer. */
    bool Streebog256::finish(const SByteSpan& out) {
        if (out.size < byteWidth()) {
            return false;
        }

        // --> Finalize a local copy, so finish() can be called more than once without
        // corrupting the live context.
        Context ctx = _ctx;

        // --> RFC 6986 step 3.1: m := 0^(511-|M|) || 1 || M. With byte position 0 first and a
        // whole number of input bytes, that is the buffered tail, then a single 0x01, then
        // zeros. Note this runs even when the message length is an exact multiple of 64
        // bytes: step 2.1's loop stops once |M| < 512, which includes |M| == 0, so a padded
        // (here entirely empty) block is always compressed last.
        uint8_t block[64];
        std::memset(block, 0, sizeof(block));
        std::memcpy(block, ctx.buffer, ctx.bufferLen);
        block[ctx.bufferLen] = 0x01;

        StreebogCore::compress(ctx.h, ctx.n, block);
        StreebogCore::addMod512(ctx.n, uint64_t(ctx.bufferLen) * 8);
        StreebogCore::addMod512(ctx.sigma, block);

        // --> Steps 3.5/3.6: two more rounds against N = 0, over N and then EPSILON.
        uint8_t zero[64];
        std::memset(zero, 0, sizeof(zero));

        StreebogCore::compress(ctx.h, zero, ctx.n);
        StreebogCore::compress(ctx.h, zero, ctx.sigma);

        // --> MSB_256 of the final state. With byte position 0 first, the most significant
        // half is the *upper* 32 bytes, not the leading ones.
        std::memcpy(out.data, ctx.h + 32, 32);
        return true;
    }

} // namespace crypto
} // namespace certpp
