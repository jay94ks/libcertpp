#include <certpp/crypto/hashers/md4.hpp>
#include <certpp/arch.hpp>
#include <cstring>

#if defined(CERTPP_ARCH_HAS_AVX512F)
#define CERTPP_MD4_AVX512 1
#include <immintrin.h>
#endif

namespace certpp {
namespace crypto {

    namespace {

#if defined(CERTPP_MD4_AVX512)
        bool hasAvx512Md4() {
            static const bool supported = __builtin_cpu_supports("avx512f")
                && __builtin_cpu_supports("avx512vl");
            return supported;
        }

        inline uint32_t loadLe32(const uint8_t* src) {
            uint32_t value;
            std::memcpy(&value, src, sizeof(value));
            return value;
        }

        /* AVX-512VL supplies the two operations scalar MD4 lacks: VPTERNLOGD evaluates F/G/H in
         * one instruction and VPROLD rotates without a shift/or pair. Only the low 32-bit lane is
         * live; using the narrow VL form avoids touching wide vector state while still reducing
         * the serial dependency chain. */
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("avx512f,avx512vl")))
#endif
        void transformAvx512(uint32_t state[4], const uint8_t block[64]) {
            __m128i a = _mm_cvtsi32_si128(static_cast<int>(state[0]));
            __m128i b = _mm_cvtsi32_si128(static_cast<int>(state[1]));
            __m128i c = _mm_cvtsi32_si128(static_cast<int>(state[2]));
            __m128i d = _mm_cvtsi32_si128(static_cast<int>(state[3]));

#define CERTPP_MD4_STEP(x, y, z, w, index, shift, truth, constant) do { \
            const __m128i booleanValue = _mm_ternarylogic_epi32((y), (z), (w), (truth)); \
            const __m128i messageValue = _mm_cvtsi32_si128(static_cast<int>( \
                loadLe32(block + (index) * 4) + uint32_t(constant))); \
            (x) = _mm_rol_epi32( \
                _mm_add_epi32(_mm_add_epi32((x), booleanValue), messageValue), (shift)); \
        } while (false)
#define CERTPP_MD4_F(x, y, z, w, index, shift) \
        CERTPP_MD4_STEP(x, y, z, w, index, shift, 0xCA, 0u)
#define CERTPP_MD4_G(x, y, z, w, index, shift) \
        CERTPP_MD4_STEP(x, y, z, w, index, shift, 0xE8, 0x5a827999u)
#define CERTPP_MD4_H(x, y, z, w, index, shift) \
        CERTPP_MD4_STEP(x, y, z, w, index, shift, 0x96, 0x6ed9eba1u)

            CERTPP_MD4_F(a, b, c, d,  0,  3); CERTPP_MD4_F(d, a, b, c,  1,  7);
            CERTPP_MD4_F(c, d, a, b,  2, 11); CERTPP_MD4_F(b, c, d, a,  3, 19);
            CERTPP_MD4_F(a, b, c, d,  4,  3); CERTPP_MD4_F(d, a, b, c,  5,  7);
            CERTPP_MD4_F(c, d, a, b,  6, 11); CERTPP_MD4_F(b, c, d, a,  7, 19);
            CERTPP_MD4_F(a, b, c, d,  8,  3); CERTPP_MD4_F(d, a, b, c,  9,  7);
            CERTPP_MD4_F(c, d, a, b, 10, 11); CERTPP_MD4_F(b, c, d, a, 11, 19);
            CERTPP_MD4_F(a, b, c, d, 12,  3); CERTPP_MD4_F(d, a, b, c, 13,  7);
            CERTPP_MD4_F(c, d, a, b, 14, 11); CERTPP_MD4_F(b, c, d, a, 15, 19);

            CERTPP_MD4_G(a, b, c, d,  0,  3); CERTPP_MD4_G(d, a, b, c,  4,  5);
            CERTPP_MD4_G(c, d, a, b,  8,  9); CERTPP_MD4_G(b, c, d, a, 12, 13);
            CERTPP_MD4_G(a, b, c, d,  1,  3); CERTPP_MD4_G(d, a, b, c,  5,  5);
            CERTPP_MD4_G(c, d, a, b,  9,  9); CERTPP_MD4_G(b, c, d, a, 13, 13);
            CERTPP_MD4_G(a, b, c, d,  2,  3); CERTPP_MD4_G(d, a, b, c,  6,  5);
            CERTPP_MD4_G(c, d, a, b, 10,  9); CERTPP_MD4_G(b, c, d, a, 14, 13);
            CERTPP_MD4_G(a, b, c, d,  3,  3); CERTPP_MD4_G(d, a, b, c,  7,  5);
            CERTPP_MD4_G(c, d, a, b, 11,  9); CERTPP_MD4_G(b, c, d, a, 15, 13);

            CERTPP_MD4_H(a, b, c, d,  0,  3); CERTPP_MD4_H(d, a, b, c,  8,  9);
            CERTPP_MD4_H(c, d, a, b,  4, 11); CERTPP_MD4_H(b, c, d, a, 12, 15);
            CERTPP_MD4_H(a, b, c, d,  2,  3); CERTPP_MD4_H(d, a, b, c, 10,  9);
            CERTPP_MD4_H(c, d, a, b,  6, 11); CERTPP_MD4_H(b, c, d, a, 14, 15);
            CERTPP_MD4_H(a, b, c, d,  1,  3); CERTPP_MD4_H(d, a, b, c,  9,  9);
            CERTPP_MD4_H(c, d, a, b,  5, 11); CERTPP_MD4_H(b, c, d, a, 13, 15);
            CERTPP_MD4_H(a, b, c, d,  3,  3); CERTPP_MD4_H(d, a, b, c, 11,  9);
            CERTPP_MD4_H(c, d, a, b,  7, 11); CERTPP_MD4_H(b, c, d, a, 15, 15);

#undef CERTPP_MD4_H
#undef CERTPP_MD4_G
#undef CERTPP_MD4_F
#undef CERTPP_MD4_STEP

            state[0] += static_cast<uint32_t>(_mm_cvtsi128_si32(a));
            state[1] += static_cast<uint32_t>(_mm_cvtsi128_si32(b));
            state[2] += static_cast<uint32_t>(_mm_cvtsi128_si32(c));
            state[3] += static_cast<uint32_t>(_mm_cvtsi128_si32(d));
        }
#endif

    } // namespace

    /* Runs the MD4 compression function over one 64-byte block, updating state in place. */
    void MD4::transform(uint32_t state[4], const uint8_t block[64]) {
#if defined(CERTPP_MD4_AVX512)
        if (hasAvx512Md4()) {
            transformAvx512(state, block);
            return;
        }
#endif
        uint32_t m[16];
#if defined(_WIN32) \
    || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
        /* MD4 words have native byte order on the maintained Windows/Linux targets. memcpy keeps
         * the access unaligned and lets the compiler emit four vector loads; spelling out the
         * shifts made GCC build an expensive byte-unpack network instead. */
        std::memcpy(m, block, sizeof(m));
#else
        for (size_t i = 0; i < 16; ++i) {
            // --> MD4 packs message words little-endian, as MD5 does and unlike the SHA family.
            m[i] = uint32_t(block[i * 4])
                | (uint32_t(block[i * 4 + 1]) << 8)
                | (uint32_t(block[i * 4 + 2]) << 16)
                | (uint32_t(block[i * 4 + 3]) << 24);
        }
#endif

        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

        /* All indices and rotations are constants in RFC 1320. Keeping the old 48-step loop made
         * every step load ORDER/SHIFTS and select one of three Boolean functions at runtime.
         * These small inline steps let the compiler keep a/b/c/d in registers and emit each
         * rotate with an immediate count. The Boolean forms are equivalent but shorter:
         * F(x,y,z) = z ^ (x & (y ^ z)); G is majority. */
        auto stepF = [](uint32_t& x, uint32_t y, uint32_t z, uint32_t w,
                        uint32_t word, uint32_t shift) {
            x = rotl(x + (w ^ (y & (z ^ w))) + word, shift);
        };
        auto stepG = [](uint32_t& x, uint32_t y, uint32_t z, uint32_t w,
                        uint32_t word, uint32_t shift) {
            x = rotl(x + ((y & z) | (w & (y | z))) + word + 0x5a827999u, shift);
        };
        auto stepH = [](uint32_t& x, uint32_t y, uint32_t z, uint32_t w,
                        uint32_t word, uint32_t shift) {
            x = rotl(x + (y ^ z ^ w) + word + 0x6ed9eba1u, shift);
        };

        stepF(a, b, c, d, m[ 0],  3); stepF(d, a, b, c, m[ 1],  7);
        stepF(c, d, a, b, m[ 2], 11); stepF(b, c, d, a, m[ 3], 19);
        stepF(a, b, c, d, m[ 4],  3); stepF(d, a, b, c, m[ 5],  7);
        stepF(c, d, a, b, m[ 6], 11); stepF(b, c, d, a, m[ 7], 19);
        stepF(a, b, c, d, m[ 8],  3); stepF(d, a, b, c, m[ 9],  7);
        stepF(c, d, a, b, m[10], 11); stepF(b, c, d, a, m[11], 19);
        stepF(a, b, c, d, m[12],  3); stepF(d, a, b, c, m[13],  7);
        stepF(c, d, a, b, m[14], 11); stepF(b, c, d, a, m[15], 19);

        stepG(a, b, c, d, m[ 0],  3); stepG(d, a, b, c, m[ 4],  5);
        stepG(c, d, a, b, m[ 8],  9); stepG(b, c, d, a, m[12], 13);
        stepG(a, b, c, d, m[ 1],  3); stepG(d, a, b, c, m[ 5],  5);
        stepG(c, d, a, b, m[ 9],  9); stepG(b, c, d, a, m[13], 13);
        stepG(a, b, c, d, m[ 2],  3); stepG(d, a, b, c, m[ 6],  5);
        stepG(c, d, a, b, m[10],  9); stepG(b, c, d, a, m[14], 13);
        stepG(a, b, c, d, m[ 3],  3); stepG(d, a, b, c, m[ 7],  5);
        stepG(c, d, a, b, m[11],  9); stepG(b, c, d, a, m[15], 13);

        stepH(a, b, c, d, m[ 0],  3); stepH(d, a, b, c, m[ 8],  9);
        stepH(c, d, a, b, m[ 4], 11); stepH(b, c, d, a, m[12], 15);
        stepH(a, b, c, d, m[ 2],  3); stepH(d, a, b, c, m[10],  9);
        stepH(c, d, a, b, m[ 6], 11); stepH(b, c, d, a, m[14], 15);
        stepH(a, b, c, d, m[ 1],  3); stepH(d, a, b, c, m[ 9],  9);
        stepH(c, d, a, b, m[ 5], 11); stepH(b, c, d, a, m[13], 15);
        stepH(a, b, c, d, m[ 3],  3); stepH(d, a, b, c, m[11],  9);
        stepH(c, d, a, b, m[ 7], 11); stepH(b, c, d, a, m[15], 15);

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
