#include <certpp/crypto/hashers/sha1.hpp>
#include <cstring>

/* Hardware-accelerated compression (Intel SHA Extensions -- SHA1RNDS4/SHA1NEXTE/SHA1MSG1/
 * SHA1MSG2) for transform()'s per-block work, gated by both the CERTPP_DISABLE_HWACCEL_SHA
 * build option and the target architecture, same pattern as CBigNum's/CGf2m's SIMD
 * acceleration (utils/bignum.cpp, utils/gf2m.cpp): x86-64-only, compiled out entirely
 * elsewhere, where transform() falls back to the portable loop unconditionally. */
#if !defined(CERTPP_DISABLE_HWACCEL_SHA) && (defined(_M_X64) || defined(__x86_64__))
#define CERTPP_SHA1_HWACCEL_AVAILABLE 1
#include <immintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

namespace certpp {
namespace crypto {

#if defined(CERTPP_SHA1_HWACCEL_AVAILABLE)
        /* Whether this CPU actually has the SHA extensions -- an optional x86-64 feature, not
         * guaranteed just because the binary was built for the architecture, so this must be
         * checked at runtime before ever emitting SHA1RNDS4/SHA1NEXTE/SHA1MSG1/SHA1MSG2.
         * Computed once (CPUID leaf 7, sub-leaf 0: EBX bit 29 = SHA). */
        bool SHA1::hasSha() {
            static const bool supported = [] {
#if defined(_MSC_VER)
                int info[4] = { 0, 0, 0, 0 };

                // --> For a leaf above the maximum it supports, CPUID returns the *highest
                // supported* leaf's data instead of zeroes -- so leaf 7 has to be gated on
                // leaf 0's reported maximum, or on a CPU whose maximum is below 7 this reads an
                // unrelated leaf-1 field (bit 29 lands in the initial-APIC-ID byte) and can
                // claim SHA support that isn't there. The __get_cpuid_count() path below makes
                // the same check internally.
                __cpuid(info, 0);
                if (info[0] < 7) {
                    return false;
                }

                __cpuidex(info, 7, 0);
                return (info[1] & (1 << 29)) != 0;
#else
                unsigned int eax, ebx, ecx, edx;
                if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
                    return false;
                }
                return (ebx & (1u << 29)) != 0;
#endif
            }();

            return supported;
        }

        /* Runs the SHA-1 compression function over one 64-byte block via the SHA extensions,
         * updating state in place -- the well-known Intel-published intrinsics sequence (see
         * "Intel SHA Extensions", also mirrored across OpenSSL/BoringSSL/the Linux kernel),
         * adapted to this file's one-block-per-call transform() shape. Produces an identical
         * result to the portable loop below; cross-checked against it by this library's
         * ordinary RFC 3174 test vectors, which this machine's SHA-NI-capable CPU exercises
         * through this path automatically.
         *
         * __attribute__((target(...))) lets GCC/Clang emit these instructions in just this one
         * function regardless of the translation unit's default -march (MSVC needs no
         * equivalent -- it allows using intrinsics for any instruction set unconditionally, and
         * relies on the runtime hasSha() check above to avoid actually executing them on a CPU
         * that lacks the feature). */
#if defined(__GNUC__) && !defined(_MSC_VER)
        __attribute__((target("sha,sse4.1")))
#endif
        void SHA1::transformAccelerated(uint32_t state[5], const uint8_t block[64]) {
            const __m128i SHUF_MASK = _mm_set_epi64x(0x0001020304050607LL, 0x08090a0b0c0d0e0fLL);

            __m128i ABCD = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state));
            __m128i E0 = _mm_set_epi32(static_cast<int>(state[4]), 0, 0, 0);
            ABCD = _mm_shuffle_epi32(ABCD, 0x1B);

            __m128i ABCD_SAVE = ABCD;
            __m128i E0_SAVE = E0;

            __m128i MSG0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 0));
            MSG0 = _mm_shuffle_epi8(MSG0, SHUF_MASK);
            E0 = _mm_add_epi32(E0, MSG0);
            __m128i E1 = ABCD;
            ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);

            __m128i MSG1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 16));
            MSG1 = _mm_shuffle_epi8(MSG1, SHUF_MASK);
            E1 = _mm_sha1nexte_epu32(E1, MSG1);
            E0 = ABCD;
            ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
            MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);

            __m128i MSG2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 32));
            MSG2 = _mm_shuffle_epi8(MSG2, SHUF_MASK);
            E0 = _mm_sha1nexte_epu32(E0, MSG2);
            E1 = ABCD;
            ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
            MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
            MSG0 = _mm_xor_si128(MSG0, MSG2);

            __m128i MSG3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 48));
            MSG3 = _mm_shuffle_epi8(MSG3, SHUF_MASK);
            E1 = _mm_sha1nexte_epu32(E1, MSG3);
            E0 = ABCD;
            MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
            MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
            MSG1 = _mm_xor_si128(MSG1, MSG3);

            E0 = _mm_sha1nexte_epu32(E0, MSG0);
            E1 = ABCD;
            MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
            MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
            MSG2 = _mm_xor_si128(MSG2, MSG0);

            E1 = _mm_sha1nexte_epu32(E1, MSG1);
            E0 = ABCD;
            MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
            MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
            MSG3 = _mm_xor_si128(MSG3, MSG1);

            E0 = _mm_sha1nexte_epu32(E0, MSG2);
            E1 = ABCD;
            MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
            MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
            MSG0 = _mm_xor_si128(MSG0, MSG2);

            E1 = _mm_sha1nexte_epu32(E1, MSG3);
            E0 = ABCD;
            MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
            MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
            MSG1 = _mm_xor_si128(MSG1, MSG3);

            E0 = _mm_sha1nexte_epu32(E0, MSG0);
            E1 = ABCD;
            MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
            MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
            MSG2 = _mm_xor_si128(MSG2, MSG0);

            E1 = _mm_sha1nexte_epu32(E1, MSG1);
            E0 = ABCD;
            MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
            MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
            MSG3 = _mm_xor_si128(MSG3, MSG1);

            E0 = _mm_sha1nexte_epu32(E0, MSG2);
            E1 = ABCD;
            MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
            MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
            MSG0 = _mm_xor_si128(MSG0, MSG2);

            E1 = _mm_sha1nexte_epu32(E1, MSG3);
            E0 = ABCD;
            MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
            MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
            MSG1 = _mm_xor_si128(MSG1, MSG3);

            E0 = _mm_sha1nexte_epu32(E0, MSG0);
            E1 = ABCD;
            MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
            MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
            MSG2 = _mm_xor_si128(MSG2, MSG0);

            E1 = _mm_sha1nexte_epu32(E1, MSG1);
            E0 = ABCD;
            MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
            MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
            MSG3 = _mm_xor_si128(MSG3, MSG1);

            E0 = _mm_sha1nexte_epu32(E0, MSG2);
            E1 = ABCD;
            MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
            MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
            MSG0 = _mm_xor_si128(MSG0, MSG2);

            E1 = _mm_sha1nexte_epu32(E1, MSG3);
            E0 = ABCD;
            MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
            MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
            MSG1 = _mm_xor_si128(MSG1, MSG3);

            E0 = _mm_sha1nexte_epu32(E0, MSG0);
            E1 = ABCD;
            MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
            MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
            MSG2 = _mm_xor_si128(MSG2, MSG0);

            E1 = _mm_sha1nexte_epu32(E1, MSG1);
            E0 = ABCD;
            MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
            MSG3 = _mm_xor_si128(MSG3, MSG1);

            E0 = _mm_sha1nexte_epu32(E0, MSG2);
            E1 = ABCD;
            MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
            ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);

            E1 = _mm_sha1nexte_epu32(E1, MSG3);
            E0 = ABCD;
            ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);

            E0 = _mm_sha1nexte_epu32(E0, E0_SAVE);
            ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);

            ABCD = _mm_shuffle_epi32(ABCD, 0x1B);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(state), ABCD);
            state[4] = static_cast<uint32_t>(_mm_extract_epi32(E0, 3));
        }
#endif

        /* Runs the SHA-1 compression function over one 64-byte block, updating state in place. */
        void SHA1::transformPortable(uint32_t state[5], const uint8_t block[64]) {
            uint32_t w[80];
            for (size_t i = 0; i < 16; ++i) {
                // --> SHA-1 packs message words big-endian.
                w[i] = (uint32_t(block[i * 4]) << 24)
                    | (uint32_t(block[i * 4 + 1]) << 16)
                    | (uint32_t(block[i * 4 + 2]) << 8)
                    | uint32_t(block[i * 4 + 3]);
            }

            for (size_t i = 16; i < 80; ++i) {
                w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
            }

            uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];

            for (uint32_t i = 0; i < 80; ++i) {
                uint32_t f;
                uint32_t k;

                if (i < 20) {
                    f = (b & c) | (~b & d);
                    k = 0x5A827999;
                } else if (i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                uint32_t temp = rotl(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = rotl(b, 30);
                b = a;
                a = temp;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
        }

    /* Resets the SHA-1 context to its initial state. */
    void SHA1::reset() {
        _ctx.state[0] = 0x67452301;
        _ctx.state[1] = 0xEFCDAB89;
        _ctx.state[2] = 0x98BADCFE;
        _ctx.state[3] = 0x10325476;
        _ctx.state[4] = 0xC3D2E1F0;

        _ctx.bufferLen = 0;
        _ctx.totalLen = 0;
    }

    /* Pushes data into the SHA-1 context for hashing. */
    size_t SHA1::push(const SReadOnlyByteSpan& buf) {
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
                transform(_ctx.state, _ctx.buffer);
                _ctx.bufferLen = 0;
            }
        }

        while (remaining >= 64) {
            transform(_ctx.state, data);
            data += 64;
            remaining -= 64;
        }

        if (remaining > 0) {
            std::memcpy(_ctx.buffer, data, remaining);
            _ctx.bufferLen = remaining;
        }

        return buf.size;
    }

    /* Finalizes the SHA-1 hash computation and writes the result to the output buffer. */
    bool SHA1::finish(SByteSpan& out) {
        if (out.size < byteWidth()) {
            return false;
        }

        // --> Finalize a local copy, so finish() can be called more than once without
        // corrupting the live context.
        SHA1 temp;
        temp._ctx = _ctx;

        uint8_t pad[64] = { 0x80 };
        size_t padLen = (temp._ctx.bufferLen < 56) ? (56 - temp._ctx.bufferLen) : (120 - temp._ctx.bufferLen);

        uint64_t bitLen = temp._ctx.totalLen * 8;
        uint8_t lengthField[8];
        for (size_t i = 0; i < 8; ++i) {
            // --> SHA-1 appends the bit length big-endian.
            lengthField[i] = uint8_t(bitLen >> (8 * (7 - i)));
        }

        temp.push(SReadOnlyByteSpan(pad, padLen));
        temp.push(SReadOnlyByteSpan(lengthField, sizeof(lengthField)));

        for (size_t i = 0; i < 5; ++i) {
            // --> SHA-1 outputs each 32-bit word big-endian, matching its input packing.
            out.data[i * 4 + 0] = uint8_t(temp._ctx.state[i] >> 24);
            out.data[i * 4 + 1] = uint8_t(temp._ctx.state[i] >> 16);
            out.data[i * 4 + 2] = uint8_t(temp._ctx.state[i] >> 8);
            out.data[i * 4 + 3] = uint8_t(temp._ctx.state[i]);
        }

        return true;
    }

} // namespace crypto
} // namespace certpp
