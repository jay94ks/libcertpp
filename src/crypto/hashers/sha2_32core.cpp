#include "sha2_32core.hpp"

/* Hardware-accelerated compression (Intel SHA Extensions -- SHA256RNDS2/SHA256MSG1/
 * SHA256MSG2), gated by both the CERTPP_DISABLE_HWACCEL_SHA build option and the target
 * architecture, same pattern as CBigNum's/CGf2m's SIMD acceleration (utils/bignum.cpp,
 * utils/gf2m.cpp) and SHA1::transform()'s own SHA1RNDS4 path (hashers/sha1.cpp): x86-64-only,
 * compiled out entirely elsewhere, where transform() falls back to the portable loop
 * unconditionally. Shared by SHA-256 and SHA-224 (FIPS 180-4's compression function is
 * identical for both -- only the initial state and output truncation differ). */
#if !defined(CERTPP_DISABLE_HWACCEL_SHA) && (defined(_M_X64) || defined(__x86_64__))
#define CERTPP_SHA2_32_HWACCEL_AVAILABLE 1
#include <immintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

namespace certpp {
namespace crypto {

#if defined(CERTPP_SHA2_32_HWACCEL_AVAILABLE)
        /* Whether this CPU actually has the SHA extensions -- an optional x86-64 feature, not
         * guaranteed just because the binary was built for the architecture, so this must be
         * checked at runtime before ever emitting SHA256RNDS2/SHA256MSG1/SHA256MSG2. Computed
         * once (CPUID leaf 7, sub-leaf 0: EBX bit 29 = SHA). */
        bool Sha2_32Core::hasSha() {
            static const bool supported = [] {
#if defined(_MSC_VER)
                int info[4] = { 0, 0, 0, 0 };
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

        /* Runs the SHA-256/SHA-224 compression function over one 64-byte block via the SHA
         * extensions, updating state in place -- the well-known Intel-published intrinsics
         * sequence (see "Intel SHA Extensions", also mirrored across OpenSSL/BoringSSL/the Linux
         * kernel). Produces an identical result to the portable loop below; cross-checked
         * against it by this library's ordinary FIPS 180-4 test vectors, which this machine's
         * SHA-NI-capable CPU exercises through this path automatically.
         *
         * __attribute__((target(...))) lets GCC/Clang emit these instructions in just this one
         * function regardless of the translation unit's default -march (MSVC needs no
         * equivalent -- it allows using intrinsics for any instruction set unconditionally, and
         * relies on the runtime hasSha() check above to avoid actually executing them on a CPU
         * that lacks the feature). */
#if defined(__GNUC__) && !defined(_MSC_VER)
        __attribute__((target("sha,sse4.1")))
#endif
        void Sha2_32Core::transformAccelerated(uint32_t state[8], const uint8_t block[64]) {
            const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);

            __m128i TMP = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[0]));
            __m128i STATE1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[4]));

            TMP = _mm_shuffle_epi32(TMP, 0xB1);
            STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);
            __m128i STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);
            STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);

            __m128i ABEF_SAVE = STATE0;
            __m128i CDGH_SAVE = STATE1;

            __m128i MSG = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 0));
            __m128i MSG0 = _mm_shuffle_epi8(MSG, MASK);
            MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFLL, 0x71374491428A2F98LL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

            __m128i MSG1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 16));
            MSG1 = _mm_shuffle_epi8(MSG1, MASK);
            MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4LL, 0x59F111F13956C25BLL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
            MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

            __m128i MSG2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 32));
            MSG2 = _mm_shuffle_epi8(MSG2, MASK);
            MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BELL, 0x12835B01D807AA98LL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
            MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

            __m128i MSG3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 48));
            MSG3 = _mm_shuffle_epi8(MSG3, MASK);
            MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7LL, 0x80DEB1FE72BE5D74LL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
            MSG0 = _mm_add_epi32(MSG0, TMP);
            MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
            MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

            MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6LL, 0xEFBE4786E49B69C1LL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
            MSG1 = _mm_add_epi32(MSG1, TMP);
            MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
            MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

            MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCLL, 0x4A7484AA2DE92C6FLL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
            MSG2 = _mm_add_epi32(MSG2, TMP);
            MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
            MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

            MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xBF597FC7B00327C8LL, 0xA831C66D983E5152LL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
            MSG3 = _mm_add_epi32(MSG3, TMP);
            MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
            MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

            MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x1429296706CA6351LL, 0xD5A79147C6E00BF3LL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
            MSG0 = _mm_add_epi32(MSG0, TMP);
            MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
            MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

            MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x53380D134D2C6DFCLL, 0x2E1B213827B70A85LL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
            MSG1 = _mm_add_epi32(MSG1, TMP);
            MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
            MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

            MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x92722C8581C2C92ELL, 0x766A0ABB650A7354LL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
            MSG2 = _mm_add_epi32(MSG2, TMP);
            MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
            MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

            MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xC76C51A3C24B8B70LL, 0xA81A664BA2BFE8A1LL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
            MSG3 = _mm_add_epi32(MSG3, TMP);
            MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
            MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

            MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x106AA070F40E3585LL, 0xD6990624D192E819LL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
            MSG0 = _mm_add_epi32(MSG0, TMP);
            MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
            MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

            MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x34B0BCB52748774CLL, 0x1E376C0819A4C116LL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
            MSG1 = _mm_add_epi32(MSG1, TMP);
            MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
            MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

            MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FLL, 0x4ED8AA4A391C0CB3LL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
            MSG2 = _mm_add_epi32(MSG2, TMP);
            MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

            MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x8CC7020884C87814LL, 0x78A5636F748F82EELL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
            MSG3 = _mm_add_epi32(MSG3, TMP);
            MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

            MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7LL, 0xA4506CEB90BEFFFALL));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
            MSG = _mm_shuffle_epi32(MSG, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

            STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
            STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

            TMP = _mm_shuffle_epi32(STATE0, 0x1B);
            STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);
            STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);
            STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[0]), STATE0);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[4]), STATE1);
        }
#endif

        /* Runs the SHA-256/SHA-224 compression function over one 64-byte block, updating state
         * in place. */
        void Sha2_32Core::transformPortable(uint32_t state[8], const uint8_t block[64]) {
            /* Round constants: the first 32 bits of the fractional parts of the cube roots of
             * the first 64 primes. */
            static constexpr uint32_t K[64] = {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
            };

            uint32_t w[64];
            for (size_t i = 0; i < 16; ++i) {
                // --> SHA-256/SHA-224 pack message words big-endian.
                w[i] = (uint32_t(block[i * 4]) << 24)
                    | (uint32_t(block[i * 4 + 1]) << 16)
                    | (uint32_t(block[i * 4 + 2]) << 8)
                    | uint32_t(block[i * 4 + 3]);
            }

            for (size_t i = 16; i < 64; ++i) {
                uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }

            uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
            uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

            for (uint32_t i = 0; i < 64; ++i) {
                uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                uint32_t ch = (e & f) ^ (~e & g);
                uint32_t temp1 = h + s1 + ch + K[i] + w[i];
                uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = s0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }

} // namespace crypto
} // namespace certpp
