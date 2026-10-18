#include "aescore.hpp"
#include <certpp/utils/secure.hpp>
#include <cstring>

/* Hardware-accelerated AES-NI block core and VAES parallel-CTR core, gated by both the
 * CERTPP_DISABLE_HWACCEL_AES build option and the target architecture -- same pattern as
 * SHA1's/CBigNum's/CGf2m's SIMD acceleration (crypto/hashers/sha1.cpp, utils/bignum.cpp,
 * utils/gf2m.cpp): x86-64-only, compiled out entirely elsewhere, where the block functions and
 * CTR helper fall back to the portable round functions. */
#if !defined(CERTPP_DISABLE_HWACCEL_AES) && (defined(_M_X64) || defined(__x86_64__))
#define CERTPP_AES_HWACCEL_AVAILABLE 1
#include <wmmintrin.h>
#define CERTPP_AES_VAES_AVAILABLE 1
#include <immintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

namespace certpp {
namespace crypto {

    namespace {

#if defined(CERTPP_AES_HWACCEL_AVAILABLE)
        /* Whether this CPU actually has AES-NI -- an optional x86-64 feature, not guaranteed
         * just because the binary was built for the architecture, so this must be checked at
         * runtime before ever emitting AESENC/AESENCLAST/AESDEC/AESDECLAST. Computed once
         * (CPUID leaf 1: ECX bit 25 = AES).
         *
         * --> Named cpuHasAesNi() rather than hasAesNi() because the public
         * AesCore::hasAesNi() below delegates to it, and two functions of the same name in
         * enclosing scopes would make every internal call site ambiguous. */
        bool cpuHasAesNi() {
            static const bool supported = [] {
#if defined(_MSC_VER)
                int info[4] = { 0, 0, 0, 0 };
                __cpuid(info, 1);
                return (info[2] & (1 << 25)) != 0;
#else
                unsigned int eax, ebx, ecx, edx;
                if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
                    return false;
                }
                return (ecx & (1u << 25)) != 0;
#endif
            }();

            return supported;
        }

#if defined(CERTPP_AES_VAES_AVAILABLE)
        /* VAES over 256-bit vectors encrypts two independent AES blocks per instruction. The OS
         * must have enabled XMM/YMM state and the CPU must advertise both AVX2 and VAES; checking
         * only the VAES bit can otherwise SIGILL. */
        bool cpuHasVaes256() {
            static const bool supported = [] {
#if defined(_MSC_VER)
                int info[4] = { 0, 0, 0, 0 };
                __cpuid(info, 0);
                if (info[0] < 7) {
                    return false;
                }
                __cpuidex(info, 1, 0);
                if ((info[2] & (1 << 27)) == 0 || (info[2] & (1 << 28)) == 0
                    || (_xgetbv(0) & 0x6) != 0x6) {
                    return false;
                }
                __cpuidex(info, 7, 0);
                return (info[1] & (1 << 5)) != 0 && (info[2] & (1 << 9)) != 0;
#else
                unsigned int eax, ebx, ecx, edx;
                if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)
                    || (ecx & (1u << 27)) == 0 || (ecx & (1u << 28)) == 0) {
                    return false;
                }
                uint32_t xcr0Low, xcr0High;
                __asm__ volatile("xgetbv" : "=a"(xcr0Low), "=d"(xcr0High) : "c"(0));
                (void)xcr0High;
                if ((xcr0Low & 0x6) != 0x6
                    || !__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
                    return false;
                }
                return (ebx & (1u << 5)) != 0 && (ecx & (1u << 9)) != 0;
#endif
            }();
            return supported;
        }

        /* Four AES blocks per 512-bit VAES instruction. As with every AVX-512 path, the CPU bit
         * is insufficient by itself: Windows must also save opmask and the high ZMM registers. */
        bool cpuHasVaes512() {
            static const bool supported = [] {
#if defined(_MSC_VER)
                int info[4] = { 0, 0, 0, 0 };
                __cpuid(info, 0);
                if (info[0] < 7) {
                    return false;
                }
                __cpuidex(info, 1, 0);
                if ((info[2] & (1 << 27)) == 0 || (info[2] & (1 << 28)) == 0 ||
                    (_xgetbv(0) & 0xE6) != 0xE6) {
                    return false;
                }
                __cpuidex(info, 7, 0);
                return (info[1] & (1 << 16)) != 0 &&
                       (info[2] & (1 << 9)) != 0;
#else
                unsigned int eax, ebx, ecx, edx;
                if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)
                    || (ecx & (1u << 27)) == 0 || (ecx & (1u << 28)) == 0) {
                    return false;
                }
                uint32_t xcr0Low, xcr0High;
                __asm__ volatile("xgetbv" : "=a"(xcr0Low), "=d"(xcr0High) : "c"(0));
                (void)xcr0High;
                if ((xcr0Low & 0xE6) != 0xE6
                    || !__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
                    return false;
                }
                return (ebx & (1u << 16)) != 0 && (ecx & (1u << 9)) != 0;
#endif
            }();
            return supported;
        }

#endif

        /* AES-NI encrypt: the round-key bytes expandKey() produces are already exactly the
         * standard FIPS-197 forward key schedule (Intel's own recommended AES-NI key expansion
         * sequence, via AESKEYGENASSIST, produces byte-identical round keys), so
         * AESENC/AESENCLAST can consume them directly -- no separate hardware key schedule
         * needed. */
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("aes,sse2")))
#endif
        void encryptBlockAccelerated(const uint8_t in[16], uint8_t out[16], const uint8_t* roundKeys, uint32_t nr) {
            __m128i state = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            state = _mm_xor_si128(state, _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys)));

            for (uint32_t round = 1; round < nr; ++round) {
                __m128i rk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys + round * 16));
                state = _mm_aesenc_si128(state, rk);
            }

            __m128i lastRk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys + nr * 16));
            state = _mm_aesenclast_si128(state, lastRk);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state);
        }

        /* AES-NI decrypt via the "Equivalent Inverse Cipher" AESDEC/AESDECLAST implement (Intel's
         * AES-NI whitepaper): round keys are consumed last-to-first, and every round key except
         * the first and last must be passed through AESIMC (InvMixColumns) first -- applied on
         * the fly here, once per round per call, rather than cached as a separate decrypt key
         * schedule, since it's a single cheap instruction and keeps this stateless and symmetric
         * with encryptBlockAccelerated() above. */
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("aes,sse2")))
#endif
        void decryptBlockAccelerated(const uint8_t in[16], uint8_t out[16], const uint8_t* roundKeys, uint32_t nr) {
            __m128i state = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            state = _mm_xor_si128(state, _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys + nr * 16)));

            for (uint32_t round = nr - 1; round >= 1; --round) {
                __m128i rk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys + round * 16));
                state = _mm_aesdec_si128(state, _mm_aesimc_si128(rk));
            }

            __m128i firstRk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys));
            state = _mm_aesdeclast_si128(state, firstRk);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state);
        }

        /* Eight independent CTR blocks fill AES-NI's pipeline while each individual AESENC
         * dependency chain waits for its previous round. CBC cannot do this because its next
         * input depends on the preceding ciphertext. */
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("aes,sse2")))
#endif
        void xorCtr8Accelerated(
            const uint8_t* in, uint8_t* out, const uint8_t counters[8][16],
            const uint8_t* roundKeys, uint32_t nr
        ) {
            __m128i states[8];
            const __m128i first =
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys));
            for (size_t lane = 0; lane < 8; ++lane) {
                states[lane] = _mm_xor_si128(
                    _mm_loadu_si128(reinterpret_cast<const __m128i*>(counters[lane])), first);
            }

            for (uint32_t round = 1; round < nr; ++round) {
                const __m128i key = _mm_loadu_si128(
                    reinterpret_cast<const __m128i*>(roundKeys + round * 16));
                for (size_t lane = 0; lane < 8; ++lane) {
                    states[lane] = _mm_aesenc_si128(states[lane], key);
                }
            }

            const __m128i last = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(roundKeys + nr * 16));
            for (size_t lane = 0; lane < 8; ++lane) {
                states[lane] = _mm_aesenclast_si128(states[lane], last);
                states[lane] = _mm_xor_si128(states[lane],
                    _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + lane * 16)));
                _mm_storeu_si128(reinterpret_cast<__m128i*>(out + lane * 16), states[lane]);
            }
        }

        /* Four counters are enough to hide most of AESENC's dependency latency for short
         * records. Keeping this separate from the eight-block bulk loop avoids falling back to
         * four complete single-block calls for the common 64-byte record size. */
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("aes,sse2")))
#endif
        void xorCtr4Accelerated(
            const uint8_t* in, uint8_t* out, const uint8_t counters[4][16],
            const uint8_t* roundKeys, uint32_t nr
        ) {
            __m128i states[4];
            const __m128i first =
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys));
            for (size_t lane = 0; lane < 4; ++lane) {
                states[lane] = _mm_xor_si128(
                    _mm_loadu_si128(reinterpret_cast<const __m128i*>(counters[lane])), first);
            }
            for (uint32_t round = 1; round < nr; ++round) {
                const __m128i key = _mm_loadu_si128(
                    reinterpret_cast<const __m128i*>(roundKeys + round * 16));
                for (size_t lane = 0; lane < 4; ++lane) {
                    states[lane] = _mm_aesenc_si128(states[lane], key);
                }
            }
            const __m128i last = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(roundKeys + nr * 16));
            for (size_t lane = 0; lane < 4; ++lane) {
                states[lane] = _mm_xor_si128(
                    _mm_aesenclast_si128(states[lane], last),
                    _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + lane * 16)));
                _mm_storeu_si128(reinterpret_cast<__m128i*>(out + lane * 16), states[lane]);
            }
        }

#if defined(CERTPP_AES_VAES_AVAILABLE)
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("avx2,vaes")))
#endif
        __m128i ctrBlock(__m128i prefix, uint32_t value) {
            const uint32_t be = ((value & 0x000000ffu) << 24)
                | ((value & 0x0000ff00u) << 8)
                | ((value & 0x00ff0000u) >> 8)
                | ((value & 0xff000000u) >> 24);
            return _mm_insert_epi32(prefix, static_cast<int>(be), 3);
        }

#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("avx2,vaes")))
#endif
        void xorCtr8Vaes256(
            const uint8_t* in, uint8_t* out, const uint8_t counter[16],
            uint32_t counterValue,
            const uint8_t* roundKeys, uint32_t nr
        ) {
            const __m128i prefix =
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(counter));
            const __m128i first128 =
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys));
            const __m256i first = _mm256_broadcastsi128_si256(first128);
            __m256i s0 = _mm256_xor_si256(
                _mm256_set_m128i(
                    ctrBlock(prefix, counterValue + 1),
                    ctrBlock(prefix, counterValue + 0)), first);
            __m256i s1 = _mm256_xor_si256(
                _mm256_set_m128i(
                    ctrBlock(prefix, counterValue + 3),
                    ctrBlock(prefix, counterValue + 2)), first);
            __m256i s2 = _mm256_xor_si256(
                _mm256_set_m128i(
                    ctrBlock(prefix, counterValue + 5),
                    ctrBlock(prefix, counterValue + 4)), first);
            __m256i s3 = _mm256_xor_si256(
                _mm256_set_m128i(
                    ctrBlock(prefix, counterValue + 7),
                    ctrBlock(prefix, counterValue + 6)), first);

            for (uint32_t round = 1; round < nr; ++round) {
                const __m256i key = _mm256_broadcastsi128_si256(_mm_loadu_si128(
                    reinterpret_cast<const __m128i*>(roundKeys + round * 16)));
                s0 = _mm256_aesenc_epi128(s0, key);
                s1 = _mm256_aesenc_epi128(s1, key);
                s2 = _mm256_aesenc_epi128(s2, key);
                s3 = _mm256_aesenc_epi128(s3, key);
            }

            const __m256i last = _mm256_broadcastsi128_si256(_mm_loadu_si128(
                reinterpret_cast<const __m128i*>(roundKeys + nr * 16)));
            s0 = _mm256_xor_si256(_mm256_aesenclast_epi128(s0, last),
                _mm256_loadu_si256(reinterpret_cast<const __m256i*>(in + 0)));
            s1 = _mm256_xor_si256(_mm256_aesenclast_epi128(s1, last),
                _mm256_loadu_si256(reinterpret_cast<const __m256i*>(in + 32)));
            s2 = _mm256_xor_si256(_mm256_aesenclast_epi128(s2, last),
                _mm256_loadu_si256(reinterpret_cast<const __m256i*>(in + 64)));
            s3 = _mm256_xor_si256(_mm256_aesenclast_epi128(s3, last),
                _mm256_loadu_si256(reinterpret_cast<const __m256i*>(in + 96)));
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + 0), s0);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + 32), s1);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + 64), s2);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + 96), s3);
        }

#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("avx512f,vaes")))
#endif
        __m512i ctrGroup4(__m128i prefix, uint32_t value) {
            __m512i result = _mm512_setzero_si512();
            result = _mm512_inserti32x4(result, ctrBlock(prefix, value + 0), 0);
            result = _mm512_inserti32x4(result, ctrBlock(prefix, value + 1), 1);
            result = _mm512_inserti32x4(result, ctrBlock(prefix, value + 2), 2);
            return _mm512_inserti32x4(result, ctrBlock(prefix, value + 3), 3);
        }

#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("avx512f,vaes")))
#endif
        void xorCtr16Vaes512(
            const uint8_t* in, uint8_t* out, const uint8_t counter[16],
            uint32_t counterValue, const uint8_t* roundKeys, uint32_t nr
        ) {
            const __m128i prefix =
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(counter));
            const __m512i first = _mm512_broadcast_i32x4(
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys)));
            __m512i s0 = _mm512_xor_si512(ctrGroup4(prefix, counterValue + 0), first);
            __m512i s1 = _mm512_xor_si512(ctrGroup4(prefix, counterValue + 4), first);
            __m512i s2 = _mm512_xor_si512(ctrGroup4(prefix, counterValue + 8), first);
            __m512i s3 = _mm512_xor_si512(ctrGroup4(prefix, counterValue + 12), first);

            for (uint32_t round = 1; round < nr; ++round) {
                const __m512i key = _mm512_broadcast_i32x4(_mm_loadu_si128(
                    reinterpret_cast<const __m128i*>(roundKeys + round * 16)));
                s0 = _mm512_aesenc_epi128(s0, key);
                s1 = _mm512_aesenc_epi128(s1, key);
                s2 = _mm512_aesenc_epi128(s2, key);
                s3 = _mm512_aesenc_epi128(s3, key);
            }

            const __m512i last = _mm512_broadcast_i32x4(_mm_loadu_si128(
                reinterpret_cast<const __m128i*>(roundKeys + nr * 16)));
            s0 = _mm512_xor_si512(_mm512_aesenclast_epi128(s0, last),
                _mm512_loadu_si512(in + 0));
            s1 = _mm512_xor_si512(_mm512_aesenclast_epi128(s1, last),
                _mm512_loadu_si512(in + 64));
            s2 = _mm512_xor_si512(_mm512_aesenclast_epi128(s2, last),
                _mm512_loadu_si512(in + 128));
            s3 = _mm512_xor_si512(_mm512_aesenclast_epi128(s3, last),
                _mm512_loadu_si512(in + 192));
            _mm512_storeu_si512(out + 0, s0);
            _mm512_storeu_si512(out + 64, s1);
            _mm512_storeu_si512(out + 128, s2);
            _mm512_storeu_si512(out + 192, s3);
        }

#endif
#endif // CERTPP_AES_HWACCEL_AVAILABLE

    } // namespace

    const uint8_t AesCore::SBOX[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    };

    const uint8_t AesCore::INV_SBOX[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    };

    const uint8_t AesCore::RCON[11] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
    };

    /* x * {02} in GF(2^8) modulo the AES polynomial. */
    uint8_t AesCore::xtime(uint8_t a) {
        return static_cast<uint8_t>((a << 1) ^ ((a & 0x80) ? 0x1B : 0x00));
    }

    /* Multiplication in GF(2^8) modulo the AES polynomial, for InvMixColumns' coefficients. */
    uint8_t AesCore::gmul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        for (int i = 0; i < 8; ++i) {
            if (b & 1) {
                p ^= a;
            }
            bool hi = (a & 0x80) != 0;
            a = static_cast<uint8_t>(a << 1);
            if (hi) {
                a ^= 0x1B;
            }
            b = static_cast<uint8_t>(b >> 1);
        }
        return p;
    }

    /* SubBytes (FIPS-197 5.1.1). */
    void AesCore::subBytes(uint8_t s[16]) {
        for (int i = 0; i < 16; ++i) {
            s[i] = SBOX[s[i]];
        }
    }

    /* InvSubBytes (FIPS-197 5.3.2). */
    void AesCore::invSubBytes(uint8_t s[16]) {
        for (int i = 0; i < 16; ++i) {
            s[i] = INV_SBOX[s[i]];
        }
    }

    /* ShiftRows (FIPS-197 5.1.2). */
    void AesCore::shiftRows(uint8_t s[16]) {
        uint8_t tmp[16];
        for (int r = 0; r < 4; ++r) {
            for (int c = 0; c < 4; ++c) {
                tmp[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
            }
        }
        std::memcpy(s, tmp, 16);
    }

    /* InvShiftRows (FIPS-197 5.3.1). */
    void AesCore::invShiftRows(uint8_t s[16]) {
        uint8_t tmp[16];
        for (int r = 0; r < 4; ++r) {
            for (int c = 0; c < 4; ++c) {
                tmp[r + 4 * c] = s[r + 4 * ((c + 4 - r) % 4)];
            }
        }
        std::memcpy(s, tmp, 16);
    }

    /* MixColumns (FIPS-197 5.1.3). */
    void AesCore::mixColumns(uint8_t s[16]) {
        for (int c = 0; c < 4; ++c) {
            uint8_t a0 = s[4 * c + 0], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];

            s[4 * c + 0] = static_cast<uint8_t>(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
            s[4 * c + 1] = static_cast<uint8_t>(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
            s[4 * c + 2] = static_cast<uint8_t>(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
            s[4 * c + 3] = static_cast<uint8_t>((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
        }
    }

    /* InvMixColumns (FIPS-197 5.3.3). */
    void AesCore::invMixColumns(uint8_t s[16]) {
        for (int c = 0; c < 4; ++c) {
            uint8_t a0 = s[4 * c + 0], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];

            s[4 * c + 0] = static_cast<uint8_t>(gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9));
            s[4 * c + 1] = static_cast<uint8_t>(gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13));
            s[4 * c + 2] = static_cast<uint8_t>(gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11));
            s[4 * c + 3] = static_cast<uint8_t>(gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14));
        }
    }

    /* AddRoundKey (FIPS-197 5.1.4). */
    void AesCore::addRoundKey(uint8_t s[16], const uint8_t* roundKey) {
        for (int i = 0; i < 16; ++i) {
            s[i] ^= roundKey[i];
        }
    }

    /* Expands a key into a caller-supplied schedule buffer. */
    bool AesCore::expandKey(const uint8_t* key, size_t keyBytes, uint8_t* roundKeys, uint32_t& nr) {
        nr = 0;

        if (!key || !roundKeys) {
            return false;
        }
        if (keyBytes != 16 && keyBytes != 24 && keyBytes != 32) {
            return false;
        }

        uint32_t nk = static_cast<uint32_t>(keyBytes / 4);
        nr = nk + 6;

        uint32_t totalWords = 4 * (nr + 1);

        // --> The first nk words of the schedule are just the key itself (FIPS-197 5.2);
        // nk * 4 == keyBytes exactly, since keyBytes is always a multiple of 4.
        std::memcpy(roundKeys, key, keyBytes);

        uint8_t temp[4];
        for (uint32_t i = nk; i < totalWords; ++i) {
            temp[0] = roundKeys[4 * (i - 1) + 0];
            temp[1] = roundKeys[4 * (i - 1) + 1];
            temp[2] = roundKeys[4 * (i - 1) + 2];
            temp[3] = roundKeys[4 * (i - 1) + 3];

            if (i % nk == 0) {
                uint8_t t0 = temp[0];
                temp[0] = static_cast<uint8_t>(SBOX[temp[1]] ^ RCON[i / nk]);
                temp[1] = SBOX[temp[2]];
                temp[2] = SBOX[temp[3]];
                temp[3] = SBOX[t0];
            } else if (nk > 6 && i % nk == 4) {
                temp[0] = SBOX[temp[0]];
                temp[1] = SBOX[temp[1]];
                temp[2] = SBOX[temp[2]];
                temp[3] = SBOX[temp[3]];
            }

            roundKeys[4 * i + 0] = static_cast<uint8_t>(roundKeys[4 * (i - nk) + 0] ^ temp[0]);
            roundKeys[4 * i + 1] = static_cast<uint8_t>(roundKeys[4 * (i - nk) + 1] ^ temp[1]);
            roundKeys[4 * i + 2] = static_cast<uint8_t>(roundKeys[4 * (i - nk) + 2] ^ temp[2]);
            roundKeys[4 * i + 3] = static_cast<uint8_t>(roundKeys[4 * (i - nk) + 3] ^ temp[3]);
        }

        return true;
    }

    /* Expands a key into a growable array. */
    bool AesCore::expandKey(const uint8_t* key, size_t keyBytes, TArray<uint8_t>& roundKeys, uint32_t& nr) {
        nr = 0;
        roundKeys.clear();

        if (keyBytes != 16 && keyBytes != 24 && keyBytes != 32) {
            return false;
        }

        roundKeys.resize(16 * (keyBytes / 4 + 7));
        return expandKey(key, keyBytes, roundKeys.begin(), nr);
    }

    /* Encrypts one block with the portable round functions. */
    void AesCore::encryptBlockPortable(const uint8_t in[16], uint8_t out[16], const uint8_t* roundKeys, uint32_t nr) {
        uint8_t state[16];
        std::memcpy(state, in, 16);

        addRoundKey(state, roundKeys);
        for (uint32_t round = 1; round < nr; ++round) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys + round * 16);
        }
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys + nr * 16);

        std::memcpy(out, state, 16);
    }

    /* Decrypts one block with the portable round functions. */
    void AesCore::decryptBlockPortable(const uint8_t in[16], uint8_t out[16], const uint8_t* roundKeys, uint32_t nr) {
        uint8_t state[16];
        std::memcpy(state, in, 16);

        addRoundKey(state, roundKeys + nr * 16);
        for (uint32_t round = nr - 1; round >= 1; --round) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, roundKeys + round * 16);
            invMixColumns(state);
        }
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, roundKeys);

        std::memcpy(out, state, 16);
    }

    /* Encrypts one 16-byte block, dispatching to AES-NI when the build supports it and this CPU
     * actually has it, otherwise the portable round functions above. */
    void AesCore::encryptBlock(const uint8_t in[16], uint8_t out[16], const uint8_t* roundKeys, uint32_t nr) {
#if defined(CERTPP_AES_HWACCEL_AVAILABLE)
        if (cpuHasAesNi()) {
            encryptBlockAccelerated(in, out, roundKeys, nr);
            return;
        }
#endif
        encryptBlockPortable(in, out, roundKeys, nr);
    }

    /* Decrypts one 16-byte block -- see encryptBlock()'s dispatch rationale. */
    void AesCore::decryptBlock(const uint8_t in[16], uint8_t out[16], const uint8_t* roundKeys, uint32_t nr) {
#if defined(CERTPP_AES_HWACCEL_AVAILABLE)
        if (cpuHasAesNi()) {
            decryptBlockAccelerated(in, out, roundKeys, nr);
            return;
        }
#endif
        decryptBlockPortable(in, out, roundKeys, nr);
    }

    bool AesCore::hasAesNi() {
#if defined(CERTPP_AES_HWACCEL_AVAILABLE)
        return cpuHasAesNi();
#else
        return false;
#endif
    }

    /* The bulk loop. Structure is the same as encryptBlockAccelerated() called per block,
     * with one important difference: the chaining value stays in a
     * register from block to block instead of being written to the caller's chain buffer and
     * read back for the next block. That is one load and one store per block rather than two
     * of each, and on a serial chain -- where block N+1 cannot begin until block N's output
     * exists -- those extra memory operations are pure addition to the critical path.
     *
     * The round keys stay in registers for as long as they fit; AES-256's fifteen of them
     * exceed the register file, so the last few are read per block. Round keys are public
     * data (a key schedule, not secret), so reading them repeatedly leaks nothing.
     *
     * CbcTransformer passes safe whole-block input directly to this function rather than first
     * copying it into its staging buffer. The output of the direct and buffered paths is held
     * identical by tests/crypto/syms/aes.cpp, which compares this
     * against AesCore::encryptBlockPortable() -- see the note on encryptCbcBulk() in
     * aescore.hpp for why a round-trip is not sufficient for that.
     *
     * Without AES-NI this is the per-block loop below, which is why the caller need not
     * check -- a caller that does not know whether AES-NI is available gets correct output
     * either way. */
#if defined(CERTPP_AES_HWACCEL_AVAILABLE) && \
    (defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER)))
        __attribute__((target("aes,sse2")))
#endif
    void AesCore::encryptCbcBulk(
        const uint8_t* in, uint8_t* out, size_t blocks, uint8_t* chain,
        const uint8_t* roundKeys, uint32_t nr
    ) {
#if defined(CERTPP_AES_HWACCEL_AVAILABLE)
        if (cpuHasAesNi()) {
            __m128i chainVec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(chain));

            __m128i k0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys));
            __m128i k1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys + 16));
            __m128i k2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys + 32));
            __m128i k3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys + 48));
            const __m128i* rest = reinterpret_cast<const __m128i*>(roundKeys + 64);
            const __m128i lastRk =
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(roundKeys + nr * 16));

            for (size_t b = 0; b < blocks; ++b) {
                __m128i state = _mm_loadu_si128(
                    reinterpret_cast<const __m128i*>(in + b * 16));
                state = _mm_xor_si128(state, chainVec);
                state = _mm_xor_si128(state, k0);

                state = _mm_aesenc_si128(state, k1);
                state = _mm_aesenc_si128(state, k2);
                state = _mm_aesenc_si128(state, k3);

                for (uint32_t r = 4; r < nr; ++r) {
                    state = _mm_aesenc_si128(state, rest[r - 4]);
                }

                state = _mm_aesenclast_si128(state, lastRk);

                _mm_storeu_si128(reinterpret_cast<__m128i*>(out + b * 16), state);
                chainVec = state;
            }

            _mm_storeu_si128(reinterpret_cast<__m128i*>(chain), chainVec);
            return;
        }
#endif
        /* No AES-NI: the per-block path, which is what the header promises. The caller
         * already declines to supply a bulk function in this case, so this is unreachable in
         * practice -- but a documented fallback that silently produces nothing would turn
         * any future caller that forgets to check into silent data loss, which is not a
         * trade worth the few lines saved. */
        uint8_t running[16];
        std::memcpy(running, chain, BLOCK_BYTES);

        for (size_t b = 0; b < blocks; ++b) {
            uint8_t blockIn[16];
            for (size_t i = 0; i < BLOCK_BYTES; ++i) {
                blockIn[i] = uint8_t(in[b * BLOCK_BYTES + i] ^ running[i]);
            }
            encryptBlock(blockIn, out + b * BLOCK_BYTES, roundKeys, nr);
            std::memcpy(running, out + b * BLOCK_BYTES, BLOCK_BYTES);
        }

        std::memcpy(chain, running, BLOCK_BYTES);
    }

    /* Applies AES-CTR to complete blocks. */
    void AesCore::xorCtrBulk(
        const uint8_t* in, uint8_t* out, size_t blocks, uint8_t counter[16],
        const uint8_t* roundKeys, uint32_t nr
    ) {
        auto storeCounter = [](uint8_t* outCounter, uint32_t value) {
            outCounter[0] = uint8_t(value >> 24);
            outCounter[1] = uint8_t(value >> 16);
            outCounter[2] = uint8_t(value >> 8);
            outCounter[3] = uint8_t(value);
        };
        uint32_t counterValue = (uint32_t(counter[12]) << 24)
            | (uint32_t(counter[13]) << 16) | (uint32_t(counter[14]) << 8)
            | uint32_t(counter[15]);

        size_t offset = 0;
#if defined(CERTPP_AES_HWACCEL_AVAILABLE)
        if (cpuHasAesNi()) {
#if defined(CERTPP_AES_VAES_AVAILABLE)
            const bool useVaes256 = cpuHasVaes256();
            const bool useVaes512 = cpuHasVaes512();
            while (useVaes512 && blocks - offset >= 16) {
                xorCtr16Vaes512(
                    in + offset * BLOCK_BYTES, out + offset * BLOCK_BYTES,
                    counter, counterValue, roundKeys, nr);
                counterValue += 16;
                offset += 16;
            }
#endif
            while (blocks - offset >= 8) {
#if defined(CERTPP_AES_VAES_AVAILABLE)
                if (useVaes256) {
                    xorCtr8Vaes256(
                        in + offset * BLOCK_BYTES, out + offset * BLOCK_BYTES,
                        counter, counterValue, roundKeys, nr);
                } else
#endif
                {
                    uint8_t counters[8][16];
                    for (size_t lane = 0; lane < 8; ++lane) {
                        std::memcpy(counters[lane], counter, BLOCK_BYTES);
                        storeCounter(
                            counters[lane] + 12, counterValue + uint32_t(lane));
                    }
                    xorCtr8Accelerated(
                    in + offset * BLOCK_BYTES, out + offset * BLOCK_BYTES,
                    counters, roundKeys, nr);
                }
                counterValue += 8;
                offset += 8;
            }
            while (blocks - offset >= 4) {
                uint8_t counters[4][16];
                for (size_t lane = 0; lane < 4; ++lane) {
                    std::memcpy(counters[lane], counter, BLOCK_BYTES);
                    storeCounter(counters[lane] + 12, counterValue + uint32_t(lane));
                }
                xorCtr4Accelerated(
                    in + offset * BLOCK_BYTES, out + offset * BLOCK_BYTES,
                    counters, roundKeys, nr);
                counterValue += 4;
                offset += 4;
            }
        }
#endif

        uint8_t stream[BLOCK_BYTES];
        while (offset < blocks) {
            storeCounter(counter + 12, counterValue);
            encryptBlock(counter, stream, roundKeys, nr);
            for (size_t i = 0; i < BLOCK_BYTES; ++i) {
                out[offset * BLOCK_BYTES + i] =
                    uint8_t(in[offset * BLOCK_BYTES + i] ^ stream[i]);
            }
            ++counterValue;
            ++offset;
        }
        storeCounter(counter + 12, counterValue);
        CSecure::zero(SByteSpan(stream, sizeof(stream)));
    }

} // namespace crypto
} // namespace certpp
