#include <certpp/crypto/hashers/md5.hpp>
#include <certpp/arch.hpp>
#include <cstring>

#if defined(CERTPP_ARCH_HAS_AVX512F)
#define CERTPP_MD5_AVX512 1
#include <immintrin.h>
#endif

#if defined(CERTPP_ARCH_HAS_ANDN) && !defined(_MSC_VER) && \
    (defined(__clang__) || defined(__GNUC__))
#define CERTPP_MD5_BMI1 1
#endif

namespace certpp {
namespace crypto {

    namespace {

        /* Round constants: floor(abs(sin(i + 1)) * 2^32), for i in [0, 64). */
        constexpr uint32_t MD5_K[64] = {
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

        inline uint32_t loadMd5Le32(const uint8_t* src) {
            uint32_t value;
            std::memcpy(&value, src, sizeof(value));
            return value;
        }

#if defined(CERTPP_MD5_BMI1)
        bool hasBmi1Md5() {
            static const bool supported = __builtin_cpu_supports("bmi");
            return supported;
        }

        /* Keep the four working words in the natural x86 accumulator registers and read message
         * words directly from L1. Clang's otherwise equivalent C expansion keeps all sixteen
         * words live for later rounds and spills them under the Windows x64 register set. The
         * explicit schedule also lets LEA combine the round constant with the Boolean value. */
        __attribute__((target("bmi,no-bmi2")))
        void transformMd5Bmi1Blocks(uint32_t* __restrict state,
                                    const uint8_t* __restrict block,
                                    size_t blocks) {
            uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
            while (blocks-- != 0) {
                uint32_t word, temp, oldA, oldB, oldC, oldD;

#define CERTPP_MD5_ASM_F(dst, p, q, r, addend, next, constant, shift) \
        "xorl %[" #q "], %[temp]\n\t" \
        "leal " #constant "(%[" #dst "],%[word]), %[" #dst "]\n\t" \
        "andl %[" #p "], %[temp]\n\t" \
        "movl " #next "*4(%[data]), %[word]\n\t" \
        "xorl %[" #r "], %[temp]\n\t" \
        "addl %[temp], %[" #dst "]\n\t" \
        "roll $" #shift ", %[" #dst "]\n\t" \
        "movl %[" #q "], %[temp]\n\t" \
        "addl %[" #addend "], %[" #dst "]\n\t"
#define CERTPP_MD5_ASM_H(dst, p, q, r, addend, next, constant, shift) \
        "leal " #constant "(%[" #dst "],%[word]), %[" #dst "]\n\t" \
        "xorl %[" #r "], %[temp]\n\t" \
        "movl " #next "*4(%[data]), %[word]\n\t" \
        "xorl %[" #p "], %[temp]\n\t" \
        "addl %[temp], %[" #dst "]\n\t" \
        "movl %[" #p "], %[temp]\n\t" \
        "roll $" #shift ", %[" #dst "]\n\t" \
        "addl %[" #addend "], %[" #dst "]\n\t"
#define CERTPP_MD5_ASM_I(dst, p, q, r, addend, next, constant, shift) \
        "leal " #constant "(%[" #dst "],%[word]), %[" #dst "]\n\t" \
        "orl %[" #p "], %[temp]\n\t" \
        "movl " #next "*4(%[data]), %[word]\n\t" \
        "xorl %[" #q "], %[temp]\n\t" \
        "addl %[temp], %[" #dst "]\n\t" \
        "movl $-1, %[temp]\n\t" \
        "roll $" #shift ", %[" #dst "]\n\t" \
        "xorl %[" #q "], %[temp]\n\t" \
        "addl %[" #addend "], %[" #dst "]\n\t"

                __asm__ volatile(
                    "movl %[a], %[oldA]\n\t"
                    "movl %[b], %[oldB]\n\t"
                    "movl %[c], %[oldC]\n\t"
                    "movl %[d], %[oldD]\n\t"
                    "movl 0(%[data]), %[word]\n\t"
                    "movl %[d], %[temp]\n\t"
                    CERTPP_MD5_ASM_F(a, b, c, d, b,  1, 0xd76aa478,  7)
                    CERTPP_MD5_ASM_F(d, a, b, c, a,  2, 0xe8c7b756, 12)
                    CERTPP_MD5_ASM_F(c, d, a, b, d,  3, 0x242070db, 17)
                    CERTPP_MD5_ASM_F(b, c, d, a, c,  4, 0xc1bdceee, 22)
                    CERTPP_MD5_ASM_F(a, b, c, d, b,  5, 0xf57c0faf,  7)
                    CERTPP_MD5_ASM_F(d, a, b, c, a,  6, 0x4787c62a, 12)
                    CERTPP_MD5_ASM_F(c, d, a, b, d,  7, 0xa8304613, 17)
                    CERTPP_MD5_ASM_F(b, c, d, a, c,  8, 0xfd469501, 22)
                    CERTPP_MD5_ASM_F(a, b, c, d, b,  9, 0x698098d8,  7)
                    CERTPP_MD5_ASM_F(d, a, b, c, a, 10, 0x8b44f7af, 12)
                    CERTPP_MD5_ASM_F(c, d, a, b, d, 11, 0xffff5bb1, 17)
                    CERTPP_MD5_ASM_F(b, c, d, a, c, 12, 0x895cd7be, 22)
                    CERTPP_MD5_ASM_F(a, b, c, d, b, 13, 0x6b901122,  7)
                    CERTPP_MD5_ASM_F(d, a, b, c, a, 14, 0xfd987193, 12)
                    CERTPP_MD5_ASM_F(c, d, a, b, d, 15, 0xa679438e, 17)
                    CERTPP_MD5_ASM_F(b, c, d, a, c,  1, 0x49b40821, 22)

                    "movl %[c], %[temp]\n\t"
                    CERTPP_MD5_ASM_F(a, d, b, c, b,  6, 0xf61e2562,  5)
                    CERTPP_MD5_ASM_F(d, c, a, b, a, 11, 0xc040b340,  9)
                    CERTPP_MD5_ASM_F(c, b, d, a, d,  0, 0x265e5a51, 14)
                    CERTPP_MD5_ASM_F(b, a, c, d, c,  5, 0xe9b6c7aa, 20)
                    CERTPP_MD5_ASM_F(a, d, b, c, b, 10, 0xd62f105d,  5)
                    CERTPP_MD5_ASM_F(d, c, a, b, a, 15, 0x02441453,  9)
                    CERTPP_MD5_ASM_F(c, b, d, a, d,  4, 0xd8a1e681, 14)
                    CERTPP_MD5_ASM_F(b, a, c, d, c,  9, 0xe7d3fbc8, 20)
                    CERTPP_MD5_ASM_F(a, d, b, c, b, 14, 0x21e1cde6,  5)
                    CERTPP_MD5_ASM_F(d, c, a, b, a,  3, 0xc33707d6,  9)
                    CERTPP_MD5_ASM_F(c, b, d, a, d,  8, 0xf4d50d87, 14)
                    CERTPP_MD5_ASM_F(b, a, c, d, c, 13, 0x455a14ed, 20)
                    CERTPP_MD5_ASM_F(a, d, b, c, b,  2, 0xa9e3e905,  5)
                    CERTPP_MD5_ASM_F(d, c, a, b, a,  7, 0xfcefa3f8,  9)
                    CERTPP_MD5_ASM_F(c, b, d, a, d, 12, 0x676f02d9, 14)
                    CERTPP_MD5_ASM_F(b, a, c, d, c,  5, 0x8d2a4c8a, 20)

                    CERTPP_MD5_ASM_H(a, b, c, d, b,  8, 0xfffa3942,  4)
                    CERTPP_MD5_ASM_H(d, a, b, c, a, 11, 0x8771f681, 11)
                    CERTPP_MD5_ASM_H(c, d, a, b, d, 14, 0x6d9d6122, 16)
                    CERTPP_MD5_ASM_H(b, c, d, a, c,  1, 0xfde5380c, 23)
                    CERTPP_MD5_ASM_H(a, b, c, d, b,  4, 0xa4beea44,  4)
                    CERTPP_MD5_ASM_H(d, a, b, c, a,  7, 0x4bdecfa9, 11)
                    CERTPP_MD5_ASM_H(c, d, a, b, d, 10, 0xf6bb4b60, 16)
                    CERTPP_MD5_ASM_H(b, c, d, a, c, 13, 0xbebfbc70, 23)
                    CERTPP_MD5_ASM_H(a, b, c, d, b,  0, 0x289b7ec6,  4)
                    CERTPP_MD5_ASM_H(d, a, b, c, a,  3, 0xeaa127fa, 11)
                    CERTPP_MD5_ASM_H(c, d, a, b, d,  6, 0xd4ef3085, 16)
                    CERTPP_MD5_ASM_H(b, c, d, a, c,  9, 0x04881d05, 23)
                    CERTPP_MD5_ASM_H(a, b, c, d, b, 12, 0xd9d4d039,  4)
                    CERTPP_MD5_ASM_H(d, a, b, c, a, 15, 0xe6db99e5, 11)
                    CERTPP_MD5_ASM_H(c, d, a, b, d,  2, 0x1fa27cf8, 16)
                    CERTPP_MD5_ASM_H(b, c, d, a, c,  0, 0xc4ac5665, 23)

                    "movl $-1, %[temp]\n\t"
                    "xorl %[d], %[temp]\n\t"
                    CERTPP_MD5_ASM_I(a, b, c, d, b,  7, 0xf4292244,  6)
                    CERTPP_MD5_ASM_I(d, a, b, c, a, 14, 0x432aff97, 10)
                    CERTPP_MD5_ASM_I(c, d, a, b, d,  5, 0xab9423a7, 15)
                    CERTPP_MD5_ASM_I(b, c, d, a, c, 12, 0xfc93a039, 21)
                    CERTPP_MD5_ASM_I(a, b, c, d, b,  3, 0x655b59c3,  6)
                    CERTPP_MD5_ASM_I(d, a, b, c, a, 10, 0x8f0ccc92, 10)
                    CERTPP_MD5_ASM_I(c, d, a, b, d,  1, 0xffeff47d, 15)
                    CERTPP_MD5_ASM_I(b, c, d, a, c,  8, 0x85845dd1, 21)
                    CERTPP_MD5_ASM_I(a, b, c, d, b, 15, 0x6fa87e4f,  6)
                    CERTPP_MD5_ASM_I(d, a, b, c, a,  6, 0xfe2ce6e0, 10)
                    CERTPP_MD5_ASM_I(c, d, a, b, d, 13, 0xa3014314, 15)
                    CERTPP_MD5_ASM_I(b, c, d, a, c,  4, 0x4e0811a1, 21)
                    CERTPP_MD5_ASM_I(a, b, c, d, b, 11, 0xf7537e82,  6)
                    CERTPP_MD5_ASM_I(d, a, b, c, a,  2, 0xbd3af235, 10)
                    CERTPP_MD5_ASM_I(c, d, a, b, d,  9, 0x2ad7d2bb, 15)
                    CERTPP_MD5_ASM_I(b, c, d, a, c,  0, 0xeb86d391, 21)
                    "addl %[oldA], %[a]\n\t"
                    "addl %[oldB], %[b]\n\t"
                    "addl %[oldC], %[c]\n\t"
                    "addl %[oldD], %[d]\n\t"
                    : [a] "+&a"(a), [b] "+&b"(b), [c] "+&c"(c), [d] "+&d"(d),
                      [word] "=&r"(word), [temp] "=&r"(temp),
                      [oldA] "=&r"(oldA), [oldB] "=&r"(oldB),
                      [oldC] "=&r"(oldC), [oldD] "=&r"(oldD)
                    : [data] "r"(block)
                    : "cc", "memory"
                );

#undef CERTPP_MD5_ASM_I
#undef CERTPP_MD5_ASM_H
#undef CERTPP_MD5_ASM_F

                block += 64;
            }
            state[0] = a;
            state[1] = b;
            state[2] = c;
            state[3] = d;
        }
#endif

#if defined(CERTPP_MD5_AVX512)
        bool hasAvx512Md5() {
            static const bool supported = __builtin_cpu_supports("avx512f")
                && __builtin_cpu_supports("avx512vl");
            return supported;
        }

#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("avx512f,avx512vl")))
#endif
        void transformMd5Avx512(uint32_t state[4], const uint8_t block[64]) {
            __m128i a = _mm_cvtsi32_si128(static_cast<int>(state[0]));
            __m128i b = _mm_cvtsi32_si128(static_cast<int>(state[1]));
            __m128i c = _mm_cvtsi32_si128(static_cast<int>(state[2]));
            __m128i d = _mm_cvtsi32_si128(static_cast<int>(state[3]));

#define CERTPP_MD5_STEP(x, p, q, r, addend, index, shift, truth) do { \
            const __m128i booleanValue = _mm_ternarylogic_epi32((p), (q), (r), (truth)); \
            const __m128i messageValue = _mm_cvtsi32_si128(static_cast<int>( \
                loadMd5Le32(block + (index) * 4) + MD5_K[stepIndex])); \
            (x) = _mm_add_epi32((addend), _mm_rol_epi32( \
                _mm_add_epi32(_mm_add_epi32((x), booleanValue), messageValue), (shift))); \
            ++stepIndex; \
        } while (false)

            size_t stepIndex = 0;
            CERTPP_MD5_STEP(a, b, c, d, b,  0,  7, 0xCA);
            CERTPP_MD5_STEP(d, a, b, c, a,  1, 12, 0xCA);
            CERTPP_MD5_STEP(c, d, a, b, d,  2, 17, 0xCA);
            CERTPP_MD5_STEP(b, c, d, a, c,  3, 22, 0xCA);
            CERTPP_MD5_STEP(a, b, c, d, b,  4,  7, 0xCA);
            CERTPP_MD5_STEP(d, a, b, c, a,  5, 12, 0xCA);
            CERTPP_MD5_STEP(c, d, a, b, d,  6, 17, 0xCA);
            CERTPP_MD5_STEP(b, c, d, a, c,  7, 22, 0xCA);
            CERTPP_MD5_STEP(a, b, c, d, b,  8,  7, 0xCA);
            CERTPP_MD5_STEP(d, a, b, c, a,  9, 12, 0xCA);
            CERTPP_MD5_STEP(c, d, a, b, d, 10, 17, 0xCA);
            CERTPP_MD5_STEP(b, c, d, a, c, 11, 22, 0xCA);
            CERTPP_MD5_STEP(a, b, c, d, b, 12,  7, 0xCA);
            CERTPP_MD5_STEP(d, a, b, c, a, 13, 12, 0xCA);
            CERTPP_MD5_STEP(c, d, a, b, d, 14, 17, 0xCA);
            CERTPP_MD5_STEP(b, c, d, a, c, 15, 22, 0xCA);

            CERTPP_MD5_STEP(a, d, b, c, b,  1,  5, 0xCA);
            CERTPP_MD5_STEP(d, c, a, b, a,  6,  9, 0xCA);
            CERTPP_MD5_STEP(c, b, d, a, d, 11, 14, 0xCA);
            CERTPP_MD5_STEP(b, a, c, d, c,  0, 20, 0xCA);
            CERTPP_MD5_STEP(a, d, b, c, b,  5,  5, 0xCA);
            CERTPP_MD5_STEP(d, c, a, b, a, 10,  9, 0xCA);
            CERTPP_MD5_STEP(c, b, d, a, d, 15, 14, 0xCA);
            CERTPP_MD5_STEP(b, a, c, d, c,  4, 20, 0xCA);
            CERTPP_MD5_STEP(a, d, b, c, b,  9,  5, 0xCA);
            CERTPP_MD5_STEP(d, c, a, b, a, 14,  9, 0xCA);
            CERTPP_MD5_STEP(c, b, d, a, d,  3, 14, 0xCA);
            CERTPP_MD5_STEP(b, a, c, d, c,  8, 20, 0xCA);
            CERTPP_MD5_STEP(a, d, b, c, b, 13,  5, 0xCA);
            CERTPP_MD5_STEP(d, c, a, b, a,  2,  9, 0xCA);
            CERTPP_MD5_STEP(c, b, d, a, d,  7, 14, 0xCA);
            CERTPP_MD5_STEP(b, a, c, d, c, 12, 20, 0xCA);

            CERTPP_MD5_STEP(a, b, c, d, b,  5,  4, 0x96);
            CERTPP_MD5_STEP(d, a, b, c, a,  8, 11, 0x96);
            CERTPP_MD5_STEP(c, d, a, b, d, 11, 16, 0x96);
            CERTPP_MD5_STEP(b, c, d, a, c, 14, 23, 0x96);
            CERTPP_MD5_STEP(a, b, c, d, b,  1,  4, 0x96);
            CERTPP_MD5_STEP(d, a, b, c, a,  4, 11, 0x96);
            CERTPP_MD5_STEP(c, d, a, b, d,  7, 16, 0x96);
            CERTPP_MD5_STEP(b, c, d, a, c, 10, 23, 0x96);
            CERTPP_MD5_STEP(a, b, c, d, b, 13,  4, 0x96);
            CERTPP_MD5_STEP(d, a, b, c, a,  0, 11, 0x96);
            CERTPP_MD5_STEP(c, d, a, b, d,  3, 16, 0x96);
            CERTPP_MD5_STEP(b, c, d, a, c,  6, 23, 0x96);
            CERTPP_MD5_STEP(a, b, c, d, b,  9,  4, 0x96);
            CERTPP_MD5_STEP(d, a, b, c, a, 12, 11, 0x96);
            CERTPP_MD5_STEP(c, d, a, b, d, 15, 16, 0x96);
            CERTPP_MD5_STEP(b, c, d, a, c,  2, 23, 0x96);

            CERTPP_MD5_STEP(a, b, c, d, b,  0,  6, 0x39);
            CERTPP_MD5_STEP(d, a, b, c, a,  7, 10, 0x39);
            CERTPP_MD5_STEP(c, d, a, b, d, 14, 15, 0x39);
            CERTPP_MD5_STEP(b, c, d, a, c,  5, 21, 0x39);
            CERTPP_MD5_STEP(a, b, c, d, b, 12,  6, 0x39);
            CERTPP_MD5_STEP(d, a, b, c, a,  3, 10, 0x39);
            CERTPP_MD5_STEP(c, d, a, b, d, 10, 15, 0x39);
            CERTPP_MD5_STEP(b, c, d, a, c,  1, 21, 0x39);
            CERTPP_MD5_STEP(a, b, c, d, b,  8,  6, 0x39);
            CERTPP_MD5_STEP(d, a, b, c, a, 15, 10, 0x39);
            CERTPP_MD5_STEP(c, d, a, b, d,  6, 15, 0x39);
            CERTPP_MD5_STEP(b, c, d, a, c, 13, 21, 0x39);
            CERTPP_MD5_STEP(a, b, c, d, b,  4,  6, 0x39);
            CERTPP_MD5_STEP(d, a, b, c, a, 11, 10, 0x39);
            CERTPP_MD5_STEP(c, d, a, b, d,  2, 15, 0x39);
            CERTPP_MD5_STEP(b, c, d, a, c,  9, 21, 0x39);

#undef CERTPP_MD5_STEP

            state[0] += static_cast<uint32_t>(_mm_cvtsi128_si32(a));
            state[1] += static_cast<uint32_t>(_mm_cvtsi128_si32(b));
            state[2] += static_cast<uint32_t>(_mm_cvtsi128_si32(c));
            state[3] += static_cast<uint32_t>(_mm_cvtsi128_si32(d));
        }
#endif

    } // namespace

    /* Runs the MD5 compression function over one 64-byte block, updating state in place. */
    void MD5::transform(uint32_t state[4], const uint8_t block[64]) {
#if defined(CERTPP_MD5_BMI1)
        if (hasBmi1Md5()) {
            transformMd5Bmi1Blocks(state, block, 1);
            return;
        }
#endif
#if defined(CERTPP_MD5_AVX512)
        if (hasAvx512Md5()) {
            transformMd5Avx512(state, block);
            return;
        }
#endif
        /* Per-round left-rotate amounts, 4 groups of 4, repeated across the 4 rounds of 16 steps each. */
        static constexpr uint32_t SHIFTS[64] = {
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
        };

        uint32_t m[16];
#if defined(_WIN32) \
    || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
        /* MD5's input words match native byte order here. Besides preserving unaligned access,
         * memcpy prevents GCC from vectorizing the explicit shifts into a much larger unpack
         * network. */
        std::memcpy(m, block, sizeof(m));
#else
        for (size_t i = 0; i < 16; ++i) {
            // --> MD5 packs message words little-endian, unlike the SHA family.
            m[i] = uint32_t(block[i * 4])
                | (uint32_t(block[i * 4 + 1]) << 8)
                | (uint32_t(block[i * 4 + 2]) << 16)
                | (uint32_t(block[i * 4 + 3]) << 24);
        }
#endif

        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

        // The four rounds written out explicitly rather than as one loop with a branch per
        // step. Measured at 1.60x the loop form on this CPU (545 to 341 cycles per block,
        // 8.5 to 5.3 per step), and the gain is the branch plus the modulo: selecting the
        // round function with if/else forces a branch on every one of the 64 steps, and
        // rounds 2--4 compute g with '% 16', which is an integer division. Writing the rounds
        // out removes both -- g becomes a mask against 15, which is a single AND.
        //
        // The per-round index expressions are the original ones re-based to the round's own
        // 16-step range, so '(5 * (i - 16) + 1) & 15' is the same sequence as
        // '(5 * i + 1) % 16' for i in [16, 32).
        for (uint32_t i = 0; i < 16; ++i) {
            uint32_t f = (b & c) | (~b & d);
            f = f + a + MD5_K[i] + m[i];
            a = d;
            d = c;
            c = b;
            b = b + rotl(f, SHIFTS[i]);
        }
        for (uint32_t i = 16; i < 32; ++i) {
            uint32_t f = (d & b) | (~d & c);
            const uint32_t g = (5 * (i - 16) + 1) & 15;
            f = f + a + MD5_K[i] + m[g];
            a = d;
            d = c;
            c = b;
            b = b + rotl(f, SHIFTS[i]);
        }
        for (uint32_t i = 32; i < 48; ++i) {
            uint32_t f = b ^ c ^ d;
            const uint32_t g = (3 * (i - 32) + 5) & 15;
            f = f + a + MD5_K[i] + m[g];
            a = d;
            d = c;
            c = b;
            b = b + rotl(f, SHIFTS[i]);
        }
        for (uint32_t i = 48; i < 64; ++i) {
            uint32_t f = c ^ (b | ~d);
            const uint32_t g = (7 * (i - 48)) & 15;
            f = f + a + MD5_K[i] + m[g];
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

        // --> Consume full blocks directly from the caller's buffer. Check the accelerated
        // feature once per push rather than once per block; large inputs otherwise repeat the
        // dispatch branch for every 64 bytes and lose part of the compression gain.
#if defined(CERTPP_MD5_BMI1)
        if (hasBmi1Md5()) {
            const size_t blocks = remaining / 64;
            transformMd5Bmi1Blocks(_ctx.state, data, blocks);
            const size_t bytes = blocks * 64;
            data += bytes;
            remaining -= bytes;
        } else
#elif defined(CERTPP_MD5_AVX512)
        if (hasAvx512Md5()) {
            while (remaining >= 64) {
                transformMd5Avx512(_ctx.state, data);
                data += 64;
                remaining -= 64;
            }
        } else
#endif
        {
            while (remaining >= 64) {
                transform(_ctx.state, data);
                data += 64;
                remaining -= 64;
            }
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
