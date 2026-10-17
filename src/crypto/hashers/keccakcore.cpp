#include "keccakcore.hpp"
#include <certpp/arch.hpp>
#include <cstring>
#if defined(CERTPP_ARCH_HAS_ANDN) || defined(CERTPP_ARCH_HAS_AVX512F)
#include <immintrin.h>
#endif
#if defined(CERTPP_ARCH_HAS_ANDN)
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

/* Whether a Keccak lane can be read straight out of the state buffer as it sits in memory.
 *
 * Keccak lanes are little-endian 64-bit words, so on a little-endian host the eight bytes of a
 * lane are already in lane order and the "conversion" is a copy. GCC and Clang define __BYTE_ORDER__;
 * MSVC has no such macro, because every target it has ever had -- x86, x64, ARM64 -- is little-endian,
 * so there is no big-endian Windows for it to name. */
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        #define CERTPP_KECCAK_HOST_LITTLE_ENDIAN 1
    #endif
#elif defined(_MSC_VER) || defined(_WIN32)
    #define CERTPP_KECCAK_HOST_LITTLE_ENDIAN 1
#endif

namespace certpp {
namespace crypto {

#if defined(CERTPP_ARCH_HAS_ANDN)
        /* Whether this CPU has BMI1 (CPUID.7.0:EBX.BMI1, bit 3). Computed once, like every other
         * guarded static in this library. */
        bool hasBmi() {
            static const bool supported = [] {
#if defined(_MSC_VER)
                int info[4] = { 0, 0, 0, 0 };
                __cpuidex(info, 7, 0);
                return (info[1] & (1 << 3)) != 0;
#else
                unsigned int eax, ebx, ecx, edx;
                if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
                    return false;
                }
                return (ebx & (1u << 3)) != 0;
#endif
            }();
            return supported;
        }

        /* dest = (~src1) & src2, in one instruction where BMI1 exists and as the pair elsewhere.
         *
         * Inline assembly rather than the compiler's own encoding of the same expression, because
         * the instruction *is* the point: chi's `~b1 & b2` compiles to notq-then-andq, two
         * instructions, and ANDN is that function in one. Measured on f1600: 408 instructions as
         * the pair, 354 with ANDN, and permute() 460.2 ns against 394.6 ns, -14.3%.
         *
         * The operand order in AT&T is reversed against Intel's, so %2 is src1 and %1 is src2.
         * Checked against the plain expression over every discriminating pair and 200,000 random
         * pairs, since a swapped order is a different function that no commutative identity would
         * reveal.
         *
         * `__attribute__((target(...)))` on this helper alone makes GCC/Clang refuse to inline it
         * into f1600(), which has no such attribute -- and 25 chi steps a round for 24 rounds means
         * 600 real calls, which is how the first attempt at this made f1600 861 instructions
         * instead of 354. So the attribute goes on the whole round loop instead, via
         * f1600Rounds<true>() below, and this helper is compiled as part of that. MSVC needs no
         * attribute at all -- see the same note on ghash.cpp's reverseBitsInBytesGfni() -- because
         * it exposes the BMI intrinsics without one. */
        inline uint64_t andn64(uint64_t a, uint64_t b) {
#if defined(__GNUC__) || defined(__clang__)
            uint64_t r;
            __asm__("andn %1, %2, %0" : "=r"(r) : "r"(b), "r"(a));
            return r;
#else
            return _andn_u64(a, b);
#endif
        }
#endif // CERTPP_ARCH_HAS_ANDN

#if defined(CERTPP_ARCH_HAS_AVX512F)
        bool hasAvx512Keccak() {
            static const bool supported = __builtin_cpu_supports("avx512f")
                && __builtin_cpu_supports("avx512vl");
            return supported;
        }

        /* Keeps all 25 lanes in the 32-register AVX-512 file. The in-place rho/pi cycle needs
         * only one temporary, while ternary logic reduces every five-input theta parity to two
         * instructions and every chi lane to one. */
        __attribute__((target("avx512f,avx512vl")))
        void f1600RoundsAvx512(uint64_t state[25]) {
            static constexpr uint64_t ROUND_CONSTANTS[24] = {
                0x0000000000000001ull, 0x0000000000008082ull,
                0x800000000000808Aull, 0x8000000080008000ull,
                0x000000000000808Bull, 0x0000000080000001ull,
                0x8000000080008081ull, 0x8000000000008009ull,
                0x000000000000008Aull, 0x0000000000000088ull,
                0x0000000080008009ull, 0x000000008000000Aull,
                0x000000008000808Bull, 0x800000000000008Bull,
                0x8000000000008089ull, 0x8000000000008003ull,
                0x8000000000008002ull, 0x8000000000000080ull,
                0x000000000000800Aull, 0x800000008000000Aull,
                0x8000000080008081ull, 0x8000000000008080ull,
                0x0000000080000001ull, 0x8000000080008008ull,
            };

#define CERTPP_KECCAK_LOAD(index) \
            __m128i a##index = _mm_cvtsi64_si128(static_cast<long long>(state[index]))
            CERTPP_KECCAK_LOAD(0);  CERTPP_KECCAK_LOAD(1);  CERTPP_KECCAK_LOAD(2);
            CERTPP_KECCAK_LOAD(3);  CERTPP_KECCAK_LOAD(4);  CERTPP_KECCAK_LOAD(5);
            CERTPP_KECCAK_LOAD(6);  CERTPP_KECCAK_LOAD(7);  CERTPP_KECCAK_LOAD(8);
            CERTPP_KECCAK_LOAD(9);  CERTPP_KECCAK_LOAD(10); CERTPP_KECCAK_LOAD(11);
            CERTPP_KECCAK_LOAD(12); CERTPP_KECCAK_LOAD(13); CERTPP_KECCAK_LOAD(14);
            CERTPP_KECCAK_LOAD(15); CERTPP_KECCAK_LOAD(16); CERTPP_KECCAK_LOAD(17);
            CERTPP_KECCAK_LOAD(18); CERTPP_KECCAK_LOAD(19); CERTPP_KECCAK_LOAD(20);
            CERTPP_KECCAK_LOAD(21); CERTPP_KECCAK_LOAD(22); CERTPP_KECCAK_LOAD(23);
            CERTPP_KECCAK_LOAD(24);
#undef CERTPP_KECCAK_LOAD

#define CERTPP_KECCAK_COLUMN_PARITY(out, v0, v1, v2, v3, v4) do { \
            (out) = _mm_ternarylogic_epi64((v0), (v1), (v2), 0x96); \
            (out) = _mm_ternarylogic_epi64((out), (v3), (v4), 0x96); \
        } while (false)
#define CERTPP_KECCAK_APPLY_COLUMN(delta, v0, v1, v2, v3, v4) do { \
            (v0) = _mm_xor_si128((v0), (delta)); \
            (v1) = _mm_xor_si128((v1), (delta)); \
            (v2) = _mm_xor_si128((v2), (delta)); \
            (v3) = _mm_xor_si128((v3), (delta)); \
            (v4) = _mm_xor_si128((v4), (delta)); \
        } while (false)
#define CERTPP_KECCAK_RHOPI(target, rotation) do { \
            const __m128i next = (target); \
            (target) = _mm_rol_epi64(current, (rotation)); \
            current = next; \
        } while (false)
#define CERTPP_KECCAK_CHI_ROW(v0, v1, v2, v3, v4) do { \
            const __m128i b0 = (v0); \
            const __m128i b1 = (v1); \
            const __m128i b2 = (v2); \
            const __m128i b3 = (v3); \
            const __m128i b4 = (v4); \
            (v0) = _mm_ternarylogic_epi64(b0, b1, b2, 0xD2); \
            (v1) = _mm_ternarylogic_epi64(b1, b2, b3, 0xD2); \
            (v2) = _mm_ternarylogic_epi64(b2, b3, b4, 0xD2); \
            (v3) = _mm_ternarylogic_epi64(b3, b4, b0, 0xD2); \
            (v4) = _mm_ternarylogic_epi64(b4, b0, b1, 0xD2); \
        } while (false)

            for (size_t round = 0; round < 24; ++round) {
                __m128i c0, c1, c2, c3, c4;
                CERTPP_KECCAK_COLUMN_PARITY(c0, a0, a5, a10, a15, a20);
                CERTPP_KECCAK_COLUMN_PARITY(c1, a1, a6, a11, a16, a21);
                CERTPP_KECCAK_COLUMN_PARITY(c2, a2, a7, a12, a17, a22);
                CERTPP_KECCAK_COLUMN_PARITY(c3, a3, a8, a13, a18, a23);
                CERTPP_KECCAK_COLUMN_PARITY(c4, a4, a9, a14, a19, a24);

                const __m128i d0 = _mm_xor_si128(c4, _mm_rol_epi64(c1, 1));
                const __m128i d1 = _mm_xor_si128(c0, _mm_rol_epi64(c2, 1));
                const __m128i d2 = _mm_xor_si128(c1, _mm_rol_epi64(c3, 1));
                const __m128i d3 = _mm_xor_si128(c2, _mm_rol_epi64(c4, 1));
                const __m128i d4 = _mm_xor_si128(c3, _mm_rol_epi64(c0, 1));
                CERTPP_KECCAK_APPLY_COLUMN(d0, a0, a5, a10, a15, a20);
                CERTPP_KECCAK_APPLY_COLUMN(d1, a1, a6, a11, a16, a21);
                CERTPP_KECCAK_APPLY_COLUMN(d2, a2, a7, a12, a17, a22);
                CERTPP_KECCAK_APPLY_COLUMN(d3, a3, a8, a13, a18, a23);
                CERTPP_KECCAK_APPLY_COLUMN(d4, a4, a9, a14, a19, a24);

                __m128i current = a1;
                CERTPP_KECCAK_RHOPI(a10, 1);  CERTPP_KECCAK_RHOPI(a7, 3);
                CERTPP_KECCAK_RHOPI(a11, 6);  CERTPP_KECCAK_RHOPI(a17, 10);
                CERTPP_KECCAK_RHOPI(a18, 15); CERTPP_KECCAK_RHOPI(a3, 21);
                CERTPP_KECCAK_RHOPI(a5, 28);  CERTPP_KECCAK_RHOPI(a16, 36);
                CERTPP_KECCAK_RHOPI(a8, 45);  CERTPP_KECCAK_RHOPI(a21, 55);
                CERTPP_KECCAK_RHOPI(a24, 2);  CERTPP_KECCAK_RHOPI(a4, 14);
                CERTPP_KECCAK_RHOPI(a15, 27); CERTPP_KECCAK_RHOPI(a23, 41);
                CERTPP_KECCAK_RHOPI(a19, 56); CERTPP_KECCAK_RHOPI(a13, 8);
                CERTPP_KECCAK_RHOPI(a12, 25); CERTPP_KECCAK_RHOPI(a2, 43);
                CERTPP_KECCAK_RHOPI(a20, 62); CERTPP_KECCAK_RHOPI(a14, 18);
                CERTPP_KECCAK_RHOPI(a22, 39); CERTPP_KECCAK_RHOPI(a9, 61);
                CERTPP_KECCAK_RHOPI(a6, 20);  CERTPP_KECCAK_RHOPI(a1, 44);

                CERTPP_KECCAK_CHI_ROW(a0, a1, a2, a3, a4);
                CERTPP_KECCAK_CHI_ROW(a5, a6, a7, a8, a9);
                CERTPP_KECCAK_CHI_ROW(a10, a11, a12, a13, a14);
                CERTPP_KECCAK_CHI_ROW(a15, a16, a17, a18, a19);
                CERTPP_KECCAK_CHI_ROW(a20, a21, a22, a23, a24);
                a0 = _mm_xor_si128(a0, _mm_cvtsi64_si128(
                    static_cast<long long>(ROUND_CONSTANTS[round])));
            }

#undef CERTPP_KECCAK_CHI_ROW
#undef CERTPP_KECCAK_RHOPI
#undef CERTPP_KECCAK_APPLY_COLUMN
#undef CERTPP_KECCAK_COLUMN_PARITY
#define CERTPP_KECCAK_STORE(index) \
            state[index] = static_cast<uint64_t>(_mm_cvtsi128_si64(a##index))
            CERTPP_KECCAK_STORE(0);  CERTPP_KECCAK_STORE(1);  CERTPP_KECCAK_STORE(2);
            CERTPP_KECCAK_STORE(3);  CERTPP_KECCAK_STORE(4);  CERTPP_KECCAK_STORE(5);
            CERTPP_KECCAK_STORE(6);  CERTPP_KECCAK_STORE(7);  CERTPP_KECCAK_STORE(8);
            CERTPP_KECCAK_STORE(9);  CERTPP_KECCAK_STORE(10); CERTPP_KECCAK_STORE(11);
            CERTPP_KECCAK_STORE(12); CERTPP_KECCAK_STORE(13); CERTPP_KECCAK_STORE(14);
            CERTPP_KECCAK_STORE(15); CERTPP_KECCAK_STORE(16); CERTPP_KECCAK_STORE(17);
            CERTPP_KECCAK_STORE(18); CERTPP_KECCAK_STORE(19); CERTPP_KECCAK_STORE(20);
            CERTPP_KECCAK_STORE(21); CERTPP_KECCAK_STORE(22); CERTPP_KECCAK_STORE(23);
            CERTPP_KECCAK_STORE(24);
#undef CERTPP_KECCAK_STORE
        }
#endif

        /* The 24 rounds of theta/rho/pi/chi/iota, templated on whether chi can use ANDN.
         *
         * Templated rather than branching inside the loop, so the compiler generates one body per
         * instantiation and the `useAndn` test disappears -- a branch per lane is 600 tests per
         * block and defeats the point. The template parameter is what decides which instantiation
         * an outer call gets. */
        template <bool UseAndn>
        static void f1600Rounds(uint64_t a[25]) {
        /* Keccak-f[1600]'s 24 round constants (FIPS 202 3.2.5), applied to lane (0, 0) at the
         * end of each round. */
        static constexpr uint64_t ROUND_CONSTANTS[24] = {
            0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808Aull, 0x8000000080008000ull,
            0x000000000000808Bull, 0x0000000080000001ull, 0x8000000080008081ull, 0x8000000000008009ull,
            0x000000000000008Aull, 0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000Aull,
            0x000000008000808Bull, 0x800000000000008Bull, 0x8000000000008089ull, 0x8000000000008003ull,
            0x8000000000008002ull, 0x8000000000000080ull, 0x000000000000800Aull, 0x800000008000000Aull,
            0x8000000080008081ull, 0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull
        };

        /* Keccak-f[1600]'s per-lane rotation offsets (FIPS 202 3.2.2), indexed [y][x] (note the
         * order: this literal reads naturally row-by-row as "all r[x][0] for x=0..4", "all
         * r[x][1] for x=0..4", etc. -- i.e. row i is the y=i slice) with lane(x, y) at flat
         * index x + 5*y. */
        static constexpr int ROTATION_OFFSETS[5][5] = {
            {  0,  1, 62, 28, 27 },
            { 36, 44,  6, 55, 20 },
            {  3, 10, 43, 25, 39 },
            { 41, 45, 15, 21,  8 },
            { 18,  2, 61, 56, 14 }
        };

        /* Whether chi uses ANDN is decided by which instantiation is called, not by a test inside
         * the loop: chi runs 25 times a round and a block is 24 rounds, so a branch per lane would
         * be 600 tests where none is needed. Templating makes `UseAndn` a constant within each
         * instantiation, so the dead branch disappears entirely. */
        (void)UseAndn;

        // The same rotate KeccakCore::rotl64() does, repeated here because a member of a private
        // header class is not visible to a free function template in this translation unit.
        const auto rotl = [](uint64_t v, int n) {
            return n == 0 ? v : (v << n) | (v >> (64 - n));
        };

        for (size_t round = 0; round < 24; ++round) {
            // Theta
            uint64_t c[5];
            for (size_t x = 0; x < 5; ++x) {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }

            uint64_t d[5];
            for (size_t x = 0; x < 5; ++x) {
                d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
            }

            for (size_t x = 0; x < 5; ++x) {
                for (size_t y = 0; y < 5; ++y) {
                    a[x + 5 * y] ^= d[x];
                }
            }

            // Rho + Pi: b[y][2x+3y mod 5] = rotl(a[x][y], r[x][y])
            uint64_t b[25];
            for (size_t x = 0; x < 5; ++x) {
                for (size_t y = 0; y < 5; ++y) {
                    size_t newX = y;
                    size_t newY = (2 * x + 3 * y) % 5;
                    b[newX + 5 * newY] = rotl(a[x + 5 * y], ROTATION_OFFSETS[y][x]);
                }
            }

            // Chi: (~b[x+1]) & b[x+2] is andn64() where BMI1 exists -- one instruction where
            // the plain form is two, measured at 14.3% of the permutation.
            for (size_t x = 0; x < 5; ++x) {
                for (size_t y = 0; y < 5; ++y) {
                    uint64_t term;
                    if constexpr (UseAndn) {
                        term = andn64(b[(x + 1) % 5 + 5 * y], b[(x + 2) % 5 + 5 * y]);
                    } else {
                        term = (~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y];
                    }
                    a[x + 5 * y] = b[x + 5 * y] ^ term;
                }
            }

            // Iota
            a[0] ^= ROUND_CONSTANTS[round];
        }
        } // end f1600Rounds

#if defined(CERTPP_ARCH_HAS_ANDN)
        /* The BMI1-enabled instantiation.
         *
         * The attribute has to sit here, on the instantiation, rather than on f1600() or on
         * andn64() itself. On f1600() it would make the whole function BMI-only; on andn64() it
         * stops GCC inlining it, which is what the first attempt did and which cost 600 real
         * calls -- f1600 went from 408 instructions to 861. A template instantiation carries its
         * own target set in GCC, so this one is compiled with BMI1 enabled and the ANDN inside
         * it inlines. MSVC takes the plain path: it exposes the BMI intrinsics without needing an
         * attribute at all, so there is nothing to say. */
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("bmi")))
#endif
        void f1600RoundsAndn(uint64_t a[25]) {
            f1600Rounds<true>(a);
        }
#endif

    /* Applies the Keccak-f[1600] permutation (24 rounds of theta/rho/pi/chi/iota) to a 1600-bit
     * state, given as 25 64-bit lanes, lane(x, y) at a[x + 5*y]. */
    void KeccakCore::f1600(uint64_t a[25]) {
#if defined(CERTPP_ARCH_HAS_AVX512F)
        if (hasAvx512Keccak()) {
            f1600RoundsAvx512(a);
            return;
        }
#endif
#if defined(CERTPP_ARCH_HAS_ANDN)
        if (hasBmi()) {
            f1600RoundsAndn(a);
            return;
        }
#endif
        f1600Rounds<false>(a);
    }

    void KeccakCore::permute(uint8_t state[STATE_BYTES]) {
        uint64_t lanes[25];

        // --> Byte-oriented, because Keccak lanes are little-endian 64-bit words regardless of host
        // endianness -- which on a little-endian host is not a conversion at all. Measured: this
        // packing costs ~484 of permute()'s 892 instructions even after GCC auto-vectorises the
        // loop into an SSE transpose, and ~50 as the copy it really is. On a big-endian host the
        // byte order has to be reversed, so that case keeps the loop and does not get a copy.
#if defined(CERTPP_KECCAK_HOST_LITTLE_ENDIAN)
        for (size_t i = 0; i < 25; ++i) {
            std::memcpy(&lanes[i], state + i * 8, sizeof(uint64_t));
        }
#else
        for (size_t i = 0; i < 25; ++i) {
            uint64_t lane = 0;
            for (size_t b = 0; b < 8; ++b) {
                lane |= uint64_t(state[i * 8 + b]) << (8 * b);
            }
            lanes[i] = lane;
        }
#endif

        f1600(lanes);

#if defined(CERTPP_KECCAK_HOST_LITTLE_ENDIAN)
        for (size_t i = 0; i < 25; ++i) {
            std::memcpy(state + i * 8, &lanes[i], sizeof(uint64_t));
        }
#else
        for (size_t i = 0; i < 25; ++i) {
            for (size_t b = 0; b < 8; ++b) {
                state[i * 8 + b] = uint8_t(lanes[i] >> (8 * b));
            }
        }
#endif
    }

    void KeccakCore::absorbBlock(uint8_t state[STATE_BYTES], const uint8_t* src, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            state[i] ^= src[i];
        }

        permute(state);
    }

} // namespace crypto
} // namespace certpp
