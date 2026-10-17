#include "sha2_64core.hpp"

#if defined(CERTPP_ARCH_HAS_AVX512F)
#include <immintrin.h>
#endif

namespace certpp {
namespace crypto {

#if defined(CERTPP_ARCH_HAS_BMI2_ROTR)
        /* Whether this CPU has BMI2 (CPUID.7.0:EBX.BMI2, bit 8). Checked once per block rather
         * than once per rotate: six rotates per round for eighty rounds is 480 reads of a guarded
         * static where one will do -- the same defect already fixed in GHASH this session. */
        bool hasBmi2() {
            static const bool supported = [] {
#if defined(_MSC_VER)
                int info[4] = { 0, 0, 0, 0 };
                __cpuid(info, 7);
                return (info[1] & (1 << 8)) != 0;
#else
                unsigned int eax, ebx, ecx, edx;
                if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
                    return false;
                }
                return (ebx & (1u << 8)) != 0;
#endif

            }();
            return supported;
        }
#endif

#if defined(CERTPP_ARCH_HAS_AVX512F)
        bool hasAvx512Sha2_64() {
            static const bool supported = __builtin_cpu_supports("avx512f")
                && __builtin_cpu_supports("avx512vl");
            return supported;
        }
#endif

    const uint64_t Sha2_64Core::K[80] = {
            0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
            0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
            0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
            0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
            0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
            0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
            0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
            0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
            0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
            0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
            0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
            0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
            0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
            0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
            0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
            0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
            0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
            0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
            0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
            0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
        };

    /* Runs the SHA-384/SHA-512 compression function over one 128-byte block.
     *
     * --> Templated on whether the rotates use BMI2's RORX, so the choice is made once per block
     * rather than once per round, and the BMI2 case is compiled with BMI2 enabled -- which is what
     * lets the target-attributed rotate inline into it. The attribute cannot sit on the rotate
     * itself: GCC refuses to inline a function whose target differs from its caller's, and there
     * would be 480 calls a block instead of none. (This is the second of those this session; the
     * first was Keccak's ANDN.) */
    template <bool UseBmi2Rotr>
    void Sha2_64Core::transformRounds(uint64_t state[8], const uint8_t* block, size_t blocks) {
        (void)UseBmi2Rotr;
        /* Round constants: the first 64 bits of the fractional parts of the cube roots of the
         * first 80 primes. */

        while (blocks-- != 0) {
        /* The recurrence only references the preceding sixteen words, so overwrite the oldest
         * one after it has been consumed instead of materializing all eighty words. */
        uint64_t w[16];
        for (size_t i = 0; i < 16; ++i) {
            // --> SHA-384/SHA-512 pack message words big-endian; loadBe64() is the byte-swap
            // for that, one instruction where this used to be eight loads and seven shift-ors.
            w[i] = loadBe64(block + i * 8);
        }
        uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

        auto round = [](uint64_t& a0, uint64_t& b0, uint64_t& c0, uint64_t& d0,
                        uint64_t& e0, uint64_t& f0, uint64_t& g0, uint64_t& h0,
                        uint64_t word, uint64_t constant) {
            uint64_t s1 = rotr<UseBmi2Rotr>(e0, 14)
                ^ rotr<UseBmi2Rotr>(e0, 18) ^ rotr<UseBmi2Rotr>(e0, 41);

            // --> Ch(e, f, g) == (e & f) ^ (~e & g), which costs a NOT the hardware does not
            // have. The form below is the same function -- g ^ (e & (f ^ g)) -- in three
            // operations and none of them a NOT. Same for Maj: (a & b) ^ (a & c) ^ (b & c) is five
            // operations, ((a | b) & c) | (a & b) is four. Neither changes any output bit; both
            // were measured rather than assumed, since this file has a history of changes of
            // this exact shape costing more than they saved.
            uint64_t ch = g0 ^ (e0 & (f0 ^ g0));
            uint64_t temp1 = h0 + s1 + ch + constant + word;
            uint64_t s0 = rotr<UseBmi2Rotr>(a0, 28)
                ^ rotr<UseBmi2Rotr>(a0, 34) ^ rotr<UseBmi2Rotr>(a0, 39);
            uint64_t maj = ((a0 | b0) & c0) | (a0 & b0);
            uint64_t temp2 = s0 + maj;

            d0 += temp1;
            h0 = temp1 + temp2;
        };

        round(a, b, c, d, e, f, g, h, w[0], K[0]);
        round(h, a, b, c, d, e, f, g, w[1], K[1]);
        round(g, h, a, b, c, d, e, f, w[2], K[2]);
        round(f, g, h, a, b, c, d, e, w[3], K[3]);
        round(e, f, g, h, a, b, c, d, w[4], K[4]);
        round(d, e, f, g, h, a, b, c, w[5], K[5]);
        round(c, d, e, f, g, h, a, b, w[6], K[6]);
        round(b, c, d, e, f, g, h, a, w[7], K[7]);
        round(a, b, c, d, e, f, g, h, w[8], K[8]);
        round(h, a, b, c, d, e, f, g, w[9], K[9]);
        round(g, h, a, b, c, d, e, f, w[10], K[10]);
        round(f, g, h, a, b, c, d, e, w[11], K[11]);
        round(e, f, g, h, a, b, c, d, w[12], K[12]);
        round(d, e, f, g, h, a, b, c, w[13], K[13]);
        round(c, d, e, f, g, h, a, b, w[14], K[14]);
        round(b, c, d, e, f, g, h, a, w[15], K[15]);

        auto expand = [&](size_t index) {
            uint64_t x0 = w[(index + 1) & 15];
            uint64_t x1 = w[(index + 14) & 15];
            uint64_t s0 = rotr<UseBmi2Rotr>(x0, 1)
                ^ rotr<UseBmi2Rotr>(x0, 8) ^ (x0 >> 7);
            uint64_t s1 = rotr<UseBmi2Rotr>(x1, 19)
                ^ rotr<UseBmi2Rotr>(x1, 61) ^ (x1 >> 6);
            w[index] += s0 + w[(index + 9) & 15] + s1;
            return w[index];
        };

        /* Passing the working variables in their next-round order removes the seven register
         * moves that a literal state shift needs after every round. Sixteen calls return the
         * variables to their original names and align with one complete schedule-ring turn. */
        for (size_t first = 16; first < 80; first += 16) {
            round(a, b, c, d, e, f, g, h, expand(0), K[first + 0]);
            round(h, a, b, c, d, e, f, g, expand(1), K[first + 1]);
            round(g, h, a, b, c, d, e, f, expand(2), K[first + 2]);
            round(f, g, h, a, b, c, d, e, expand(3), K[first + 3]);
            round(e, f, g, h, a, b, c, d, expand(4), K[first + 4]);
            round(d, e, f, g, h, a, b, c, expand(5), K[first + 5]);
            round(c, d, e, f, g, h, a, b, expand(6), K[first + 6]);
            round(b, c, d, e, f, g, h, a, expand(7), K[first + 7]);
            round(a, b, c, d, e, f, g, h, expand(8), K[first + 8]);
            round(h, a, b, c, d, e, f, g, expand(9), K[first + 9]);
            round(g, h, a, b, c, d, e, f, expand(10), K[first + 10]);
            round(f, g, h, a, b, c, d, e, expand(11), K[first + 11]);
            round(e, f, g, h, a, b, c, d, expand(12), K[first + 12]);
            round(d, e, f, g, h, a, b, c, expand(13), K[first + 13]);
            round(c, d, e, f, g, h, a, b, expand(14), K[first + 14]);
            round(b, c, d, e, f, g, h, a, expand(15), K[first + 15]);
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
        block += 128;
        }
    }

#if defined(CERTPP_ARCH_HAS_AVX512F)
    /* Uses AVX-512VL ternary logic and rotates in the low 64-bit lane. SHA-512's state chain is
     * serial, but Ch and Maj each collapse to one instruction and every fixed rotate remains
     * non-destructive. The upper lane is deliberately ignored. */
    __attribute__((target("avx512f,avx512vl")))
    void Sha2_64Core::transformRoundsAvx512(uint64_t* __restrict state,
                                            const uint8_t* __restrict block, size_t blocks) {
#define CERTPP_SHA512_ROR(value, count) _mm_ror_epi64((value), (count))
#define CERTPP_SHA512_ROUND(a0, b0, c0, d0, e0, f0, g0, h0, word, index) do { \
        const __m128i wk = _mm_add_epi64((word), \
            _mm_cvtsi64_si128(static_cast<long long>(K[(index)]))); \
        const __m128i s1 = _mm_xor_si128( \
            _mm_xor_si128(CERTPP_SHA512_ROR((e0), 14), CERTPP_SHA512_ROR((e0), 18)), \
            CERTPP_SHA512_ROR((e0), 41)); \
        const __m128i ch = _mm_ternarylogic_epi64((e0), (f0), (g0), 0xCA); \
        const __m128i temp1 = _mm_add_epi64( \
            _mm_add_epi64(_mm_add_epi64((h0), s1), ch), wk); \
        const __m128i s0 = _mm_xor_si128( \
            _mm_xor_si128(CERTPP_SHA512_ROR((a0), 28), CERTPP_SHA512_ROR((a0), 34)), \
            CERTPP_SHA512_ROR((a0), 39)); \
        const __m128i maj = _mm_ternarylogic_epi64((a0), (b0), (c0), 0xE8); \
        const __m128i temp2 = _mm_add_epi64(s0, maj); \
        (d0) = _mm_add_epi64((d0), temp1); \
        (h0) = _mm_add_epi64(temp1, temp2); \
    } while (false)
#define CERTPP_SHA512_PREPARED_ROUND(a0, b0, c0, d0, e0, f0, g0, h0, word) do { \
        const __m128i s1 = _mm_xor_si128( \
            _mm_xor_si128(CERTPP_SHA512_ROR((e0), 14), CERTPP_SHA512_ROR((e0), 18)), \
            CERTPP_SHA512_ROR((e0), 41)); \
        const __m128i ch = _mm_ternarylogic_epi64((e0), (f0), (g0), 0xCA); \
        const __m128i temp1 = _mm_add_epi64( \
            _mm_add_epi64(_mm_add_epi64((h0), s1), ch), (word)); \
        const __m128i s0 = _mm_xor_si128( \
            _mm_xor_si128(CERTPP_SHA512_ROR((a0), 28), CERTPP_SHA512_ROR((a0), 34)), \
            CERTPP_SHA512_ROR((a0), 39)); \
        const __m128i maj = _mm_ternarylogic_epi64((a0), (b0), (c0), 0xE8); \
        const __m128i temp2 = _mm_add_epi64(s0, maj); \
        (d0) = _mm_add_epi64((d0), temp1); \
        (h0) = _mm_add_epi64(temp1, temp2); \
    } while (false)
#define CERTPP_SHA512_EXPAND(index) do { \
        const __m128i x0 = w[((index) + 1) & 15]; \
        const __m128i x1 = w[((index) + 14) & 15]; \
        const __m128i s0 = _mm_xor_si128( \
            _mm_xor_si128(CERTPP_SHA512_ROR(x0, 1), CERTPP_SHA512_ROR(x0, 8)), \
            _mm_srli_epi64(x0, 7)); \
        const __m128i s1 = _mm_xor_si128( \
            _mm_xor_si128(CERTPP_SHA512_ROR(x1, 19), CERTPP_SHA512_ROR(x1, 61)), \
            _mm_srli_epi64(x1, 6)); \
        w[(index)] = _mm_add_epi64(_mm_add_epi64(_mm_add_epi64( \
            w[(index)], s0), w[((index) + 9) & 15]), s1); \
    } while (false)
#define CERTPP_SHA512_EXPAND4(index) do { \
        const __m256i x0 = w4[((index) + 1) & 15]; \
        const __m256i x1 = w4[((index) + 14) & 15]; \
        const __m256i s0 = _mm256_xor_si256( \
            _mm256_xor_si256(_mm256_ror_epi64(x0, 1), _mm256_ror_epi64(x0, 8)), \
            _mm256_srli_epi64(x0, 7)); \
        const __m256i s1 = _mm256_xor_si256( \
            _mm256_xor_si256(_mm256_ror_epi64(x1, 19), _mm256_ror_epi64(x1, 61)), \
            _mm256_srli_epi64(x1, 6)); \
        w4[(index)] = _mm256_add_epi64(_mm256_add_epi64(_mm256_add_epi64( \
            w4[(index)], s0), w4[((index) + 9) & 15]), s1); \
    } while (false)
#define CERTPP_SHA512_COMPRESS_PREPARED(schedule) do { \
        __m128i pa = _mm_cvtsi64_si128(static_cast<long long>(state[0])); \
        __m128i pb = _mm_cvtsi64_si128(static_cast<long long>(state[1])); \
        __m128i pc = _mm_cvtsi64_si128(static_cast<long long>(state[2])); \
        __m128i pd = _mm_cvtsi64_si128(static_cast<long long>(state[3])); \
        __m128i pe = _mm_cvtsi64_si128(static_cast<long long>(state[4])); \
        __m128i pf = _mm_cvtsi64_si128(static_cast<long long>(state[5])); \
        __m128i pg = _mm_cvtsi64_si128(static_cast<long long>(state[6])); \
        __m128i ph = _mm_cvtsi64_si128(static_cast<long long>(state[7])); \
        for (size_t preparedFirst = 0; preparedFirst < 80; preparedFirst += 16) { \
            CERTPP_SHA512_PREPARED_ROUND(pa, pb, pc, pd, pe, pf, pg, ph, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 0]))); \
            CERTPP_SHA512_PREPARED_ROUND(ph, pa, pb, pc, pd, pe, pf, pg, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 1]))); \
            CERTPP_SHA512_PREPARED_ROUND(pg, ph, pa, pb, pc, pd, pe, pf, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 2]))); \
            CERTPP_SHA512_PREPARED_ROUND(pf, pg, ph, pa, pb, pc, pd, pe, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 3]))); \
            CERTPP_SHA512_PREPARED_ROUND(pe, pf, pg, ph, pa, pb, pc, pd, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 4]))); \
            CERTPP_SHA512_PREPARED_ROUND(pd, pe, pf, pg, ph, pa, pb, pc, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 5]))); \
            CERTPP_SHA512_PREPARED_ROUND(pc, pd, pe, pf, pg, ph, pa, pb, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 6]))); \
            CERTPP_SHA512_PREPARED_ROUND(pb, pc, pd, pe, pf, pg, ph, pa, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 7]))); \
            CERTPP_SHA512_PREPARED_ROUND(pa, pb, pc, pd, pe, pf, pg, ph, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 8]))); \
            CERTPP_SHA512_PREPARED_ROUND(ph, pa, pb, pc, pd, pe, pf, pg, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 9]))); \
            CERTPP_SHA512_PREPARED_ROUND(pg, ph, pa, pb, pc, pd, pe, pf, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 10]))); \
            CERTPP_SHA512_PREPARED_ROUND(pf, pg, ph, pa, pb, pc, pd, pe, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 11]))); \
            CERTPP_SHA512_PREPARED_ROUND(pe, pf, pg, ph, pa, pb, pc, pd, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 12]))); \
            CERTPP_SHA512_PREPARED_ROUND(pd, pe, pf, pg, ph, pa, pb, pc, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 13]))); \
            CERTPP_SHA512_PREPARED_ROUND(pc, pd, pe, pf, pg, ph, pa, pb, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 14]))); \
            CERTPP_SHA512_PREPARED_ROUND(pb, pc, pd, pe, pf, pg, ph, pa, \
                _mm_cvtsi64_si128(static_cast<long long>((schedule)[preparedFirst + 15]))); \
        } \
        state[0] += static_cast<uint64_t>(_mm_cvtsi128_si64(pa)); \
        state[1] += static_cast<uint64_t>(_mm_cvtsi128_si64(pb)); \
        state[2] += static_cast<uint64_t>(_mm_cvtsi128_si64(pc)); \
        state[3] += static_cast<uint64_t>(_mm_cvtsi128_si64(pd)); \
        state[4] += static_cast<uint64_t>(_mm_cvtsi128_si64(pe)); \
        state[5] += static_cast<uint64_t>(_mm_cvtsi128_si64(pf)); \
        state[6] += static_cast<uint64_t>(_mm_cvtsi128_si64(pg)); \
        state[7] += static_cast<uint64_t>(_mm_cvtsi128_si64(ph)); \
    } while (false)

        while (blocks >= 4) {
            __m256i w4[16];
            alignas(64) uint64_t prepared[3][80];
            for (size_t i = 0; i < 16; ++i) {
                const uint64_t word0 = loadBe64(block + i * 8);
                const uint64_t word1 = loadBe64(block + 128 + i * 8);
                const uint64_t word2 = loadBe64(block + 256 + i * 8);
                const uint64_t word3 = loadBe64(block + 384 + i * 8);
                w4[i] = _mm256_set_epi64x(static_cast<long long>(word3),
                                          static_cast<long long>(word2),
                                          static_cast<long long>(word1),
                                          static_cast<long long>(word0));
                prepared[0][i] = word1 + K[i];
                prepared[1][i] = word2 + K[i];
                prepared[2][i] = word3 + K[i];
            }

            __m128i a = _mm_cvtsi64_si128(static_cast<long long>(state[0]));
            __m128i b = _mm_cvtsi64_si128(static_cast<long long>(state[1]));
            __m128i c = _mm_cvtsi64_si128(static_cast<long long>(state[2]));
            __m128i d = _mm_cvtsi64_si128(static_cast<long long>(state[3]));
            __m128i e = _mm_cvtsi64_si128(static_cast<long long>(state[4]));
            __m128i f = _mm_cvtsi64_si128(static_cast<long long>(state[5]));
            __m128i g = _mm_cvtsi64_si128(static_cast<long long>(state[6]));
            __m128i h = _mm_cvtsi64_si128(static_cast<long long>(state[7]));

#define CERTPP_SHA512_ROUND4(index, a0, b0, c0, d0, e0, f0, g0, h0) \
            CERTPP_SHA512_ROUND(a0, b0, c0, d0, e0, f0, g0, h0, \
                                _mm256_castsi256_si128(w4[(index)]), (index))
            CERTPP_SHA512_ROUND4(0, a, b, c, d, e, f, g, h);
            CERTPP_SHA512_ROUND4(1, h, a, b, c, d, e, f, g);
            CERTPP_SHA512_ROUND4(2, g, h, a, b, c, d, e, f);
            CERTPP_SHA512_ROUND4(3, f, g, h, a, b, c, d, e);
            CERTPP_SHA512_ROUND4(4, e, f, g, h, a, b, c, d);
            CERTPP_SHA512_ROUND4(5, d, e, f, g, h, a, b, c);
            CERTPP_SHA512_ROUND4(6, c, d, e, f, g, h, a, b);
            CERTPP_SHA512_ROUND4(7, b, c, d, e, f, g, h, a);
            CERTPP_SHA512_ROUND4(8, a, b, c, d, e, f, g, h);
            CERTPP_SHA512_ROUND4(9, h, a, b, c, d, e, f, g);
            CERTPP_SHA512_ROUND4(10, g, h, a, b, c, d, e, f);
            CERTPP_SHA512_ROUND4(11, f, g, h, a, b, c, d, e);
            CERTPP_SHA512_ROUND4(12, e, f, g, h, a, b, c, d);
            CERTPP_SHA512_ROUND4(13, d, e, f, g, h, a, b, c);
            CERTPP_SHA512_ROUND4(14, c, d, e, f, g, h, a, b);
            CERTPP_SHA512_ROUND4(15, b, c, d, e, f, g, h, a);
#undef CERTPP_SHA512_ROUND4

            for (size_t first = 16; first < 80; first += 16) {
#define CERTPP_SHA512_EXPAND4_ROUND(index, a0, b0, c0, d0, e0, f0, g0, h0) do { \
                CERTPP_SHA512_EXPAND4(index); \
                prepared[0][first + (index)] = \
                    static_cast<uint64_t>(_mm256_extract_epi64(w4[(index)], 1)) \
                        + K[first + (index)]; \
                prepared[1][first + (index)] = \
                    static_cast<uint64_t>(_mm256_extract_epi64(w4[(index)], 2)) \
                        + K[first + (index)]; \
                prepared[2][first + (index)] = \
                    static_cast<uint64_t>(_mm256_extract_epi64(w4[(index)], 3)) \
                        + K[first + (index)]; \
                CERTPP_SHA512_ROUND(a0, b0, c0, d0, e0, f0, g0, h0, \
                    _mm256_castsi256_si128(w4[(index)]), first + (index)); \
            } while (false)
                CERTPP_SHA512_EXPAND4_ROUND(0, a, b, c, d, e, f, g, h);
                CERTPP_SHA512_EXPAND4_ROUND(1, h, a, b, c, d, e, f, g);
                CERTPP_SHA512_EXPAND4_ROUND(2, g, h, a, b, c, d, e, f);
                CERTPP_SHA512_EXPAND4_ROUND(3, f, g, h, a, b, c, d, e);
                CERTPP_SHA512_EXPAND4_ROUND(4, e, f, g, h, a, b, c, d);
                CERTPP_SHA512_EXPAND4_ROUND(5, d, e, f, g, h, a, b, c);
                CERTPP_SHA512_EXPAND4_ROUND(6, c, d, e, f, g, h, a, b);
                CERTPP_SHA512_EXPAND4_ROUND(7, b, c, d, e, f, g, h, a);
                CERTPP_SHA512_EXPAND4_ROUND(8, a, b, c, d, e, f, g, h);
                CERTPP_SHA512_EXPAND4_ROUND(9, h, a, b, c, d, e, f, g);
                CERTPP_SHA512_EXPAND4_ROUND(10, g, h, a, b, c, d, e, f);
                CERTPP_SHA512_EXPAND4_ROUND(11, f, g, h, a, b, c, d, e);
                CERTPP_SHA512_EXPAND4_ROUND(12, e, f, g, h, a, b, c, d);
                CERTPP_SHA512_EXPAND4_ROUND(13, d, e, f, g, h, a, b, c);
                CERTPP_SHA512_EXPAND4_ROUND(14, c, d, e, f, g, h, a, b);
                CERTPP_SHA512_EXPAND4_ROUND(15, b, c, d, e, f, g, h, a);
#undef CERTPP_SHA512_EXPAND4_ROUND
            }

            state[0] += static_cast<uint64_t>(_mm_cvtsi128_si64(a));
            state[1] += static_cast<uint64_t>(_mm_cvtsi128_si64(b));
            state[2] += static_cast<uint64_t>(_mm_cvtsi128_si64(c));
            state[3] += static_cast<uint64_t>(_mm_cvtsi128_si64(d));
            state[4] += static_cast<uint64_t>(_mm_cvtsi128_si64(e));
            state[5] += static_cast<uint64_t>(_mm_cvtsi128_si64(f));
            state[6] += static_cast<uint64_t>(_mm_cvtsi128_si64(g));
            state[7] += static_cast<uint64_t>(_mm_cvtsi128_si64(h));
            CERTPP_SHA512_COMPRESS_PREPARED(prepared[0]);
            CERTPP_SHA512_COMPRESS_PREPARED(prepared[1]);
            CERTPP_SHA512_COMPRESS_PREPARED(prepared[2]);

            block += 512;
            blocks -= 4;
        }

        while (blocks != 0) {
            const bool paired = blocks >= 2;
            __m128i w[16];
            uint64_t secondSchedule[80];
            if (paired) {
                for (size_t i = 0; i < 16; ++i) {
                    const uint64_t firstWord = loadBe64(block + i * 8);
                    const uint64_t secondWord = loadBe64(block + 128 + i * 8);
                    w[i] = _mm_set_epi64x(static_cast<long long>(secondWord),
                                         static_cast<long long>(firstWord));
                    secondSchedule[i] = secondWord + K[i];
                }
            } else {
                for (size_t i = 0; i < 16; ++i) {
                    w[i] = _mm_cvtsi64_si128(static_cast<long long>(loadBe64(block + i * 8)));
                }
            }

            __m128i a = _mm_cvtsi64_si128(static_cast<long long>(state[0]));
            __m128i b = _mm_cvtsi64_si128(static_cast<long long>(state[1]));
            __m128i c = _mm_cvtsi64_si128(static_cast<long long>(state[2]));
            __m128i d = _mm_cvtsi64_si128(static_cast<long long>(state[3]));
            __m128i e = _mm_cvtsi64_si128(static_cast<long long>(state[4]));
            __m128i f = _mm_cvtsi64_si128(static_cast<long long>(state[5]));
            __m128i g = _mm_cvtsi64_si128(static_cast<long long>(state[6]));
            __m128i h = _mm_cvtsi64_si128(static_cast<long long>(state[7]));

            CERTPP_SHA512_ROUND(a, b, c, d, e, f, g, h, w[0], 0);
            CERTPP_SHA512_ROUND(h, a, b, c, d, e, f, g, w[1], 1);
            CERTPP_SHA512_ROUND(g, h, a, b, c, d, e, f, w[2], 2);
            CERTPP_SHA512_ROUND(f, g, h, a, b, c, d, e, w[3], 3);
            CERTPP_SHA512_ROUND(e, f, g, h, a, b, c, d, w[4], 4);
            CERTPP_SHA512_ROUND(d, e, f, g, h, a, b, c, w[5], 5);
            CERTPP_SHA512_ROUND(c, d, e, f, g, h, a, b, w[6], 6);
            CERTPP_SHA512_ROUND(b, c, d, e, f, g, h, a, w[7], 7);
            CERTPP_SHA512_ROUND(a, b, c, d, e, f, g, h, w[8], 8);
            CERTPP_SHA512_ROUND(h, a, b, c, d, e, f, g, w[9], 9);
            CERTPP_SHA512_ROUND(g, h, a, b, c, d, e, f, w[10], 10);
            CERTPP_SHA512_ROUND(f, g, h, a, b, c, d, e, w[11], 11);
            CERTPP_SHA512_ROUND(e, f, g, h, a, b, c, d, w[12], 12);
            CERTPP_SHA512_ROUND(d, e, f, g, h, a, b, c, w[13], 13);
            CERTPP_SHA512_ROUND(c, d, e, f, g, h, a, b, w[14], 14);
            CERTPP_SHA512_ROUND(b, c, d, e, f, g, h, a, w[15], 15);

            for (size_t first = 16; first < 80; first += 16) {
#define CERTPP_SHA512_EXPAND_ROUND(index, a0, b0, c0, d0, e0, f0, g0, h0) do { \
                CERTPP_SHA512_EXPAND(index); \
                secondSchedule[first + (index)] = \
                    static_cast<uint64_t>(_mm_extract_epi64(w[(index)], 1)) \
                        + K[first + (index)]; \
                CERTPP_SHA512_ROUND(a0, b0, c0, d0, e0, f0, g0, h0, \
                                    w[(index)], first + (index)); \
            } while (false)
                CERTPP_SHA512_EXPAND_ROUND(0, a, b, c, d, e, f, g, h);
                CERTPP_SHA512_EXPAND_ROUND(1, h, a, b, c, d, e, f, g);
                CERTPP_SHA512_EXPAND_ROUND(2, g, h, a, b, c, d, e, f);
                CERTPP_SHA512_EXPAND_ROUND(3, f, g, h, a, b, c, d, e);
                CERTPP_SHA512_EXPAND_ROUND(4, e, f, g, h, a, b, c, d);
                CERTPP_SHA512_EXPAND_ROUND(5, d, e, f, g, h, a, b, c);
                CERTPP_SHA512_EXPAND_ROUND(6, c, d, e, f, g, h, a, b);
                CERTPP_SHA512_EXPAND_ROUND(7, b, c, d, e, f, g, h, a);
                CERTPP_SHA512_EXPAND_ROUND(8, a, b, c, d, e, f, g, h);
                CERTPP_SHA512_EXPAND_ROUND(9, h, a, b, c, d, e, f, g);
                CERTPP_SHA512_EXPAND_ROUND(10, g, h, a, b, c, d, e, f);
                CERTPP_SHA512_EXPAND_ROUND(11, f, g, h, a, b, c, d, e);
                CERTPP_SHA512_EXPAND_ROUND(12, e, f, g, h, a, b, c, d);
                CERTPP_SHA512_EXPAND_ROUND(13, d, e, f, g, h, a, b, c);
                CERTPP_SHA512_EXPAND_ROUND(14, c, d, e, f, g, h, a, b);
                CERTPP_SHA512_EXPAND_ROUND(15, b, c, d, e, f, g, h, a);
#undef CERTPP_SHA512_EXPAND_ROUND
            }

            state[0] += static_cast<uint64_t>(_mm_cvtsi128_si64(a));
            state[1] += static_cast<uint64_t>(_mm_cvtsi128_si64(b));
            state[2] += static_cast<uint64_t>(_mm_cvtsi128_si64(c));
            state[3] += static_cast<uint64_t>(_mm_cvtsi128_si64(d));
            state[4] += static_cast<uint64_t>(_mm_cvtsi128_si64(e));
            state[5] += static_cast<uint64_t>(_mm_cvtsi128_si64(f));
            state[6] += static_cast<uint64_t>(_mm_cvtsi128_si64(g));
            state[7] += static_cast<uint64_t>(_mm_cvtsi128_si64(h));
            block += 128;
            --blocks;

            if (paired) {
                CERTPP_SHA512_COMPRESS_PREPARED(secondSchedule);
                block += 128;
                --blocks;
            }
        }

#undef CERTPP_SHA512_COMPRESS_PREPARED
#undef CERTPP_SHA512_PREPARED_ROUND
#undef CERTPP_SHA512_EXPAND4
#undef CERTPP_SHA512_EXPAND
#undef CERTPP_SHA512_ROUND
#undef CERTPP_SHA512_ROR
    }
#endif

#if defined(CERTPP_ARCH_HAS_BMI2_ROTR)
    /* The BMI2-enabled instantiation. The attribute has to sit here, on a function compiled as a
     * whole with BMI2, rather than on the rotate helper inside it -- see the note on
     * transformRounds(). */
#  if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
    __attribute__((target("bmi2")))
#  endif
    void Sha2_64Core::transformRoundsBmi2(uint64_t state[8], const uint8_t* block, size_t blocks) {
        transformRounds<true>(state, block, blocks);
    }
#endif

    /* Runs the SHA-384/SHA-512 compression function over one 128-byte block. */
    void Sha2_64Core::transform(uint64_t state[8], const uint8_t block[128]) {
        transformBlocks(state, block, 1);
    }

    /* Runs the SHA-384/SHA-512 compression function over contiguous complete blocks. */
    void Sha2_64Core::transformBlocks(uint64_t state[8], const uint8_t* blocks,
                                      size_t blockCount) {
#if defined(CERTPP_ARCH_HAS_AVX512F)
        if (hasAvx512Sha2_64()) {
            transformRoundsAvx512(state, blocks, blockCount);
            return;
        }
#endif
#if defined(CERTPP_ARCH_HAS_BMI2_ROTR)
        if (hasBmi2()) {
            transformRoundsBmi2(state, blocks, blockCount);
            return;
        }
#endif
        transformRounds<false>(state, blocks, blockCount);
    }

} // namespace crypto
} // namespace certpp
