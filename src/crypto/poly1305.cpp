#include <certpp/crypto/poly1305.hpp>
#include <certpp/arch.hpp>
#include <certpp/utils/secure.hpp>
#include <cstring>

#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
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

        uint32_t loadLE32(const uint8_t* p) {
            return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
                 | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
        }

        void storeLE32(uint8_t* p, uint32_t v) {
            p[0] = uint8_t(v);
            p[1] = uint8_t(v >> 8);
            p[2] = uint8_t(v >> 16);
            p[3] = uint8_t(v >> 24);
        }

    } // namespace

#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
        /* A 130-bit value in five 26-bit limbs: v = limb[0] + limb[1]*2^26 + ... + limb[4]*2^104. */
        struct SLimbs {
            uint32_t v[5];
        };

        /* Whether this CPU has AVX512-IFMA (CPUID.7.0:EBX.AVX512IFMA, bit 21) and AVX-512F to go
         * with it. The bit was read off the machine, not recalled: leaf 7 sub-leaf 1 reports
         * nothing on this CPU, and a wrong bit either misses the feature or SIGILLs on a CPU
         * without it. */
        bool hasIfma() {
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
                       (info[1] & (1 << 21)) != 0;
#else
                __builtin_cpu_init();
                return __builtin_cpu_supports("avx512f") != 0 &&
                       __builtin_cpu_supports("avx512ifma") != 0;
#endif
            }();
            return supported;
        }

        /* The limbs of a 16-byte block plus the bit appended above it (RFC 8439 2.5): a full
         * block gets 2^128, which is exactly 2^24 * 2^104 -- i.e. bit 24 of limb 4 -- and a short
         * final block gets the bit just above the bytes it holds, which for fewer than 16 bytes
         * is always inside bits 0..127. */
        SLimbs blockLimbs(const uint8_t block[16], uint32_t high) {
            uint64_t lo = 0, hi = 0;
            std::memcpy(&lo, block, 8);
            std::memcpy(&hi, block + 8, 8);

            // --> Spread the 128-bit little-endian value across 26-bit limbs.
            SLimbs out;
            out.v[0] = uint32_t(lo) & 0x3FFFFFFu;
            out.v[1] = uint32_t(lo >> 26) & 0x3FFFFFFu;
            out.v[2] = uint32_t(lo >> 52) | (uint32_t(hi) << 12);
            out.v[2] &= 0x3FFFFFFu;
            out.v[3] = uint32_t(hi >> 14) & 0x3FFFFFFu;
            out.v[4] = uint32_t(hi >> 40) & 0x3FFFFFFu;
            out.v[4] += high;
            return out;
        }

        /* Multiplies two reduced five-limb values modulo 2^130 - 5. Terms above limb 4 fold
         * directly into the low half with a factor of five, avoiding the nine-limb temporary and
         * separate reduction pass this table setup originally used. */
        void multiplyLimbs(const uint32_t a[5], const uint32_t b[5], uint32_t out[5]) {
            const uint64_t b1_5 = uint64_t(b[1]) * 5;
            const uint64_t b2_5 = uint64_t(b[2]) * 5;
            const uint64_t b3_5 = uint64_t(b[3]) * 5;
            const uint64_t b4_5 = uint64_t(b[4]) * 5;
            const uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];

            uint64_t d0 = a0*b[0] + a1*b4_5 + a2*b3_5 + a3*b2_5 + a4*b1_5;
            uint64_t d1 = a0*b[1] + a1*b[0] + a2*b4_5 + a3*b3_5 + a4*b2_5;
            uint64_t d2 = a0*b[2] + a1*b[1] + a2*b[0] + a3*b4_5 + a4*b3_5;
            uint64_t d3 = a0*b[3] + a1*b[2] + a2*b[1] + a3*b[0] + a4*b4_5;
            uint64_t d4 = a0*b[4] + a1*b[3] + a2*b[2] + a3*b[1] + a4*b[0];

            uint64_t carry = d0 >> 26; d0 &= 0x3ffffffu; d1 += carry;
            carry = d1 >> 26; d1 &= 0x3ffffffu; d2 += carry;
            carry = d2 >> 26; d2 &= 0x3ffffffu; d3 += carry;
            carry = d3 >> 26; d3 &= 0x3ffffffu; d4 += carry;
            carry = d4 >> 26; d4 &= 0x3ffffffu; d0 += carry * 5;
            carry = d0 >> 26; d0 &= 0x3ffffffu; d1 += carry;

            out[0] = uint32_t(d0);
            out[1] = uint32_t(d1);
            out[2] = uint32_t(d2);
            out[3] = uint32_t(d3);
            out[4] = uint32_t(d4);
        }

        /* r^1 .. r^16 in limb form, stored in the lower-power half of the table.
         *
         * `out[m][j]` is limb m of r^(32-j). That descending layout lets products8 load the eight
         * powers for a group directly. The eight- and sixteen-block paths use slots 24..31 and
         * 16..31, so they do not need the higher powers in slots 0..15.
         *
         * Lane 0 carries the oldest block and therefore takes the largest power in its group.
         * Reversing that order computes a different, equally plausible polynomial; the long-message
         * known-answer tests cover this ordering. */
        void computePowers(const uint32_t r[5], uint64_t out[5][32]) {
            uint32_t power[5];
            std::memcpy(power, r, sizeof(power));
            for (int exponent = 1; exponent <= 16; ++exponent) {
                const int slot = 32 - exponent;
                for (int limb = 0; limb < 5; ++limb) {
                    out[limb][slot] = power[limb];
                }
                if (exponent != 16) {
                    uint32_t next[5];
                    multiplyLimbs(power, r, next);
                    std::memcpy(power, next, sizeof(power));
                }
            }
        }

        /* Extends an r^1..r^16 table through r^32. Starting from the stored r^16 avoids repeating
         * any setup work and reserves the extra sixteen multiplications for messages large enough
         * to enter absorb32. */
        void extendPowers(const uint32_t r[5], uint64_t out[5][32]) {
            uint32_t power[5];
            for (int limb = 0; limb < 5; ++limb) {
                power[limb] = uint32_t(out[limb][16]);
            }
            for (int exponent = 17; exponent <= 32; ++exponent) {
                uint32_t next[5];
                multiplyLimbs(power, r, next);
                std::memcpy(power, next, sizeof(power));
                const int slot = 32 - exponent;
                for (int limb = 0; limb < 5; ++limb) {
                    out[limb][slot] = power[limb];
                }
            }
        }
        /* Products for eight blocks, left in five vector limbs so several groups can be combined
         * before the horizontal reductions. `powerOffset` selects the descending eight-power
         * slice that corresponds to this group's position in the recurrence. */
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((always_inline, target("avx512ifma,avx512f")))
#endif
        inline void products8(__m512i d[5], const uint64_t powers[5][32],
                              size_t powerOffset, const uint8_t blocks[8][16]) {
            const __m512i first = _mm512_loadu_si512(blocks);
            const __m512i second = _mm512_loadu_si512(blocks + 4);
            const __m512i lo = _mm512_permutex2var_epi64(first,
                _mm512_setr_epi64(0, 2, 4, 6, 8, 10, 12, 14), second);
            const __m512i hi = _mm512_permutex2var_epi64(first,
                _mm512_setr_epi64(1, 3, 5, 7, 9, 11, 13, 15), second);
            const __m512i mask26 = _mm512_set1_epi64(0x3ffffffu);
            __m512i n[5], p[5];
            n[0] = _mm512_and_si512(lo, mask26);
            n[1] = _mm512_and_si512(_mm512_srli_epi64(lo, 26), mask26);
            n[2] = _mm512_and_si512(_mm512_or_si512(
                _mm512_srli_epi64(lo, 52), _mm512_slli_epi64(hi, 12)), mask26);
            n[3] = _mm512_and_si512(_mm512_srli_epi64(hi, 14), mask26);
            n[4] = _mm512_add_epi64(
                _mm512_and_si512(_mm512_srli_epi64(hi, 40), mask26),
                _mm512_set1_epi64(1u << 24));
            for (int limb = 0; limb < 5; ++limb) {
                p[limb] = _mm512_loadu_si512(powers[limb] + powerOffset);
            }

            __m512i wrap;
            d[0] = _mm512_madd52lo_epu64(_mm512_setzero_si512(), n[0], p[0]);
            wrap = _mm512_madd52lo_epu64(_mm512_setzero_si512(), n[1], p[4]);
            wrap = _mm512_madd52lo_epu64(wrap, n[2], p[3]);
            wrap = _mm512_madd52lo_epu64(wrap, n[3], p[2]);
            wrap = _mm512_madd52lo_epu64(wrap, n[4], p[1]);
            d[0] = _mm512_add_epi64(d[0], _mm512_add_epi64(wrap, _mm512_slli_epi64(wrap, 2)));

            d[1] = _mm512_madd52lo_epu64(_mm512_setzero_si512(), n[0], p[1]);
            d[1] = _mm512_madd52lo_epu64(d[1], n[1], p[0]);
            wrap = _mm512_madd52lo_epu64(_mm512_setzero_si512(), n[2], p[4]);
            wrap = _mm512_madd52lo_epu64(wrap, n[3], p[3]);
            wrap = _mm512_madd52lo_epu64(wrap, n[4], p[2]);
            d[1] = _mm512_add_epi64(d[1], _mm512_add_epi64(wrap, _mm512_slli_epi64(wrap, 2)));

            d[2] = _mm512_madd52lo_epu64(_mm512_setzero_si512(), n[0], p[2]);
            d[2] = _mm512_madd52lo_epu64(d[2], n[1], p[1]);
            d[2] = _mm512_madd52lo_epu64(d[2], n[2], p[0]);
            wrap = _mm512_madd52lo_epu64(_mm512_setzero_si512(), n[3], p[4]);
            wrap = _mm512_madd52lo_epu64(wrap, n[4], p[3]);
            d[2] = _mm512_add_epi64(d[2], _mm512_add_epi64(wrap, _mm512_slli_epi64(wrap, 2)));

            d[3] = _mm512_madd52lo_epu64(_mm512_setzero_si512(), n[0], p[3]);
            d[3] = _mm512_madd52lo_epu64(d[3], n[1], p[2]);
            d[3] = _mm512_madd52lo_epu64(d[3], n[2], p[1]);
            d[3] = _mm512_madd52lo_epu64(d[3], n[3], p[0]);
            wrap = _mm512_madd52lo_epu64(_mm512_setzero_si512(), n[4], p[4]);
            d[3] = _mm512_add_epi64(d[3], _mm512_add_epi64(wrap, _mm512_slli_epi64(wrap, 2)));

            d[4] = _mm512_madd52lo_epu64(_mm512_setzero_si512(), n[0], p[4]);
            d[4] = _mm512_madd52lo_epu64(d[4], n[1], p[3]);
            d[4] = _mm512_madd52lo_epu64(d[4], n[2], p[2]);
            d[4] = _mm512_madd52lo_epu64(d[4], n[3], p[1]);
            d[4] = _mm512_madd52lo_epu64(d[4], n[4], p[0]);
        }

        /* Adds accumulator * r^count to the horizontally summed block products and reduces. */
        void finishWideProduct(uint32_t accumulator[5], const uint64_t powers[5][32],
                               size_t powerIndex, const uint64_t sum[5]) {
            uint32_t rp[5];
            for (int i = 0; i < 5; ++i) { rp[i] = uint32_t(powers[i][powerIndex]); }
            const uint64_t rp1 = uint64_t(rp[1]) * 5;
            const uint64_t rp2 = uint64_t(rp[2]) * 5;
            const uint64_t rp3 = uint64_t(rp[3]) * 5;
            const uint64_t rp4 = uint64_t(rp[4]) * 5;
            const uint64_t a0 = accumulator[0], a1 = accumulator[1];
            const uint64_t a2 = accumulator[2], a3 = accumulator[3];
            const uint64_t a4 = accumulator[4];
            uint64_t q0 = sum[0] + a0 * rp[0] + a1 * rp4 + a2 * rp3 + a3 * rp2 + a4 * rp1;
            uint64_t q1 = sum[1] + a0 * rp[1] + a1 * rp[0] + a2 * rp4 + a3 * rp3 + a4 * rp2;
            uint64_t q2 = sum[2] + a0 * rp[2] + a1 * rp[1] + a2 * rp[0] + a3 * rp4 + a4 * rp3;
            uint64_t q3 = sum[3] + a0 * rp[3] + a1 * rp[2] + a2 * rp[1] + a3 * rp[0] + a4 * rp4;
            uint64_t q4 = sum[4] + a0 * rp[4] + a1 * rp[3] + a2 * rp[2] + a3 * rp[1] + a4 * rp[0];

            uint64_t carry = q0 >> 26; q0 &= 0x3ffffffu; q1 += carry;
            carry = q1 >> 26; q1 &= 0x3ffffffu; q2 += carry;
            carry = q2 >> 26; q2 &= 0x3ffffffu; q3 += carry;
            carry = q3 >> 26; q3 &= 0x3ffffffu; q4 += carry;
            carry = q4 >> 26; q4 &= 0x3ffffffu; q0 += carry * 5;
            carry = q0 >> 26; q0 &= 0x3ffffffu; q1 += carry;

            accumulator[0] = uint32_t(q0);
            accumulator[1] = uint32_t(q1);
            accumulator[2] = uint32_t(q2);
            accumulator[3] = uint32_t(q3);
            accumulator[4] = uint32_t(q4);
        }

#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("avx512ifma,avx512f")))
#endif
        void absorb8(uint32_t accumulator[5], const uint64_t powers[5][32],
                     const uint8_t blocks[8][16]) {
            __m512i product[5];
            products8(product, powers, 24, blocks);
            uint64_t sum[5];
            for (int limb = 0; limb < 5; ++limb) {
                sum[limb] = _mm512_reduce_add_epi64(product[limb]);
            }
            finishWideProduct(accumulator, powers, 24, sum); // r^8
        }

#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("avx512ifma,avx512f")))
#endif
        void absorb16(uint32_t accumulator[5], const uint64_t powers[5][32],
                      const uint8_t blocks[16][16]) {
            __m512i first[5], second[5];
            products8(first, powers, 16,
                reinterpret_cast<const uint8_t (*)[16]>(blocks));
            products8(second, powers, 24,
                reinterpret_cast<const uint8_t (*)[16]>(blocks + 8));
            uint64_t sum[5];
            for (int limb = 0; limb < 5; ++limb) {
                sum[limb] = _mm512_reduce_add_epi64(
                    _mm512_add_epi64(first[limb], second[limb]));
            }
            finishWideProduct(accumulator, powers, 16, sum); // r^16
        }

#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("avx512ifma,avx512f")))
#endif
        void absorb32(uint32_t accumulator[5], const uint64_t powers[5][32],
                      const uint8_t blocks[32][16]) {
            __m512i sum[5];
            products8(sum, powers, 0,
                reinterpret_cast<const uint8_t (*)[16]>(blocks));
            for (size_t group = 1; group < 4; ++group) {
                __m512i part[5];
                products8(part, powers, group * 8,
                    reinterpret_cast<const uint8_t (*)[16]>(blocks + group * 8));
                for (int limb = 0; limb < 5; ++limb) {
                    sum[limb] = _mm512_add_epi64(sum[limb], part[limb]);
                }
            }
            uint64_t horizontal[5];
            for (int limb = 0; limb < 5; ++limb) {
                horizontal[limb] = _mm512_reduce_add_epi64(sum[limb]);
            }
            finishWideProduct(accumulator, powers, 0, horizontal); // r^32
        }

#endif // CERTPP_ARCH_HAS_IFMA_POLY1305

    /* Constructs an unkeyed instance. */
    CPoly1305::CPoly1305()
#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
        : _buffered(0), _keyed(false), _powersReady(false), _widePowersReady(false)
#else
        : _buffered(0), _keyed(false)
#endif
    {
        std::memset(_r, 0, sizeof(_r));
        std::memset(_s, 0, sizeof(_s));
        std::memset(_accumulator, 0, sizeof(_accumulator));
        std::memset(_buffer, 0, sizeof(_buffer));
    }

    /* Clears the key and accumulator. */
    CPoly1305::~CPoly1305() {
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_r), sizeof(_r)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_s), sizeof(_s)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_accumulator), sizeof(_accumulator)));
        CSecure::zero(SByteSpan(_buffer, sizeof(_buffer)));
#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
        // --> The powers are derived from r, which is key material.
        if (_powersReady) {
            CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_powers), sizeof(_powers)));
        }
#endif
    }

    /* Keys this instance and starts a fresh message. */
    bool CPoly1305::reset(const SReadOnlyByteSpan& key) {
        if (key.size != KEY_BYTES || !key.data) {
            return false;
        }

#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
        if (_powersReady) {
            CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_powers), sizeof(_powers)));
        }
#endif

        // --> r, in five 26-bit limbs, with RFC 8439 2.5's clamping applied: the top four bits
        // of each of bytes 3, 7, 11, 15 are cleared, and the low two bits of bytes 4, 8, 12.
        // That is 22 bits in total, and it is what keeps the partial products below 2^64 so the
        // multiply-reduce step cannot overflow. An implementation that skips the clamping
        // produces tags that are self-consistent and wrong.
        const uint32_t t0 = loadLE32(key.data + 0);
        const uint32_t t1 = loadLE32(key.data + 4);
        const uint32_t t2 = loadLE32(key.data + 8);
        const uint32_t t3 = loadLE32(key.data + 12);

        _r[0] = (t0) & 0x3FFFFFFu;
        _r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3FFFF03u;
        _r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3FFC0FFu;
        _r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3F03FFFu;
        _r[4] = ((t3 >> 8)) & 0x00FFFFFu;

        _s[0] = loadLE32(key.data + 16);
        _s[1] = loadLE32(key.data + 20);
        _s[2] = loadLE32(key.data + 24);
        _s[3] = loadLE32(key.data + 28);

        std::memset(_accumulator, 0, sizeof(_accumulator));
        std::memset(_buffer, 0, sizeof(_buffer));
        _buffered = 0;
#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
        _powersReady = false;
        _widePowersReady = false;
#endif
        _keyed = true;

        return true;
    }

    namespace {

        /* One block into the accumulator: a = (a + n) * r mod (2^130 - 5), where n is the block
         * read little-endian with `high` appended above its 128 bits. `high` is 1 for a full
         * block and 1 << (8 * partial) for the final short one (RFC 8439 2.5). */
        void absorbBlock(
            uint32_t accumulator[5], const uint32_t r[5], const uint8_t block[16], uint32_t high
        ) {
            const uint32_t t0 = loadLE32(block + 0);
            const uint32_t t1 = loadLE32(block + 4);
            const uint32_t t2 = loadLE32(block + 8);
            const uint32_t t3 = loadLE32(block + 12);

            accumulator[0] += (t0) & 0x3FFFFFFu;
            accumulator[1] += ((t0 >> 26) | (t1 << 6)) & 0x3FFFFFFu;
            accumulator[2] += ((t1 >> 20) | (t2 << 12)) & 0x3FFFFFFu;
            accumulator[3] += ((t2 >> 14) | (t3 << 18)) & 0x3FFFFFFu;
            accumulator[4] += (t3 >> 8) | high;

            // Schoolbook multiply in 26-bit limbs. The 2^130 == 5 reduction folds the overflow
            // back in as a factor of 5 on the wrapped limbs, which is where the 5 * r[i] terms
            // come from.
            const uint64_t s1 = uint64_t(r[1]) * 5;
            const uint64_t s2 = uint64_t(r[2]) * 5;
            const uint64_t s3 = uint64_t(r[3]) * 5;
            const uint64_t s4 = uint64_t(r[4]) * 5;

            const uint64_t a0 = accumulator[0];
            const uint64_t a1 = accumulator[1];
            const uint64_t a2 = accumulator[2];
            const uint64_t a3 = accumulator[3];
            const uint64_t a4 = accumulator[4];

            uint64_t d0 = a0 * r[0] + a1 * s4 + a2 * s3 + a3 * s2 + a4 * s1;
            uint64_t d1 = a0 * r[1] + a1 * r[0] + a2 * s4 + a3 * s3 + a4 * s2;
            uint64_t d2 = a0 * r[2] + a1 * r[1] + a2 * r[0] + a3 * s4 + a4 * s3;
            uint64_t d3 = a0 * r[3] + a1 * r[2] + a2 * r[1] + a3 * r[0] + a4 * s4;
            uint64_t d4 = a0 * r[4] + a1 * r[3] + a2 * r[2] + a3 * r[1] + a4 * r[0];

            // Carry propagation, finishing with the wrap from limb 4 back into limb 0 times 5.
            uint64_t carry = d0 >> 26; d0 &= 0x3FFFFFFu;
            d1 += carry; carry = d1 >> 26; d1 &= 0x3FFFFFFu;
            d2 += carry; carry = d2 >> 26; d2 &= 0x3FFFFFFu;
            d3 += carry; carry = d3 >> 26; d3 &= 0x3FFFFFFu;
            d4 += carry; carry = d4 >> 26; d4 &= 0x3FFFFFFu;
            d0 += carry * 5; carry = d0 >> 26; d0 &= 0x3FFFFFFu;
            d1 += carry;

            accumulator[0] = uint32_t(d0);
            accumulator[1] = uint32_t(d1);
            accumulator[2] = uint32_t(d2);
            accumulator[3] = uint32_t(d3);
            accumulator[4] = uint32_t(d4);
        }

    } // namespace

#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
    /* Builds r^16..r for the eight- and sixteen-block paths. */
    void CPoly1305::preparePowers() {
        computePowers(_r, _powers);
        _powersReady = true;
    }

    /* Extends the power table through r^32 for the thirty-two-block path. */
    void CPoly1305::prepareWidePowers() {
        if (!_powersReady) {
            preparePowers();
        }
        extendPowers(_r, _powers);
        _widePowersReady = true;
    }
#endif

    /* Absorbs message bytes. */
    size_t CPoly1305::push(const SReadOnlyByteSpan& buf) {
        if (!_keyed || buf.size == 0) {
            return 0;
        }
        if (!buf.data) {
            return 0;
        }

        size_t consumed = 0;

        // Top up a partial block first, so the caller's chunking cannot change the result.
        if (_buffered != 0) {
            const size_t take = (BLOCK_BYTES - _buffered < buf.size)
                ? (BLOCK_BYTES - _buffered) : buf.size;

            std::memcpy(_buffer + _buffered, buf.data, take);
            _buffered += take;
            consumed += take;

            if (_buffered == BLOCK_BYTES) {
                absorbBlock(_accumulator, _r, _buffer, 1u << 24);
                _buffered = 0;
            }
        }

        // --> Thirty-two at a time first, where this CPU can. Sixteen- and eight-block tails, and
        // any final partial block, retain their narrower paths, so all paths have to agree exactly
        // and the short-message result is unchanged. Powers r^1..r^16 are built only once there is
        // a whole eight-block group to use them; r^17..r^32 wait until a thirty-two-block group.
#if defined(CERTPP_ARCH_HAS_IFMA_POLY1305)
        if (hasIfma() && buf.size - consumed >= 8 * BLOCK_BYTES) {
            if (!_powersReady) {
                preparePowers();
            }
            if (buf.size - consumed >= 32 * BLOCK_BYTES && !_widePowersReady) {
                prepareWidePowers();
            }
            while (buf.size - consumed >= 32 * BLOCK_BYTES) {
                absorb32(_accumulator, _powers,
                         reinterpret_cast<const uint8_t (*)[16]>(buf.data + consumed));
                consumed += 32 * BLOCK_BYTES;
            }
            while (buf.size - consumed >= 16 * BLOCK_BYTES) {
                absorb16(_accumulator, _powers,
                         reinterpret_cast<const uint8_t (*)[16]>(buf.data + consumed));
                consumed += 16 * BLOCK_BYTES;
            }
            while (buf.size - consumed >= 8 * BLOCK_BYTES) {
                absorb8(_accumulator, _powers,
                        reinterpret_cast<const uint8_t (*)[16]>(buf.data + consumed));
                consumed += 8 * BLOCK_BYTES;
            }
        }
#endif
        while (buf.size - consumed >= BLOCK_BYTES) {
            absorbBlock(_accumulator, _r, buf.data + consumed, 1u << 24);
            consumed += BLOCK_BYTES;
        }

        if (consumed < buf.size) {
            const size_t rest = buf.size - consumed;
            std::memcpy(_buffer + _buffered, buf.data + consumed, rest);
            _buffered += rest;
            consumed += rest;
        }

        return consumed;
    }

    /* Pads the message to a 16-byte boundary with zeros. */
    bool CPoly1305::padToBlock() {
        if (!_keyed) {
            return false;
        }
        if (_buffered == 0) {
            return true; // already aligned; pad16 of an aligned length adds nothing
        }

        // --> This closes the current block rather than extending the message, which is why the
        // AEAD cannot get the same effect by pushing zeros: pushing them would be
        // indistinguishable from the message containing those zeros, and pad16's whole purpose
        // is to keep the AEAD's four fields from running into one another.
        std::memset(_buffer + _buffered, 0, BLOCK_BYTES - _buffered);
        absorbBlock(_accumulator, _r, _buffer, 1u << 24);
        _buffered = 0;

        return true;
    }

    /* Finalizes and writes the tag. */
    bool CPoly1305::finish(const SByteSpan& out) {
        if (!_keyed || out.size != TAG_BYTES || !out.data) {
            return false;
        }

        // The final partial block gets its 1 bit at the position just above the bytes present,
        // not at bit 128 -- which is what makes a short block distinguishable from a full one
        // and keeps the padding unambiguous.
        if (_buffered != 0) {
            const size_t partial = _buffered;
            _buffer[partial] = 1;
            std::memset(_buffer + partial + 1, 0, BLOCK_BYTES - partial - 1);
            absorbBlock(_accumulator, _r, _buffer, 0);
            _buffered = 0;
        }

        uint32_t h0 = _accumulator[0];
        uint32_t h1 = _accumulator[1];
        uint32_t h2 = _accumulator[2];
        uint32_t h3 = _accumulator[3];
        uint32_t h4 = _accumulator[4];

        uint32_t carry = h1 >> 26; h1 &= 0x3FFFFFFu;
        h2 += carry; carry = h2 >> 26; h2 &= 0x3FFFFFFu;
        h3 += carry; carry = h3 >> 26; h3 &= 0x3FFFFFFu;
        h4 += carry; carry = h4 >> 26; h4 &= 0x3FFFFFFu;
        h0 += carry * 5; carry = h0 >> 26; h0 &= 0x3FFFFFFu;
        h1 += carry;

        // Conditionally subtract 2^130 - 5, in constant time: the accumulator may be in
        // [p, 2^130) at this point, and branching on whether it is would leak a bit of the tag.
        uint32_t g0 = h0 + 5; carry = g0 >> 26; g0 &= 0x3FFFFFFu;
        uint32_t g1 = h1 + carry; carry = g1 >> 26; g1 &= 0x3FFFFFFu;
        uint32_t g2 = h2 + carry; carry = g2 >> 26; g2 &= 0x3FFFFFFu;
        uint32_t g3 = h3 + carry; carry = g3 >> 26; g3 &= 0x3FFFFFFu;
        uint32_t g4 = h4 + carry - (1u << 26);

        uint32_t mask = (g4 >> 31) - 1;  // all ones when g4 did not borrow, i.e. take g
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;

        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // Back to four 32-bit words, then add s with a carry chain.
        const uint32_t f0 = (h0 | (h1 << 26));
        const uint32_t f1 = ((h1 >> 6) | (h2 << 20));
        const uint32_t f2 = ((h2 >> 12) | (h3 << 14));
        const uint32_t f3 = ((h3 >> 18) | (h4 << 8));

        uint64_t sum = uint64_t(f0) + _s[0];
        storeLE32(out.data + 0, uint32_t(sum));
        sum = uint64_t(f1) + _s[1] + (sum >> 32);
        storeLE32(out.data + 4, uint32_t(sum));
        sum = uint64_t(f2) + _s[2] + (sum >> 32);
        storeLE32(out.data + 8, uint32_t(sum));
        sum = uint64_t(f3) + _s[3] + (sum >> 32);
        storeLE32(out.data + 12, uint32_t(sum));

        // The state is spent -- a one-time MAC has nothing to offer a second message, so it is
        // cleared rather than left usable.
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_accumulator), sizeof(_accumulator)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_r), sizeof(_r)));
        CSecure::zero(SByteSpan(reinterpret_cast<uint8_t*>(_s), sizeof(_s)));
        CSecure::zero(SByteSpan(_buffer, sizeof(_buffer)));
        _keyed = false;

        return true;
    }

    /* One-shot Poly1305. */
    bool CPoly1305::compute(
        const SReadOnlyByteSpan& key, const SReadOnlyByteSpan& message, const SByteSpan& out
    ) {
        CPoly1305 mac;

        if (!mac.reset(key)) {
            return false;
        }
        if (message.size != 0 && mac.push(message) != message.size) {
            return false;
        }

        return mac.finish(out);
    }

} // namespace crypto
} // namespace certpp
