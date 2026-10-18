#include "ghash.hpp"
#include <certpp/utils/secure.hpp>
#include <cstring>

/* The guard in ghash.hpp decides whether an accelerated path exists at all; this one only pulls
 * in the intrinsics and CPUID headers it needs, and must stay in step with it. */
#if defined(CERTPP_GHASH_HWACCEL_AVAILABLE)
#include <immintrin.h>   // GFNI's GF2P8AFFINEQB is newer than the wmmintrin.h that PCLMULQDQ needs
#if defined(_MSC_VER) && !defined(__clang__)
#include <zmmintrin.h>   // ...and MSVC declares the GFNI intrinsics here rather than there
#endif
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

namespace certpp {
namespace crypto {

    namespace {

        /* The wrap-around term of GCM's reduction polynomial as Algorithm 1 applies it: R =
         * 11100001 || 0^120, i.e. 0xE1 in the first byte and nothing else, which lands in the
         * high word of the (hi, lo) big-endian pair below. */
        constexpr uint64_t GHASH_R_HI = 0xE100000000000000ULL;

        /* Reads eight bytes big-endian. GCM is a big-endian specification throughout -- the
         * block's first byte is its most significant, and the length block's two counts are
         * big-endian too. */
        uint64_t loadBE64(const uint8_t* in) {
            return (uint64_t(in[0]) << 56) | (uint64_t(in[1]) << 48)
                 | (uint64_t(in[2]) << 40) | (uint64_t(in[3]) << 32)
                 | (uint64_t(in[4]) << 24) | (uint64_t(in[5]) << 16)
                 | (uint64_t(in[6]) << 8)  | uint64_t(in[7]);
        }

        /* Writes eight bytes big-endian. */
        void storeBE64(uint8_t* out, uint64_t value) {
            out[0] = uint8_t(value >> 56);
            out[1] = uint8_t(value >> 48);
            out[2] = uint8_t(value >> 40);
            out[3] = uint8_t(value >> 32);
            out[4] = uint8_t(value >> 24);
            out[5] = uint8_t(value >> 16);
            out[6] = uint8_t(value >> 8);
            out[7] = uint8_t(value);
        }

#if defined(CERTPP_GHASH_HWACCEL_AVAILABLE)
        /* Whether this CPU actually has PCLMULQDQ -- an optional x86-64 feature, not guaranteed
         * just because the binary was built for the architecture, so it must be checked at
         * runtime (CPUID.1:ECX.PCLMULQDQ, bit 1) before the instruction is ever emitted;
         * emitting it unconditionally risks SIGILL on an older CPU. Computed once. */
        bool hasPclmul() {
            static const bool supported = [] {
#if defined(_MSC_VER)
                int info[4] = { 0, 0, 0, 0 };
                __cpuid(info, 1);
                return (info[2] & (1 << 1)) != 0;
#else
                unsigned int eax, ebx, ecx, edx;
                if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
                    return false;
                }
                return (ecx & (1u << 1)) != 0;
#endif
            }();

            return supported;
        }

        /* Whether this CPU also has GFNI (CPUID.7.0:ECX.GFNI, bit 8). GFNI is a separate and newer
         * feature from PCLMULQDQ -- a CPU can have either without the other, and plenty have
         * neither -- so it is its own check rather than an assumption about the one above. */
        bool hasGfni() {
            static const bool supported = [] {
#if defined(_MSC_VER)
                int info[4] = { 0, 0, 0, 0 };
                __cpuidex(info, 7, 0);
                return (info[2] & (1 << 8)) != 0;
#else
                unsigned int eax, ebx, ecx, edx;
                if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
                    return false;
                }
                return (ecx & (1u << 8)) != 0;
#endif
            }();

            return supported;
        }

        /* The eight-block fold uses 512-bit GFNI plus VPCLMULQDQ. Check both the instruction
         * bits and the OS-managed ZMM state: advertising AVX-512 while XCR0 lacks the opmask or
         * high-ZMM bits still makes the first instruction fault. */
        bool hasWideGhash() {
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
                return (info[1] & (1 << 16)) != 0 &&  // AVX512F
                       (info[1] & (1 << 30)) != 0 &&  // AVX512BW
                       (info[2] & (1 << 8)) != 0 &&   // GFNI
                       (info[2] & (1 << 10)) != 0;    // VPCLMULQDQ
#else
                __builtin_cpu_init();
                return __builtin_cpu_supports("avx512f") != 0 &&
                       __builtin_cpu_supports("avx512bw") != 0 &&
                       __builtin_cpu_supports("gfni") != 0 &&
                       __builtin_cpu_supports("vpclmulqdq") != 0;
#endif
            }();
            return supported;
        }

        /* Reverses the bits within each byte of a vector, leaving the bytes themselves where they
         * are -- the three masked swap steps (adjacent bits, adjacent pairs, nibbles) of the
         * classic bit-reversal, stopped before the byte/word steps that would reverse the whole
         * value. Each mask clears whatever a shift dragged in from the neighbouring byte, so this
         * is per-byte despite _mm_srli_epi64 shifting across byte boundaries.
         *
         * This is what moves a block out of GCM's bit-reflected convention and into the ordinary
         * one, where bit i of the 128-bit little-endian value is the coefficient of x^i: GCM puts
         * the x^0 coefficient in the most significant bit of the first byte, so reversing each
         * byte's bits (and keeping little-endian byte order, which _mm_loadu_si128 already gives)
         * is the whole of the conversion. It is its own inverse, so the same function brings the
         * product back. */
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("pclmul,sse2")))
#endif
        __m128i reverseBitsInBytes(__m128i v) {
            const __m128i m55 = _mm_set1_epi8(0x55);
            const __m128i m33 = _mm_set1_epi8(0x33);
            const __m128i m0f = _mm_set1_epi8(0x0F);

            v = _mm_or_si128(
                _mm_and_si128(_mm_srli_epi64(v, 1), m55),
                _mm_slli_epi64(_mm_and_si128(v, m55), 1));
            v = _mm_or_si128(
                _mm_and_si128(_mm_srli_epi64(v, 2), m33),
                _mm_slli_epi64(_mm_and_si128(v, m33), 2));
            v = _mm_or_si128(
                _mm_and_si128(_mm_srli_epi64(v, 4), m0f),
                _mm_slli_epi64(_mm_and_si128(v, m0f), 4));

            return v;
        }

        /* The same per-byte bit reversal, in one instruction.
         *
         * GF2P8AFFINEQB applies an 8x8 bit matrix, given as eight rows in a vector, to each byte
         * of its input. The reversal matrix's rows, in the order the instruction reads them, are
         * 01 02 04 08 10 20 40 80 -- which is 0x8040201008040201 read little-endian, and is not
         * the 0x0102040810204080 that the same reasoning produces from the transpose. That
         * reversed nothing: it made GFNI compute the identity. The constant here was therefore
         * not reasoned out, it was measured -- see the note on reverseBitsInBytesGfni below.
         * The imm8 is 0, so nothing is XORed in afterwards.
         *
         * GFNI makes this reflection, which is twenty instructions by hand, one instruction.
         * Checked against the SSE2 version above by tests/crypto/aeads/ghash.cpp rather than
         * taken on the constant's word. */
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
        __attribute__((target("gfni,sse2")))
#endif
        __m128i reverseBitsInBytesGfni(__m128i v) {
            const __m128i matrix = _mm_set1_epi64x(
                static_cast<long long>(0x8040201008040201ULL));
            return _mm_gf2p8affine_epi64_epi8(v, matrix, 0);
        }
#endif // CERTPP_GHASH_HWACCEL_AVAILABLE

    } // namespace

    /* GCM's GF(2^128) multiplication, SP 800-38D Algorithm 1. */
    void Ghash::multiplyPortable(uint8_t block[BLOCK_BYTES], const uint8_t h[BLOCK_BYTES]) {
        // A block is carried as the pair of 64-bit words it reads as big-endian, so bit i of the
        // byte string -- GCM's index, numbered from the most significant bit of the first byte --
        // is bit (63 - i) of hi for i < 64 and bit (127 - i) of lo otherwise.
        const uint64_t xh = loadBE64(block);
        const uint64_t xl = loadBE64(block + 8);

        uint64_t vh = loadBE64(h);
        uint64_t vl = loadBE64(h + 8);

        uint64_t zh = 0;
        uint64_t zl = 0;

        // --> Algorithm 1 verbatim, but with every branch replaced by a mask: both the "is bit i
        // of X set" test and the "did a 1 fall off the bottom" test are over secret data (X is
        // ciphertext-and-accumulator, H is the MAC key), so a conditional XOR here would make
        // both observable. There is no table and no data-dependent index either, which is what
        // rules out the cache-timing leak the usual windowed GHASH has.
        for (size_t i = 0; i < 128; ++i) {
            const uint64_t bit = (i < 64)
                ? ((xh >> (63 - i)) & 1)
                : ((xl >> (127 - i)) & 1);
            const uint64_t take = uint64_t(0) - bit;

            zh ^= vh & take;
            zl ^= vl & take;

            // V <- V >> 1, and XOR R back in if the bit shifted off the bottom was a 1: that is
            // multiplication of V by x in this field, with the reduction folded in.
            const uint64_t wrap = uint64_t(0) - (vl & 1);
            vl = (vl >> 1) | (vh << 63);
            vh = (vh >> 1) ^ (GHASH_R_HI & wrap);
        }

        storeBE64(block, zh);
        storeBE64(block + 8, zl);
    }

#if defined(CERTPP_GHASH_HWACCEL_AVAILABLE)
    /* The multiplication proper, by PCLMULQDQ, shared by every accelerated route into it.
     *
     * Rather than multiply in GCM's reflected convention -- where the classic trick is a
     * shift-by-one plus a reduction whose constants are easy to transcribe and impossible to
     * eyeball -- this converts into the ordinary basis (bit i of the 128-bit little-endian value
     * is the coefficient of x^i), multiplies there, and converts the product back. The conversion
     * makes the reduction the textbook one: x^128 = x^7 + x^2 + x + 1, i.e. 0x87.
     *
     * It used to cost a dozen SSE2 instructions per operand, twenty in all for the block and the
     * product, which is nearly half of what this function spends -- so it is now one
     * GF2P8AFFINEQB each where GFNI exists. The subkey's conversion is the caller's: H does not
     * change while an accumulator is in use, and absorb() reflects it once per message.
     *
     * __attribute__((target(...))) lets GCC/Clang emit these in just this one function
     * regardless of the translation unit's default -march (MSVC needs no equivalent -- see the
     * identical note on gf2m.cpp's wideProductAccelerated()).
     *
     * @param useGfni Whether to reflect with GFNI rather than the SSE2 sequence. Only ever
     * true where hasGfni() is true, which is what makes emitting GF2P8AFFINEQB here safe. */
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
    __attribute__((target("gfni,pclmul,sse2")))
#endif
    void Ghash::multiplyCore(uint8_t block[BLOCK_BYTES], const uint8_t h[BLOCK_BYTES],
                             bool useGfni) {
        const __m128i loaded = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block));
        const __m128i a = useGfni ? reverseBitsInBytesGfni(loaded) : reverseBitsInBytes(loaded);
        const __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(h));

        // The 256-bit carry-less product, schoolbook over the two 64-bit halves: the two middle
        // partial products straddle bit 64, so they are split between the halves by hand.
        const __m128i t00 = _mm_clmulepi64_si128(a, b, 0x00); // a0 * b0
        const __m128i t11 = _mm_clmulepi64_si128(a, b, 0x11); // a1 * b1
        const __m128i t01 = _mm_clmulepi64_si128(a, b, 0x01); // a1 * b0
        const __m128i t10 = _mm_clmulepi64_si128(a, b, 0x10); // a0 * b1

        const __m128i mid = _mm_xor_si128(t01, t10);
        __m128i lo = _mm_xor_si128(t00, _mm_slli_si128(mid, 8));
        const __m128i hi = _mm_xor_si128(t11, _mm_srli_si128(mid, 8));

        // Reduction modulo x^128 + x^7 + x^2 + x + 1: every bit at position 128 + k folds down to
        // k + {7, 2, 1, 0}, which is a carry-less multiply of the high half by 0x87.
        const __m128i poly = _mm_cvtsi64_si128(0x87);

        const __m128i f0 = _mm_clmulepi64_si128(hi, poly, 0x00); // hi_low * 0x87
        const __m128i f1 = _mm_clmulepi64_si128(hi, poly, 0x01); // hi_high * 0x87

        lo = _mm_xor_si128(lo, f0);
        lo = _mm_xor_si128(lo, _mm_slli_si128(f1, 8));

        // f1's top 64 bits hold whatever spilled back past bit 128 -- at most seven bits, since
        // 0x87's degree is 7 -- so one more fold finishes it, and that fold cannot spill again
        // (seven bits times eight is still well inside the low word).
        const __m128i spill = _mm_srli_si128(f1, 8);
        lo = _mm_xor_si128(lo, _mm_clmulepi64_si128(spill, poly, 0x00));

        _mm_storeu_si128(reinterpret_cast<__m128i*>(block),
                         useGfni ? reverseBitsInBytesGfni(lo) : reverseBitsInBytes(lo));
    }

    /* The public entry point, which reflects the subkey itself and so needs no prepared copy. */
    void Ghash::multiplyAccelerated(uint8_t block[BLOCK_BYTES], const uint8_t h[BLOCK_BYTES]) {
        uint8_t hReflected[BLOCK_BYTES];
        _mm_storeu_si128(reinterpret_cast<__m128i*>(hReflected),
                         reverseBitsInBytes(_mm_loadu_si128(reinterpret_cast<const __m128i*>(h))));
        multiplyCore(block, hReflected, hasGfni());
    }
#endif // CERTPP_GHASH_HWACCEL_AVAILABLE

    /* Whether multiply() takes the accelerated path here. */
    bool Ghash::accelerated() {
#if defined(CERTPP_GHASH_HWACCEL_AVAILABLE)
        return hasPclmul();
#else
        return false;
#endif
    }

    /* Multiplies in GCM's GF(2^128), on PCLMULQDQ where available. */
    void Ghash::multiply(uint8_t block[BLOCK_BYTES], const uint8_t h[BLOCK_BYTES]) {
#if defined(CERTPP_GHASH_HWACCEL_AVAILABLE)
        if (hasPclmul()) {
            multiplyAccelerated(block, h);
            return;
        }
#endif
        multiplyPortable(block, h);
    }

    /* Constructs an unkeyed accumulator. */
    Ghash::Ghash()
        : _buffered(0), _externalPowers(nullptr), _accelerated(false),
          _useGfni(false), _wide(false),
          _smallPowersReady(false), _powersReady(false) {
        std::memset(_h, 0, sizeof(_h));
        std::memset(_y, 0, sizeof(_y));
        std::memset(_block, 0, sizeof(_block));
        reflectSubkey();
    }

    /* Clears the subkey and the accumulator. */
    Ghash::~Ghash() {
        CSecure::zero(SByteSpan(_h, sizeof(_h)));
        CSecure::zero(SByteSpan(_hReflected, sizeof(_hReflected)));
        if (!_externalPowers && (_smallPowersReady || _powersReady)) {
            CSecure::zero(SByteSpan(
                reinterpret_cast<uint8_t*>(_hPowersReflected),
                sizeof(_hPowersReflected)));
        }
        CSecure::zero(SByteSpan(_y, sizeof(_y)));
        CSecure::zero(SByteSpan(_block, sizeof(_block)));
    }

    /* Y <- (Y ^ block) * H, one step of SP 800-38D 6.4's recurrence. */
    void Ghash::absorb(const uint8_t* block) {
#if defined(CERTPP_GHASH_HWACCEL_AVAILABLE)
        if (_accelerated) {
            // --> Y ^= block as one 16-byte operation. This was a byte-at-a-time loop, which is
            // sixteen loads, sixteen xors and sixteen stores per block -- and because both
            // operands are uint8_t* the compiler has to assume they may alias, so it cannot
            // vectorise the loop either. Measured at 48.5 cycles/block for push() against 20.0
            // for multiply() alone: roughly 28 cycles a block of loop, and the multiply itself
            // is already close to the floor for a serial PCLMULQDQ chain.
            _mm_storeu_si128(reinterpret_cast<__m128i*>(_y),
                _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(_y)),
                              _mm_loadu_si128(reinterpret_cast<const __m128i*>(block))));
            multiplyCore(_y, _hReflected, _useGfni);
            return;
        }
#endif
        for (size_t i = 0; i < BLOCK_BYTES; ++i) {
            _y[i] ^= block[i];
        }
        multiply(_y, _h);
    }

#if defined(CERTPP_GHASH_HWACCEL_AVAILABLE)
    /* Prepares just H^4..H for a four-block record. Computing the remaining twelve powers would
     * cost more than the payload itself at this size. */
    void Ghash::prepareSmallPowers() {
        if (_smallPowersReady) {
            return;
        }
        std::memcpy(_hPowersReflected[15], _hReflected, BLOCK_BYTES);
        uint8_t power[BLOCK_BYTES];
        std::memcpy(power, _h, BLOCK_BYTES);
        for (size_t exponent = 2; exponent <= 4; ++exponent) {
            multiplyAccelerated(power, _h);
            const __m128i reflected = reverseBitsInBytes(
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(power)));
            _mm_storeu_si128(
                reinterpret_cast<__m128i*>(_hPowersReflected[16 - exponent]), reflected);
        }
        CSecure::zero(SByteSpan(power, sizeof(power)));
        _smallPowersReady = true;
    }

    /* Precomputes the full H^16..H table only for a long input. */
    void Ghash::preparePowers() {
        if (_powersReady) {
            return;
        }

        std::memcpy(_hPowersReflected[15], _hReflected, BLOCK_BYTES); // H^1
        uint8_t power[BLOCK_BYTES];
        std::memcpy(power, _h, BLOCK_BYTES);
        for (size_t exponent = 2; exponent <= 16; ++exponent) {
            multiplyAccelerated(power, _h);
            const __m128i reflected = reverseBitsInBytes(
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(power)));
            _mm_storeu_si128(
                reinterpret_cast<__m128i*>(_hPowersReflected[16 - exponent]), reflected);
        }
        CSecure::zero(SByteSpan(power, sizeof(power)));
        _smallPowersReady = true;
        _powersReady = true;
    }

    /* Four recurrence steps at once:
     * Y4 = (Y0 xor X1)H^4 xor X2 H^3 xor X3 H^2 xor X4 H.
     * Carry-less multiplication and reduction are linear, so the four 256-bit products can be
     * XORed before one reduction. This removes three serial reductions and exposes enough
     * independent PCLMULQDQ work to fill the instruction pipeline. */
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
    __attribute__((target("gfni,pclmul,sse2")))
#endif
    void Ghash::absorb4(const uint8_t* blocks) {
        __m128i values[4];
        values[0] = _mm_xor_si128(
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(_y)),
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(blocks)));
        for (size_t i = 1; i < 4; ++i) {
            values[i] = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(blocks + i * BLOCK_BYTES));
        }
        for (size_t i = 0; i < 4; ++i) {
            values[i] = _useGfni
                ? reverseBitsInBytesGfni(values[i]) : reverseBitsInBytes(values[i]);
        }

        const auto powersTable = powerTable();
        const uint8_t* powers[4] = {
            powersTable[12], powersTable[13],
            powersTable[14], powersTable[15]
        };
        __m128i p00 = _mm_setzero_si128();
        __m128i p11 = _mm_setzero_si128();
        __m128i p01 = _mm_setzero_si128();
        __m128i p10 = _mm_setzero_si128();
        for (size_t i = 0; i < 4; ++i) {
            const __m128i power =
                _mm_loadu_si128(reinterpret_cast<const __m128i*>(powers[i]));
            p00 = _mm_xor_si128(p00, _mm_clmulepi64_si128(values[i], power, 0x00));
            p11 = _mm_xor_si128(p11, _mm_clmulepi64_si128(values[i], power, 0x11));
            p01 = _mm_xor_si128(p01, _mm_clmulepi64_si128(values[i], power, 0x01));
            p10 = _mm_xor_si128(p10, _mm_clmulepi64_si128(values[i], power, 0x10));
        }

        const __m128i mid = _mm_xor_si128(p01, p10);
        __m128i lo = _mm_xor_si128(p00, _mm_slli_si128(mid, 8));
        const __m128i hi = _mm_xor_si128(p11, _mm_srli_si128(mid, 8));
        const __m128i poly = _mm_cvtsi64_si128(0x87);
        const __m128i f0 = _mm_clmulepi64_si128(hi, poly, 0x00);
        const __m128i f1 = _mm_clmulepi64_si128(hi, poly, 0x01);
        lo = _mm_xor_si128(lo, f0);
        lo = _mm_xor_si128(lo, _mm_slli_si128(f1, 8));
        lo = _mm_xor_si128(lo, _mm_clmulepi64_si128(
            _mm_srli_si128(f1, 8), poly, 0x00));

        _mm_storeu_si128(reinterpret_cast<__m128i*>(_y),
            _useGfni ? reverseBitsInBytesGfni(lo) : reverseBitsInBytes(lo));
    }

    /* Eight recurrence steps with two groups of four independent field products. VPCLMULQDQ
     * performs one carry-less multiply in each 128-bit lane, so Karatsuba needs six vector
     * multiplies for all eight blocks. The lane products are XOR-folded before the one shared
     * reduction; the ordinary four-block path needs sixteen scalar PCLMUL products and a
     * reduction for each group. */
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
    __attribute__((target("avx512f,avx512bw,gfni,vpclmulqdq")))
#endif
    void Ghash::absorb8(const uint8_t* blocks) {
        const __m512i matrix = _mm512_set1_epi64(
            static_cast<long long>(0x8040201008040201ULL));

        __m512i a0 = _mm512_loadu_si512(blocks);
        __m512i a1 = _mm512_loadu_si512(blocks + 4 * BLOCK_BYTES);
        const __m128i y = _mm_loadu_si128(reinterpret_cast<const __m128i*>(_y));
        const __m512i y0 = _mm512_maskz_mov_epi64(
            0x03, _mm512_castsi128_si512(y));
        a0 = _mm512_xor_si512(a0, y0);
        a0 = _mm512_gf2p8affine_epi64_epi8(a0, matrix, 0);
        a1 = _mm512_gf2p8affine_epi64_epi8(a1, matrix, 0);

        const auto powers = powerTable();
        const __m512i b0 = _mm512_loadu_si512(powers + 8);
        const __m512i b1 = _mm512_loadu_si512(powers + 12);

        __m512i lo = _mm512_xor_si512(
            _mm512_clmulepi64_epi128(a0, b0, 0x00),
            _mm512_clmulepi64_epi128(a1, b1, 0x00));
        __m512i hi = _mm512_xor_si512(
            _mm512_clmulepi64_epi128(a0, b0, 0x11),
            _mm512_clmulepi64_epi128(a1, b1, 0x11));

        const __m512i a0Mixed = _mm512_xor_si512(
            a0, _mm512_shuffle_epi32(a0, 0x4e));
        const __m512i a1Mixed = _mm512_xor_si512(
            a1, _mm512_shuffle_epi32(a1, 0x4e));
        const __m512i b0Mixed = _mm512_xor_si512(
            b0, _mm512_shuffle_epi32(b0, 0x4e));
        const __m512i b1Mixed = _mm512_xor_si512(
            b1, _mm512_shuffle_epi32(b1, 0x4e));
        __m512i mid = _mm512_xor_si512(
            _mm512_clmulepi64_epi128(a0Mixed, b0Mixed, 0x00),
            _mm512_clmulepi64_epi128(a1Mixed, b1Mixed, 0x00));
        mid = _mm512_xor_si512(mid, _mm512_xor_si512(lo, hi));

        // XOR the four 128-bit lane products into one product before reducing.
        __m256i lo256 = _mm256_xor_si256(
            _mm512_castsi512_si256(lo), _mm512_extracti64x4_epi64(lo, 1));
        __m256i hi256 = _mm256_xor_si256(
            _mm512_castsi512_si256(hi), _mm512_extracti64x4_epi64(hi, 1));
        __m256i mid256 = _mm256_xor_si256(
            _mm512_castsi512_si256(mid), _mm512_extracti64x4_epi64(mid, 1));
        __m128i lo128 = _mm_xor_si128(
            _mm256_castsi256_si128(lo256), _mm256_extracti128_si256(lo256, 1));
        __m128i hi128 = _mm_xor_si128(
            _mm256_castsi256_si128(hi256), _mm256_extracti128_si256(hi256, 1));
        const __m128i mid128 = _mm_xor_si128(
            _mm256_castsi256_si128(mid256), _mm256_extracti128_si256(mid256, 1));

        lo128 = _mm_xor_si128(lo128, _mm_slli_si128(mid128, 8));
        hi128 = _mm_xor_si128(hi128, _mm_srli_si128(mid128, 8));

        const __m128i poly = _mm_cvtsi64_si128(0x87);
        const __m128i f0 = _mm_clmulepi64_si128(hi128, poly, 0x00);
        const __m128i f1 = _mm_clmulepi64_si128(hi128, poly, 0x01);
        lo128 = _mm_xor_si128(lo128, f0);
        lo128 = _mm_xor_si128(lo128, _mm_slli_si128(f1, 8));
        lo128 = _mm_xor_si128(lo128, _mm_clmulepi64_si128(
            _mm_srli_si128(f1, 8), poly, 0x00));

        const __m128i matrix128 = _mm_set1_epi64x(
            static_cast<long long>(0x8040201008040201ULL));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(_y),
            _mm_gf2p8affine_epi64_epi8(lo128, matrix128, 0));
    }

    /* Sixteen-step version of absorb8(). Four independent 512-bit groups amortise the final
     * reduction and the accumulator dependency over a full 256 bytes. */
#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
    __attribute__((target("avx512f,avx512bw,gfni,vpclmulqdq")))
#endif
    void Ghash::absorb16(const uint8_t* blocks) {
        const __m512i matrix = _mm512_set1_epi64(
            static_cast<long long>(0x8040201008040201ULL));
        const __m128i y = _mm_loadu_si128(reinterpret_cast<const __m128i*>(_y));
        const __m512i y0 = _mm512_maskz_mov_epi64(
            0x03, _mm512_castsi128_si512(y));

        const auto powers = powerTable();
        __m512i lo = _mm512_setzero_si512();
        __m512i hi = _mm512_setzero_si512();
        __m512i mid = _mm512_setzero_si512();
        for (size_t group = 0; group < 4; ++group) {
            __m512i a = _mm512_loadu_si512(blocks + group * 4 * BLOCK_BYTES);
            if (group == 0) {
                a = _mm512_xor_si512(a, y0);
            }
            a = _mm512_gf2p8affine_epi64_epi8(a, matrix, 0);
            const __m512i b = _mm512_loadu_si512(powers + group * 4);

            const __m512i partLo = _mm512_clmulepi64_epi128(a, b, 0x00);
            const __m512i partHi = _mm512_clmulepi64_epi128(a, b, 0x11);
            const __m512i aMixed = _mm512_xor_si512(
                a, _mm512_shuffle_epi32(a, 0x4e));
            const __m512i bMixed = _mm512_xor_si512(
                b, _mm512_shuffle_epi32(b, 0x4e));
            __m512i partMid = _mm512_clmulepi64_epi128(aMixed, bMixed, 0x00);
            partMid = _mm512_xor_si512(partMid, _mm512_xor_si512(partLo, partHi));

            lo = _mm512_xor_si512(lo, partLo);
            hi = _mm512_xor_si512(hi, partHi);
            mid = _mm512_xor_si512(mid, partMid);
        }

        __m256i lo256 = _mm256_xor_si256(
            _mm512_castsi512_si256(lo), _mm512_extracti64x4_epi64(lo, 1));
        __m256i hi256 = _mm256_xor_si256(
            _mm512_castsi512_si256(hi), _mm512_extracti64x4_epi64(hi, 1));
        __m256i mid256 = _mm256_xor_si256(
            _mm512_castsi512_si256(mid), _mm512_extracti64x4_epi64(mid, 1));
        __m128i lo128 = _mm_xor_si128(
            _mm256_castsi256_si128(lo256), _mm256_extracti128_si256(lo256, 1));
        __m128i hi128 = _mm_xor_si128(
            _mm256_castsi256_si128(hi256), _mm256_extracti128_si256(hi256, 1));
        const __m128i mid128 = _mm_xor_si128(
            _mm256_castsi256_si128(mid256), _mm256_extracti128_si256(mid256, 1));
        lo128 = _mm_xor_si128(lo128, _mm_slli_si128(mid128, 8));
        hi128 = _mm_xor_si128(hi128, _mm_srli_si128(mid128, 8));

        const __m128i poly = _mm_cvtsi64_si128(0x87);
        const __m128i f0 = _mm_clmulepi64_si128(hi128, poly, 0x00);
        const __m128i f1 = _mm_clmulepi64_si128(hi128, poly, 0x01);
        lo128 = _mm_xor_si128(lo128, f0);
        lo128 = _mm_xor_si128(lo128, _mm_slli_si128(f1, 8));
        lo128 = _mm_xor_si128(lo128, _mm_clmulepi64_si128(
            _mm_srli_si128(f1, 8), poly, 0x00));

        const __m128i matrix128 = _mm_set1_epi64x(
            static_cast<long long>(0x8040201008040201ULL));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(_y),
            _mm_gf2p8affine_epi64_epi8(lo128, matrix128, 0));
    }
#endif

    /* Converts the subkey into the basis the accelerated multiply wants, once per message. */
    void Ghash::reflectSubkey() {
        std::memset(_hReflected, 0, sizeof(_hReflected));
        _externalPowers = nullptr;
#if defined(CERTPP_GHASH_HWACCEL_AVAILABLE)
        _mm_storeu_si128(reinterpret_cast<__m128i*>(_hReflected),
                         reverseBitsInBytes(_mm_loadu_si128(reinterpret_cast<const __m128i*>(_h))));

        // --> Read once here so absorb() does not read a guarded static per block.
        _accelerated = hasPclmul();
        _useGfni = _accelerated && hasGfni();
        _wide = _accelerated && hasWideGhash();
        _smallPowersReady = false;
        _powersReady = false;
#else
        _accelerated = false;
        _useGfni = false;
        _wide = false;
        _smallPowersReady = false;
        _powersReady = false;
#endif
    }

    /* Keys this accumulator and clears its state. */
    void Ghash::reset(const uint8_t h[BLOCK_BYTES]) {
        if (!_externalPowers && (_smallPowersReady || _powersReady)) {
            CSecure::zero(SByteSpan(
                reinterpret_cast<uint8_t*>(_hPowersReflected),
                sizeof(_hPowersReflected)));
        }
        std::memcpy(_h, h, BLOCK_BYTES);
        std::memset(_y, 0, sizeof(_y));
        std::memset(_block, 0, sizeof(_block));
        _buffered = 0;
        reflectSubkey();
    }

    /* Keys this accumulator while borrowing a prepared immutable power table. */
    void Ghash::reset(
        const uint8_t h[BLOCK_BYTES],
        const uint8_t preparedPowers[16][BLOCK_BYTES]
    ) {
        reset(h);
#if defined(CERTPP_GHASH_HWACCEL_AVAILABLE)
        if (preparedPowers && _wide) {
            _externalPowers = preparedPowers;
            _smallPowersReady = true;
            _powersReady = true;
        }
#else
        (void)preparedPowers;
#endif
    }

    /* Selects the borrowed table when a keyed owner has already prepared it. */
    const uint8_t (*Ghash::powerTable() const)[BLOCK_BYTES] {
        return _externalPowers ? _externalPowers : _hPowersReflected;
    }

    /* Absorbs more input. */
    void Ghash::push(const uint8_t* data, size_t length) {
        if (!data || length == 0) {
            return;
        }

        size_t offset = 0;

        if (_buffered != 0) {
            const size_t room = BLOCK_BYTES - _buffered;
            const size_t take = (length < room) ? length : room;

            std::memcpy(_block + _buffered, data, take);
            _buffered += take;
            offset += take;

            if (_buffered < BLOCK_BYTES) {
                return;
            }

            absorb(_block);
            _buffered = 0;
        }

#if defined(CERTPP_GHASH_HWACCEL_AVAILABLE)
        if (_wide && length - offset >= 16 * BLOCK_BYTES) {
            preparePowers();
            while (length - offset >= 16 * BLOCK_BYTES) {
                absorb16(data + offset);
                offset += 16 * BLOCK_BYTES;
            }
            while (length - offset >= 8 * BLOCK_BYTES) {
                absorb8(data + offset);
                offset += 8 * BLOCK_BYTES;
            }
        }
        if (_accelerated && length - offset >= 4 * BLOCK_BYTES) {
            prepareSmallPowers();
            while (length - offset >= 4 * BLOCK_BYTES) {
                absorb4(data + offset);
                offset += 4 * BLOCK_BYTES;
            }
        }
#endif

        while (length - offset >= BLOCK_BYTES) {
            absorb(data + offset);
            offset += BLOCK_BYTES;
        }

        const size_t rest = length - offset;
        if (rest != 0) {
            std::memcpy(_block, data + offset, rest);
            _buffered = rest;
        }
    }

    /* Zero-fills and absorbs a partially buffered block. */
    void Ghash::padToBlock() {
        if (_buffered == 0) {
            return;
        }

        std::memset(_block + _buffered, 0, BLOCK_BYTES - _buffered);
        absorb(_block);
        _buffered = 0;
    }

    /* Finishes the hash. */
    void Ghash::finish(uint8_t out[BLOCK_BYTES]) {
        padToBlock();
        std::memcpy(out, _y, BLOCK_BYTES);
    }

    /* Supplies AES-GCM's fused wide kernel with the state it needs. */
    bool Ghash::exportWideState(
        uint8_t accumulator[BLOCK_BYTES], uint8_t powers[16][BLOCK_BYTES]
    ) {
#if defined(CERTPP_GHASH_HWACCEL_AVAILABLE)
        if (!_wide || _buffered != 0 || !accumulator || !powers) {
            return false;
        }
        preparePowers();
        std::memcpy(accumulator, _y, BLOCK_BYTES);
        std::memcpy(powers, powerTable(), sizeof(_hPowersReflected));
        return true;
#else
        (void)accumulator;
        (void)powers;
        return false;
#endif
    }

    /* Takes back the accumulator produced by AES-GCM's fused wide kernel. */
    void Ghash::replaceAccumulator(const uint8_t accumulator[BLOCK_BYTES]) {
        if (!accumulator) {
            return;
        }
        std::memcpy(_y, accumulator, BLOCK_BYTES);
        std::memset(_block, 0, sizeof(_block));
        _buffered = 0;
    }

} // namespace crypto
} // namespace certpp
