#include "ghash.hpp"
#include <certpp/utils/secure.hpp>
#include <cstring>

/* The guard in ghash.hpp decides whether an accelerated path exists at all; this one only pulls
 * in the intrinsics and CPUID headers it needs, and must stay in step with it. */
#if defined(CERTPP_GHASH_HWACCEL_AVAILABLE)
#include <wmmintrin.h>
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
#if defined(__GNUC__) && !defined(_MSC_VER)
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
    /* The same multiplication via PCLMULQDQ.
     *
     * Rather than multiply in GCM's reflected convention -- where the classic trick is a
     * shift-by-one plus a reduction whose constants are easy to transcribe and impossible to
     * eyeball -- this converts both operands into the ordinary one (bit i of the 128-bit
     * little-endian value is the coefficient of x^i) with reverseBitsInBytes(), multiplies there,
     * and converts the product back. The conversion costs a dozen SSE2 instructions per operand
     * and makes the reduction the textbook one: x^128 = x^7 + x^2 + x + 1, i.e. 0x87.
     *
     * __attribute__((target(...))) lets GCC/Clang emit PCLMULQDQ in just this one function
     * regardless of the translation unit's default -march (MSVC needs no equivalent -- see the
     * identical note on gf2m.cpp's wideProductAccelerated()). */
#if defined(__GNUC__) && !defined(_MSC_VER)
    __attribute__((target("pclmul,sse2")))
#endif
    void Ghash::multiplyAccelerated(uint8_t block[BLOCK_BYTES], const uint8_t h[BLOCK_BYTES]) {
        const __m128i a = reverseBitsInBytes(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block)));
        const __m128i b = reverseBitsInBytes(_mm_loadu_si128(reinterpret_cast<const __m128i*>(h)));

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

        _mm_storeu_si128(reinterpret_cast<__m128i*>(block), reverseBitsInBytes(lo));
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
    Ghash::Ghash() : _buffered(0) {
        std::memset(_h, 0, sizeof(_h));
        std::memset(_y, 0, sizeof(_y));
        std::memset(_block, 0, sizeof(_block));
    }

    /* Clears the subkey and the accumulator. */
    Ghash::~Ghash() {
        CSecure::zero(SByteSpan(_h, sizeof(_h)));
        CSecure::zero(SByteSpan(_y, sizeof(_y)));
        CSecure::zero(SByteSpan(_block, sizeof(_block)));
    }

    /* Y <- (Y ^ block) * H, one step of SP 800-38D 6.4's recurrence. */
    void Ghash::absorb(const uint8_t* block) {
        for (size_t i = 0; i < BLOCK_BYTES; ++i) {
            _y[i] ^= block[i];
        }

        multiply(_y, _h);
    }

    /* Keys this accumulator and clears its state. */
    void Ghash::reset(const uint8_t h[BLOCK_BYTES]) {
        std::memcpy(_h, h, BLOCK_BYTES);
        std::memset(_y, 0, sizeof(_y));
        std::memset(_block, 0, sizeof(_block));
        _buffered = 0;
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

} // namespace crypto
} // namespace certpp
