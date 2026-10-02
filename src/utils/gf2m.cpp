#include <certpp/utils/gf2m.hpp>
#include <certpp/utils/hex.hpp>
#include <cstring>
#include <utility>

/* Hardware-accelerated carry-less multiply (PCLMULQDQ) for mul()'s wide-product step, gated by
 * both the CERTPP_DISABLE_HWACCEL_SIMD build option and the target architecture -- on anything other
 * than x86/x86-64 this whole block (and CERTPP_GF2M_HWACCEL_AVAILABLE with it) is compiled out
 * entirely, and mul() falls back to the portable shift-and-XOR loop unconditionally. */
#if !defined(CERTPP_DISABLE_HWACCEL_SIMD) && \
    (defined(_M_X64) || defined(__x86_64__) || defined(_M_IX86) || defined(__i386__))
#define CERTPP_GF2M_HWACCEL_AVAILABLE 1
#include <wmmintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

namespace certpp {

#if defined(CERTPP_GF2M_HWACCEL_AVAILABLE)
        /* Whether this CPU actually has PCLMULQDQ -- it's an optional x86-64 feature, not
         * guaranteed just because the binary was built for the architecture, so this must be
         * checked at runtime (CPUID.1:ECX.PCLMULQDQ, bit 1) before ever emitting the
         * instruction; unconditionally emitting it risks SIGILL on an older CPU. Computed once. */
        bool CGf2m::hasPclmul() {
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

        /* Computes the same WIDE_LIMBS-limb carry-less product xorShiftedInto()'s per-bit loop
         * (in mul()) would, but via PCLMULQDQ's 64x64->128-bit carry-less multiply as the
         * "digit multiply" primitive (schoolbook multiplication over pairs of 64-bit limbs)
         * instead of iterating one bit of `b` at a time -- a fixed 9x9 grid of hardware
         * multiplies regardless of the field's degree, versus up to 571 shift-and-XOR steps.
         * wide must already be zeroed; reduceWide() (unchanged either way) does the rest.
         *
         * __attribute__((target(...))) lets GCC/Clang emit PCLMULQDQ in just this one function
         * regardless of the translation unit's default -march (MSVC needs no equivalent -- see
         * the identical note on bignum.cpp's mulAccelerated()). */
#if defined(__GNUC__) && !defined(_MSC_VER)
        __attribute__((target("pclmul,sse2")))
#endif
        void CGf2m::wideProductAccelerated(uint64_t* wide, const uint64_t* a, const uint64_t* b) {
            for (size_t i = 0; i < LIMB_COUNT; ++i) {
                if (a[i] == 0) {
                    continue;
                }

                __m128i va = _mm_cvtsi64_si128(static_cast<long long>(a[i]));

                for (size_t j = 0; j < LIMB_COUNT; ++j) {
                    if (b[j] == 0) {
                        continue;
                    }

                    __m128i vb = _mm_cvtsi64_si128(static_cast<long long>(b[j]));
                    __m128i prod = _mm_clmulepi64_si128(va, vb, 0x00);

                    uint64_t lo = static_cast<uint64_t>(_mm_cvtsi128_si64(prod));
                    uint64_t hi = static_cast<uint64_t>(_mm_cvtsi128_si64(_mm_srli_si128(prod, 8)));

                    wide[i + j] ^= lo;
                    wide[i + j + 1] ^= hi;
                }
            }
        }
#endif

        bool CGf2m::testBitIn(const uint64_t* limbs, size_t nLimbs, size_t bit) {
            size_t limb = bit / 64, b = bit % 64;
            if (limb >= nLimbs) {
                return false;
            }
            return (limbs[limb] >> b) & uint64_t(1);
        }

        void CGf2m::toggleBitIn(uint64_t* limbs, size_t nLimbs, size_t bit) {
            size_t limb = bit / 64, b = bit % 64;
            if (limb < nLimbs) {
                limbs[limb] ^= (uint64_t(1) << b);
            }
        }

        /* dst ^= (src << shift), where dst has dstLimbs limbs and src has srcLimbs limbs. Bits
         * shifted beyond dst's capacity are silently dropped (every caller sizes dst so this
         * never actually happens for the values it passes). */
        void CGf2m::xorShiftedInto(uint64_t* dst, size_t dstLimbs, const uint64_t* src, size_t srcLimbs, size_t shift) {
            size_t limbShift = shift / 64;
            size_t bitShift = shift % 64;

            for (size_t i = 0; i < srcLimbs; ++i) {
                if (src[i] == 0) {
                    continue;
                }

                size_t di = i + limbShift;
                if (di < dstLimbs) {
                    dst[di] ^= (bitShift == 0) ? src[i] : (src[i] << bitShift);
                }

                if (bitShift != 0) {
                    size_t di2 = di + 1;
                    if (di2 < dstLimbs) {
                        dst[di2] ^= (src[i] >> (64 - bitShift));
                    }
                }
            }
        }

        /* Highest set bit index of a polynomial, or SIZE_MAX if it's zero. */
        size_t CGf2m::degreeOf(const uint64_t* limbs, size_t nLimbs) {
            for (size_t i = nLimbs; i-- > 0; ) {
                if (limbs[i] != 0) {
                    uint64_t v = limbs[i];
                    size_t bit = 63;
                    while (!((v >> bit) & uint64_t(1))) {
                        --bit;
                    }
                    return i * 64 + bit;
                }
            }
            return SIZE_MAX;
        }

        bool CGf2m::isOneIn(const uint64_t* limbs, size_t nLimbs) {
            if (limbs[0] != 1) {
                return false;
            }
            for (size_t i = 1; i < nLimbs; ++i) {
                if (limbs[i] != 0) {
                    return false;
                }
            }
            return true;
        }

        /* dst = src >> shift. */
        void CGf2m::shiftRightInto(uint64_t* dst, const uint64_t* src, size_t nLimbs, size_t shift) {
            const size_t limbShift = shift / 64;
            const size_t bitShift = shift % 64;

            for (size_t i = 0; i < nLimbs; ++i) {
                const size_t from = i + limbShift;
                uint64_t value = from < nLimbs ? src[from] : 0;

                if (bitShift != 0) {
                    value >>= bitShift;

                    if ((from + 1) < nLimbs) {
                        value |= uint64_t(src[from + 1] << (64 - bitShift));
                    }
                }

                dst[i] = value;
            }
        }

        /* Truncates to a polynomial of degree < bit. */
        void CGf2m::clearBitsFrom(uint64_t* limbs, size_t nLimbs, size_t bit) {
            const size_t limbIndex = bit / 64;
            const size_t bitIndex = bit % 64;

            if (limbIndex >= nLimbs) {
                return;
            }

            limbs[limbIndex] &= bitIndex != 0 ? ((uint64_t(1) << bitIndex) - 1) : uint64_t(0);

            for (size_t i = limbIndex + 1; i < nLimbs; ++i) {
                limbs[i] = 0;
            }
        }

        /* Reduces a WIDE_LIMBS-limb product (degree up to 2*field.m - 2) modulo field's
         * reduction polynomial in place, leaving the result in wide's low LIMB_COUNT limbs (its high
         * limbs end up zero) -- see Hankerson/Menezes/Vanstone "Guide to Elliptic Curve
         * Cryptography" 2.35 for the general method.
         *
         * Word-level rather than bit-serial. The identity is x^m == x^terms[0] + ... + 1, so every
         * bit at position p >= m moves down to p-m and to p-m+terms[t]; crucially, that is the
         * *same* displacement for every such bit, so the whole excess can be folded at once:
         * take hi = wide >> m, clear everything from bit m up, then XOR hi back in at 0 and at
         * each term offset. The previous implementation walked one bit at a time from 2m-2 down to
         * m, toggling 1+termCount bits (each with its own divide and modulo) per set bit -- for
         * B-571 that is ~570 iterations and thousands of toggles where this does two folds. The
         * reduction had been measured at 95-98% of a multiplication's cost, which meant the
         * PCLMULQDQ-accelerated product above was buying almost nothing; this is what lets that
         * acceleration actually show up in binary-curve ECDSA.
         *
         * Folding can leave bits at or above m again (p-m+terms[t] >= m whenever p >= 2m-terms[t]),
         * so it loops. For all five fields this library ships the loop runs exactly twice -- the
         * second fold always lands strictly below m -- but it is written as a loop rather than two
         * unrolled passes so it stays correct for any reduction polynomial. */
        void CGf2m::reduceWide(uint64_t* wide, const SGf2mField& field) {
            const size_t m = field.m;

            while (true) {
                const size_t degree = degreeOf(wide, WIDE_LIMBS);
                if (degree == SIZE_MAX || degree < m) {
                    return;
                }

                uint64_t hi[WIDE_LIMBS] = {};
                shiftRightInto(hi, wide, WIDE_LIMBS, m);

                clearBitsFrom(wide, WIDE_LIMBS, m);

                xorShiftedInto(wide, WIDE_LIMBS, hi, WIDE_LIMBS, 0); // the "+1" term
                for (size_t t = 0; t < field.termCount; ++t) {
                    xorShiftedInto(wide, WIDE_LIMBS, hi, WIDE_LIMBS, field.terms[t]);
                }
            }
        }

        /* NIST-recommended reduction polynomials for the binary fields this library's B-x/K-x
         * curves share (FIPS 186-4 Appendix D / SEC 2); independently confirmed irreducible of
         * the stated degree via a standalone check (Python's sympy:
         * Poly(..., modulus=2).is_irreducible) before hardcoding, per this module's established
         * constant-verification discipline.
         *
         * Returns a reference to a function-local static ("construct on first use") rather than
         * being a plain CGf2m::_knownFields class-static array: another translation unit's
         * static initializer (CEc2Curve::_knownCurves, in ec2curve.cpp) calls knownFieldPtr()
         * while it itself is being constructed, and the relative order in which different TUs'
         * static objects are initialized is unspecified by the standard -- a plain static array
         * here would risk being read before its own elements were populated. A function-local
         * static is guaranteed initialized on first use regardless of that ordering, which is
         * exactly what this dependency needs. */
        const SGf2mField* CGf2m::knownFieldsTable() {
            static const SGf2mField table[EGF2M_MAX - 1] = {
                // EGF2M_M163: pentanomial x^163 + x^7 + x^6 + x^3 + 1
                SGf2mField{ 163, 3, { 7, 6, 3 } },
                // EGF2M_M233: trinomial x^233 + x^74 + 1
                SGf2mField{ 233, 1, { 74, 0, 0 } },
                // EGF2M_M283: pentanomial x^283 + x^12 + x^7 + x^5 + 1
                SGf2mField{ 283, 3, { 12, 7, 5 } },
                // EGF2M_M409: trinomial x^409 + x^87 + 1
                SGf2mField{ 409, 1, { 87, 0, 0 } },
                // EGF2M_M571: pentanomial x^571 + x^10 + x^5 + x^2 + 1
                SGf2mField{ 571, 3, { 10, 5, 2 } },
            };

            return table;
        }

    bool CGf2m::knownField(EGf2mKnownField field, SGf2mField& out) {
        if (field <= EGF2M_UNKNOWN || field >= EGF2M_MAX) {
            return false;
        }

        out = knownFieldsTable()[field - 1];
        return true;
    }

    const SGf2mField* CGf2m::knownFieldPtr(EGf2mKnownField field) {
        if (field <= EGF2M_UNKNOWN || field >= EGF2M_MAX) {
            return nullptr;
        }

        return &knownFieldsTable()[field - 1];
    }

    CGf2m::CGf2m(const SGf2mField& field, uint64_t value) : _field(&field) {
        _limbs[0] = value;
    }

    bool CGf2m::fromBigEndian(const SGf2mField& field, SReadOnlyByteSpan bytes, CGf2m& out) {
        CGf2m result(field, 0);

        for (size_t i = 0; i < bytes.size; ++i) {
            uint8_t byte = bytes.data[bytes.size - 1 - i];
            if (byte == 0) {
                continue;
            }

            for (size_t b = 0; b < 8; ++b) {
                if ((byte >> b) & 1u) {
                    size_t bitIndex = i * 8 + b;
                    if (bitIndex >= field.m) {
                        return false;
                    }
                    result.setBit(bitIndex);
                }
            }
        }

        out = result;
        return true;
    }

    bool CGf2m::fromHex(const SGf2mField& field, const char* hex, CGf2m& out) {
        TArray<uint8_t> bytes;
        if (!CHex::decode(hex, bytes)) {
            return false;
        }

        return fromBigEndian(field, SReadOnlyByteSpan(bytes.begin(), bytes.size()), out);
    }

    void CGf2m::toBigEndian(TArray<uint8_t>& out) const {
        size_t byteLen = fieldByteLen();
        out.resize(byteLen);

        for (size_t i = 0; i < byteLen; ++i) {
            uint8_t byte = 0;
            for (size_t b = 0; b < 8; ++b) {
                size_t bitIndex = i * 8 + b;
                if (bitIndex < _field->m && testBit(bitIndex)) {
                    byte |= uint8_t(1u << b);
                }
            }
            out[byteLen - 1 - i] = byte;
        }
    }

    CBigNum CGf2m::toInteger() const {
        TArray<uint8_t> bytes;
        toBigEndian(bytes);
        return CBigNum::fromBigEndian(SReadOnlyByteSpan(bytes.begin(), bytes.size()));
    }

    size_t CGf2m::fieldByteLen() const {
        return (_field->m + 7) / 8;
    }

    bool CGf2m::isZero() const {
        for (size_t i = 0; i < LIMB_COUNT; ++i) {
            if (_limbs[i] != 0) {
                return false;
            }
        }
        return true;
    }

    bool CGf2m::testBit(size_t index) const {
        return testBitIn(_limbs, LIMB_COUNT, index);
    }

    void CGf2m::setBit(size_t index) {
        size_t limb = index / 64, bit = index % 64;
        if (limb < LIMB_COUNT) {
            _limbs[limb] |= (uint64_t(1) << bit);
        }
    }

    bool CGf2m::equals(const CGf2m& other) const {
        for (size_t i = 0; i < LIMB_COUNT; ++i) {
            if (_limbs[i] != other._limbs[i]) {
                return false;
            }
        }
        return true;
    }

    CGf2m& CGf2m::add(const CGf2m& other) {
        if (!_field) {
            _field = other._field;
        }

        for (size_t i = 0; i < LIMB_COUNT; ++i) {
            _limbs[i] ^= other._limbs[i];
        }
        return *this;
    }

    CGf2m& CGf2m::mul(const CGf2m& other) {
        uint64_t wide[WIDE_LIMBS] = {};

#if defined(CERTPP_GF2M_HWACCEL_AVAILABLE)
        if (hasPclmul()) {
            wideProductAccelerated(wide, _limbs, other._limbs);
        } else
#endif
        {
            for (size_t i = 0; i < _field->m; ++i) {
                if (other.testBit(i)) {
                    xorShiftedInto(wide, WIDE_LIMBS, _limbs, LIMB_COUNT, i);
                }
            }
        }

        reduceWide(wide, *_field);

        std::memcpy(_limbs, wide, LIMB_COUNT * sizeof(uint64_t));
        return *this;
    }

    /* Implemented as mul(self) rather than a dedicated bit-spread fast path: correct and much
     * simpler, at the cost of doing a full multiply's work for what could be a cheaper
     * operation -- consistent with this module's/CBigNum's/CEcCurve's existing correctness-and-
     * simplicity-over-performance stance. A dedicated fast path is a valid later optimization,
     * not a correctness gap. */
    CGf2m& CGf2m::square() {
        return mul(*this);
    }

    CGf2m& CGf2m::inverse() {
        const SGf2mField& field = *_field;

        if (isZero()) {
            return *this;
        }

        uint64_t u[LIMB_COUNT];
        std::memcpy(u, _limbs, sizeof(u));

        uint64_t v[LIMB_COUNT] = {};
        toggleBitIn(v, LIMB_COUNT, field.m);
        toggleBitIn(v, LIMB_COUNT, 0);
        for (size_t t = 0; t < field.termCount; ++t) {
            toggleBitIn(v, LIMB_COUNT, field.terms[t]);
        }

        uint64_t g1[LIMB_COUNT] = {};
        g1[0] = 1;
        uint64_t g2[LIMB_COUNT] = {};

        // Binary extended Euclidean algorithm over GF(2)[x] (Hankerson/Menezes/Vanstone "Guide
        // to Elliptic Curve Cryptography" Algorithm 2.48).
        while (!isOneIn(u, LIMB_COUNT)) {
            ptrdiff_t degU = ptrdiff_t(degreeOf(u, LIMB_COUNT));
            ptrdiff_t degV = ptrdiff_t(degreeOf(v, LIMB_COUNT));
            ptrdiff_t j = degU - degV;

            if (j < 0) {
                for (size_t i = 0; i < LIMB_COUNT; ++i) {
                    std::swap(u[i], v[i]);
                }
                for (size_t i = 0; i < LIMB_COUNT; ++i) {
                    std::swap(g1[i], g2[i]);
                }
                j = -j;
            }

            xorShiftedInto(u, LIMB_COUNT, v, LIMB_COUNT, size_t(j));
            xorShiftedInto(g1, LIMB_COUNT, g2, LIMB_COUNT, size_t(j));
        }

        std::memcpy(_limbs, g1, sizeof(_limbs));
        return *this;
    }

} // namespace certpp
