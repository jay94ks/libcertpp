#ifndef __INCLUDE_CERTPP_UTILS_GF2M_HPP__
#define __INCLUDE_CERTPP_UTILS_GF2M_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/array.hpp>
#include <certpp/utils/bignum.hpp>

namespace certpp {

    /**
     * The known GF(2^m) fields CGf2m::knownField() can retrieve by identifier, in the same
     * order they're defined in CGf2m::_knownFields. Each field is shared by a "B" (random) and
     * "K" (Koblitz) NIST binary curve of the same m -- the field itself doesn't depend on the
     * curve equation, only on m and the reduction polynomial.
     */
    enum EGf2mKnownField {
        EGF2M_UNKNOWN = 0, /**< Not a valid field identifier. */
        EGF2M_M163,        /**< GF(2^163), shared by B-163/K-163. */
        EGF2M_M233,        /**< GF(2^233), shared by B-233/K-233. */
        EGF2M_M283,        /**< GF(2^283), shared by B-283/K-283. */
        EGF2M_M409,        /**< GF(2^409), shared by B-409/K-409. */
        EGF2M_M571,        /**< GF(2^571), shared by B-571/K-571. */

        EGF2M_MAX /**< Sentinel value representing the maximum known field ID. */
    };

    /**
     * A binary field GF(2^m)'s domain parameters: its degree m and the reduction polynomial
     * f(x) = x^m + x^(terms[0]) + ... + x^(terms[termCount-1]) + 1 elements are reduced modulo
     * (a trinomial has termCount == 1, a pentanomial termCount == 3 -- every NIST binary curve
     * field uses one or the other).
     */
    struct SGf2mField {
        size_t m;             /**< The field's degree (163/233/283/409/571 for this library's known fields). */
        size_t termCount;     /**< The number of middle terms in the reduction polynomial (1 or 3). */
        size_t terms[3];      /**< The middle terms' exponents (0 < terms[i] < m); only the first termCount entries are used. */
    };

    /**
     * An element of a binary field GF(2^m), in polynomial basis. Fixed-capacity (covers m up to
     * 576 bits, enough for every field this library defines up to GF(2^571)) rather than
     * arbitrary-precision like CBigNum: unlike an integer, a field element's width never grows
     * past its field's fixed m, so there's no canonicalization/growth logic to get right.
     *
     * Addition is XOR (also serves as subtraction, since characteristic-2 fields have a - b ==
     * a + b); multiplication is carry-less polynomial multiplication followed by reduction
     * modulo the field's reduction polynomial; inversion is the binary extended Euclidean
     * algorithm over GF(2)[x]. There is no ordering (<, > are meaningless over a field) and no
     * constant-time hardening, matching this library's existing CBigNum/CEcCurve stance of
     * correctness/simplicity over performance and side-channel resistance.
     *
     * A CGf2m doesn't own its SGf2mField -- it stores a non-owning pointer to one, always a
     * `static const` singleton (e.g. from CGf2m::knownField() or a caller's own static
     * instance), never a per-instance owner. This is a deliberate, narrower exception to the
     * by-value-curve-ownership rule CEcdsa's key classes follow (see ecdsa.cpp): that rule
     * exists because a CEcCurve can be a per-*instance* member whose owner (a CEcdsa object)
     * may be destroyed before a key derived from it, whereas an SGf2mField is only ever a
     * program-lifetime constant, so there is no equivalent dangling-pointer risk here.
     */
    class CERTPP_API CGf2m {
    public:
        /** Fixed limb capacity: 9 * 64 = 576 bits, enough for m up to 571 (this library's largest known field). */
        static constexpr size_t LIMB_COUNT = 9;

    private:
        uint64_t _limbs[LIMB_COUNT] = {}; // little-endian 64-bit limbs; unused high bits/limbs are always zero.
        const SGf2mField* _field = nullptr;

        static constexpr size_t WIDE_LIMBS = 2 * LIMB_COUNT;

#if !defined(CERTPP_DISABLE_HWACCEL_SIMD) && \
    (defined(_M_X64) || defined(__x86_64__) || defined(_M_IX86) || defined(__i386__))
        /* Hardware-accelerated carry-less multiply (PCLMULQDQ) for mul()'s wide-product step --
         * see gf2m.cpp's identical guard (which this must match exactly) for the full rationale. */
        static bool hasPclmul();

#if defined(__GNUC__) && !defined(_MSC_VER)
        __attribute__((target("pclmul,sse2")))
#endif
        static void wideProductAccelerated(uint64_t* wide, const uint64_t* a, const uint64_t* b);
#endif

        static bool testBitIn(const uint64_t* limbs, size_t nLimbs, size_t bit);
        static void toggleBitIn(uint64_t* limbs, size_t nLimbs, size_t bit);

        /* dst ^= (src << shift), where dst has dstLimbs limbs and src has srcLimbs limbs. Bits
         * shifted beyond dst's capacity are silently dropped. */
        static void xorShiftedInto(uint64_t* dst, size_t dstLimbs, const uint64_t* src, size_t srcLimbs, size_t shift);

        /* dst = src >> shift, over nLimbs limbs each (dst and src must not overlap). */
        static void shiftRightInto(uint64_t* dst, const uint64_t* src, size_t nLimbs, size_t shift);

        /* Zeroes every bit at index >= bit, i.e. truncates to a polynomial of degree < bit. */
        static void clearBitsFrom(uint64_t* limbs, size_t nLimbs, size_t bit);

        /* Highest set bit index of a polynomial, or SIZE_MAX if it's zero. */
        static size_t degreeOf(const uint64_t* limbs, size_t nLimbs);

        static bool isOneIn(const uint64_t* limbs, size_t nLimbs);

        /* Reduces a WIDE_LIMBS-limb product modulo field's reduction polynomial in place -- see
         * gf2m.cpp's definition for the full algorithm description. */
        static void reduceWide(uint64_t* wide, const SGf2mField& field);

        /* NIST-recommended reduction polynomials for the binary fields this library's B-x/K-x
         * curves share -- see gf2m.cpp's definition for the full rationale. */
        static const SGf2mField* knownFieldsTable();

    public:
        /**
         * Default constructor; a zero-valued element with no associated field. Only meaningful
         * once assigned from a properly constructed instance.
         */
        CGf2m() = default;

        /**
         * @param field The field this element belongs to.
         * @param value The value to initialize this element with (interpreted as a small
         * integer, i.e. its bits directly become this element's polynomial coefficients).
         */
        CGf2m(const SGf2mField& field, uint64_t value);

        /**
         * Retrieves a known field by its enum identifier.
         * @param field The known field identifier.
         * @param out Receives the corresponding SGf2mField instance.
         * @return true if field was a valid, known identifier; false otherwise (out is left unchanged).
         */
        static bool knownField(EGf2mKnownField field, SGf2mField& out);

        /**
         * Retrieves a known field by its enum identifier, as a stable pointer to the
         * program-lifetime singleton itself rather than a copy -- suitable for storing in a
         * CGf2m's own non-owning field pointer (see this class's own doc comment on that
         * design), unlike knownField() above, which copies the value out.
         * @param field The known field identifier.
         * @return A pointer to the corresponding SGf2mField singleton; null if field wasn't a
         * valid, known identifier.
         */
        static const SGf2mField* knownFieldPtr(EGf2mKnownField field);

        /**
         * Parses a big-endian byte sequence into a field element.
         * @param field The field to parse the value into.
         * @param bytes The big-endian bytes to parse.
         * @param out Receives the parsed value.
         * @return true if bytes encoded a value strictly less than 2^field.m; false otherwise
         * (out is left unchanged).
         */
        static bool fromBigEndian(const SGf2mField& field, SReadOnlyByteSpan bytes, CGf2m& out);

        /**
         * Parses a hex string (optionally "0x"/"0X"-prefixed) into a field element.
         * @param field The field to parse the value into.
         * @param hex The hex string to parse.
         * @param out Receives the parsed value.
         * @return true if hex was well-formed and encoded a value strictly less than 2^field.m;
         * false otherwise (out is left unchanged).
         */
        static bool fromHex(const SGf2mField& field, const char* hex, CGf2m& out);

        /**
         * Serializes this value to a fixed-width, zero-padded big-endian byte sequence,
         * ceil(field.m / 8) bytes wide.
         * @param out The destination array, replacing any content it previously held.
         */
        void toBigEndian(TArray<uint8_t>& out) const;

        /**
         * Converts this element to an integer, per FIPS 186-4 Appendix C.2: this element's m-bit
         * polynomial-basis representation, reinterpreted directly as an unsigned integer.
         * @return The equivalent CBigNum value.
         */
        CBigNum toInteger() const;

        /**
         * @return The field this element belongs to (null if default-constructed).
         */
        inline const SGf2mField* field() const {
            return _field;
        }

        /**
         * @return The width, in bytes, of one field element (ceil(field()->m / 8)).
         */
        size_t fieldByteLen() const;

        /**
         * @return true if this value is zero.
         */
        bool isZero() const;

        /**
         * Tests a single bit (polynomial coefficient).
         * @param index The zero-based bit position (0 = the constant term).
         * @return true if the bit is set; false if it's clear or beyond LIMB_COUNT * 64.
         */
        bool testBit(size_t index) const;

        /**
         * Sets a single bit (polynomial coefficient).
         * @param index The zero-based bit position (0 = the constant term); ignored if beyond
         * LIMB_COUNT * 64.
         */
        void setBit(size_t index);

        /**
         * @param other The other value to compare with.
         * @return true if both values are equal.
         */
        bool equals(const CGf2m& other) const;

        inline bool operator==(const CGf2m& other) const { return equals(other); }
        inline bool operator!=(const CGf2m& other) const { return !equals(other); }

        // The operations below mutate this value in place and return *this by reference, only
        // to allow chaining -- they are not a functional/copy-returning API. A caller that still
        // needs the pre-operation value must copy it explicitly first (CGf2m saved = original;
        // saved.mul(x);).

        /**
         * @param other The value to add.
         * @return *this, mutated to this + other (bitwise XOR).
         */
        CGf2m& add(const CGf2m& other);

        /**
         * @param other The value to multiply by.
         * @return *this, mutated to (this * other) mod field()'s reduction polynomial.
         */
        CGf2m& mul(const CGf2m& other);

        /**
         * @return *this, mutated to this^2 mod field()'s reduction polynomial.
         */
        CGf2m& square();

        /**
         * Computes the multiplicative inverse via the binary extended Euclidean algorithm.
         * @return *this, mutated to this^-1 mod field()'s reduction polynomial. Undefined if
         * this is zero.
         */
        CGf2m& inverse();
    };

} // namespace certpp

#endif
