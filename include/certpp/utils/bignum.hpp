#ifndef __INCLUDE_CERTPP_UTILS_BIGNUM_HPP__
#define __INCLUDE_CERTPP_UTILS_BIGNUM_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/array.hpp>

namespace certpp {

    // --> Forward declaration; defined after CBigNum below (a CBigNum member can't be nested
    // inside CBigNum itself, since CBigNum isn't a complete type yet at that point).
    struct SignedBig;

    /**
     * An arbitrary-precision, non-negative integer, stored as a little-endian array of 32-bit
     * limbs. Backs the modular arithmetic (RSA/DSA key generation and sign/verify, elliptic-curve
     * field/scalar arithmetic) every crypto/asyms/ implementation needs -- not tied to any one
     * algorithm (or even to crypto/ specifically), so it lives under utils/ rather than crypto/.
     */
    class CERTPP_API CBigNum {
    private:
        TArray<uint32_t> _limbs; // little-endian limbs; canonical (no leading zero limb); empty == 0.

    private:
        /**
         * Builds a canonical CBigNum out of a (possibly non-canonical) little-endian limb array,
         * trimming any leading (high) zero limbs.
         * @param limbs The limbs to adopt; left empty afterward.
         * @return The resulting, canonicalized value.
         */
        static CBigNum fromLimbsTrimmed(TArray<uint32_t>&& limbs);

#if !defined(CERTPP_DISABLE_HWACCEL_SIMD) && (defined(_M_X64) || defined(__x86_64__))
        /* Hardware-accelerated multiply (MULX/BMI2 + ADCX/ADX) for mul()'s inner loop -- see
         * bignum.cpp's identical guard (which this must match exactly) for the full rationale. */
        static bool hasAdxBmi2();

        /* Reinterprets a little-endian 32-bit limb buffer as len64 64-bit digits, zero-padded
         * past src's actual length (and past len32 if len32 is odd). */
        static void packInto64(const uint32_t* src, size_t len32, uint64_t* dst64, size_t len64);

#if defined(__GNUC__) && !defined(_MSC_VER)
        __attribute__((target("bmi2,adx")))
#endif
        static void mulAccelerated(
            const uint32_t* a, size_t aLen, const uint32_t* b, size_t bLen,
            uint32_t* result, size_t resultLen
        );
#endif

        /**
         * Reverses a byte span in place -- bridges this class's big-endian convention to RFC
         * 7748/RFC 8032's little-endian wire format.
         */
        static void reverseBytesInPlace(const SByteSpan& bytes);

        /**
         * Shifts a raw little-endian limb buffer left by exactly 1 bit in place, discarding any
         * overflow beyond count limbs (callers size the buffer with enough headroom).
         */
        static void shiftLeft1(uint32_t* limbs, size_t count);

        /**
         * Compares two same-length raw little-endian limb buffers.
         */
        static int compareLimbs(const uint32_t* a, const uint32_t* b, size_t count);

        /**
         * Subtracts b from a in place, assuming a >= b (same-length raw little-endian buffers).
         */
        static void subtractLimbs(uint32_t* a, const uint32_t* b, size_t count);

        // --> SignedBig is used only by modInverse()'s extended-Euclidean bookkeeping (the
        // Bezout coefficients can go negative, even though CBigNum itself never does); see its
        // own doc comment (defined just after this class, for the reason given above it).
        static SignedBig signedAdd(const SignedBig& x, const SignedBig& y);
        static SignedBig signedSub(const SignedBig& x, const SignedBig& y);
        static SignedBig signedMul(const CBigNum& q, const SignedBig& s);

    public:
        /**
         * Default constructor; the value zero.
         */
        CBigNum();

        /**
         * @param value The value to initialize this CBigNum with.
         */
        CBigNum(uint64_t value);

        CBigNum(const CBigNum& other) = default;
        CBigNum(CBigNum&& other) noexcept = default;
        CBigNum& operator=(const CBigNum& other) = default;
        CBigNum& operator=(CBigNum&& other) noexcept = default;
        ~CBigNum() = default;

    public:
        /**
         * Parses a big-endian byte sequence (an unsigned magnitude) into a CBigNum.
         * @param bytes The big-endian bytes to parse.
         * @return The parsed value.
         */
        static CBigNum fromBigEndian(SReadOnlyByteSpan bytes);

        /**
         * Parses a little-endian byte sequence (an unsigned magnitude) into a CBigNum -- the
         * wire format RFC 7748/RFC 8032 use, as opposed to this class's own big-endian
         * convention.
         * @param bytes The little-endian bytes to parse.
         * @return The parsed value.
         */
        static CBigNum fromLittleEndian(SReadOnlyByteSpan bytes);

        /**
         * Parses the leftmost bitsN bits of a big-endian byte sequence into a CBigNum (or all of
         * it, if it's shorter than bitsN bits) -- FIPS 186-4 4.6/6.4's digest-truncation rule for
         * DSA/ECDSA signing and verification ("z").
         * @param bytes The big-endian bytes to parse (typically a message digest).
         * @param bitsN The number of leading bits to keep.
         * @return The parsed, possibly-truncated value.
         */
        static CBigNum fromBigEndianTruncated(SReadOnlyByteSpan bytes, size_t bitsN);

        /**
         * Parses a hex string (optionally "0x"/"0X"-prefixed) into a CBigNum.
         * @param hex The hex string to parse.
         * @param out Receives the parsed value.
         * @return true if hex was well-formed; false otherwise (out is left unchanged).
         */
        static bool fromHex(const char* hex, CBigNum& out);

        /**
         * Serializes this value to a minimal-length big-endian byte sequence. Zero serializes
         * as a single 0x00 byte.
         * @param out The destination array, replacing any content it previously held.
         */
        void toBigEndian(TArray<uint8_t>& out) const;

        /**
         * Serializes this value to a fixed-width, zero-padded big-endian byte sequence.
         * @param out The destination span; its size fixes the output width.
         * @return true if this value fits in out.size bytes; false otherwise (out is left unchanged).
         */
        bool toBigEndian(const SByteSpan& out) const;

        /**
         * Serializes this value to a fixed-width, zero-padded little-endian byte sequence -- the
         * wire format RFC 7748/RFC 8032 use, as opposed to this class's own big-endian
         * convention.
         * @param out The destination span; its size fixes the output width.
         * @return true if this value fits in out.size bytes; false otherwise (out is left unchanged).
         */
        bool toLittleEndian(const SByteSpan& out) const;

    public:
        /**
         * @return true if this value is zero.
         */
        bool isZero() const;

        /**
         * @return true if this value is even.
         */
        bool isEven() const;

        /**
         * Tests a single bit.
         * @param index The zero-based bit position (0 = least significant).
         * @return true if the bit is set; false if it's clear or beyond bitLength().
         */
        bool testBit(size_t index) const;

        /**
         * Sets a single bit, growing this value's storage if needed.
         * @param index The zero-based bit position (0 = least significant) to set.
         */
        void setBit(size_t index);

        /**
         * @return The number of significant bits (0 for a zero value).
         */
        size_t bitLength() const;

        /**
         * Compares this value with another.
         * @param other The other value to compare with.
         * @return A negative value if this is less than other, zero if equal, positive if greater.
         */
        int32_t compare(const CBigNum& other) const;

        inline bool operator==(const CBigNum& other) const { return compare(other) == 0; }
        inline bool operator!=(const CBigNum& other) const { return compare(other) != 0; }
        inline bool operator<(const CBigNum& other) const { return compare(other) < 0; }
        inline bool operator<=(const CBigNum& other) const { return compare(other) <= 0; }
        inline bool operator>(const CBigNum& other) const { return compare(other) > 0; }
        inline bool operator>=(const CBigNum& other) const { return compare(other) >= 0; }

    public:
        // The operations below mutate this value in place (this := this OP other) and return
        // *this by reference, only to allow chaining (a.mulMod(b, m).add(c)) -- they are not a
        // functional/copy-returning API. A caller that still needs the pre-operation value must
        // copy it explicitly first (CBigNum saved = original; saved.add(x);).

        /**
         * @param other The value to add.
         * @return *this, mutated to this + other.
         */
        CBigNum& add(const CBigNum& other);

        /**
         * @param other The value to subtract; must not exceed this value.
         * @return *this, mutated to this - other.
         */
        CBigNum& sub(const CBigNum& other);

        /**
         * @param other The value to multiply by.
         * @return *this, mutated to this * other.
         */
        CBigNum& mul(const CBigNum& other);

        /**
         * Divides this value by divisor, computing both the quotient and remainder. Unlike the
         * mutating operations above, this leaves this value unchanged -- it already reports its
         * results via the two out parameters instead of returning a changed copy of this value.
         * @param divisor The divisor; must not be zero.
         * @param outQuotient Receives this / divisor.
         * @param outRemainder Receives this % divisor.
         */
        void divMod(const CBigNum& divisor, CBigNum& outQuotient, CBigNum& outRemainder) const;

        /**
         * @param modulus The modulus; must not be zero.
         * @return *this, mutated to this % modulus.
         */
        CBigNum& mod(const CBigNum& modulus);

        /**
         * @param other The value to multiply by.
         * @param modulus The modulus; must not be zero.
         * @return *this, mutated to (this * other) % modulus.
         */
        CBigNum& mulMod(const CBigNum& other, const CBigNum& modulus);

        /**
         * @param other The value to subtract.
         * @param modulus The modulus; must not be zero.
         * @return *this, mutated to (this - other) mod modulus, without sub()'s this >= other
         * precondition.
         */
        CBigNum& modSub(const CBigNum& other, const CBigNum& modulus);

        /**
         * @param modulus The modulus; must not be zero.
         * @return *this, mutated to -this mod modulus (0 if this is a multiple of modulus).
         */
        CBigNum& modNeg(const CBigNum& modulus);

        /**
         * @param bits The number of bits to shift by.
         * @return *this, mutated to this shifted left by bits (this * 2^bits).
         */
        CBigNum& shl(size_t bits);

        /**
         * @param bits The number of bits to shift by.
         * @return *this, mutated to this shifted right by bits (this / 2^bits, truncated).
         */
        CBigNum& shr(size_t bits);

    public:
        /**
         * @param a One value.
         * @param b The other value.
         * @return The greatest common divisor of a and b.
         */
        static CBigNum gcd(CBigNum a, CBigNum b);

        /**
         * Computes the modular multiplicative inverse.
         * @param value The value to invert.
         * @param modulus The modulus; must not be zero.
         * @param out Receives value^-1 mod modulus.
         * @return true if value and modulus are coprime (an inverse exists); false otherwise.
         */
        static bool modInverse(const CBigNum& value, const CBigNum& modulus, CBigNum& out);

        /**
         * Computes modular exponentiation via square-and-multiply.
         * @param base The base.
         * @param exponent The exponent.
         * @param modulus The modulus; must not be zero.
         * @return (base ^ exponent) % modulus.
         */
        static CBigNum modExp(const CBigNum& base, const CBigNum& exponent, const CBigNum& modulus);

        /**
         * Conditionally swaps a and b. NOT constant-time (a plain branch) -- this class's
         * schoolbook arithmetic already isn't constant-time, so this adds no new side channel;
         * correctness/simplicity over side-channel hardening, consistent with this library's
         * other early-stage priorities (see eccurve.hpp's own doc comment).
         * @param swap Whether to swap a and b.
         * @param a One value.
         * @param b The other value.
         */
        static void condSwap(bool swap, CBigNum& a, CBigNum& b);

    public:
        /**
         * Generates a uniformly random value in [0, 2^bits), via crypto::CRng.
         * @param bits The number of bits of randomness to draw.
         * @param out Receives the random value.
         * @return true on success; false if the underlying CRng::fill() call failed.
         */
        static bool random(size_t bits, CBigNum& out);

        /**
         * Generates a uniformly random value in [0, bound), via crypto::CRng.
         * @param bound The exclusive upper bound; must not be zero.
         * @param out Receives the random value.
         * @return true on success; false if bound is zero or the underlying CRng::fill() call failed.
         */
        static bool randomBelow(const CBigNum& bound, CBigNum& out);

        /**
         * Tests whether this value is probably prime, via Miller-Rabin (preceded by trial
         * division against the small primes below 1000).
         * @param rounds The number of Miller-Rabin rounds to run.
         * @return true if this value is probably prime (false-positive probability at most
         * 4^-rounds); false if it's definitely composite.
         */
        bool isProbablePrime(size_t rounds = 20) const;

        /**
         * Generates a random probable prime of exactly bits bits. The top two bits and the
         * bottom bit are always set, so a product of two such primes always has exactly 2*bits
         * bits and is always odd.
         * @param bits The bit length to generate; must be at least 2.
         * @param out Receives the generated prime.
         * @return true on success; false on failure (invalid bits, or a CRng::fill() failure).
         */
        static bool generatePrime(size_t bits, CBigNum& out);
    };

    /**
     * A signed magnitude used only by CBigNum::modInverse()'s extended-Euclidean bookkeeping
     * (the Bezout coefficients can go negative, even though CBigNum itself never does) -- an
     * implementation detail of bignum.cpp, not part of the public API proper, but declared here
     * (rather than private-nested inside CBigNum) since a CBigNum-valued member can't be nested
     * inside CBigNum itself.
     */
    struct SignedBig {
        CBigNum mag;
        bool neg;
    };

} // namespace certpp

#endif
