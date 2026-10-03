#ifndef __INCLUDE_CERTPP_UTILS_MONTGOMERY_HPP__
#define __INCLUDE_CERTPP_UTILS_MONTGOMERY_HPP__

#include <certpp/common.hpp>
#include <certpp/utils/bignum.hpp>

namespace certpp {

    /**
     * A fixed, odd modulus together with the constants that let modular arithmetic against it
     * run without any big-number division: Montgomery's n' = -m^-1 mod 2^32 and R^2 mod m,
     * where R = 2^(32*limbs(m)).
     *
     * CBigNum::mulMod() has nowhere to cache anything, so it is necessarily mul() followed by
     * mod(), and mod() is a full Knuth-D long division -- which every single modular multiply in
     * a scalar multiplication then pays for. This class exists to hoist that cost out of the
     * loop: build one instance per modulus, then every mul()/add()/sub() against it costs
     * multiplications and limb-wise carries instead. It does not replace CBigNum::mulMod() or
     * CBigNum::mod(): Montgomery reduction requires an odd modulus, and those two must keep
     * working for any non-zero modulus (including an even one), so they are left exactly as they
     * were and this is an additional, opt-in fast path alongside them.
     *
     * Two domains are in play, and mixing them up is the one way to misuse this class:
     *
     * - *Ordinary* form is the plain residue a, in [0, m).
     * - *Montgomery* form is a*R mod m. toMont()/fromMont() convert between the two, one()
     *   is the Montgomery form of 1, and mul() multiplies two Montgomery-form values into a
     *   third (mul(A, B) where A = a*R and B = b*R yields a*b*R, still Montgomery form).
     *
     * add(), sub(), dbl() and neg() are the same operation in either domain (the mapping
     * a -> a*R is linear), so a caller that works wholly in Montgomery form converts its inputs
     * in, runs the whole computation, and converts only its results back out. mulMod() is
     * provided for a caller that does not want to think about domains at all: it takes and
     * returns ordinary form, matching CBigNum::mulMod()'s semantics exactly, at the cost of one
     * extra reduction per call.
     *
     * Every operation mutates its first argument in place and returns a reference to it, matching
     * CBigNum's own convention -- a caller that still needs an operand's previous value must copy
     * it first. The modulus itself is immutable, so an instance is safe to share across threads.
     */
    class CERTPP_API CMontgomery {
    private:
        CBigNum _m;      // the modulus; odd, with _count limbs.
        CBigNum _rr;     // R^2 mod m -- toMont()'s multiplier.
        CBigNum _one;    // R mod m -- the Montgomery form of 1.
        size_t _count;   // the number of limbs in _m; R == 2^(32*_count).
        uint32_t _n0inv; // -m^-1 mod 2^32.
        bool _valid;     // whether the modulus was usable (non-zero and odd) at all.

    private:
        /**
         * The largest modulus, in limbs, whose scratch space fits in an on-stack buffer; a
         * larger one allocates. Sized well past the 17 limbs of P-521 (this library's widest
         * curve field) so no curve operation ever allocates here.
         */
        static constexpr size_t STACK_LIMBS = 80;

        /**
         * Computes -value^-1 mod 2^32 by Newton's iteration (each step doubles the number of
         * correct low bits, starting from 3 correct bits for any odd value).
         * @param value The value to invert; must be odd.
         * @return -value^-1 mod 2^32.
         */
        static uint32_t negInverse32(uint32_t value);

        /**
         * Copies value's limbs into a count-limb buffer, zero-extending past its length.
         * @param dst The destination buffer, count limbs.
         * @param count The buffer's limb count; must be at least value's own limb count.
         * @param value The value to load.
         */
        static void load(uint32_t* dst, size_t count, const CBigNum& value);

        /**
         * Writes a raw little-endian limb buffer back into a CBigNum, trimming leading zeroes.
         * @param out Receives the value; reuses its existing allocation where it is big enough.
         * @param src The source buffer.
         * @param count The number of limbs to read from src.
         */
        static void store(CBigNum& out, const uint32_t* src, size_t count);

        /**
         * @param value The value to test.
         * @return true if value needs reducing before it can be fed to mulInternal() (either it
         * has more limbs than the modulus, or it is numerically at least the modulus).
         */
        bool needsReduce(const CBigNum& value) const;

        /**
         * The CIOS (Coarsely Integrated Operand Scanning) Montgomery multiplication proper:
         * out = a*b*R^-1 mod m, interleaving the schoolbook multiply with the reduction so the
         * intermediate never exceeds _count+2 limbs.
         * @param a The first operand's limbs; must be numerically below the modulus.
         * @param aLen The first operand's limb count; must not exceed the modulus's.
         * @param b The second operand's limbs; must be numerically below the modulus.
         * @param bLen The second operand's limb count; must not exceed the modulus's.
         * @param out Receives the result; may alias either operand's owner.
         */
        void mulInternal(
            const uint32_t* a, size_t aLen, const uint32_t* b, size_t bLen, CBigNum& out
        ) const;

    public:
        /**
         * Default constructor; an invalid, unusable context (isValid() returns false). Only
         * meaningful once copy-assigned from a properly constructed instance.
         */
        CMontgomery();

        /**
         * @param modulus The modulus to precompute against; must be non-zero and odd, or the
         * resulting instance is invalid (see isValid()).
         */
        explicit CMontgomery(const CBigNum& modulus);

        CMontgomery(const CMontgomery& other) = default;
        CMontgomery(CMontgomery&& other) noexcept = default;
        CMontgomery& operator=(const CMontgomery& other) = default;
        CMontgomery& operator=(CMontgomery&& other) noexcept = default;
        ~CMontgomery() = default;

    public:
        /**
         * @return true if this context was built from a non-zero, odd modulus and every
         * operation below will behave; false otherwise, in which case every operation below is a
         * no-op (leaving its operand untouched, returning its argument unchanged, or returning
         * zero from modExp()) and the caller should be using CBigNum::mod()/mulMod() instead.
         */
        bool isValid() const;

        /**
         * @return The modulus this context was built from (zero for an invalid context).
         */
        const CBigNum& modulus() const;

        /**
         * @return The Montgomery form of 1 (R mod m) -- the multiplicative identity in the
         * Montgomery domain, which is what a Jacobian/projective "Z = 1" has to be initialized
         * to when the whole computation runs in that domain.
         */
        const CBigNum& one() const;

    public:
        /**
         * Converts an ordinary residue into Montgomery form (value*R mod m). Accepts a value of
         * any magnitude, reducing it first if it is not already below the modulus.
         * @param value The ordinary-form value to convert.
         * @return value*R mod m.
         */
        CBigNum toMont(const CBigNum& value) const;

        /**
         * Converts a Montgomery-form value back to an ordinary residue.
         * @param value The Montgomery-form value to convert.
         * @return value*R^-1 mod m.
         */
        CBigNum fromMont(const CBigNum& value) const;

        /**
         * Multiplies two Montgomery-form values, yielding a Montgomery-form product. Passing the
         * same object as both arguments (squaring) is explicitly supported.
         * @param acc The first operand, in Montgomery form; receives the product.
         * @param other The second operand, in Montgomery form.
         * @return acc, mutated to acc*other*R^-1 mod m.
         */
        CBigNum& mul(CBigNum& acc, const CBigNum& other) const;

        /**
         * Multiplies two *ordinary*-form values modulo the modulus -- the division-free
         * equivalent of acc.mulMod(other, modulus()), for a caller that does not otherwise work
         * in the Montgomery domain. Costs one more reduction pass than mul().
         * @param acc The first operand, in ordinary form; receives the product.
         * @param other The second operand, in ordinary form.
         * @return acc, mutated to (acc*other) mod m.
         */
        CBigNum& mulMod(CBigNum& acc, const CBigNum& other) const;

        /**
         * Adds modulo the modulus. Valid in either domain, since a -> a*R is linear.
         * @param acc The first operand; receives the sum.
         * @param other The second operand.
         * @return acc, mutated to (acc + other) mod m.
         */
        CBigNum& add(CBigNum& acc, const CBigNum& other) const;

        /**
         * Subtracts modulo the modulus, without CBigNum::sub()'s acc >= other precondition.
         * Valid in either domain, since a -> a*R is linear.
         * @param acc The value to subtract from; receives the difference.
         * @param other The value to subtract.
         * @return acc, mutated to (acc - other) mod m.
         */
        CBigNum& sub(CBigNum& acc, const CBigNum& other) const;

        /**
         * Doubles modulo the modulus. Valid in either domain, since a -> a*R is linear.
         * @param acc The value to double.
         * @return acc, mutated to (acc + acc) mod m.
         */
        CBigNum& dbl(CBigNum& acc) const;

        /**
         * Negates modulo the modulus. Valid in either domain, since a -> a*R is linear.
         * @param acc The value to negate.
         * @return acc, mutated to (-acc) mod m (zero if acc is a multiple of m).
         */
        CBigNum& neg(CBigNum& acc) const;

    public:
        /**
         * Modular exponentiation via square-and-multiply in the Montgomery domain -- the
         * division-free equivalent of CBigNum::modExp(base, exponent, modulus()), which pays for
         * a long division per squaring.
         * @param base The base, in ordinary form.
         * @param exponent The exponent.
         * @return (base ^ exponent) mod m, in ordinary form (1 for a zero exponent, including
         * 0^0, matching CBigNum::modExp()).
         */
        CBigNum modExp(const CBigNum& base, const CBigNum& exponent) const;
    };

} // namespace certpp

#endif
