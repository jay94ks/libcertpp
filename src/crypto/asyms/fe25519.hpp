#ifndef __SRC_CRYPTO_ASYMS_FE25519_HPP__
#define __SRC_CRYPTO_ASYMS_FE25519_HPP__

#include <certpp/common.hpp>

namespace certpp {
namespace crypto {

    /**
     * An element of GF(2^255 - 19), in ten signed limbs at radix 2^25.5, with every operation
     * free of data-dependent branches, memory indices and divisions. Private to `src/`, and
     * shared by `x25519.cpp` (Curve25519's Montgomery ladder) and `ed25519.cpp` (edwards25519's
     * point coordinates) -- the two curves are different shapes over the same field.
     *
     * **Only valid for p.** Ed25519 also works modulo the group order L = 2^252 +
     * 27742317777372353535851937790883648493, for scalars; that is *not* this modulus, and
     * reducing a scalar here produces a signature that verifies against itself and against
     * nothing else in the world. There is deliberately no conversion between this type and
     * `CBigNum`, in either direction, so the mistake does not compile -- see `ed25519.cpp`'s
     * own note on keeping the two apart.
     *
     * This exists because `CBigNum` cannot be made constant-time in the shape X25519 needs.
     * `CBigNum` stores a *canonical* limb array -- leading zero limbs are trimmed -- so the
     * number of limbs, and therefore the work done, depends on the value being operated on.
     * Every add, multiply and reduction over it leaks something about its operands through
     * timing. For an offline operation like certificate verification that is tolerable; for an
     * online handshake with ephemeral keys, which is what a downstream consumer is using X25519
     * for, it is a live side channel. Here the limb count is fixed at ten regardless of the
     * value, so the work is identical for every input.
     *
     * **Why radix 2^25.5 rather than 2^51.** A 51-bit radix is the faster layout and what most
     * 64-bit implementations use, but its products need 128-bit arithmetic, and MSVC has no
     * `__int128`. With alternating 26- and 25-bit limbs every product fits comfortably in
     * `int64_t`: the worst-case multiply accumulator is 10 * (2^26-1)^2 * 38, which is 2^60 --
     * three bits of headroom, verified rather than estimated. This is ref10's 32-bit layout.
     *
     * **Limbs are signed, and that is load-bearing.** It means `sub()` needs no borrow
     * handling: a limb simply goes negative and the next carry pass propagates it through an
     * arithmetic shift. Making them unsigned would require either adding a multiple of p before
     * every subtraction or branching on the sign, and the second is exactly what this class
     * exists to avoid.
     *
     * Every entry point leaves limbs carry-reduced, so a product of two of them stays inside
     * the bound above. That costs a carry pass on `add()`/`sub()` that a bounds-tracking
     * implementation could skip, and buys an invariant that holds at every boundary instead of
     * one that has to be re-argued per call site -- the right trade for this library, which
     * states correctness and simplicity over performance as its priority.
     */
    class Fe25519 {
    public:
        /** Limbs per element. */
        static constexpr size_t LIMBS = 10;

        /** Encoded length in bytes. */
        static constexpr size_t BYTES = 32;

        /** Limb i holds this many bits: 26 for even i, 25 for odd. */
        static constexpr int widthOf(size_t index) {
            return (index % 2 == 0) ? 26 : 25;
        }

    public:
        int32_t limbs[LIMBS];

    public:
        /**
         * Sets this element to zero.
         */
        void setZero();

        /**
         * Sets this element to one.
         */
        void setOne();

        /**
         * Decodes a little-endian 32-byte value, masking bit 255.
         *
         * RFC 7748 5 requires the top bit of a u-coordinate to be ignored rather than rejected,
         * and the result is *reduced* rather than refused if it is at or above p -- the same
         * non-canonical-input rule `X25519::decodeUCoordinate()` already follows, and
         * deliberately unlike Ed25519's stricter point decoding.
         * @param in 32 bytes, little-endian.
         */
        void fromBytes(const uint8_t in[BYTES]);

        /**
         * Encodes as a little-endian 32-byte value, fully reduced into [0, p).
         *
         * The final conditional subtraction of p is an arithmetic cascade rather than a
         * comparison, so it does not branch on the value. An implementation that skips it
         * produces the right answer for most inputs and a representative in [p, 2^255) for the
         * rest -- which still round-trips through `fromBytes()` and so survives every self-test.
         * @param out Receives 32 bytes.
         */
        void toBytes(uint8_t out[BYTES]) const;

        /**
         * out = a + b.
         * @param out Receives the sum; may alias either input.
         * @param a First operand.
         * @param b Second operand.
         */
        static void add(Fe25519& out, const Fe25519& a, const Fe25519& b);

        /**
         * out = a - b.
         * @param out Receives the difference; may alias either input.
         * @param a Minuend.
         * @param b Subtrahend.
         */
        static void sub(Fe25519& out, const Fe25519& a, const Fe25519& b);

        /**
         * out = a * b.
         * @param out Receives the product; may alias either input.
         * @param a First operand.
         * @param b Second operand.
         */
        static void mul(Fe25519& out, const Fe25519& a, const Fe25519& b);

        /**
         * out = a^2.
         * @param out Receives the square; may alias the input.
         * @param a The operand.
         */
        static void square(Fe25519& out, const Fe25519& a);

        /**
         * out = a * 121665, the Montgomery ladder's (A - 2) / 4 constant.
         * @param out Receives the product; may alias the input.
         * @param a The operand.
         */
        static void mulA24(Fe25519& out, const Fe25519& a);

        /**
         * out = -a.
         *
         * Signed limbs make this a subtraction from zero with nothing special about it -- no
         * comparison against p, and no branch on whether a is already zero (0 - 0 is 0).
         * @param out Receives the negation; may alias the input.
         * @param a The operand.
         */
        static void neg(Fe25519& out, const Fe25519& a);

        /**
         * out = a^-1, by the fixed a^(p-2) addition chain: 254 squarings and 11 multiplications
         * in the same order for every input, so the exponent leaks nothing.
         *
         * Zero has no inverse; this returns zero for it rather than failing, which keeps the
         * operation branch-free. The one caller that matters, the ladder's final conversion out
         * of projective coordinates, treats a zero denominator as the all-zero shared secret
         * that RFC 7748 6.1 already requires be rejected.
         * @param out Receives the inverse; may alias the input.
         * @param a The operand.
         */
        static void invert(Fe25519& out, const Fe25519& a);

        /**
         * out = a square root of a, if a has one.
         *
         * p is 5 mod 8, so a^((p+3)/8) is either a square root of a or sqrt(-1) times one; the
         * second case is fixed by one multiplication, and anything left over means a is a
         * quadratic non-residue. Both candidates are verified by squaring them back, so a
         * non-residue is reported rather than silently returning a wrong root.
         *
         * Unlike every other operation here, this one *does* branch on the value: which of the
         * two candidates is the root, and whether either is. That is deliberate and
         * confined -- the only caller is Ed25519's point decoding, whose input is a public key or
         * the R half of a signature, both public. Nothing secret reaches this function. The
         * exponentiation itself is still a fixed chain.
         *
         * Of the two roots, this returns the one a^((p+3)/8) happens to land on; a caller that
         * needs a particular sign (RFC 8032 5.1.3 does) picks with `isOdd()` and `neg()`.
         * @param out Receives a square root; may alias the input, and is untouched when there is
         *            none.
         * @param a The operand.
         * @return true if a is a quadratic residue mod p.
         */
        static bool squareRoot(Fe25519& out, const Fe25519& a);

        /**
         * Swaps a and b if mask is all ones, leaves them if it is zero -- without branching.
         *
         * This is what replaces `CBigNum::condSwap`, whose own documentation admits it is a
         * plain branch. In a Montgomery ladder the swap condition *is* a bit of the private
         * scalar, so a branch there leaks the key one bit per iteration.
         * @param mask 0 or 0xFFFFFFFF; any other value mixes the two element-wise.
         * @param a First element.
         * @param b Second element.
         */
        static void condSwap(uint32_t mask, Fe25519& a, Fe25519& b);

        /**
         * Reports whether this element is zero, reading every limb regardless.
         * @return true if the value is congruent to zero mod p.
         */
        bool isZero() const;

        /**
         * Reports whether this element equals another.
         *
         * Compared by difference rather than limb by limb, because two limb arrays can hold the
         * same field element without being identical -- the representation is redundant, and
         * `memcmp` over the limbs would call equal values different.
         * @param other The element to compare against.
         * @return true if the two are congruent mod p.
         */
        bool isEqual(const Fe25519& other) const;

        /**
         * Reports the low bit of the canonical representative in [0, p) -- RFC 8032 5.1.2's
         * "sign" of a coordinate, which its compressed point encoding carries in the top bit of
         * the last byte.
         *
         * This is a property of the *canonical* value, not of limb 0: the redundant
         * representation means an unreduced limb array can have either parity in limb 0 while
         * standing for the same element, so the value has to be encoded first.
         * @return true if the canonical representative is odd.
         */
        bool isOdd() const;
    };

} // namespace crypto
} // namespace certpp

#endif
