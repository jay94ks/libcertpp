#ifndef __SRC_CRYPTO_AEADS_GHASH_HPP__
#define __SRC_CRYPTO_AEADS_GHASH_HPP__

#include <certpp/common.hpp>

/* Hardware-accelerated carry-less multiply (PCLMULQDQ) for Ghash::multiply(), gated by both the
 * CERTPP_DISABLE_HWACCEL_SIMD build option and the target architecture -- the same guard
 * utils/gf2m.cpp uses for the same instruction, and it must match ghash.cpp's copy exactly.
 * Restricted to x86-64 (not 32-bit x86, unlike CGf2m) only because this needs _mm_cvtsi64_si128
 * and PCLMULQDQ's 64-bit halves, which MSVC does not expose on 32-bit targets. */
#if !defined(CERTPP_DISABLE_HWACCEL_SIMD) && (defined(_M_X64) || defined(__x86_64__))
#define CERTPP_GHASH_HWACCEL_AVAILABLE 1
#endif

namespace certpp {
namespace crypto {

    /**
     * GHASH (NIST SP 800-38D 6.4): the universal hash AES-GCM authenticates with, keyed by the
     * subkey H = E_K(0^128), together with the GF(2^128) multiplication it is built on. Private
     * to `src/`, since GCM is its only caller and it is not a general-purpose field.
     *
     * **Why this is not `CGf2m`.** `utils/gf2m.hpp` already multiplies in GF(2^m) with a
     * PCLMULQDQ path, and GHASH's modulus x^128 + x^7 + x^2 + x + 1 would even fit its
     * pentanomial `SGf2mField`. It is still the wrong tool, for three independent reasons:
     *
     * - **The representation is bit-reflected.** GCM numbers the bits of a 16-byte block so that
     *   the *most significant* bit of the *first* byte is the x^0 coefficient (SP 800-38D 6.3),
     *   the opposite of the polynomial-basis convention `CGf2m` and every other part of this
     *   library use. Handing `CGf2m` the bytes as they arrive produces a product that is
     *   perfectly self-consistent -- it round-trips, it is associative, every algebraic identity
     *   holds -- and is not GHASH. Nothing short of a published vector catches it, which is
     *   exactly the class of bug this library has been bitten by before.
     * - **H is secret, so the multiply must be constant-time.** `CGf2m` documents that it has no
     *   constant-time hardening (its portable `mul()` branches per bit of the operand, and skips
     *   zero limbs in the accelerated path), which is the right trade for ECDSA's public curve
     *   arithmetic and the wrong one for a MAC key an attacker would love to recover.
     * - **It is sized for other fields.** A `CGf2m` carries 9 limbs (576 bits) and reduces an
     *   18-limb product through a generic pentanomial routine; GHASH is two 64-bit words with one
     *   fixed modulus, and GCM performs one multiply per 16 bytes of message.
     *
     * So this is a dedicated implementation rather than a reuse or an extension of `CGf2m`, and
     * the two deliberately share no code.
     *
     * The portable multiply is SP 800-38D's own Algorithm 1 (shift and XOR, 128 iterations),
     * written without a data-dependent branch or memory access -- no precomputed tables, whose
     * key-dependent indices are what makes the usual 4-bit/8-bit windowed GHASH leak H through
     * the cache. The accelerated path is chosen per call behind a runtime CPUID check; both are
     * exposed so a test can hold them against one another, since a vectorized path that only
     * runs on long inputs is not something short published vectors can see.
     */
    class Ghash {
    public:
        /** Block length in bytes; GHASH has no other granularity. */
        static constexpr size_t BLOCK_BYTES = 16;

    private:
        uint8_t _h[BLOCK_BYTES];        // --> the subkey H.
        uint8_t _y[BLOCK_BYTES];        // --> the accumulator, Y_i.
        uint8_t _block[BLOCK_BYTES];    // --> input not yet absorbed.
        size_t _buffered;               // --> how much of _block is filled.

        void absorb(const uint8_t* block);

    public:
        /**
         * Constructs an unkeyed accumulator; call reset() before use.
         */
        Ghash();

        /**
         * Destructor; clears the subkey and the accumulator.
         */
        ~Ghash();

        Ghash(const Ghash&) = delete;
        Ghash& operator=(const Ghash&) = delete;

    public:
        /**
         * Keys this accumulator with a subkey and clears its state. May be called again to
         * restart.
         * @param h The subkey H = E_K(0^128), exactly BLOCK_BYTES.
         */
        void reset(const uint8_t h[BLOCK_BYTES]);

        /**
         * Absorbs more input, buffering whatever does not complete a block.
         * @param data The bytes to absorb; ignored if null.
         * @param length How many bytes to absorb.
         */
        void push(const uint8_t* data, size_t length);

        /**
         * Zero-fills and absorbs a partially buffered block, so the next push() starts on a block
         * boundary -- GCM's `pad(A) || pad(C)` construction, where the zeros close a field rather
         * than extend it. A no-op when nothing is buffered.
         */
        void padToBlock();

        /**
         * Finishes the hash. Any buffered partial block is zero-filled and absorbed first, so a
         * caller that ends on a boundary and one that does not are both handled.
         * @param out Receives BLOCK_BYTES.
         */
        void finish(uint8_t out[BLOCK_BYTES]);

    public:
        /**
         * Multiplies in GCM's GF(2^128) (SP 800-38D 6.3), in place: `block` becomes
         * `block * h`. Dispatches to PCLMULQDQ where the build and the CPU both offer it.
         * @param block The left operand; receives the product.
         * @param h The right operand, normally the subkey H.
         */
        static void multiply(uint8_t block[BLOCK_BYTES], const uint8_t h[BLOCK_BYTES]);

        /**
         * The same multiplication by SP 800-38D's Algorithm 1, whatever this CPU supports --
         * exposed so a test can hold the two paths against one another.
         * @param block The left operand; receives the product.
         * @param h The right operand.
         */
        static void multiplyPortable(uint8_t block[BLOCK_BYTES], const uint8_t h[BLOCK_BYTES]);

        /**
         * @return true if multiply() will actually use the accelerated path on this CPU, in this
         * build; false if it falls through to multiplyPortable().
         */
        static bool accelerated();

#if defined(CERTPP_GHASH_HWACCEL_AVAILABLE)
        /**
         * The same multiplication via PCLMULQDQ. Only declared where the build and the target
         * architecture allow it, and only safe to call where accelerated() is true -- the
         * instruction is optional on x86-64, so calling this on a CPU without it is a SIGILL.
         * @param block The left operand; receives the product.
         * @param h The right operand.
         */
        static void multiplyAccelerated(uint8_t block[BLOCK_BYTES], const uint8_t h[BLOCK_BYTES]);
#endif
    };

} // namespace crypto
} // namespace certpp

#endif
