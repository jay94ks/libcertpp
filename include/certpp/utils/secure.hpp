#ifndef __INCLUDE_CERTPP_UTILS_SECURE_HPP__
#define __INCLUDE_CERTPP_UTILS_SECURE_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {

    /**
     * Operations on secret bytes that must not leak through timing or survive in memory:
     * zeroization that the compiler is not allowed to elide, and comparison/selection whose
     * running time depends only on the length of its inputs, never on their contents.
     *
     * Three things this cannot do, and that a caller still has to think about:
     *
     * - It cannot reach a copy the compiler made. A secret that was spilled to a register or a
     *   stack slot outside the buffer passed in stays there; zero() clears the buffer it is
     *   given and nothing else. Keeping secrets in as few places as possible is still the
     *   caller's job.
     * - It cannot hide a length. equalsMask() and select() both read every byte of their inputs
     *   unconditionally, so the *contents* leak nothing -- but the size does, and
     *   mismatched-length inputs are reported immediately. That is the right trade for every
     *   use in this library, where lengths are fixed by the algorithm and public.
     * - "Constant-time" here means the source contains no data-dependent branch, memory access
     *   or division. That is as far as portable C++ reaches; it is not a guarantee about any
     *   particular compiler's output, still less about a CPU's microarchitecture.
     *
     * The inline mask arithmetic in RSA's EME-PKCS1-v1_5 unpadding and CbcTransformer's PKCS#7
     * padding check is deliberately *not* rewritten in terms of this class. Neither of those is
     * "compare two buffers" or "choose between two buffers": they interleave masking with a scan
     * over the padding, so there is nothing here for them to call.
     */
    class CERTPP_API CSecure {
    public:
        /**
         * Overwrites a buffer with zeroes in a way the compiler may not optimize away, for
         * clearing key material, intermediate secrets and the like before they go out of scope.
         *
         * An ordinary memset() over a local buffer that is never read again is dead code, and
         * compilers do remove it; this routes the same memset through a volatile function
         * pointer, so the call cannot be proven to have no effect and therefore cannot be
         * dropped.
         * @param buffer The bytes to clear. A null or empty span is a no-op.
         */
        static void zero(const SByteSpan& buffer);

        /**
         * Compares two byte spans in time that depends only on their length, yielding a mask
         * rather than a bool so that a caller can act on the result without branching on it.
         *
         * Unlike memcmp(), this reads every byte of both inputs even once a difference is known
         * -- memcmp() stops at the first mismatch, so its running time reveals the length of the
         * matching prefix.
         * @param first The first span.
         * @param second The second span.
         * @return 0xFF if the spans have the same length and the same contents (two empty spans
         * included); 0x00 otherwise.
         */
        static uint8_t equalsMask(
            const SReadOnlyByteSpan& first, const SReadOnlyByteSpan& second
        );

        /**
         * Reports whether two byte spans are equal, in time that depends only on their length.
         *
         * Prefer equalsMask() with select() where the comparison's outcome is itself a secret --
         * as the Fujisaki-Okamoto transform's re-encryption check is, since whether a ciphertext
         * was valid is exactly what must not be observable. This overload's bool makes the next
         * branch the caller's, which is right only when that one bit is not sensitive (a MAC
         * check whose failure is reported anyway, say).
         * @param first The first span.
         * @param second The second span.
         * @return true if the spans have the same length and the same contents.
         */
        static inline bool equals(
            const SReadOnlyByteSpan& first, const SReadOnlyByteSpan& second
        ) {
            return equalsMask(first, second) != 0;
        }

        /**
         * Copies one of two spans into out according to a mask, without branching on it: out
         * receives ifSet where mask is 0xFF and ifClear where it is 0x00.
         *
         * The mask must be one equalsMask() produces -- all ones or all zeroes. Any other value
         * mixes the two inputs bit by bit, which is not a useful result but is not checked for,
         * since checking would mean branching on it.
         * @param mask 0xFF to select ifSet, 0x00 to select ifClear.
         * @param ifSet The span copied when mask is 0xFF.
         * @param ifClear The span copied when mask is 0x00.
         * @param out Receives the selected bytes; may alias neither input.
         * @return true on success; false if any span is null or the three sizes differ.
         */
        static bool select(
            uint8_t mask, const SReadOnlyByteSpan& ifSet, const SReadOnlyByteSpan& ifClear,
            const SByteSpan& out
        );
    };

} // namespace certpp

#endif
