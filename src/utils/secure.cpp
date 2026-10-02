#include <certpp/utils/secure.hpp>
#include <cstring>

namespace certpp {

    namespace {

        /* --> memset reached through a volatile function pointer. The compiler cannot prove what
         * this points to, so it cannot prove the call has no effect, so it cannot remove it --
         * which is the whole point: a plain memset() over a buffer nothing reads again is dead
         * code, and optimizers do delete it. The pointer is written once, at initialization, and
         * only ever read afterwards. */
        void* (* volatile const SECURE_MEMSET)(void*, int, size_t) = &std::memset;

    } // namespace

    /* Overwrites a buffer with zeroes in a way the compiler may not optimize away. */
    void CSecure::zero(const SByteSpan& buffer) {
        if (!buffer.data || buffer.size == 0) {
            return;
        }

        SECURE_MEMSET(buffer.data, 0, buffer.size);
    }

    /* Compares two byte spans in time that depends only on their length. */
    uint8_t CSecure::equalsMask(const SReadOnlyByteSpan& first, const SReadOnlyByteSpan& second) {
        // The length is public (see the class doc comment), so returning early on a mismatch
        // leaks nothing the caller didn't already know.
        if (first.size != second.size) {
            return 0x00u;
        }
        if (first.size == 0) {
            return 0xFFu; // two empty spans are equal, and neither pointer is dereferenced
        }
        if (!first.data || !second.data) {
            return 0x00u;
        }

        // Every byte is read whatever the outcome -- no break, no early return. This is the one
        // place an element-wise loop is the right shape rather than a bulk call: memcmp() would
        // stop at the first mismatch, which is precisely the leak being avoided.
        uint8_t diff = 0;
        for (size_t i = 0; i < first.size; ++i) {
            diff = uint8_t(diff | uint8_t(first.data[i] ^ second.data[i]));
        }

        // diff is 0 exactly when every byte matched. Folding that to a mask arithmetically,
        // rather than writing `diff == 0`, avoids relying on the compiler to turn a comparison
        // into a flag set instead of a branch: for diff == 0, both diff and its two's complement
        // are 0, so bit 7 of their OR is clear and the subtraction wraps to 0xFF; for any
        // nonzero byte one of the two has bit 7 set, giving 1 - 1 == 0.
        return uint8_t((uint8_t(diff | uint8_t(~diff + 1)) >> 7) - 1);
    }

    /* Copies one of two spans into out according to a mask, without branching on it. */
    bool CSecure::select(
        uint8_t mask, const SReadOnlyByteSpan& ifSet, const SReadOnlyByteSpan& ifClear,
        const SByteSpan& out
    ) {
        if (!ifSet.data || !ifClear.data || !out.data) {
            return false;
        }
        if (ifSet.size != out.size || ifClear.size != out.size) {
            return false;
        }

        const uint8_t inverse = uint8_t(~mask);

        for (size_t i = 0; i < out.size; ++i) {
            out.data[i] = uint8_t((ifSet.data[i] & mask) | (ifClear.data[i] & inverse));
        }

        return true;
    }

} // namespace certpp
