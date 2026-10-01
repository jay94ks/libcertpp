#include <certpp/utils/Djb.hpp>

namespace certpp {

    /**
     * Computes the Djb hash for the given span of characters, starting from the specified hash.
     */
    SDjbValue CDjb::compute(SDjbValue hash, TReadOnlySpan<uint8_t> span) {
        for (uint8_t c : span) {
            hash
                = ((hash << 5) + hash) 
                + static_cast<SDjbValue>(c);
        }

        return hash;
    }

    /* Computes the Djb hash for the given span of characters in a case-insensitive manner by converting them to uppercase, starting from the specified hash. */
    SDjbValue CDjb::computeAsUpper(SDjbValue hash, TReadOnlySpan<char> span) {
        for (char c : span) {
            char upper = (c >= 'a' && c <= 'z') ? ((c - 'a') + 'A') : c;

            // --> Widen through uint8_t first: char's signedness is implementation-defined, and
            // widening a signed char with the high bit set (e.g. an escaped non-ASCII byte, see
            // CName) straight to SDjbValue would sign-extend it, hashing a different value than
            // compute() does for the identical byte.
            hash
                = ((hash << 5) + hash)
                + static_cast<SDjbValue>(static_cast<uint8_t>(upper));
        }

        return hash;
    }

    /**
     * Computes the Djb hash for the given span of characters in a case-insensitive manner by converting them to lowercase, starting from the specified hash.
     */
    SDjbValue CDjb::computeAsLower(SDjbValue hash, TReadOnlySpan<char> span) {
        for (char c : span) {
            char lower = (c >= 'A' && c <= 'Z') ? ((c - 'A') + 'a') : c;

            // --> See computeAsUpper()'s comment: widen through uint8_t first to avoid
            // sign-extending a high-bit-set byte differently than compute() would.
            hash
                = ((hash << 5) + hash)
                + static_cast<SDjbValue>(static_cast<uint8_t>(lower));
        }

        return hash;
    }

} // namespace certpp