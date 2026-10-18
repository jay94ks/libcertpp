#ifndef __INCLUDE_CERTPP_UTILS_DJB_HPP__
#define __INCLUDE_CERTPP_UTILS_DJB_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {
    
    /**
     * Represents the value type for the Djb hash function.
     */
    using SDjbValue = uint32_t;
    
    /**
     * Djb hash function utility class.
     * Provides a static method to compute the Djb hash for a given span of bytes or characters.
     * And, it also provides an instance-based interface for incremental hash computation.
     */
    class CERTPP_API CDjb {
    public:
        /**
         * The initial seed value for the Djb hash function.
         */
        static constexpr SDjbValue SEED = 5381;

    public:
        /**
         * Combines two Djb hash values into a single hash value.
         *
         * @param hash1 The first hash value.
         * @param hash2 The second hash value.
         * @return The combined Djb hash value.
         */
        static inline SDjbValue combine(SDjbValue hash1, SDjbValue hash2) {
            return (hash1 << 5) ^ hash2;
        }

        /**
         * Computes the Djb hash for the given span of bytes, starting from the specified hash.
         *
         * @param hash The partial hash value to start from.
         * @param span The span of bytes to hash.
         * @return The computed Djb hash value.
         */
        static SDjbValue compute(SDjbValue hash, TReadOnlySpan<uint8_t> span);

        /**
         * Computes the Djb hash for the given span of bytes.
         *
         * @param span The span of bytes to hash.
         * @return The computed Djb hash value.
         */
        static inline SDjbValue compute(TReadOnlySpan<uint8_t> span) {
            return compute(SEED, span);
        }

        /**
         * Computes the Djb hash for the given span of characters in a case-insensitive manner 
         * by converting them to uppercase, starting from the specified hash.
         *
         * @param hash The partial hash value to start from.
         * @param span The span of characters to hash.
         * @return The computed Djb hash value.
         */
        static SDjbValue computeAsUpper(SDjbValue hash, TReadOnlySpan<char> span);

        /**
         * Computes the Djb hash for the given span of characters in a case-insensitive manner 
         * by converting them to uppercase.
         *
         * @param span The span of characters to hash.
         * @return The computed Djb hash value.
         */
        static inline SDjbValue computeAsUpper(TReadOnlySpan<char> span) {
            return computeAsUpper(SEED, span);
        }
        
        /**
         * Computes the Djb hash for the given span of characters in a case-insensitive manner 
         * by converting them to lowercase, starting from the specified hash.
         *
         * @param hash The partial hash value to start from.
         * @param span The span of characters to hash.
         * @return The computed Djb hash value.
         */
        static SDjbValue computeAsLower(SDjbValue hash, TReadOnlySpan<char> span);

        /**
         * Computes the Djb hash for the given span of characters in a case-insensitive manner 
         * by converting them to lowercase.
         *
         * @param span The span of characters to hash.
         * @return The computed Djb hash value.
         */
        static inline SDjbValue computeAsLower(TReadOnlySpan<char> span) {
            return computeAsLower(SEED, span);
        }

    private:
        SDjbValue _cur;

    public:
        CDjb() : _cur(SEED) {}

    public:
        /**
         * Resets the current hash value to the initial seed.
         */
        inline void reset() {
            _cur = SEED;
        }

        /**
         * Returns the current hash value.
         *
         * @return The current Djb hash value.
         */
        inline SDjbValue current() const {
            return _cur;
        }

        /**
         * Pushes a byte into the current hash computation.
         *
         * @param byte The byte to push.
         */
        inline void push(uint8_t byte) {
            _cur = ((_cur << 5) + _cur) + SDjbValue(byte);
        }

        /**
         * Pushes a span of bytes into the current hash computation.
         *
         * @param span The span of bytes to push.
         */
        inline void push(const TReadOnlySpan<uint8_t>& span) {
            _cur = compute(_cur, span);
        }

        /**
         * Pushes a span of characters into the current hash computation in a case-insensitive manner
         * by converting them to uppercase.
         *
         * @param span The span of characters to push.
         */
        inline void pushAsUpper(const TReadOnlySpan<char>& span) {
            _cur = computeAsUpper(_cur, span);
        }

        /**
         * Pushes a span of characters into the current hash computation in a case-insensitive manner
         * by converting them to lowercase.
         *
         * @param span The span of characters to push.
         */
        inline void pushAsLower(const TReadOnlySpan<char>& span) {
            _cur = computeAsLower(_cur, span);
        }
    };
} // namespace certpp

#endif
