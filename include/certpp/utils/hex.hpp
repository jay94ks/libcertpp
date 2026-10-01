#ifndef __INCLUDE_CERTPP_UTILS_HEX_HPP__
#define __INCLUDE_CERTPP_UTILS_HEX_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/array.hpp>

namespace certpp {

    /**
     * Hex string decoding. A hex string may optionally be "0x"/"0X"-prefixed; an odd number of
     * digits is treated as if left-padded with one more '0' (so "abc" decodes the same as
     * "0abc"). Lives under utils/ since it's generic text/byte conversion, not tied to any one
     * algorithm -- CBigNum::fromHex()/CGf2m::fromHex() are both thin wrappers over this.
     */
    class CERTPP_API CHex {
    private:
        /**
         * Maps a hex digit to its 0-15 value, or -1 if c isn't a hex digit.
         */
        static int hexDigit(char c);

    public:
        /**
         * Decodes a hex string into raw bytes, most-significant digit pair first.
         * @param hex The hex string to decode.
         * @param out Receives the decoded bytes, replacing any content it previously held.
         * @return true if hex was well-formed (every character after an optional "0x"/"0X"
         * prefix is a hex digit); false otherwise (out is left unchanged).
         */
        static bool decode(const char* hex, TArray<uint8_t>& out);
    };

} // namespace certpp

#endif
