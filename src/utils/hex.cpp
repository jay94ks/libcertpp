#include <certpp/utils/hex.hpp>
#include <cstring>
#include <utility>

namespace certpp {

    /* Maps a hex digit to its 0-15 value, or -1 if c isn't a hex digit. */
    int CHex::hexDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    bool CHex::decode(const char* hex, TArray<uint8_t>& out) {
        if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
            hex += 2;
        }

        size_t len = std::strlen(hex);

        TArray<uint8_t> bytes;
        bytes.resize((len + 1) / 2);

        size_t bi = bytes.size();
        size_t hi = len;
        while (hi > 0) {
            int lo = hexDigit(hex[--hi]);
            if (lo < 0) {
                return false;
            }

            int high = 0;
            if (hi > 0) {
                high = hexDigit(hex[--hi]);
                if (high < 0) {
                    return false;
                }
            }

            bytes[--bi] = uint8_t((high << 4) | lo);
        }

        out = std::move(bytes);
        return true;
    }

} // namespace certpp
