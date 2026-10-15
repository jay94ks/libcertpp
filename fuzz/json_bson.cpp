#include <certpp.hpp>
#include <cstddef>
#include <cstdint>
#include <string>

using namespace certpp;
using namespace certpp::utils;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!data || size < 1 || size > 1024 * 1024) {
        return 0;
    }

    if (data[0] & 1) {
        parseJson(std::string(reinterpret_cast<const char*>(data + 1), size - 1));
    } else {
        CBuffer copy(data + 1, size - 1);
        parseBson(copy.toSpan(), (data[0] & 2) != 0);
    }
    return 0;
}
