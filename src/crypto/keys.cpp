#include <certpp/crypto/keys.hpp>

namespace certpp {
namespace crypto {

    /* Compares this key size specification with another. */
    int32_t SKeySizeSpec::compare(const SKeySizeSpec& other) const {
        if (minSize != other.minSize) {
            return static_cast<int32_t>(minSize) - static_cast<int32_t>(other.minSize);
        }

        if (maxSize != other.maxSize) {
            return static_cast<int32_t>(maxSize) - static_cast<int32_t>(other.maxSize);
        }

        return static_cast<int32_t>(step) - static_cast<int32_t>(other.step);
    }

} // namespace crypto
} // namespace certpp
