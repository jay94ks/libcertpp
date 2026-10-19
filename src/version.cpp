#include <certpp/version.hpp>

namespace certpp {

    namespace {
        constexpr uint32_t semanticMajor(const SVersion& version) noexcept {
            return version.major & ~VERSION_FLAG_SECURE_MEM_DISABLED;
        }
    }

    /* Retrieves the version of the library. */
    SVersion GetLibraryVersion() {
#if defined(CERTPP_DISABLE_SECURE_MEM)
        static constexpr SVersion LIBRARY_VERSION{
            HEADER_VERSION.major | VERSION_FLAG_SECURE_MEM_DISABLED,
            HEADER_VERSION.minor,
            HEADER_VERSION.patch
        };
#else
        static constexpr SVersion LIBRARY_VERSION = HEADER_VERSION;
#endif
        return LIBRARY_VERSION;
    }

    /* Compares this version with another version for equality. */
    bool SVersion::operator==(const SVersion& other) const {
        return semanticMajor(*this) == semanticMajor(other)
            && minor == other.minor && patch == other.patch;
    }

    /* Compares this version with another version to determine if it is less than the other version. */
    bool SVersion::operator<(const SVersion& other) const {
        const uint32_t thisMajor = semanticMajor(*this);
        const uint32_t otherMajor = semanticMajor(other);
        return (thisMajor < otherMajor) ||
               (thisMajor == otherMajor && minor < other.minor) ||
               (thisMajor == otherMajor && minor == other.minor && patch < other.patch);
    }
    
    /* Compares this version with another version to determine if it is greater than the other version. */
    bool SVersion::operator>(const SVersion& other) const {
        const uint32_t thisMajor = semanticMajor(*this);
        const uint32_t otherMajor = semanticMajor(other);
        return (thisMajor > otherMajor) ||
               (thisMajor == otherMajor && minor > other.minor) ||
               (thisMajor == otherMajor && minor == other.minor && patch > other.patch);
    }

    /* Compares this version with another version to determine if it is less than or equal to the other version. */
    bool SVersion::operator<=(const SVersion& other) const {
        return !(*this > other);
    }

    /* Compares this version with another version to determine if it is greater than or equal to the other version. */
    bool SVersion::operator>=(const SVersion& other) const {
        return !(*this < other);
    }
} // namespace certpp
