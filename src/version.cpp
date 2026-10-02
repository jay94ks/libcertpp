#include <certpp/version.hpp>

namespace certpp {

    /* Retrieves the version of the library. */
    SVersion GetLibraryVersion() {
        static constexpr SVersion LIBRARY_VERSION = HEADER_VERSION;
        return LIBRARY_VERSION;
    }

    /* Compares this version with another version for equality. */
    bool SVersion::operator==(const SVersion& other) const {
        return major == other.major && minor == other.minor && patch == other.patch;
    }

    /* Compares this version with another version to determine if it is less than the other version. */
    bool SVersion::operator<(const SVersion& other) const {
        return (major < other.major) ||
               (major == other.major && minor < other.minor) ||
               (major == other.major && minor == other.minor && patch < other.patch);
    }
    
    /* Compares this version with another version to determine if it is greater than the other version. */
    bool SVersion::operator>(const SVersion& other) const {
        return (major > other.major) ||
               (major == other.major && minor > other.minor) ||
               (major == other.major && minor == other.minor && patch > other.patch);
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
