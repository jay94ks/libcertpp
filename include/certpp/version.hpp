#ifndef __INCLUDE_CERTPP_VERSION_HPP__
#define __INCLUDE_CERTPP_VERSION_HPP__

#include "common.hpp"

namespace certpp {

    /**
     * Represents a version with major, minor, and patch components.
     */
    struct CERTPP_API SVersion {
        uint32_t major;
        uint32_t minor;
        uint32_t patch;

        /**
         * Constructs an SVersion with the specified major, minor, and patch components.
         */
        constexpr SVersion(uint32_t maj = 0, uint32_t min = 0, uint32_t pat = 0)
            : major(maj), minor(min), patch(pat) {}

        /**
         * Compares this version with another version for equality.
         * @param other The other version to compare with.
         * @return true if all components (major, minor, patch) are equal, false otherwise.
         */
        bool operator==(const SVersion& other) const;

        /**
         * Compares this version with another version for inequality.
         * @param other The other version to compare with.
         * @return true if any component (major, minor, patch) is different, false otherwise.
         */
        bool operator!=(const SVersion& other) const {
            return !(*this == other);
        }

        /**
         * Compares this version with another version to determine if it is less than the other version.
         * @param other The other version to compare with.
         * @return true if this version is less than the other version, false otherwise.
         */
        bool operator<(const SVersion& other) const;
        
        /**
         * Compares this version with another version to determine if it is greater than the other version.
         * @param other The other version to compare with.
         * @return true if this version is greater than the other version, false otherwise.
         */
        bool operator>(const SVersion& other) const;
        
        /**
         * Compares this version with another version to determine if it is less than or equal to the other version.
         * @param other The other version to compare with.
         * @return true if this version is less than or equal to the other version, false otherwise.
         */
        bool operator<=(const SVersion& other) const;

        /**
         * Compares this version with another version to determine if it is greater than or equal to the other version.
         * @param other The other version to compare with.
         * @return true if this version is greater than or equal to the other version, false otherwise.
         */
        bool operator>=(const SVersion& other) const;
    };

    /**
     * The version of the header file.
     */
    static constexpr SVersion HEADER_VERSION{1, 0, 0};

    /**
     * Retrieves the version of the library.
     * @return The library version as an SVersion structure.
     */
    SVersion GetLibraryVersion();
} // namespace certpp

#endif
