#ifndef __INCLUDE_CERTPP_VERSION_HPP__
#define __INCLUDE_CERTPP_VERSION_HPP__

#include <certpp/common.hpp>

namespace certpp {

    /**
     * Bit set in SVersion::major when the linked library was built with
     * CERTPP_DISABLE_SECURE_MEM and CSecure allocations use ordinary heap memory.
     * Mask this bit out to obtain the semantic major-version number.
     */
    static constexpr uint32_t VERSION_FLAG_SECURE_MEM_DISABLED = UINT32_C(0x80000000);

    /**
     * Represents a version with major, minor, and patch components.
     * GetLibraryVersion() may set VERSION_FLAG_SECURE_MEM_DISABLED in major. Version comparison
     * masks that feature bit; use isSecureMemory() to inspect the linked build's setting.
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
         * Reports whether protected page-backed allocation is enabled in this version value.
         * @return true when the secure-memory-disabled flag is clear; false otherwise.
         */
        constexpr bool isSecureMemory() const noexcept {
            return (major & VERSION_FLAG_SECURE_MEM_DISABLED) == 0;
        }

        /**
         * Compares this version with another version for equality.
         * @param other The other version to compare with.
         * The secure-memory feature bit is ignored; inspect isSecureMemory() separately.
         * @return true if all semantic components (major, minor, patch) are equal.
         */
        bool operator==(const SVersion& other) const;

        /**
         * Compares this version with another version for inequality.
         * @param other The other version to compare with.
         * The secure-memory feature bit is ignored; inspect isSecureMemory() separately.
         * @return true if any semantic component (major, minor, patch) is different.
         */
        bool operator!=(const SVersion& other) const {
            return !(*this == other);
        }

        /**
         * Compares this version with another version to determine if it is less than the other version.
         * @param other The other version to compare with.
         * The secure-memory feature bit is ignored; inspect isSecureMemory() separately.
         * @return true if this version is less than the other version, false otherwise.
         */
        bool operator<(const SVersion& other) const;
        
        /**
         * Compares this version with another version to determine if it is greater than the other version.
         * @param other The other version to compare with.
         * The secure-memory feature bit is ignored; inspect isSecureMemory() separately.
         * @return true if this version is greater than the other version, false otherwise.
         */
        bool operator>(const SVersion& other) const;
        
        /**
         * Compares this version with another version to determine if it is less than or equal to the other version.
         * @param other The other version to compare with.
         * The secure-memory feature bit is ignored; inspect isSecureMemory() separately.
         * @return true if this version is less than or equal to the other version, false otherwise.
         */
        bool operator<=(const SVersion& other) const;

        /**
         * Compares this version with another version to determine if it is greater than or equal to the other version.
         * @param other The other version to compare with.
         * The secure-memory feature bit is ignored; inspect isSecureMemory() separately.
         * @return true if this version is greater than or equal to the other version, false otherwise.
         */
        bool operator>=(const SVersion& other) const;
    };

    /**
     * The version of the header file.
     */
    static constexpr SVersion HEADER_VERSION{1, 2, 0};

    /**
     * Retrieves the version of the library.
     * @return The library version as an SVersion structure.
     */
    CERTPP_API SVersion GetLibraryVersion();
} // namespace certpp

#endif
