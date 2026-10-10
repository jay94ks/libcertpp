#ifndef __INCLUDE_CERTPP_OID_HPP__
#define __INCLUDE_CERTPP_OID_HPP__

#include <certpp/common.hpp>
#include <certpp/string.hpp>

namespace certpp {

    /**
     * Represents a raw Object Identifier (OID) in its binary form.
     */
    struct CERTPP_API SRawOid {
        /**
         * The maximum number of arcs (components) an OID can have.
         */
        static constexpr size_t MAX_OID_ARCS = 32;

        // --
        size_t count;                   /**< The number of valid arcs in the OID. */
        uint32_t arcs[MAX_OID_ARCS];    /**< The array of arcs (components) of the OID. */

        /**
         * Initializes a new instance of the SRawOid structure with zero arcs.
         */
        SRawOid() : count(0) {}

        /**
         * Initializes a new instance of the SRawOid structure by copying another instance.
         *
         * @param other The SRawOid instance to copy.
         */
        SRawOid(const SRawOid& other) {
            count = other.count;

            // --> Copy the arcs from the other instance.
            std::memcpy(arcs, other.arcs, sizeof(uint32_t) * count);
        }

        /**
         * Initializes a new instance of the SRawOid structure by moving another instance.
         *
         * @param other The SRawOid instance to move.
         */
        SRawOid(SRawOid&& other) noexcept {
            count = other.count;

            // --> Move the arcs from the other instance.
            std::memcpy(arcs, other.arcs, sizeof(uint32_t) * count);
            other.count = 0;
        }

        /**
         * Initializes a new instance of the SRawOid structure from a fixed-size array of arcs.
         *
         * @tparam N The number of arcs in the input array.
         * @param arcs The array of arcs to initialize the OID with.
         */
        template<size_t N>
        explicit SRawOid(const uint32_t (&arcs)[N]) {
            count = (N > MAX_OID_ARCS) ? MAX_OID_ARCS : N;
            std::memcpy(this->arcs, arcs, sizeof(uint32_t) * count);
        }

        /**
         * Copy assignment operator.
         *
         * @param other The SRawOid instance to copy.
         * @return A reference to the current instance after copying.
         */
        inline SRawOid& operator=(const SRawOid& other) {
            if (this != &other && (count = other.count) > 0) {
                std::memcpy(arcs, other.arcs, sizeof(uint32_t) * count);
            }

            return *this;
        }

        /**
         * Move assignment operator.
         *
         * @param other The SRawOid instance to move.
         * @return A reference to the current instance after moving.
         */
        inline SRawOid& operator=(SRawOid&& other) noexcept  {
            if (this != &other) {
                SRawOid tmp;

                // --> Backup the current instance into tmp.
                if ((tmp.count = count) > 0) {
                    std::memcpy(tmp.arcs, arcs, sizeof(uint32_t) * tmp.count);
                }

                // --> Move the other instance into the current instance.
                if ((count = other.count) > 0) {
                    std::memcpy(arcs, other.arcs, sizeof(uint32_t) * count);
                }

                // --> Move the backup (tmp) into the other instance.
                if ((other.count = tmp.count) > 0) {
                    std::memcpy(other.arcs, tmp.arcs, sizeof(uint32_t) * other.count);
                }
            }

            return *this;
        }

        /**
         * Checks if the OID is empty (has no arcs).
         *
         * @return true if the OID has no arcs, false otherwise.
         */
        inline bool empty() const {
            return count == 0;
        }

        /**
         * Checks if the OID has any arcs (is not empty).
         *
         * @return true if the OID has at least one arc, false otherwise.
         */
        inline operator bool() const {
            return count > 0;
        }

        /**
         * Checks if the OID is empty using the logical NOT operator.
         *
         * @return true if the OID has no arcs, false otherwise.
         */
        inline bool operator!() const {
            return count == 0;
        }

        /**
         * Compares the current OID with another OID.
         *
         * @param other The SRawOid instance to compare with.
         * @return A negative value if the current OID is less than the other OID,
         *         zero if they are equal,
         *         a positive value if the current OID is greater than the other OID.
         */
        int32_t compare(const SRawOid& other) const;

        /**
         * Equality comparison operator.
         *
         * @param other The SRawOid instance to compare with.
         * @return true if the current OID is equal to the other OID, false otherwise.
         */
        inline bool operator==(const SRawOid& other) const {
            return compare(other) == 0;
        }

        /**
         * Inequality comparison operator.
         *
         * @param other The SRawOid instance to compare with.
         * @return true if the current OID is not equal to the other OID, false otherwise.
         */
        inline bool operator!=(const SRawOid& other) const {
            return compare(other) != 0;
        }

        /**
         * Less-than comparison operator.
         *
         * @param other The SRawOid instance to compare with.
         * @return true if the current OID is less than the other OID, false otherwise.
         */
        inline bool operator<(const SRawOid& other) const {
            return compare(other) < 0;
        }

        /**
         * Less-than-or-equal-to comparison operator.
         *
         * @param other The SRawOid instance to compare with.
         * @return true if the current OID is less than or equal to the other OID, false otherwise.
         */
        inline bool operator<=(const SRawOid& other) const {
            return compare(other) <= 0;
        }

        /**
         * Greater-than comparison operator.
         *
         * @param other The SRawOid instance to compare with.
         * @return true if the current OID is greater than the other OID, false otherwise.
         */
        inline bool operator>(const SRawOid& other) const {
            return compare(other) > 0;
        }

        /**
         * Greater-than-or-equal-to comparison operator.
         *
         * @param other The SRawOid instance to compare with.
         * @return true if the current OID is greater than or equal to the other OID, false otherwise.
         */
        inline bool operator>=(const SRawOid& other) const {
            return compare(other) >= 0;
        }

        /**
         * Parses a string representation of an OID into its binary form.
         *
         * @param out The output SRawOid structure to store the parsed OID.
         * @param str The string representation of the OID.
         * @return An ERetCode indicating success or failure of the parsing operation.
         */
        static ERetCode parse(SRawOid& out, const CString& str);

        /**
         * Converts the binary representation of the OID into its string form.
         *
         * @param out The output CString to store the string representation of the OID.
         */
        void toString(CString& out) const;

        /**
         * Converts the binary representation of the OID into its string form and returns it as a CString.
         *
         * @return A CString containing the string representation of the OID.
         */
        inline CString toString() const {
            CString result;
            toString(result);
            return result;
        }
    };

    /**
     * Represents a known OID within the COid class. 
     * DO NOT define these OIDs duplicated anywhere.
     * because this does not compare the string representation of the OID, 
     * only the raw binary form and string pointer.
     */
    struct SKnownOid {
        uint32_t nth;                           /**< The internal index of the known OID within the library. */
        const char* s;                          /**< The string representation of the known OID, compiled into the library. */
        size_t count;                           /**< The number of arcs in the raw binary representation of the known OID. */
        uint32_t arcs[SRawOid::MAX_OID_ARCS];   /**< The raw binary representation of the known OID. */

        /**
         * Checks if the current known OID is equal to another known OID.
         *
         * @param other The SKnownOid instance to compare with.
         * @return true if the current known OID is equal to the other known OID, false otherwise.
         */
        bool equals(const SKnownOid& other) const;
    };

    /**
     * Represents an OID (Object Identifier) in a more abstract form.
     */
    class CERTPP_API COid {
    private:
        struct Slot {
            CString str;
            SRawOid raw;
        };

    public:
        // TODO: add all known OIDs here that are defined in the library.
        static const SKnownOid SHA1;    /**< The SHA-1 OID. */

    private:
        /**
         * A cached shared pointer to a Slot structure for reuse.
         */
        static std::shared_ptr<Slot> CACHED[];

        /**
         * Get or create a cached shared pointer to a Slot structure for a known OID.
         *
         * @param known The known OID for which to retrieve the cached Slot.
         * @return A shared pointer to the cached Slot structure.
         */
        static std::shared_ptr<Slot> cacheFor(const SKnownOid& known);

    private:
        /**
         * The shared pointer to the Slot structure containing 
         * the string and binary representations of the OID.
         */
        std::shared_ptr<Slot> _slot;

    public:
        /**
         * Default constructor.
         */
        COid() { }

        /**
         * Constructs a COid instance from a string representation of an OID.
         *
         * @param str The string representation of the OID.
         */
        COid(const CString& str) {
            auto s = std::make_shared<Slot>();

            // --> parse the string into the raw binary representation
            if (SRawOid::parse(s->raw, str) == ERET_OK) {
                s->str = str;
                _slot = s;
            }
        }

        /**
         * Constructs a COid instance from a binary representation of an OID.
         *
         * @param raw The binary representation of the OID.
         */
        COid(const SRawOid& raw) {
            auto s = std::make_shared<Slot>();
            s->raw = raw;
            _slot = s;
        }

        /**
         * Constructs a COid instance from a known OID.
         *
         * @param known The known OID.
         */
        COid(const SKnownOid& known) {
            _slot = cacheFor(known);
        }

        /**
         * Copy constructor.
         *
         * @param other The COid instance to copy from.
         */
        COid(const COid& other) : _slot(other._slot) { }

        /**
         * Move constructor.
         *
         * @param other The COid instance to move from.
         */
        COid(COid&& other) : _slot(std::move(other._slot)) { 
            other._slot.reset();
        }

        /**
         * Assignment operator for a string representation of an OID.
         *
         * @param str The string representation of the OID to assign from.
         * @return A reference to the current COid instance.
         */
        inline COid& operator=(const CString& str) {
            auto s = std::make_shared<Slot>();

            // --> parse the string into the raw binary representation
            if (SRawOid::parse(s->raw, str) == ERET_OK) {
                s->str = str;
                _slot = s;
            }

            return *this;
        }

        /**
         * Assignment operator for a binary representation of an OID.
         *
         * @param raw The binary representation of the OID to assign from.
         * @return A reference to the current COid instance.
         */
        inline COid& operator=(const SRawOid& raw) {
            auto s = std::make_shared<Slot>();
            s->raw = raw;
            _slot = s;

            return *this;
        }

        /**
         * Assignment operator for a known OID.
         *
         * @param known The known OID to assign from.
         * @return A reference to the current COid instance.
         */
        COid& operator=(const SKnownOid& known);

        /**
         * Copy assignment operator.
         *
         * @param other The COid instance to copy from.
         * @return A reference to the current COid instance.
         */
        inline COid& operator=(const COid& other) {
            if (this != &other) {
                _slot = other._slot;
            }

            return *this;
        }

        /**
         * Move assignment operator.
         *
         * @param other The COid instance to move from.
         * @return A reference to the current COid instance.
         */
        inline COid& operator=(COid&& other) {
            if (this != &other) {
                swap(_slot, other._slot);
            }

            return *this;
        }

    public:
        /**
         * Checks if the COid instance is empty.
         *
         * @return true if the COid instance is empty, false otherwise.
         */
        inline bool empty() const {
            return !_slot;
        }

        /**
         * Checks if the COid instance is valid (non-empty).
         *
         * @return true if the COid instance is valid, false otherwise.
         */
        inline operator bool() const {
            return _slot != nullptr;
        }

        /**
         * Checks if the COid instance is not valid (empty).
         *
         * @return true if the COid instance is not valid, false otherwise.
         */
        inline bool operator!() const {
            return !_slot;
        }
        
        /**
         * Compares the current COid instance with another COid instance.
         *
         * @param other The COid instance to compare with.
         * @return A negative value if the current instance is less than the other,
         *         zero if they are equal,
         *         a positive value if the current instance is greater than the other.
         */
        int32_t compare(const COid& other) const;

        /**
         * Checks if the current COid instance is equal to another COid instance.
         *
         * @param other The COid instance to compare with.
         * @return true if the current instance is equal to the other, false otherwise.
         */
        inline bool equals(const COid& other) const {
            return compare(other) == 0;
        }

        /**
         * Checks if the current COid instance is equal to another COid instance.
         *
         * @param other The COid instance to compare with.
         * @return true if the current instance is equal to the other, false otherwise.
         */
        inline bool operator==(const COid& other) const {
            return equals(other);
        }

        /**
         * Checks if the current COid instance is not equal to another COid instance.
         *
         * @param other The COid instance to compare with.
         * @return true if the current instance is not equal to the other, false otherwise.
         */
        inline bool operator!=(const COid& other) const {
            return !equals(other);
        }

        /**
         * Checks if the current COid instance is less than another COid instance.
         *
         * @param other The COid instance to compare with.
         * @return true if the current instance is less than the other, false otherwise.
         */
        inline bool operator<(const COid& other) const {
            return compare(other) < 0;
        }

        /**
         * Checks if the current COid instance is less than or equal to another COid instance.
         *
         * @param other The COid instance to compare with.
         * @return true if the current instance is less than or equal to the other, false otherwise.
         */
        inline bool operator<=(const COid& other) const {
            return compare(other) <= 0;
        }

        /**
         * Checks if the current COid instance is greater than another COid instance.
         *
         * @param other The COid instance to compare with.
         * @return true if the current instance is greater than the other, false otherwise.
         */
        inline bool operator>(const COid& other) const {
            return compare(other) > 0;
        }

        /**
         * Checks if the current COid instance is greater than or equal to another COid instance.
         *
         * @param other The COid instance to compare with.
         * @return true if the current instance is greater than or equal to the other, false otherwise.
         */
        inline bool operator>=(const COid& other) const {
            return compare(other) >= 0;
        }

        /**
         * Converts the COid instance to its string representation.
         *
         * @param out The output CString to store the string representation of the OID.
         */
        inline void toString(CString& out) const {
            out.clear();

            if (_slot) {
                if (_slot->str) {
                    out = _slot->str;
                }

                else if (_slot->raw) {
                    _slot->raw.toString(out);
                }
            }
        }

        /**
         * Converts the COid instance to its string representation and returns it as a CString.
         *
         * @return The string representation of the OID.
         */
        inline CString toString() const {
            CString out;
            toString(out);
            return out;
        }
    };

} // namespace certpp

#endif
