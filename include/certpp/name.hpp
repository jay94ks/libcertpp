#ifndef __INCLUDE_CERTPP_NAME_HPP__
#define __INCLUDE_CERTPP_NAME_HPP__

#include <certpp/common.hpp>
#include <certpp/utils/djb.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/array.hpp>
#include <certpp/string.hpp>
#include <utility>

namespace certpp {

    /**
     * Represents the type of a name component in a distinguished name (DN).
     */
    enum ENameType : uint8_t {
        ENAME_NONE = 0,
        ENAME_CN,       // --> Common Name.
        ENAME_OU,       // --> Organizational Unit.
        ENAME_O,        // --> Organization.
        ENAME_L,        // --> Locality.
        ENAME_ST,       // --> State or Province.
        ENAME_C,        // --> Country.

        // --
        ENAME_MAX
    };

    /**
     * Represents a name component of a distinguished name (DN) in a certificate.
     * This only can take `ASCII` characters. Non-ASCII characters are escaped.
     */
    class CERTPP_API CName {
    public:
        /**
         * The maximum length of a name component.
         */
        static constexpr size_t MAX_LEN = 256;

    private:
        static constexpr uint16_t MASK_TYPE = 0x00ffu;

        /**
         * Indicates that the name component contains escaped non-ASCII characters.
         */
        static constexpr uint16_t FLAG_ESCAPED = 0x0100u;

        /**
         * Keys corresponding to each name type.
         */
        static const char* TYPE_KEYS[ENAME_MAX];

        /**
         * Labels corresponding to each name type.
         */
        static const char* TYPE_LABELS[ENAME_MAX];

        /**
         * X.520 attribute-type OBJECT IDENTIFIER arcs corresponding to each name type, as a
         * fixed 4-arc {2, 5, 4, N} tuple (e.g. ENAME_CN -> {2, 5, 4, 3}). Index ENAME_NONE is
         * unused (all zero).
         */
        static const uint32_t TYPE_OIDS[ENAME_MAX][4];

    private:
        uint16_t _type;
        SDjbValue _hash;

        char* _data;
        size_t _len;

    public:
        /**
         * Default constructor for the CName class.
         * Initializes the name type to ENAME_NONE and sets the data pointer to nullptr.
         */
        CName() : _type(ENAME_NONE), _hash(0), _data(nullptr), _len(0) { }

        /**
         * Constructs a CName with the specified type and string data. Non-ASCII bytes (> 127)
         * are escaped with a leading backslash -- see reset() for the exact rules.
         *
         * If str is null, limit is zero, or the string is empty (up to limit, or up to its own
         * NUL if that comes first), the result is an empty CName (type() == ENAME_NONE, same as
         * the default constructor), rather than reporting failure.
         *
         * @param type The type of the name component.
         * @param str The string data for the name component.
         * @param limit The maximum number of characters to consider from str; a NUL within
         * limit ends the string early, same as reset().
         */
        CName(ENameType type, const char* str, size_t limit = size_t(-1))
            : _type(ENAME_NONE), _hash(0), _data(nullptr), _len(0)
        {
            reset(type, str, limit);
        }

        /**
         * Copy constructor for the CName class.
         *
         * @param other The other CName object to copy from.
         */
        CName(const CName& other) : _type(ENAME_NONE), _hash(0), _data(nullptr), _len(0) {
            // --> Deep-copies other's internal state verbatim, rather than calling reset() with
            // other._data: other._data may already contain escape markers from a previous
            // reset(), and reset()'s escaping logic doesn't know that, so it would prepend a
            // *new* backslash ahead of every already-escaped byte it found instead of just
            // copying it as-is.
            if (!other.empty()) {
                _data = new char[other._len + 1];

                TStringFunctions<char>::copy(_data, other._data, other._len);
                _data[other._len] = '\0';
                
                _len = other._len;
                _hash = other._hash;
                _type = other._type;
            }
        }

        /**
         * Move constructor for the CName class.
         *
         * @param other The other CName object to move from.
         */
        CName(CName&& other) noexcept : _type(other._type), _hash(other._hash), _data(other._data), _len(other._len) {
            other._type = ENAME_NONE;
            other._hash = 0;
            other._data = nullptr;
            other._len = 0;
        }

        /**
         * Destructor for the CName class.
         * Frees the allocated memory for the name data.
         */
        ~CName() { reset(ENAME_NONE, nullptr); }

        /**
         * Copy assignment operator for the CName class.
         *
         * @param other The other CName object to copy from.
         * @return A reference to the current CName object.
         */
        inline CName& operator=(const CName& other) {
            if (this != &other) {
                // --> See the copy constructor's comment: deep-copies verbatim rather than
                // calling reset(), which would re-escape other._data's already-escaped bytes.
                if (_data) {
                    delete[] _data;
                    _data = nullptr;
                }

                _len = 0;
                _hash = 0;
                _type = ENAME_NONE;

                if (!other.empty()) {
                    _data = new char[other._len + 1];

                    TStringFunctions<char>::copy(_data, other._data, other._len);
                    _data[other._len] = '\0';

                    _len = other._len;
                    _hash = other._hash;
                    _type = other._type;
                }
            }

            return *this;
        }

        /**
         * Move assignment operator for the CName class.
         *
         * @param other The other CName object to move from.
         * @return A reference to the current CName object.
         */
        inline CName& operator=(CName&& other) noexcept {
            if (this != &other) {
                swap(_type, other._type);
                swap(_hash, other._hash);
                swap(_data, other._data);
                swap(_len, other._len);
            }

            return *this;
        }
        
    private:
        /**
         * Resets the name component with the specified type and string data.
         * Frees any previously allocated memory and allocates new memory for the new data.
         *
         * @param type The type of the name component.
         * @param str The string data for the name component.
         * @param limit The maximum number of characters to copy from the string data.
         * @return true if the reset was successful, false otherwise.
         */
        bool reset(ENameType type, const char* str, size_t limit = size_t(-1));

    public:
        /**
         * Checks if the name component is empty (i.e., has a type of ENAME_NONE).
         *
         * @return true if the name component is empty, false otherwise.
         */
        inline bool empty() const {
            return ENameType(_type & MASK_TYPE) == ENAME_NONE;
        }

        /**
         * Checks if the name component is not empty.
         *
         * @return true if the name component is not empty, false otherwise.
         */
        inline operator bool() const {
            return !empty();
        }

        /**
         * Checks if the name component is empty (i.e., has a type of ENAME_NONE).
         *
         * @return true if the name component is empty, false otherwise.
         */
        inline bool operator !() const {
            return empty();
        }

        /**
         * Retrieves the type of the name component.
         *
         * @return The type of the name component.
         */
        inline ENameType type() const {
            return ENameType(_type & MASK_TYPE);
        }

        /**
         * Retrieves the precomputed DJB hash value of the name component.
         *
         * @return The DJB hash value of the name component.
         */
        inline SDjbValue hash() const {
            return _hash;
        }

        /**
         * Retrieves the name component type corresponding to a given key.
         *
         * @param key The key representing the name component.
         * @return The type of the name component corresponding to the specified key.
         */
        static ENameType typeOf(const char* key);

        /**
         * Retrieves the key corresponding to a given name component type.
         *
         * @param type The type of the name component.
         * @return The key corresponding to the specified type.
         */
        static inline const char* keyOf(ENameType type) {
            if (type <= 0 || type >= ENAME_MAX) {
                return nullptr;
            }

            return TYPE_KEYS[type];
        }

        /**
         * Retrieves the label corresponding to a given name component type.
         *
         * @param type The type of the name component.
         * @return The label corresponding to the specified type.
         */
        static inline const char* labelOf(ENameType type) {
            if (type <= 0 || type >= ENAME_MAX) {
                return nullptr;
            }

            return TYPE_LABELS[type];
        }

        /**
         * Retrieves the X.520 attribute-type OBJECT IDENTIFIER arcs corresponding to a given
         * name component type (e.g. ENAME_CN -> {2, 5, 4, 3}). Used by the asn1 module to encode
         * a CDistinguishedName's components as AttributeTypeAndValue.type.
         *
         * @param type The name component type.
         * @param outArcs The destination for the OID's arc values; must be at least 4 long.
         * @param outArcCount The number of arcs written to outArcs (always 4 on success).
         * @return true if type is a recognized, non-ENAME_NONE type and outArcs had enough
         * room; otherwise, false.
         */
        static bool attributeOid(ENameType type, TSpan<uint32_t> outArcs, size_t& outArcCount);

        /**
         * Retrieves the name component type corresponding to a given X.520 attribute-type
         * OBJECT IDENTIFIER's arc values, the inverse of attributeOid(). Used by the asn1 module
         * to decode a CDistinguishedName's components from AttributeTypeAndValue.type.
         *
         * @param arcs The OID's arc values.
         * @return The corresponding name component type, or ENAME_NONE if arcs isn't a
         * recognized X.520 DN attribute OID.
         */
        static ENameType attributeTypeOf(TReadOnlySpan<uint32_t> arcs);

        /**
         * Retrieves the key corresponding to the name component's type.
         *
         * @return The key corresponding to the name component's type.
         */
        inline const char* key() const {
            return TYPE_KEYS[type()];
        }

        /**
         * Retrieves the label corresponding to the name component's type.
         *
         * @return The label corresponding to the name component's type.
         */
        inline const char* label() const {
            return TYPE_LABELS[type()];
        }

        /**
         * Retrieves the size (length) of the name component's data.
         *
         * @return The size of the name component's data.
         */
        inline size_t size() const {
            return _len;
        }
        
        /**
         * Converts the name component to a read-only span of characters.
         *
         * @return A read-only span representing the name component's data.
         */
        inline TReadOnlySpan<char> toSpan() const {
            return TReadOnlySpan<char>(_data, _len);
        }

        /**
         * Compares the current name component with another name component.
         *
         * @param other The other name component to compare with.
         * @return A negative value if the current component is less than the other,
         *         zero if they are equal, and a positive value if the current component is greater.
         */
        int32_t compare(const CName& other) const;

        /**
         * Compares the current name component with another name component for equality.
         * This internally uses the `DJB` hash for quick comparison based on the precomputed hash values.
         * And, if the hashes match, it performs a full memory comparison to ensure equality.
         *
         * @param other The other name component to compare with.
         * @return true if the name components are equal, false otherwise.
         */
        bool equals(const CName& other) const;

        /**
         * Checks if the current name component is equal to another name component.
         *
         * @param other The other name component to compare with.
         * @return true if the name components are equal, false otherwise.
         */
        inline bool operator==(const CName& other) const {
            return equals(other);
        }

        /**
         * Checks if the current name component is not equal to another name component.
         *
         * @param other The other name component to compare with.
         * @return true if the name components are not equal, false otherwise.
         */
        inline bool operator!=(const CName& other) const {
            return !equals(other);
        }
        
        /**
         * Converts the name component to a string representation.
         *
         * @return A string representing the name component's data.
         */
        void toString(CString& out, bool escaped = false) const;

        /**
         * Converts the name component to a wide string representation.
         *
         * @param out The output wide string to store the name component's data.
         * @param escaped Whether to include escaped non-ASCII characters.
         */
        void toString(CWideString& out, bool escaped = false) const;

        /**
         * Converts the name component to a string representation of a different character type.
         *
         * @tparam U The character type of the resulting string.
         * @param escaped Whether to include escaped non-ASCII characters.
         * @return A TString of the specified character type representing the name component's data.
         */
        template<typename U>
        inline TString<U> toString(bool escaped = false) const {
            TString<U> result;
            toString(result, escaped);
            return result;
        }
    };

    /**
     * Represents a distinguished name, which is a sequence of name components.
     */
    class CERTPP_API CDistinguishedName {
    private:
        std::map<ENameType, CName> _components;

    public:
        /**
         * Constructs an empty distinguished name.
         */
        CDistinguishedName() { }

        /**
         * Copy constructor for the distinguished name.
         *
         * @param other The distinguished name to copy from.
         */
        CDistinguishedName(const CDistinguishedName& other)
            : _components(other._components) { }

        /**
         * Move constructor for the distinguished name.
         *
         * @param other The distinguished name to move from.
         */
        CDistinguishedName(CDistinguishedName&& other) noexcept {
            swap(_components, other._components);
        }

        /**
         * Copy assignment operator for the distinguished name.
         *
         * @param other The distinguished name to copy from.
         * @return A reference to the current distinguished name.
         */
        inline CDistinguishedName& operator=(const CDistinguishedName& other) {
            if (this != &other) {
                _components = other._components;
            }

            return *this;
        }

        /**
         * Move assignment operator for the distinguished name.
         *
         * @param other The distinguished name to move from.
         * @return A reference to the current distinguished name.
         */
        inline CDistinguishedName& operator=(CDistinguishedName&& other) noexcept {
            if (this != &other) {
                swap(_components, other._components);
            }

            return *this;
        }

        /**
         * Attempts to parse a distinguished name from a string.
         *
         * @param out The distinguished name object to populate.
         * @param s The input string containing the distinguished name.
         * @return true if parsing was successful, false otherwise.
         */
        static bool tryParse(CDistinguishedName& out, const CString& s);

        /**
         * Attempts to parse a distinguished name from a wide string.
         *
         * @param out The distinguished name object to populate.
         * @param s The input wide string containing the distinguished name.
         * @return true if parsing was successful, false otherwise.
         */
        static bool tryParse(CDistinguishedName& out, const CWideString& s);

    public:
        /**
         * Checks if the distinguished name is empty.
         *
         * @return true if the distinguished name has no components, false otherwise.
         */
        inline bool empty() const {
            return _components.empty();
        }

        /**
         * Checks if the distinguished name is not empty.
         *
         * @return true if the distinguished name has at least one component, false otherwise.
         */
        inline operator bool() const {
            return !empty();
        }

        /**
         * Checks if the distinguished name is empty.
         *
         * @return true if the distinguished name has no components, false otherwise.
         */
        inline bool operator !() const {
            return empty();
        }

        /**
         * Retrieves the number of name components in the distinguished name.
         *
         * @return The number of name components.
         */
        inline size_t size() const {
            return _components.size();
        }

        /**
         * Retrieves the keys (name component types) of the distinguished name.
         *
         * @param c The array to store the keys.
         */
        inline void keys(TArray<ENameType>& c) const {
            c.clear();

            // --> Reserve space in the array to avoid multiple reallocations.
            c.reserve(_components.size());
            for (const auto& [key, name] : _components) {
                c.add(key);
            }
        }

        /**
         * Checks if the distinguished name contains a name component of the specified type.
         *
         * @param type The type of the name component to check.
         * @return true if the name component exists, false otherwise.
         */
        inline bool has(ENameType type) const {
            return _components.find(type) != _components.end();
        }

        /**
         * Attempts to set the name component for the specified type.
         *
         * @param value The value of the name component to set.
         * @param overwrite Indicates whether to overwrite the existing name component if it already exists.
         * @return true if the name component is set successfully, false otherwise.
         */
        bool trySet(const CName& value, bool overwrite = false);

        /**
         * Attempts to retrieve the name component corresponding to the specified type.
         *
         * @param type The type of the name component to retrieve.
         * @param out The output parameter to store the retrieved name component.
         * @return true if the name component exists and is retrieved successfully, false otherwise.
         */
        bool tryGet(ENameType type, CName& out) const;

        /**
         * Compares the current distinguished name with another distinguished name.
         *
         * @param other The other distinguished name to compare with.
         * @return A negative value if the current distinguished name is less than the other,
         *         zero if they are equal, and a positive value if the current distinguished name is greater than the other.
         */
        int32_t compare(const CDistinguishedName& other) const;

        /**
         * Checks if the current distinguished name is equal to another distinguished name.
         *
         * @param other The other distinguished name to compare with.
         * @return true if the distinguished names are equal, false otherwise.
         */
        inline bool operator==(const CDistinguishedName& other) const {
            return compare(other) == 0;
        }

        /**
         * Checks if the current distinguished name is not equal to another distinguished name.
         *
         * @param other The other distinguished name to compare with.
         * @return true if the distinguished names are not equal, false otherwise.
         */
        inline bool operator!=(const CDistinguishedName& other) const {
            return compare(other) != 0;
        }

        /**
         * Converts the distinguished name to a string representation.
         *
         * @param out The output parameter to store the string representation of the distinguished name.
         * @param escaped Indicates whether to escape special characters in the string representation.
         */
        void toString(CString& out, bool escaped = false) const;

        /**
         * Converts the distinguished name to a wide string representation.
         *
         * @param out The output parameter to store the wide string representation of the distinguished name.
         * @param escaped Indicates whether to escape special characters in the wide string representation.
         */
        void toString(CWideString& out, bool escaped = false) const;
        
        /**
         * Converts the distinguished name to a string representation of a different character type.
         *
         * @tparam U The character type of the resulting string.
         * @param escaped Indicates whether to escape special characters in the string representation.
         * @return A TString of the specified character type representing the distinguished name.
         */
        template<typename U>
        inline TString<U> toString(bool escaped = false) const {
            TString<U> result;
            toString(result, escaped);
            return result;
        }
    };

} // namespace certpp

#endif
