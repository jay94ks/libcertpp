#ifndef __INCLUDE_CERTPP_ASN1_TAG_HPP__
#define __INCLUDE_CERTPP_ASN1_TAG_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {
namespace asn1 {

    /**
     * Represents the different classes of ASN.1 tags.
     */
    enum ETagClass {
        EATAG_INVALID            = 0xFF,  // --> Invalid tag.
        EATAG_UNIVERSAL          = 0,
        EATAG_APPLICATION        = 1u << 6,
        EATAG_CONTEXT_SPECIFIC   = 1u << 7,
        EATAG_PRIVATE            = (EATAG_APPLICATION | EATAG_CONTEXT_SPECIFIC)
    };

    /** 
     * Represents the different universal ASN.1 tags.
     */
    enum EUniversalTags {
        EAUTAG_INVALID               = 0xFF,           // --> Invalid tag.
        EAUTAG_EOC                   = 0,              // --> End Of Contents.
        EAUTAG_BOOLEAN               = 1,              // --> Boolean.
        EAUTAG_INTEGER               = 2,              // --> Integer.
        EAUTAG_STRING_BIT            = 3,              // --> Bit String.
        EAUTAG_STRING_OCTET          = 4,              // --> Octet String.
        EAUTAG_NULL                  = 5,              // --> Null.
        EAUTAG_OBJ_ID                = 6,              // --> Object Identifier.
        EAUTAG_OBJ_DESC              = 7,              // --> Object Descriptor.
        EAUTAG_EXTERNAL              = 8,              // --> External.
        EAUTAG_INSTANCE_OF           = 8,              // --> Instance Of.
        EAUTAG_REAL                  = 9,              // --> Real.
        EAUTAG_ENUMERATED            = 10,             // --> Enumerated.
        EAUTAG_EMBEDDED              = 11,             // --> Embedded.
        EAUTAG_STRING_UTF8           = 12,             // --> UTF8 String.
        EAUTAG_OID_REL               = 13,             // --> Relative Object Identifier.
        EAUTAG_TIME                  = 14,             // --> Time.
        EAUTAG_SEQ                   = 16,             // --> Sequence.
        EAUTAG_SEQ_OF                = 16,             // --> Sequence Of.
        EAUTAG_SET                   = 17,             // --> Set.
        EAUTAG_SET_OF                = 17,             // --> Set Of.
        EAUTAG_STRING_N              = 18,             // --> Numeric String.
        EAUTAG_STRING_P              = 19,             // --> Printable String.
        EAUTAG_STRING_T61            = 20,             // --> T61 String.
        EAUTAG_STRING_TELETEX        = 20,             // --> Teletex String.
        EAUTAG_STRING_VIDEOTEX       = 21,             // --> Videotex String.
        EAUTAG_STRING_IA5            = 22,             // --> IA5 String.
        EAUTAG_TIME_UTC              = 23,             // --> UTC Time.
        EAUTAG_TIME_GENERAL          = 24,             // --> Generalized Time.
        EAUTAG_STRING_GRAPHI         = 25,             // --> Graphic String.
        EAUTAG_STRING_ISO646         = 26,             // --> ISO646 String.
        EAUTAG_STRING_VISIBLE        = 26,             // --> Visible String.
        EAUTAG_STRING_GENERAL        = 27,             // --> General String.
        EAUTAG_STRING_UNIVERSAL      = 28,             // --> Universal String.
        EAUTAG_STRING_UCS            = 29,             // --> Unrestricted Character String.
        EAUTAG_STRING_BMP            = 30,             // --> BMP String.
        EAUTAG_DATE                  = 31,             // --> Date.
        EAUTAG_TIMEOFDAY             = 32,             // --> Time Of Day.
        EAUTAG_DATETIME              = 33,             // --> Date Time.
        EAUTAG_DURATION              = 34,             // --> Duration.
        EAUTAG_OBJ_ID_IRI            = 35,             // --> Object Identifier IRI.
        EAUTAG_OBJ_ID_RELIRI         = 36,             // --> Relative Object Identifier IRI.
        EAUTAG_MAX                   = 37              // --> Maximum tag value.
    };

    /**
     * Represents an ASN.1 tag.
     */
    class CERTPP_API CTag {
    private:
        static constexpr uint8_t MASK_CLS = 0xC0;  // Class mask (bits 7 and 8).
        static constexpr uint8_t MASK_CON = 0x20;  // Constructed mask (bit 6).
        static constexpr uint8_t MASK_CTL = MASK_CLS | MASK_CON;
        static constexpr uint8_t MASK_TAG = 0x1F;  // Tag number mask (bits 1 to 5).
        static constexpr uint8_t FLAG_INVALID = 0xFF;  // Invalid flag.

        // --
        static constexpr uint8_t FLAG_CONTINUE = 0x80;  // Continue flag (bit 8).
        static constexpr uint8_t MASK_VALUE = FLAG_CONTINUE - 1;  // Value mask (bits 1 to 7).

    public:
        struct Shortcut { 
            uint8_t flags;
            uint32_t value;
        };

        /* Represents the End-of-Content (EOC) ASN.1 tag. */
        static constexpr Shortcut EOC = { 0, uint32_t(EAUTAG_EOC) };

        /* Represents the Boolean ASN.1 tag. */
        static constexpr Shortcut BOOLEAN = { 0, uint32_t(EAUTAG_BOOLEAN) };

        /* Represents the Integer ASN.1 tag. */
        static constexpr Shortcut INTEGER = { 0, uint32_t(EAUTAG_INTEGER) };

        /* Represents the Primitive Bit String ASN.1 tag. */
        static constexpr Shortcut STRING_BIT = { 0, uint32_t(EAUTAG_STRING_BIT) };

        /* Represents the Constructed Bit String ASN.1 tag. */
        static constexpr Shortcut CONSTRUCTED_STRING_BIT = { MASK_CON, uint32_t(EAUTAG_STRING_BIT) };

        /* Represents the Octet String ASN.1 tag. */
        static constexpr Shortcut STRING_OCTET = { 0, uint32_t(EAUTAG_STRING_OCTET) };

        /* Represents the Constructed Octet String ASN.1 tag. */
        static constexpr Shortcut CONSTRUCTED_STRING_OCTET = { MASK_CON, uint32_t(EAUTAG_STRING_OCTET) };

        /* Represents the Null ASN.1 tag. */
        static constexpr Shortcut NULL_ = { 0, uint32_t(EAUTAG_NULL) };

        /* Represents the Object Identifier ASN.1 tag. */
        static constexpr Shortcut OBJ_ID = { 0, uint32_t(EAUTAG_OBJ_ID) };

        /* Represents the Enumerated ASN.1 tag. */
        static constexpr Shortcut ENUMERATED = { 0, uint32_t(EAUTAG_ENUMERATED) };

        /* Represents the Sequence ASN.1 tag. */
        static constexpr Shortcut SEQ = { MASK_CON, uint32_t(EAUTAG_SEQ) };

        /* Represents the Set ASN.1 tag. */
        static constexpr Shortcut SET_OF = { MASK_CON, uint32_t(EAUTAG_SET_OF) };

        /* Represents the UTC Time ASN.1 tag. */
        static constexpr Shortcut TIME_UTC_ = { 0, uint32_t(EAUTAG_TIME_UTC) };

        /* Represents the Generalized Time ASN.1 tag. */
        static constexpr Shortcut TIME_GENERAL = { 0, uint32_t(EAUTAG_TIME_GENERAL) };

    private:
        uint8_t _flags;
        uint32_t _value;

    public:
        /**
         * Constructs an invalid ASN.1 tag.
         */
        CTag() : _flags(FLAG_INVALID), _value(0) { }

    private:
        /** 
         * Constructs an ASN.1 tag with the specified flags and value.
         * @param flags The flags for the ASN.1 tag.
         * @param value The value of the ASN.1 tag.
         */
        CTag(uint8_t flags, uint32_t value)
            : _flags(flags), _value(value) 
        {
        }

    public:
        /**
         * Constructs an ASN.1 tag from a shortcut structure.
         * @param shortcut The shortcut structure containing the flags and value.
         */
        CTag(const Shortcut& shortcut)
            : CTag(shortcut.flags, shortcut.value)
        {
        }

        /**
         * Constructs an ASN.1 tag with the specified universal tag and constructed flag.
         * @param tag The universal tag.
         * @param constructed True if the tag is constructed, false otherwise.
         */
        CTag(EUniversalTags tag, bool constructed = false) 
            : CTag(constructed ? MASK_CON : 0, static_cast<uint32_t>(tag))
        {
            constexpr EUniversalTags RESERVED = EUniversalTags(15);
            const EUniversalTags Current = EUniversalTags(_value);

            if (Current >= EAUTAG_MAX || Current == RESERVED) {
                _flags = FLAG_INVALID;
            }
        }

        /**
         * Constructs an ASN.1 tag with the specified tag class, value, and constructed flag.
         * @param tagClass The class of the ASN.1 tag.
         * @param value The value of the ASN.1 tag.
         * @param constructed True if the tag is constructed, false otherwise.
         */
        CTag(ETagClass tagClass, uint32_t value, bool constructed = false)
            : CTag((uint8_t(tagClass) & MASK_CLS) | (constructed ? MASK_CON : 0), value)
        {
            switch (tagClass) {
                case EATAG_UNIVERSAL:
                case EATAG_APPLICATION:
                case EATAG_CONTEXT_SPECIFIC:
                case EATAG_PRIVATE:
                    break;
                    
                default:
                    _flags = FLAG_INVALID;
                    break;
            }
        }

        /**
         * Constructs a copy of the given ASN.1 tag.
         * @param other The ASN.1 tag to copy.
         */
        CTag(const CTag& other)
            : _flags(other._flags), _value(other._value)
        {
        }

        /**
         * Constructs an ASN.1 tag by moving the contents of another ASN.1 tag.
         * @param other The ASN.1 tag to move.
         */
        CTag(CTag&& other) noexcept
            : _flags(other._flags), _value(other._value)
        {
        }

        /**
         * Assigns the contents of another ASN.1 tag to this tag.
         * @param other The ASN.1 tag to assign from.
         * @return A reference to this ASN.1 tag.
         */
        inline CTag& operator=(const CTag& other) {
            if (this != &other) {
                _flags = other._flags;
                _value = other._value;
            }

            return *this;
        }

        /**
         * Assigns the contents of another ASN.1 tag to this tag using move semantics.
         * @param other The ASN.1 tag to move from.
         * @return A reference to this ASN.1 tag.
         */
        inline CTag& operator=(CTag&& other) noexcept {
            if (this != &other) {
                swap(_flags, other._flags);
                swap(_value, other._value);
            }

            return *this;
        }
        
    public:
        /**
         * Checks if the ASN.1 tag is valid.
         * @return True if the tag is valid, false otherwise.
         */
        inline bool isValid() const {
            return _flags != FLAG_INVALID;
        }

        /**
         * Checks if the ASN.1 tag is valid.
         * @return True if the tag is valid, false otherwise.
         */
        inline operator bool() const {
            return isValid();
        }

        /**
         * Checks if the ASN.1 tag is not valid.
         * @return True if the tag is not valid, false otherwise.
         */
        inline bool operator!() const {
            return !isValid();
        }

        /**
         * Returns the class of the ASN.1 tag.
         */
        inline ETagClass tagClass() const {
            if (_flags == FLAG_INVALID) {
                return EATAG_INVALID;
            }

            return static_cast<ETagClass>(_flags & MASK_CLS);
        }
        
        /**
         * Returns true if the ASN.1 tag is constructed.
         */
        inline bool isConstructed() const {
            return (_flags & MASK_CON) != 0;
        }

        /**
         * Returns the value of the ASN.1 tag.
         */
        inline uint32_t value() const {
            return _value;
        }

        /** 
         * Returns a copy of the ASN.1 tag marked as constructed.
         */
        inline CTag asConstructed() const {
            return CTag(tagClass(), value(), true);
        }

        /**
         * Returns a copy of the ASN.1 tag marked as primitive.
         */
        inline CTag asPrimitive() const {
            return CTag(tagClass(), value(), false);
        }

        /**
         * Tries to decode an ASN.1 tag from the given source span.
         *
         * @param source The source span containing the encoded ASN.1 tag.
         * @param bytesRead The number of bytes read from the source span.
         * @return The decoded ASN.1 tag.
         */
        static CTag decode(TReadOnlySpan<uint8_t> source, size_t& bytesRead);

        /**
         * Returns the size of the encoded ASN.1 tag.
         */
        inline size_t encodedSize() const {
            if (isValid() == false) {
                return 0;
            }

            constexpr uint32_t BITS_7 = (1u << 7) - 1;
            constexpr uint32_t BITS_14 = (1u << 14) - 1;
            constexpr uint32_t BITS_21 = (1u << 21) - 1;
            constexpr uint32_t BITS_28 = (1u << 28) - 1;

            if (_value < MASK_TAG) {
                return 1;
            } else if (_value <= BITS_7) {
                return 2;
            } else if (_value <= BITS_14) {
                return 3;
            } else if (_value <= BITS_21) {
                return 4;
            } else if (_value <= BITS_28) {
                return 5;
            }
            
            return 6;
        }

        /**
         * Encodes the ASN.1 tag into the given destination span.
         *
         * @param destination The destination span to write the encoded ASN.1 tag.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if the encoding was successful, false otherwise.
         */
        bool encode(TSpan<uint8_t> destination, size_t& bytesWritten) const;

        /**
         * Checks if this ASN.1 tag is equal to another ASN.1 tag.
         *
         * @param other The other ASN.1 tag to compare with.
         * @return True if the tags are equal, false otherwise.
         */
        inline bool equals(const CTag& other) const {
            if (isValid() == false) {
                if (other.isValid() == false) {
                    return true;
                }

                return false;
            }

            if (other.isValid() == false) {
                return false;
            }

            // --> Compare class+constructed only: _flags' low 5 bits are incidental encoding
            // detail (decode() stores the raw first octet, whose low bits carry the short-form
            // tag number or the 0x1F multi-byte escape marker; every constructor leaves them 0).
            return (_flags & MASK_CTL) == (other._flags & MASK_CTL) && _value == other._value;
        }

        /**
         * Checks if this ASN.1 tag is equal to another ASN.1 tag using the equality operator.
         *
         * @param other The other ASN.1 tag to compare with.
         * @return True if the tags are equal, false otherwise.
         */
        inline bool operator==(const CTag& other) const {
            return equals(other);
        }

        /**
         * Checks if this ASN.1 tag is not equal to another ASN.1 tag using the inequality operator.
         *
         * @param other The other ASN.1 tag to compare with.
         * @return True if the tags are not equal, false otherwise.
         */
        inline bool operator!=(const CTag& other) const {
            return !equals(other);
        }

        /**
         * Checks if this ASN.1 tag has the same class as another ASN.1 tag.
         *
         * @param other The other ASN.1 tag to compare with.
         * @return True if the tags have the same class, false otherwise.
         */
        inline bool hasSameClass(const CTag& other) const {
            return tagClass() == other.tagClass();
        }
        
        /**
         * Checks if this ASN.1 tag has the same value as another ASN.1 tag.
         *
         * @param other The other ASN.1 tag to compare with.
         * @return True if the tags have the same value, false otherwise.
         */
        inline bool hasSameValue(const CTag& other) const {
            return _value == other._value;
        }

        /**
         * Checks if this ASN.1 tag has the same class and value as another ASN.1 tag.
         *
         * @param other The other ASN.1 tag to compare with.
         * @return True if the tags have the same class and value, false otherwise.
         */
        inline bool hasSameClassAndValue(const CTag& other) const {
            return hasSameClass(other) && hasSameValue(other);
        }
    };
} // namespace asn1
} // namespace certpp

#endif
