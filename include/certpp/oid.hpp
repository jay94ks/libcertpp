#ifndef __INCLUDE_CERTPP_OID_HPP__
#define __INCLUDE_CERTPP_OID_HPP__

#include <certpp/common.hpp>
#include <certpp/string.hpp>
#include <certpp/io/span.hpp>

#include <atomic>

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
        SRawOid() : count(0) {
            // --> Zero the rest so a memcmp against a shorter or zeroed OID is meaningful, and
            // so a slot that never had its arcs filled still compares as empty rather than as
            // whatever happened to be on the stack.
            std::memset(arcs, 0, sizeof(arcs));
        }

        /**
         * Initializes a new instance of the SRawOid structure by copying another instance.
         *
         * @param other The SRawOid instance to copy.
         */
        SRawOid(const SRawOid& other) : count(other.count) {
            std::memcpy(arcs, other.arcs, sizeof(arcs));
        }

        /**
         * Initializes a new instance of the SRawOid structure by moving another instance.
         *
         * @param other The SRawOid instance to move.
         */
        SRawOid(SRawOid&& other) noexcept : count(other.count) {
            std::memcpy(arcs, other.arcs, sizeof(arcs));
            other.count = 0;
            std::memset(other.arcs, 0, sizeof(other.arcs));
        }

        /**
         * Initializes a new instance of the SRawOid structure from a fixed-size array of arcs.
         *
         * @tparam N The number of arcs in the input array.
         * @param arcs The array of arcs to initialize the OID with.
         */
        template<size_t N>
        explicit SRawOid(const uint32_t (&arcs)[N]) : count((N > MAX_OID_ARCS) ? MAX_OID_ARCS : N) {
            std::memcpy(this->arcs, arcs, sizeof(uint32_t) * count);
        }

        /**
         * Copy assignment operator.
         *
         * @param other The SRawOid instance to copy.
         * @return A reference to the current instance after copying.
         */
        inline SRawOid& operator=(const SRawOid& other) {
            if (this != &other) {
                count = other.count;
                std::memcpy(arcs, other.arcs, sizeof(arcs));
            }

            return *this;
        }

        /**
         * Move assignment operator.
         *
         * @param other The SRawOid instance to move.
         * @return A reference to the current instance after moving.
         */
        inline SRawOid& operator=(SRawOid&& other) noexcept {
            if (this != &other) {
                count = other.count;
                std::memcpy(arcs, other.arcs, sizeof(arcs));

                other.count = 0;
                std::memset(other.arcs, 0, sizeof(other.arcs));
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
         * Parses a string representation of an OID into its binary form.
         *
         * @param out The output SRawOid structure to store the parsed OID.
         * @param str The string representation of the OID.
         * @return An ERetCode indicating success or failure of the parsing operation.
         */
        static ERetCode parse(SRawOid& out, const CWideString& str);

        /**
         * Converts the binary representation of the OID into its string form.
         *
         * @param out The output CString to store the string representation of the OID.
         */
        void toString(CString& out) const;

        /**
         * Converts the binary representation of the OID into its string form.
         *
         * @param out The output CWideString to store the string representation of the OID.
         */
        void toString(CWideString& out) const;

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
    struct CERTPP_API SKnownOid {
        uint32_t nth;      /**< The internal index of the known OID within the library. */
        const char* s;     /**< The string representation of the known OID, compiled into the library. */

        /**
         * Checks if the current known OID is equal to another known OID.
         *
         * @param other The SKnownOid instance to compare with.
         * @return true if the current known OID is equal to the other known OID, false otherwise.
         */
        bool equals(const SKnownOid& other) const;
    };

    /**
     * The library's known OIDs, in one place.
     *
     * Every OID this library names is listed here exactly once as `_(NAME, "dotted.decimal")`,
     * and this one list drives three things: the public `COid::NAME` constants, the size of
     * `COid::CACHED`, and -- through `SRawOid::parse()` in oid.cpp -- the arc table each of
     * them carries. Adding an OID means adding one line and nothing else.
     *
     * --> The macro is deliberately left defined after this header. oid.cpp needs it to define
     * the constants' storage, and there is no separate list file for it to read.
     *
     * --> The arc values are derived from the text rather than written out by hand. A table
     * that spells out both the string and the arcs has two chances to be wrong and no way to
     * notice, which is how the DN tables came to disagree with each other. The derivation
     * happens in parseKnownOid() in oid.cpp, which is constexpr, so every entry below is
     * fully evaluated at compile time and nothing runs when the library loads.
     */
#define CERTPP_KNOWN_OIDS(_) \
    _(  0, SHA1,                          "1.3.14.3.2.26") \
    _(  1, SHA224,                        "2.16.840.1.101.3.4.2.4") \
    _(  2, SHA256,                        "2.16.840.1.101.3.4.2.1") \
    _(  3, SHA384,                        "2.16.840.1.101.3.4.2.2") \
    _(  4, SHA512,                        "2.16.840.1.101.3.4.2.3") \
    _(  5, RSA,                           "1.2.840.113549.1.1.1") \
    _(  6, DSA,                           "1.2.840.10040.4.1") \
    _(  7, EC_PUBLIC_KEY,                 "1.2.840.10045.2.1") \
    _(  8, X25519,                        "1.3.101.110") \
    _(  9, ED25519,                       "1.3.101.112") \
    _( 10, ED448,                         "1.3.101.113") \
    _( 11, MLDSA44,                       "2.16.840.1.101.3.4.3.17") \
    _( 12, MLDSA65,                       "2.16.840.1.101.3.4.3.18") \
    _( 13, MLDSA87,                       "2.16.840.1.101.3.4.3.19") \
    _( 14, RSASSA_PSS,                    "1.2.840.113549.1.1.10") \
    _( 15, MGF1,                          "1.2.840.113549.1.1.8") \
    _( 16, MD5_RSA,                       "1.2.840.113549.1.1.4") \
    _( 17, SHA1_RSA,                      "1.2.840.113549.1.1.5") \
    _( 18, SHA224_RSA,                    "1.2.840.113549.1.1.14") \
    _( 19, SHA256_RSA,                    "1.2.840.113549.1.1.11") \
    _( 20, SHA384_RSA,                    "1.2.840.113549.1.1.12") \
    _( 21, SHA512_RSA,                    "1.2.840.113549.1.1.13") \
    _( 22, SHA1_DSA,                      "1.2.840.10040.4.3") \
    _( 23, SHA224_DSA,                    "2.16.840.1.101.3.4.3.1") \
    _( 24, SHA256_DSA,                    "2.16.840.1.101.3.4.3.2") \
    _( 25, SHA1_ECDSA,                    "1.2.840.10045.4.1") \
    _( 26, SHA224_ECDSA,                  "1.2.840.10045.4.3.1") \
    _( 27, SHA256_ECDSA,                  "1.2.840.10045.4.3.2") \
    _( 28, SHA384_ECDSA,                  "1.2.840.10045.4.3.3") \
    _( 29, SHA512_ECDSA,                  "1.2.840.10045.4.3.4") \
    _( 30, CURVE_P192,                    "1.2.840.10045.3.1.1") \
    _( 31, CURVE_P224,                    "1.3.132.0.33") \
    _( 32, CURVE_P256,                    "1.2.840.10045.3.1.7") \
    _( 33, CURVE_P384,                    "1.3.132.0.34") \
    _( 34, CURVE_P521,                    "1.3.132.0.35") \
    _( 35, CURVE_SECP256K1,               "1.3.132.0.10") \
    _( 36, CURVE_BRAINPOOL_P160R1,        "1.3.36.3.3.2.8.1.1.1") \
    _( 37, CURVE_BRAINPOOL_P160T1,        "1.3.36.3.3.2.8.1.1.2") \
    _( 38, CURVE_BRAINPOOL_P192R1,        "1.3.36.3.3.2.8.1.1.3") \
    _( 39, CURVE_BRAINPOOL_P192T1,        "1.3.36.3.3.2.8.1.1.4") \
    _( 40, CURVE_BRAINPOOL_P224R1,        "1.3.36.3.3.2.8.1.1.5") \
    _( 41, CURVE_BRAINPOOL_P224T1,        "1.3.36.3.3.2.8.1.1.6") \
    _( 42, CURVE_BRAINPOOL_P256R1,        "1.3.36.3.3.2.8.1.1.7") \
    _( 43, CURVE_BRAINPOOL_P256T1,        "1.3.36.3.3.2.8.1.1.8") \
    _( 44, CURVE_BRAINPOOL_P320R1,        "1.3.36.3.3.2.8.1.1.9") \
    _( 45, CURVE_BRAINPOOL_P320T1,        "1.3.36.3.3.2.8.1.1.10") \
    _( 46, CURVE_BRAINPOOL_P384R1,        "1.3.36.3.3.2.8.1.1.11") \
    _( 47, CURVE_BRAINPOOL_P384T1,        "1.3.36.3.3.2.8.1.1.12") \
    _( 48, CURVE_BRAINPOOL_P512R1,        "1.3.36.3.3.2.8.1.1.13") \
    _( 49, CURVE_BRAINPOOL_P512T1,        "1.3.36.3.3.2.8.1.1.14") \
    _( 50, CURVE_K163,                    "1.3.132.0.1") \
    _( 51, CURVE_B163,                    "1.3.132.0.15") \
    _( 52, CURVE_K233,                    "1.3.132.0.26") \
    _( 53, CURVE_B233,                    "1.3.132.0.27") \
    _( 54, CURVE_K283,                    "1.3.132.0.16") \
    _( 55, CURVE_B283,                    "1.3.132.0.17") \
    _( 56, CURVE_K409,                    "1.3.132.0.36") \
    _( 57, CURVE_B409,                    "1.3.132.0.37") \
    _( 58, CURVE_K571,                    "1.3.132.0.38") \
    _( 59, CURVE_B571,                    "1.3.132.0.39") \
    _( 60, EXT_BASIC_CONSTRAINTS,         "2.5.29.19") \
    _( 61, EXT_KEY_USAGE,                 "2.5.29.15") \
    _( 62, EXT_EXTENDED_KEY_USAGE,        "2.5.29.37") \
    _( 63, EXT_SUBJECT_ALT_NAME,          "2.5.29.17") \
    _( 64, EXT_SUBJECT_KEY_IDENTIFIER,    "2.5.29.14") \
    _( 65, EXT_AUTHORITY_KEY_IDENTIFIER,  "2.5.29.35") \
    _( 66, EXT_CRL_DISTRIBUTION_POINTS,   "2.5.29.31") \
    _( 67, EXT_CERTIFICATE_POLICIES,      "2.5.29.32") \
    _( 68, EXT_AUTHORITY_INFO_ACCESS,     "1.3.6.1.5.5.7.1.1") \
    _( 69, EXT_NAME_CONSTRAINTS,          "2.5.29.30") \
    _( 70, EXT_CRL_REASON_CODE,           "2.5.29.21") \
    _( 71, ANY_POLICY,                    "2.5.29.32.0") \
    _( 72, EXT_EXTENSION_REQUEST,         "1.2.840.113549.1.9.14") \
    _( 73, METHOD_OCSP,                   "1.3.6.1.5.5.7.48.1") \
    _( 74, METHOD_CA_ISSUERS,             "1.3.6.1.5.5.7.48.2") \
    _( 75, PURPOSE_SERVER_AUTH,           "1.3.6.1.5.5.7.3.1") \
    _( 76, PURPOSE_CLIENT_AUTH,           "1.3.6.1.5.5.7.3.2") \
    _( 77, PURPOSE_CODE_SIGNING,          "1.3.6.1.5.5.7.3.3") \
    _( 78, PURPOSE_EMAIL_PROTECTION,      "1.3.6.1.5.5.7.3.4") \
    _( 79, PURPOSE_TIME_STAMPING,         "1.3.6.1.5.5.7.3.8") \
    _( 80, PURPOSE_OCSP_SIGNING,          "1.3.6.1.5.5.7.3.9") \
    _( 81, PURPOSE_ANY_EXTENDED_KEY_USAGE, "2.5.29.37.0") \
    _( 82, OCSP_BASIC_RESPONSE,           "1.3.6.1.5.5.7.48.1.1") \
    _( 83, OCSP_NONCE,                    "1.3.6.1.5.5.7.48.1.2") \
    _( 84, PKCS7_DATA,                    "1.2.840.113549.1.7.1") \
    _( 85, PKCS7_ENCRYPTED_DATA,          "1.2.840.113549.1.7.6") \
    _( 86, KEY_BAG,                       "1.2.840.113549.1.12.10.1.1") \
    _( 87, SHROUDED_KEY_BAG,              "1.2.840.113549.1.12.10.1.2") \
    _( 88, CERT_BAG,                      "1.2.840.113549.1.12.10.1.3") \
    _( 89, X509_CERTIFICATE,              "1.2.840.113549.1.9.22.1") \
    _( 90, FRIENDLY_NAME,                 "1.2.840.113549.1.9.20") \
    _( 91, LOCAL_KEY_ID,                  "1.2.840.113549.1.9.21") \
    _( 92, PBES2,                         "1.2.840.113549.1.5.13") \
    _( 93, PBKDF2,                        "1.2.840.113549.1.5.12") \
    _( 94, AES128_CBC,                    "2.16.840.1.101.3.4.1.2") \
    _( 95, AES192_CBC,                    "2.16.840.1.101.3.4.1.22") \
    _( 96, AES256_CBC,                    "2.16.840.1.101.3.4.1.42") \
    _( 97, HMAC_SHA1,                     "1.2.840.113549.2.7") \
    _( 98, HMAC_SHA224,                   "1.2.840.113549.2.8") \
    _( 99, HMAC_SHA256,                   "1.2.840.113549.2.9") \
    _(100, HMAC_SHA384,                   "1.2.840.113549.2.10") \
    _(101, HMAC_SHA512,                   "1.2.840.113549.2.11") \
    _(102, CHALLENGE_PASSWORD,            "1.2.840.113549.1.9.7") \
    _(103, UNSTRUCTURED_NAME,             "1.2.840.113549.1.9.2") \
    _(104, DN_COMMON_NAME,                "2.5.4.3") \
    _(105, DN_SURNAME,                    "2.5.4.4") \
    _(106, DN_SERIAL_NUMBER,              "2.5.4.5") \
    _(107, DN_COUNTRY_NAME,               "2.5.4.6") \
    _(108, DN_LOCALITY_NAME,              "2.5.4.7") \
    _(109, DN_STATE_OR_PROVINCE_NAME,     "2.5.4.8") \
    _(110, DN_ORGANIZATION_NAME,          "2.5.4.10") \
    _(111, DN_ORGANIZATIONAL_UNIT_NAME,   "2.5.4.11") \
    _(112, DN_TITLE,                      "2.5.4.12") \
    _(113, DN_GIVEN_NAME,                 "2.5.4.42") \
    _(114, DN_DN_QUALIFIER,               "2.5.4.46") \
    _(115, DN_PSEUDONYM,                  "2.5.4.65") \
    _(116, DN_ORGANIZATION_IDENTIFIER,    "2.5.4.97") \
    _(117, DN_DOMAIN_COMPONENT,           "0.9.2342.19200300.100.1.25")

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
        /* --> static constexpr, which in C++17 makes each of these implicitly inline: the
         * header declaration is the definition, and there is no out-of-line storage to keep
         * in step in a second file. The value is a constant expression, so it lands in the
         * binary's read-only data and costs nothing when the library loads.
         *
         * --> No arcs are stored here and nothing is parsed at compile time. A SKnownOid is
         * an index and a string; the arcs are derived by SRawOid::parse() when a COid is
         * actually built from one, in cacheFor(). Storing them as well would make the string
         * and the arcs two spellings of the same fact that can disagree -- which is how the
         * DN tables came to carry a domainComponent of 10 arcs where the OID has 7 -- and it
         * would need a second parser here instead of reusing the one every caller's OID
         * string already goes through.
         *
         * --> The index is spelled out in the list above rather than counted by a macro.
         * Counting it makes the value correct but invisible: an entry inserted in the middle
         * silently renumbers everything after it, and the only way to notice is to read the
         * macro argument of every entry. Spelled out, the index is on the line it belongs to,
         * and tests/oid.cpp checks each one against its position in the list. */

#define CERTPP_DECLARE_KNOWN_OID(Index, Name, Text) static constexpr SKnownOid Name { Index, Text };
        CERTPP_KNOWN_OIDS(CERTPP_DECLARE_KNOWN_OID)
#undef CERTPP_DECLARE_KNOWN_OID

        /** How many known OIDs there are, counted off the same list that declares them. */
#define CERTPP_COUNT_KNOWN_OID(Index, Name, Text) + 1u
        static constexpr size_t MAX_KNOWN_OID_COUNT = 0 CERTPP_KNOWN_OIDS(CERTPP_COUNT_KNOWN_OID);
#undef CERTPP_COUNT_KNOWN_OID

    private:
        /**
         * A cached Slot for each known OID, built on first use.
         *
         * --> Atomic pointers rather than an array of shared_ptr, because the cache is filled
         * at run time and the fill has to be safe to race on: every thread that asks for the
         * same known OID must end up with the same Slot, or the pointer short-circuit in
         * compare() would start depending on which thread happened to get there first. A
         * compare-exchange in cacheFor() gives that, with no lock on the read path.
         *
         * --> Built on demand rather than up front so that nothing about OID handling is on
         * the library's load path. A program that never names a known OID pays nothing.
         */
        static std::atomic<Slot*> CACHED[MAX_KNOWN_OID_COUNT];

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
         * A malformed string yields an empty COid, exactly as the assignment operator does.
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
         * --> A malformed string empties this instance rather than leaving it holding the
         * previous OID. A silent no-op would let a caller that checked nothing keep using an
         * OID it had just tried to replace, which is indistinguishable from success at the
         * call site.
         *
         * @param str The string representation of the OID to assign from.
         * @return A reference to the current COid instance.
         */
        inline COid& operator=(const CString& str) {
            std::shared_ptr<Slot> s = std::make_shared<Slot>();

            // --> parse the string into the raw binary representation
            if (SRawOid::parse(s->raw, str) == ERET_OK) {
                s->str = str;
                _slot = s;
            } else {
                _slot.reset();
            }

            return *this;
        }

        /**
         * Constructs a COid instance from a NUL-terminated OID string.
         *
         * @param str The NUL-terminated OID string.
         */
        COid(const char* str);

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
         * Assignment operator for a NUL-terminated OID string.
         *
         * Exists so `oid = "2.5.29.19";` keeps working the way it reads. A malformed string
         * empties this instance rather than leaving it holding the previous OID -- see
         * operator=(const CString&).
         *
         * @param str The NUL-terminated OID string to assign from.
         * @return A reference to the current COid instance.
         */
        inline COid& operator=(const char* str) {
            return *this = CString(str);
        }

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
                _slot = std::move(other._slot);
                other._slot.reset();
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
         * @return true if the current instance is equal to the other instance, false otherwise.
         */
        inline bool equals(const COid& other) const {
            return compare(other) == 0;
        }

        /**
         * Checks if the current COid instance is equal to another COid instance.
         *
         * @param other The COid instance to compare with.
         * @return true if the current instance is equal to the other instance, false otherwise.
         */
        inline bool operator==(const COid& other) const {
            return equals(other);
        }

        /**
         * Checks if the current COid instance is not equal to another COid instance.
         *
         * @param other The COid instance to compare with.
         * @return true if the current instance is not equal to the other instance, false otherwise.
         */
        inline bool operator!=(const COid& other) const {
            return !equals(other);
        }

        /**
         * Checks if the current COid instance is less than another COid instance.
         *
         * @param other The COid instance to compare with.
         * @return true if the current instance is less than the other instance, false otherwise.
         */
        inline bool operator<(const COid& other) const {
            return compare(other) < 0;
        }

        /**
         * Checks if the current COid instance is less than or equal to another COid instance.
         *
         * @param other The COid instance to compare with.
         * @return true if the current instance is less than or equal to the other instance, false otherwise.
         */
        inline bool operator<=(const COid& other) const {
            return compare(other) <= 0;
        }

        /**
         * Checks if the current COid instance is greater than another COid instance.
         *
         * @param other The COid instance to compare with.
         * @return true if the current instance is greater than the other instance, false otherwise.
         */
        inline bool operator>(const COid& other) const {
            return compare(other) > 0;
        }

        /**
         * Checks if the current COid instance is greater than or equal to another COid instance.
         *
         * @param other The COid instance to compare with.
         * @return true if the current instance is greater than or equal to the other instance, false otherwise.
         */
        inline bool operator>=(const COid& other) const {
            return compare(other) >= 0;
        }

        /**
         * Returns the binary representation of the OID, which is empty when this instance
         * holds no OID at all.
         *
         * @return A reference to the raw OID held by this instance.
         */
        inline const SRawOid& raw() const {
            static const SRawOid EMPTY;
            return _slot ? _slot->raw : EMPTY;
        }

        /**
         * Returns the string representation of the OID, decoding it from the binary form
         * when it was built from one.
         *
         * @param out The output string to store the string representation of the OID.
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
