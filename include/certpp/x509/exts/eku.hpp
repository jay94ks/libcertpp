#ifndef __INCLUDE_CERTPP_X509_EXTS_EKU_HPP__
#define __INCLUDE_CERTPP_X509_EXTS_EKU_HPP__

#include <certpp/oid.hpp>
#include <certpp/x509/ext.hpp>
#include <certpp/io/array.hpp>

namespace certpp {
namespace x509 {

    /**
     * @brief ExtKeyUsageSyntax (RFC 5280 4.2.1.12, OID 2.5.29.37): the specific purposes
     * (KeyPurposeId OIDs) this certificate's key may additionally be restricted to, beyond
     * KeyUsage's coarser bit flags.
     */
    class CERTPP_API CEkuExtension : public IExtension {
    public:
        static constexpr SKnownOid OID = COid::EXT_EXTENDED_KEY_USAGE; // --> id-ce-extKeyUsage

        // --> Well-known KeyPurposeId OIDs (RFC 5280 4.2.1.12, RFC 6960).
        static constexpr SKnownOid OID_SERVER_AUTH = COid::PURPOSE_SERVER_AUTH;
        static constexpr SKnownOid OID_CLIENT_AUTH = COid::PURPOSE_CLIENT_AUTH;
        static constexpr SKnownOid OID_CODE_SIGNING = COid::PURPOSE_CODE_SIGNING;
        static constexpr SKnownOid OID_EMAIL_PROTECTION = COid::PURPOSE_EMAIL_PROTECTION;
        static constexpr SKnownOid OID_TIME_STAMPING = COid::PURPOSE_TIME_STAMPING;
        static constexpr SKnownOid OID_OCSP_SIGNING = COid::PURPOSE_OCSP_SIGNING;
        static constexpr SKnownOid OID_ANY_EXTENDED_KEY_USAGE = COid::PURPOSE_ANY_EXTENDED_KEY_USAGE;

    private:
        TArray<COid> _purposes;

    public:
        /**
         * @brief Parses an ExtendedKeyUsage extension from its raw extnValue.
         * @param value The extension's raw extnValue bytes.
         */
        CEkuExtension(const COctet& value);

        /**
         * @brief The decoded KeyPurposeId OIDs, as dotted-decimal text. Empty if value didn't
         * decode as a SEQUENCE OF OBJECT IDENTIFIER.
         * @return The purposes.
         */
        inline const TArray<COid>& purposes() const { return _purposes; }

        /**
         * @brief Checks whether a specific KeyPurposeId OID is present.
         * @param purposeOid The dotted-decimal OID to look for (e.g. OID_SERVER_AUTH).
         * @return true if present.
         */
        bool has(const SKnownOid& purposeOid) const;

        /* Encodes this extension, replaying its already-decoded value() bytes. */
        bool encode(CBuffer& out) const override;
    };

    /**
     * @brief Builds an ExtendedKeyUsage extension (see CEkuExtension).
     */
    class CERTPP_API CEkuExtensionBuilder : public IExtensionBuilder {
    private:
        TArray<COid> _purposes;

    public:
        /**
         * @brief Adds a KeyPurposeId OID (e.g. CEkuExtension::OID_SERVER_AUTH).
         *
         * The SKnownOid form is the one to reach for: a KeyPurposeId this library names costs
         * nothing to add and cannot be misspelled.
         * @param purposeOid The KeyPurposeId OID to add.
         * @return A reference to this builder, for chaining.
         */
        inline CEkuExtensionBuilder& addPurpose(const SKnownOid& purposeOid) {
            _purposes.add(purposeOid);
            return *this;
        }

        /**
         * @brief Adds a KeyPurposeId OID given as dotted-decimal text.
         *
         * For a KeyPurposeId the library does not name -- an enterprise or vendor-specific one.
         * A string that is not a well-formed OID becomes an empty COid, which build() then
         * refuses, so a typo surfaces as a null from build() rather than as a certificate
         * carrying a KeyPurposeId of nothing.
         * @param purposeOid The dotted-decimal OID to add.
         * @return A reference to this builder, for chaining.
         */
        inline CEkuExtensionBuilder& addPurpose(const char* purposeOid) {
            _purposes.add(COid(purposeOid));
            return *this;
        }

        /* Builds the ExtendedKeyUsage extension. */
        IExtensionPtr build() const override;
    };

} // namespace x509
} // namespace certpp

#endif
