#ifndef __INCLUDE_CERTPP_X509_EXTS_EKU_HPP__
#define __INCLUDE_CERTPP_X509_EXTS_EKU_HPP__

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
        static constexpr const char* OID = "2.5.29.37"; // --> id-ce-extKeyUsage

        // --> Well-known KeyPurposeId OIDs (RFC 5280 4.2.1.12, RFC 6960).
        static constexpr const char* OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
        static constexpr const char* OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
        static constexpr const char* OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
        static constexpr const char* OID_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4";
        static constexpr const char* OID_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
        static constexpr const char* OID_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";
        static constexpr const char* OID_ANY_EXTENDED_KEY_USAGE = "2.5.29.37.0";

    private:
        TArray<CString> _purposes;

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
        inline const TArray<CString>& purposes() const { return _purposes; }

        /**
         * @brief Checks whether a specific KeyPurposeId OID is present.
         * @param purposeOid The dotted-decimal OID to look for (e.g. OID_SERVER_AUTH).
         * @return true if present.
         */
        bool has(const char* purposeOid) const;

        /* Encodes this extension, replaying its already-decoded value() bytes. */
        bool encode(CBuffer& out) const override;
    };

    /**
     * @brief Builds an ExtendedKeyUsage extension (see CEkuExtension).
     */
    class CERTPP_API CEkuExtensionBuilder : public IExtensionBuilder {
    private:
        TArray<CString> _purposes;

    public:
        /**
         * @brief Adds a KeyPurposeId OID (e.g. CEkuExtension::OID_SERVER_AUTH).
         * @param purposeOid The dotted-decimal OID to add.
         * @return A reference to this builder, for chaining.
         */
        inline CEkuExtensionBuilder& addPurpose(const CString& purposeOid) {
            _purposes.add(purposeOid);
            return *this;
        }

        /* Builds the ExtendedKeyUsage extension. */
        IExtensionPtr build() const override;
    };

} // namespace x509
} // namespace certpp

#endif
