#ifndef __INCLUDE_CERTPP_X509_EXTS_AIA_HPP__
#define __INCLUDE_CERTPP_X509_EXTS_AIA_HPP__

#include <certpp/x509/ext.hpp>
#include <certpp/x509/access.hpp>

namespace certpp {
namespace x509 {

    /**
     * @brief AuthorityInformationAccess (RFC 5280 4.2.2.1, OID 1.3.6.1.5.5.7.1.1): how to reach
     * services related to the issuing CA -- most commonly an OCSP responder
     * (OID_OCSP_METHOD) and/or a URL to fetch the issuing CA's own certificate
     * (OID_CA_ISSUERS_METHOD).
     */
    class CERTPP_API CAiaExtension : public IExtension {
    public:
        static constexpr SKnownOid OID = COid::EXT_AUTHORITY_INFO_ACCESS; // --> id-pe-authorityInfoAccess
        static constexpr SKnownOid OID_OCSP_METHOD = COid::METHOD_OCSP;       // --> id-ad-ocsp
        static constexpr SKnownOid OID_CA_ISSUERS_METHOD = COid::METHOD_CA_ISSUERS; // --> id-ad-caIssuers

    private:
        TArray<CAccessDescription> _descriptions;

    public:
        /**
         * @brief Parses an AuthorityInformationAccess extension from its raw extnValue.
         * @param value The extension's raw extnValue bytes.
         */
        CAiaExtension(const COctet& value);

        /**
         * @brief The decoded access descriptions. Empty if value didn't decode as a SEQUENCE OF
         * AccessDescription.
         * @return The access descriptions.
         */
        inline const TArray<CAccessDescription>& descriptions() const { return _descriptions; }

        /* Encodes this extension, replaying its already-decoded value() bytes. */
        bool encode(CBuffer& out) const override;
    };

    /**
     * @brief Builds an AuthorityInformationAccess extension (see CAiaExtension).
     */
    class CERTPP_API CAiaExtensionBuilder : public IExtensionBuilder {
    private:
        TArray<CAccessDescription> _descriptions;

    public:
        /**
         * @brief Adds an access description.
         * @param description The access description to add.
         * @return A reference to this builder, for chaining.
         */
        inline CAiaExtensionBuilder& addDescription(const CAccessDescription& description) {
            _descriptions.add(description);
            return *this;
        }

        /* Builds the AuthorityInformationAccess extension. */
        IExtensionPtr build() const override;
    };

} // namespace x509
} // namespace certpp

#endif
