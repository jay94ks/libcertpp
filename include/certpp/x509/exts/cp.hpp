#ifndef __INCLUDE_CERTPP_X509_EXTS_CP_HPP__
#define __INCLUDE_CERTPP_X509_EXTS_CP_HPP__

#include <certpp/x509/ext.hpp>
#include <certpp/x509/policy.hpp>
#include <certpp/io/array.hpp>

namespace certpp {
namespace x509 {

    /**
     * @brief CertificatePolicies (RFC 5280 4.2.1.4, OID 2.5.29.32): the policies this
     * certificate was issued under (e.g. domain-validated vs. extended-validation).
     */
    class CERTPP_API CPoliciesExtension : public IExtension {
    public:
        static constexpr SKnownOid OID = COid::EXT_CERTIFICATE_POLICIES;              // --> id-ce-certificatePolicies
        static constexpr SKnownOid OID_ANY_POLICY = COid::ANY_POLICY; // --> anyPolicy

    private:
        TArray<CPolicyInformation> _policies;

    public:
        /**
         * @brief Parses a CertificatePolicies extension from its raw extnValue.
         * @param value The extension's raw extnValue bytes.
         */
        CPoliciesExtension(const COctet& value);

        /**
         * @brief The decoded policies. Empty if value didn't decode as a SEQUENCE OF
         * PolicyInformation.
         * @return The policies.
         */
        inline const TArray<CPolicyInformation>& policies() const { return _policies; }

        /* Encodes this extension, replaying its already-decoded value() bytes. */
        bool encode(CBuffer& out) const override;
    };

    /**
     * @brief Builds a CertificatePolicies extension (see CPoliciesExtension).
     */
    class CERTPP_API CPoliciesExtensionBuilder : public IExtensionBuilder {
    private:
        TArray<CPolicyInformation> _policies;

    public:
        /**
         * @brief Adds a policy.
         * @param policy The policy to add.
         * @return A reference to this builder, for chaining.
         */
        inline CPoliciesExtensionBuilder& addPolicy(const CPolicyInformation& policy) {
            _policies.add(policy);
            return *this;
        }

        /* Builds the CertificatePolicies extension. */
        IExtensionPtr build() const override;
    };

} // namespace x509
} // namespace certpp

#endif
