#ifndef __INCLUDE_CERTPP_X509_POLICY_HPP__
#define __INCLUDE_CERTPP_X509_POLICY_HPP__

#include <certpp/common.hpp>
#include <certpp/string.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/buffer.hpp>

namespace certpp {
namespace x509 {

    /**
     * @brief One PolicyInformation (RFC 5280 4.2.1.4): a certificate policy this certificate
     * was issued under. policyQualifiersRaw() is kept raw (rather than modeling
     * PolicyQualifierInfo's CPSuri/UserNotice CHOICE in full) since callers overwhelmingly only
     * need policyIdentifier() itself (e.g. to check for a specific CA/Browser Forum policy OID).
     */
    class CERTPP_API CPolicyInformation {
    private:
        CString _policyIdentifier;
        COctet _qualifiersRaw;

    public:
        /**
         * @brief Constructs an empty PolicyInformation.
         */
        CPolicyInformation() = default;

        /**
         * @brief Constructs a PolicyInformation from its decoded fields.
         * @param policyIdentifier The policy OID's dotted-decimal text.
         * @param qualifiersRaw The policyQualifiers SEQUENCE's raw content, if present.
         */
        CPolicyInformation(const CString& policyIdentifier, const COctet& qualifiersRaw)
            : _policyIdentifier(policyIdentifier), _qualifiersRaw(qualifiersRaw)
        {
        }

        /**
         * @brief The policy OID's dotted-decimal text (e.g.
         * CPoliciesExtension::OID_ANY_POLICY).
         * @return The policy identifier.
         */
        inline const CString& policyIdentifier() const { return _policyIdentifier; }

        /**
         * @brief Whether policyQualifiersRaw() is present.
         * @return true if present.
         */
        inline bool hasPolicyQualifiers() const { return !_qualifiersRaw.empty(); }

        /**
         * @brief The policyQualifiers SEQUENCE's raw, still-DER-encoded content (a SEQUENCE OF
         * PolicyQualifierInfo). Empty if absent.
         * @return The raw policy qualifiers.
         */
        inline const COctet& policyQualifiersRaw() const { return _qualifiersRaw; }

        /**
         * @brief Encodes this PolicyInformation as its own SEQUENCE tag-length-value, appending
         * it to out.
         * @param out The destination array; the encoded TLV is appended to whatever it already holds.
         * @return true on success; false if policyIdentifier() isn't a well-formed dotted-decimal OID.
         */
        bool encode(CBuffer& out) const;
    };

}
}

#endif
