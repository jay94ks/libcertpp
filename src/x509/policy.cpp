#include <certpp/x509/policy.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/asn1/tag.hpp>

namespace certpp {
namespace x509 {

    using asn1::CEncoder;
    using asn1::CDer;
    using asn1::CTag;

    /* Encodes this PolicyInformation as its own SEQUENCE tag-length-value. */
    bool CPolicyInformation::encode(CBuffer& out) const {
        // PolicyInformation ::= SEQUENCE {
        //     policyIdentifier   CertPolicyId,
        //     policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
        size_t needed = CEncoder::encodedOidSize(_policyIdentifier.raw());
        if (!needed) {
            return false;
        }

        CBuffer oidContent;
        if (!oidContent.resize(needed)) {
            return false;
        }

        size_t written = 0;
        if (!CEncoder::encodeOid(oidContent.toSpan(), _policyIdentifier.raw(), written)) {
            return false;
        }

        CBuffer body;
        if (!CDer::appendTlv(body, CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), written))) {
            return false;
        }

        if (!_qualifiersRaw.empty() && !CDer::appendSequence(body, _qualifiersRaw.toSpan())) {
            return false;
        }

        return CDer::appendSequence(out, body.toSpan());
    }

} // namespace x509
} // namespace certpp
