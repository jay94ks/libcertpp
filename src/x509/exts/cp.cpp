#include <certpp/x509/exts/cp.hpp>
#include <certpp/asn1/reader.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/asn1/tag.hpp>

namespace certpp {
namespace x509 {

    using asn1::CReader;
    using asn1::CDecoder;
    using asn1::CDer;
    using asn1::CTag;
    using asn1::EAENC_DER;

    /* Parses a CertificatePolicies extension from its raw extnValue. */
    CPoliciesExtension::CPoliciesExtension(const COctet& value)
        : IExtension(OID, value)
    {
        // CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
        // PolicyInformation ::= SEQUENCE {
        //     policyIdentifier   CertPolicyId,
        //     policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
        CTag tag;
        SReadOnlyByteSpan content;
        SReadOnlyByteSpan cursor = value.toSpan();
        if (!CDecoder::readNextElement(cursor, EAENC_DER, tag, content) || tag != CTag::SEQ) {
            return;
        }

        SReadOnlyByteSpan listCursor = content;
        CTag piTag;
        SReadOnlyByteSpan piContent;
        while (CDecoder::readNextElement(listCursor, EAENC_DER, piTag, piContent)) {
            if (piTag != CTag::SEQ) {
                continue;
            }

            CReader piSeq(piContent, EAENC_DER);
            CString policyId;
            if (!piSeq.readOidString(policyId)) {
                continue;
            }

            COctet qualifiers;
            if (!piSeq.atEnd()) {
                CTag qTag;
                SReadOnlyByteSpan qContent;
                if (piSeq.readNextElement(qTag, qContent) && qTag == CTag::SEQ) {
                    qualifiers = COctet(qContent);
                }
            }

            _policies.add(CPolicyInformation(policyId, qualifiers));
        }
    }

    /* Encodes this extension, replaying its already-decoded value() bytes. */
    bool CPoliciesExtension::encode(CBuffer& out) const {
        return encodeValue(out);
    }

    /* Builds the CertificatePolicies extension. */
    IExtensionPtr CPoliciesExtensionBuilder::build() const {
        // CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
        CBuffer body;

        for (const CPolicyInformation& policy : _policies) {
            if (!policy.encode(body)) {
                return nullptr;
            }
        }

        CBuffer full;
        if (!CDer::appendSequence(full, body.toSpan())) {
            return nullptr;
        }

        COctet value(full.toSpan());
        return std::make_shared<CPoliciesExtension>(value);
    }

} // namespace x509
} // namespace certpp
