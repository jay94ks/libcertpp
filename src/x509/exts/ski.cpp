#include <certpp/x509/exts/ski.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/asn1/tag.hpp>

namespace certpp {
namespace x509 {

    using asn1::CDecoder;
    using asn1::CDer;
    using asn1::CTag;
    using asn1::EAENC_DER;

    /* Parses a SubjectKeyIdentifier extension from its raw extnValue. */
    CSkiExtension::CSkiExtension(const COctet& value)
        : IExtension(OID, value)
    {
        // SubjectKeyIdentifier ::= KeyIdentifier (OCTET STRING)
        CTag tag;
        SReadOnlyByteSpan content;
        SReadOnlyByteSpan cursor = value.toSpan();
        if (CDecoder::readNextElement(cursor, EAENC_DER, tag, content) && tag == CTag::STRING_OCTET) {
            _keyIdentifier = COctet(content);
        }
    }

    /* Encodes this extension, replaying its already-decoded value() bytes. */
    bool CSkiExtension::encode(CBuffer& out) const {
        return encodeValue(out);
    }

    /* Builds the SubjectKeyIdentifier extension. */
    IExtensionPtr CSkiExtensionBuilder::build() const {
        // SubjectKeyIdentifier ::= KeyIdentifier (OCTET STRING)
        CBuffer full;
        if (!CDer::appendTlv(full, CTag::STRING_OCTET, _keyIdentifier.toSpan())) {
            return nullptr;
        }

        COctet value(full.toSpan());
        return std::make_shared<CSkiExtension>(value);
    }

}
}
