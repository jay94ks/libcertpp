#include <certpp/x509/exts/san.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/asn1/tag.hpp>

namespace certpp {
namespace x509 {

    using asn1::CDecoder;
    using asn1::CDer;
    using asn1::CTag;
    using asn1::EAENC_DER;

    /* Parses a SubjectAltName extension from its raw extnValue. */
    CSanExtension::CSanExtension(const COctet& value)
        : IExtension(OID, value)
    {
        // SubjectAltName ::= GeneralNames (SEQUENCE OF GeneralName)
        CTag tag;
        SReadOnlyByteSpan content;
        SReadOnlyByteSpan cursor = value.toSpan();
        if (CDecoder::readNextElement(cursor, EAENC_DER, tag, content) && tag == CTag::SEQ) {
            CGeneralName::decodeList(content, _names);
        }
    }

    /* Encodes this extension, replaying its already-decoded value() bytes. */
    bool CSanExtension::encode(CBuffer& out) const {
        return encodeValue(out);
    }

    /* Builds the SubjectAltName extension. */
    IExtensionPtr CSanExtensionBuilder::build() const {
        // SubjectAltName ::= GeneralNames (SEQUENCE OF GeneralName)
        CBuffer content;
        if (!CGeneralName::encodeList(_names, content)) {
            return nullptr;
        }

        CBuffer full;
        if (!CDer::appendSequence(full, content.toSpan())) {
            return nullptr;
        }

        COctet value(full.toSpan());
        return std::make_shared<CSanExtension>(value);
    }

}
}
