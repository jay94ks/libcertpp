#include <certpp/x509/exts/aia.hpp>
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
    using asn1::EATAG_CONTEXT_SPECIFIC;

    /* Parses an AuthorityInformationAccess extension from its raw extnValue. */
    CAiaExtension::CAiaExtension(const COctet& value)
        : IExtension(OID, value)
    {
        // AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
        // AccessDescription ::= SEQUENCE { accessMethod OBJECT IDENTIFIER,
        //                                   accessLocation GeneralName }
        CTag tag;
        SReadOnlyByteSpan content;
        SReadOnlyByteSpan cursor = value.toSpan();
        if (!CDecoder::readNextElement(cursor, EAENC_DER, tag, content) || tag != CTag::SEQ) {
            return;
        }

        SReadOnlyByteSpan listCursor = content;
        CTag adTag;
        SReadOnlyByteSpan adContent;
        while (CDecoder::readNextElement(listCursor, EAENC_DER, adTag, adContent)) {
            if (adTag != CTag::SEQ) {
                continue;
            }

            CReader adSeq(adContent, EAENC_DER);

            // --> As a COid: CAccessDescription holds one, and reading it as text only to have
            // it parsed back at the constructor call would round-trip the OID for nothing.
            SRawOid rawMethod;
            if (!adSeq.readOid(rawMethod)) {
                continue;
            }

            const COid method(rawMethod);

            CTag locTag;
            SReadOnlyByteSpan locContent;
            if (!adSeq.readNextElement(locTag, locContent) || locTag.tagClass() != EATAG_CONTEXT_SPECIFIC) {
                continue;
            }

            CGeneralName location;
            if (!CGeneralName::decode(locContent, locTag.value(), locTag.isConstructed(), location)) {
                continue;
            }

            _descriptions.add(CAccessDescription(method, location));
        }
    }

    /* Encodes this extension, replaying its already-decoded value() bytes. */
    bool CAiaExtension::encode(CBuffer& out) const {
        return encodeValue(out);
    }

    /* Builds the AuthorityInformationAccess extension. */
    IExtensionPtr CAiaExtensionBuilder::build() const {
        // AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
        CBuffer body;

        for (const CAccessDescription& description : _descriptions) {
            if (!description.encode(body)) {
                return nullptr;
            }
        }

        CBuffer full;
        if (!CDer::appendSequence(full, body.toSpan())) {
            return nullptr;
        }

        COctet value(full.toSpan());
        return std::make_shared<CAiaExtension>(value);
    }

} // namespace x509
} // namespace certpp
