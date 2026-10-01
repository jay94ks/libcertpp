#include <certpp/x509/exts/cdp.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/asn1/tag.hpp>

namespace certpp {
namespace x509 {

    using asn1::CDecoder;
    using asn1::CDer;
    using asn1::CTag;
    using asn1::EAENC_DER;

    /* Parses a CRLDistributionPoints extension from its raw extnValue. */
    CCdpExtension::CCdpExtension(const COctet& value)
        : IExtension(OID, value)
    {
        // CRLDistPointSyntax ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
        CTag tag;
        SReadOnlyByteSpan content;
        SReadOnlyByteSpan cursor = value.toSpan();
        if (!CDecoder::readNextElement(cursor, EAENC_DER, tag, content) || tag != CTag::SEQ) {
            return;
        }

        SReadOnlyByteSpan listCursor = content;
        CTag pointTag;
        SReadOnlyByteSpan pointContent;
        while (CDecoder::readNextElement(listCursor, EAENC_DER, pointTag, pointContent)) {
            if (pointTag != CTag::SEQ) {
                continue;
            }

            CDistributionPoint point;
            if (CDistributionPoint::decode(pointContent, point)) {
                _points.add(point);
            }
        }
    }

    /* Encodes this extension, replaying its already-decoded value() bytes. */
    bool CCdpExtension::encode(CBuffer& out) const {
        return encodeValue(out);
    }

    /* Builds the CRLDistributionPoints extension. */
    IExtensionPtr CCdpExtensionBuilder::build() const {
        // CRLDistPointSyntax ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
        CBuffer body;

        for (const CDistributionPoint& point : _points) {
            if (!point.encode(body)) {
                return nullptr;
            }
        }

        CBuffer full;
        if (!CDer::appendSequence(full, body.toSpan())) {
            return nullptr;
        }

        COctet value(full.toSpan());
        return std::make_shared<CCdpExtension>(value);
    }

}
}
