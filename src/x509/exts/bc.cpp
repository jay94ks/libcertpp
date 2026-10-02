#include <certpp/x509/exts/bc.hpp>
#include <certpp/asn1/reader.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/der.hpp>

namespace certpp {
namespace x509 {

    using asn1::CReader;
    using asn1::CEncoder;
    using asn1::CDer;
    using asn1::CTag;
    using asn1::EAENC_DER;

    /* Parses a BasicConstraints extension from its raw extnValue. */
    CBasicConstraintsExtension::CBasicConstraintsExtension(const COctet& value)
        : IExtension(OID, value)
    {
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
        //                                 pathLenConstraint INTEGER OPTIONAL }
        CReader wrapper(value.toSpan(), EAENC_DER);
        CReader seq;
        if (!wrapper.readSequence(seq)) {
            return;
        }

        seq.readBoolean(_isCa); // OPTIONAL DEFAULT FALSE -- absent leaves _isCa false

        int64_t pathLen = 0;
        if (seq.readInteger(pathLen) && pathLen >= 0) {
            // --> pathLenConstraint is INTEGER (0..MAX) (RFC 5280 4.2.1.9), so a negative value
            // is malformed, not a constraint of -1. A path-length check written as
            // `depth <= pathLenConstraint()` against a negative value would reject everything,
            // but one written as a decrementing counter could just as easily wrap -- better to
            // leave hasPathLenConstraint() false and let the caller treat it as absent.
            _hasPathLenConstraint = true;
            _pathLenConstraint = pathLen;
        }
    }

    /* Encodes this extension, replaying its already-decoded value() bytes. */
    bool CBasicConstraintsExtension::encode(CBuffer& out) const {
        return encodeValue(out);
    }

    /* Builds the BasicConstraints extension. */
    IExtensionPtr CBasicConstraintsExtensionBuilder::build() const {
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
        //                                 pathLenConstraint INTEGER OPTIONAL }
        CBuffer body;

        if (_isCa) {
            uint8_t boolContent = 0;
            size_t written = 0;
            if (!CEncoder::encodeBoolean(SByteSpan(&boolContent, 1), true, written)
                || !CDer::appendTlv(body, CTag::BOOLEAN, SReadOnlyByteSpan(&boolContent, written)))
            {
                return nullptr;
            }
        }

        if (_hasPathLenConstraint) {
            uint8_t buf[9];
            size_t written = 0;
            if (!CEncoder::encodeInteger(SByteSpan(buf, sizeof(buf)), _pathLenConstraint, written)
                || !CDer::appendTlv(body, CTag::INTEGER, SReadOnlyByteSpan(buf, written)))
            {
                return nullptr;
            }
        }

        CBuffer full;
        if (!CDer::appendSequence(full, body.toSpan())) {
            return nullptr;
        }

        COctet value(full.toSpan());
        return std::make_shared<CBasicConstraintsExtension>(value);
    }

}
}
