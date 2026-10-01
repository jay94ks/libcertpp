#include "ocspcodec.hpp"
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/der.hpp>

namespace certpp {
namespace x509 {

    using asn1::CReader;
    using asn1::CDecoder;
    using asn1::CEncoder;
    using asn1::CDer;
    using asn1::CTag;
    using asn1::EAENC_DER;

    /* Appends one Extension { extnID = oid, extnValue = extnValue } SEQUENCE OF Extension to out. */
    bool OcspCodec::appendSingleExtensionList(CBuffer& out, const char* oid, SReadOnlyByteSpan extnValue) {
        size_t needed = CEncoder::encodedOidStringSize(CString(oid));
        if (!needed) {
            return false;
        }

        CBuffer oidContent;
        size_t written = 0;
        if (!oidContent.resize(needed) || !CEncoder::encodeOidString(oidContent.toSpan(), CString(oid), written)) {
            return false;
        }

        CBuffer extBody;
        if (!CDer::appendTlv(extBody, CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), written))
            || !CDer::appendTlv(extBody, CTag::STRING_OCTET, extnValue))
        {
            return false;
        }

        CBuffer oneExtTlv;
        if (!CDer::appendSequence(oneExtTlv, extBody.toSpan())) {
            return false;
        }

        return CDer::appendSequence(out, oneExtTlv.toSpan());
    }

    /* Builds the Nonce extension's own extnValue (RFC 8954): an OCTET STRING wrapping nonce's raw
     * bytes. */
    bool OcspCodec::buildNonceExtnValue(SReadOnlyByteSpan nonce, CBuffer& out) {
        return CDer::appendTlv(out, CTag::STRING_OCTET, nonce);
    }

    /* Scans extList for the Nonce extension and, if found, unwraps its own double-OCTET-STRING
     * into outNonce. */
    void OcspCodec::scanForNonce(CReader& extList, COctet& outNonce) {
        while (!extList.atEnd()) {
            CReader extSeq;
            if (!extList.readSequence(extSeq)) {
                break;
            }

            CString extnOid;
            if (!extSeq.readOidString(extnOid)) {
                continue;
            }

            bool critical = false;
            extSeq.readBoolean(critical); // OPTIONAL DEFAULT FALSE -- not otherwise used

            COctet extnValue;
            if (!extSeq.readOctetString(extnValue)) {
                continue;
            }

            if (extnOid.compare(OID_NONCE) == 0) {
                SReadOnlyByteSpan cursor = extnValue.toSpan();
                CTag innerTag;
                SReadOnlyByteSpan innerContent;
                if (CDecoder::readNextElement(cursor, EAENC_DER, innerTag, innerContent) && innerTag == CTag::STRING_OCTET) {
                    outNonce = COctet(innerContent);
                } else {
                    outNonce = extnValue; // --> tolerate a non-double-wrapped nonce too
                }
            }
        }
    }

    /* Encodes time as a plain GeneralizedTime TLV -- see this method's own doc comment. */
    bool OcspCodec::encodeGeneralizedTime(const SDateTime& time, CBuffer& out) {
        size_t needed = CEncoder::encodedGeneralizedTimeSize(time);
        if (!needed) {
            return false;
        }

        CBuffer content;
        if (!content.resize(needed)) {
            return false;
        }

        size_t written = 0;
        if (!CEncoder::encodeGeneralizedTime(content.toSpan(), time, written)) {
            return false;
        }

        return CDer::appendTlv(out, CTag::TIME_GENERAL, SReadOnlyByteSpan(content.toPtr(), written));
    }

} // namespace x509
} // namespace certpp
