#include <certpp/x509/generalname.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/asn1/tag.hpp>

namespace certpp {
namespace x509 {

    using asn1::CDecoder;
    using asn1::CEncoder;
    using asn1::CDer;
    using asn1::CTag;
    using asn1::EAENC_DER;
    using asn1::EATAG_CONTEXT_SPECIFIC;
    using asn1::EAUTAG_STRING_IA5;

    /* Decodes one GeneralName from its outer context-specific tag-length-value. */
    bool CGeneralName::decode(SReadOnlyByteSpan content, uint32_t tagValue, bool constructed, CGeneralName& out) {
        switch (tagValue) {
            case EGNAME_RFC822:
            case EGNAME_DNS:
            case EGNAME_URI: {
                // --> IMPLICIT IA5String: always primitive.
                if (constructed) {
                    return false;
                }

                CString text;
                if (!CDecoder::decodeString(content, EAUTAG_STRING_IA5, text)) {
                    return false;
                }

                out = CGeneralName(static_cast<EGeneralNameType>(tagValue), text);
                return true;
            }

            case EGNAME_REGISTERED_ID: {
                // --> IMPLICIT OBJECT IDENTIFIER: always primitive.
                if (constructed) {
                    return false;
                }

                CString text;
                if (!CDecoder::decodeOidString(content, text)) {
                    return false;
                }

                out = CGeneralName(EGNAME_REGISTERED_ID, text);
                return true;
            }

            case EGNAME_IP_ADDRESS: {
                // --> IMPLICIT OCTET STRING: always primitive. Any byte sequence is valid (4
                // octets for IPv4, 16 for IPv6; a subnet mask/prefix suffix is possible too, in
                // NameConstraints' GeneralSubtree.base -- left to the caller to interpret).
                if (constructed) {
                    return false;
                }

                out = CGeneralName(EGNAME_IP_ADDRESS, COctet(content));
                return true;
            }

            case EGNAME_DIRECTORY: {
                // --> directoryName [4] is EXPLICIT (Name is a CHOICE, which ASN.1 doesn't allow
                // implicitly tagging) -- content is the [4] wrapper's own content, itself one
                // more TLV: the Name's actual RDNSequence SEQUENCE.
                CTag innerTag;
                SReadOnlyByteSpan innerContent;
                SReadOnlyByteSpan cursor = content;
                if (!CDecoder::readNextElement(cursor, EAENC_DER, innerTag, innerContent) || innerTag != CTag::SEQ) {
                    return false;
                }

                CDistinguishedName name;
                if (!CDecoder::decodeDistinguishedName(innerContent, name)) {
                    return false;
                }

                out = CGeneralName(name);
                return true;
            }

            case EGNAME_OTHER:
            case EGNAME_X400_ADDRESS:
            case EGNAME_EDI_PARTY:
                // --> Structurally rare in practice; kept as raw, still-DER-encoded content
                // rather than modeling OtherName/ORAddress/EDIPartyName in full.
                out = CGeneralName(static_cast<EGeneralNameType>(tagValue), COctet(content));
                return true;

            default:
                return false;
        }
    }

    /* Decodes a GeneralNames (SEQUENCE OF GeneralName) from its outer SEQUENCE's content. */
    void CGeneralName::decodeList(SReadOnlyByteSpan content, TArray<CGeneralName>& out) {
        out.clear();

        SReadOnlyByteSpan cursor = content;
        CTag tag;
        SReadOnlyByteSpan elementContent;

        while (CDecoder::readNextElement(cursor, EAENC_DER, tag, elementContent)) {
            if (tag.tagClass() != EATAG_CONTEXT_SPECIFIC) {
                continue;
            }

            CGeneralName name;
            if (decode(elementContent, tag.value(), tag.isConstructed(), name)) {
                out.add(name);
            }
        }
    }

    /* Encodes this GeneralName as its own context-specific tag-length-value. */
    bool CGeneralName::encode(CBuffer& out) const {
        switch (_type) {
            case EGNAME_RFC822:
            case EGNAME_DNS:
            case EGNAME_URI: {
                // --> IMPLICIT IA5String: content is the text's own bytes, validated as ASCII.
                SReadOnlyByteSpan textBytes(reinterpret_cast<const uint8_t*>(_text.toPtr()), _text.size());

                CBuffer content;
                if (!content.resize(textBytes.size)) {
                    return false;
                }

                size_t written = 0;
                if (!CEncoder::encodeText(content.toSpan(), EAUTAG_STRING_IA5, textBytes, written)) {
                    return false;
                }

                return CDer::appendTlv(out, CTag(EATAG_CONTEXT_SPECIFIC, uint32_t(_type), false), SReadOnlyByteSpan(content.toPtr(), written));
            }

            case EGNAME_REGISTERED_ID: {
                // --> IMPLICIT OBJECT IDENTIFIER.
                size_t needed = CEncoder::encodedOidStringSize(_text);
                if (!needed) {
                    return false;
                }

                CBuffer content;
                if (!content.resize(needed)) {
                    return false;
                }

                size_t written = 0;
                if (!CEncoder::encodeOidString(content.toSpan(), _text, written)) {
                    return false;
                }

                return CDer::appendTlv(out, CTag(EATAG_CONTEXT_SPECIFIC, uint32_t(EGNAME_REGISTERED_ID), false), SReadOnlyByteSpan(content.toPtr(), written));
            }

            case EGNAME_IP_ADDRESS:
                // --> IMPLICIT OCTET STRING: raw() already holds the exact content bytes.
                return CDer::appendTlv(out, CTag(EATAG_CONTEXT_SPECIFIC, uint32_t(EGNAME_IP_ADDRESS), false), _raw.toSpan());

            case EGNAME_DIRECTORY: {
                // --> directoryName [4] EXPLICIT: wrap the encoded RDNSequence SEQUENCE inside
                // one more [4] wrapper, mirroring decode()'s own two-layer unwrap.
                size_t needed = CEncoder::encodedDistinguishedNameSize(_directoryName);

                CBuffer content;
                size_t written = 0;
                if (needed) {
                    if (!content.resize(needed)) {
                        return false;
                    }

                    if (!CEncoder::encodeDistinguishedName(content.toSpan(), _directoryName, written)) {
                        return false;
                    }
                }

                CBuffer seqTlv;
                if (!CDer::appendSequence(seqTlv, SReadOnlyByteSpan(content.toPtr(), written))) {
                    return false;
                }

                return CDer::appendTlv(out, CTag(EATAG_CONTEXT_SPECIFIC, uint32_t(EGNAME_DIRECTORY), true), seqTlv.toSpan());
            }

            case EGNAME_OTHER:
            case EGNAME_X400_ADDRESS:
            case EGNAME_EDI_PARTY:
                // --> Never parsed further on decode -- raw() is written back out verbatim, under
                // a constructed tag since every one of these alternatives is itself SEQUENCE-shaped.
                return CDer::appendTlv(out, CTag(EATAG_CONTEXT_SPECIFIC, uint32_t(_type), true), _raw.toSpan());

            default:
                return false;
        }
    }

    /* Encodes a GeneralNames (SEQUENCE OF GeneralName) list, the inverse of decodeList(). */
    bool CGeneralName::encodeList(const TArray<CGeneralName>& names, CBuffer& out) {
        for (const CGeneralName& name : names) {
            if (!name.encode(out)) {
                return false;
            }
        }

        return true;
    }

    /* Encodes this GeneralSubtree as its own SEQUENCE tag-length-value. */
    bool CGeneralSubtree::encode(CBuffer& out) const {
        // GeneralSubtree ::= SEQUENCE {
        //     base     GeneralName,
        //     minimum  [0] IMPLICIT BaseDistance DEFAULT 0,
        //     maximum  [1] IMPLICIT BaseDistance OPTIONAL }
        CBuffer body;
        if (!_base.encode(body)) {
            return false;
        }

        if (_minimum != 0) {
            uint8_t buf[9];
            size_t written = 0;
            if (!CEncoder::encodeInteger(SByteSpan(buf, sizeof(buf)), _minimum, written)
                || !CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 0, false), SReadOnlyByteSpan(buf, written)))
            {
                return false;
            }
        }

        if (_hasMaximum) {
            uint8_t buf[9];
            size_t written = 0;
            if (!CEncoder::encodeInteger(SByteSpan(buf, sizeof(buf)), _maximum, written)
                || !CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 1, false), SReadOnlyByteSpan(buf, written)))
            {
                return false;
            }
        }

        return CDer::appendSequence(out, body.toSpan());
    }

} // namespace x509
} // namespace certpp
