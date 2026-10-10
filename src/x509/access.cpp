#include <certpp/x509/access.hpp>
#include <certpp/asn1/reader.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/asn1/tag.hpp>

namespace certpp {
namespace x509 {

    using asn1::CReader;
    using asn1::CDecoder;
    using asn1::CEncoder;
    using asn1::CDer;
    using asn1::CTag;
    using asn1::EAENC_DER;
    using asn1::EATAG_CONTEXT_SPECIFIC;

    /* Decodes one DistributionPoint from its own SEQUENCE's content octets. */
    bool CDistributionPoint::decode(SReadOnlyByteSpan content, CDistributionPoint& out) {
        // DistributionPoint ::= SEQUENCE {
        //     distributionPoint [0] DistributionPointName OPTIONAL,
        //     reasons           [1] IMPLICIT ReasonFlags OPTIONAL,
        //     cRLIssuer         [2] IMPLICIT GeneralNames OPTIONAL }
        CReader seq(content, EAENC_DER);

        while (!seq.atEnd()) {
            CTag tag;
            SReadOnlyByteSpan fieldContent;
            if (!seq.readNextElement(tag, fieldContent) || tag.tagClass() != EATAG_CONTEXT_SPECIFIC) {
                break;
            }

            switch (tag.value()) {
                case 0: {
                    // distributionPoint [0] EXPLICIT DistributionPointName -- DistributionPointName
                    // is a CHOICE, which ASN.1 doesn't allow implicitly tagging, so fieldContent
                    // is the [0] wrapper's own content: one more TLV, the CHOICE's actual
                    // alternative.
                    // DistributionPointName ::= CHOICE {
                    //     fullName                [0] IMPLICIT GeneralNames,
                    //     nameRelativeToCRLIssuer  [1] IMPLICIT RelativeDistinguishedName }
                    CTag dpnTag;
                    SReadOnlyByteSpan dpnContent;
                    SReadOnlyByteSpan cursor = fieldContent;
                    if (CDecoder::readNextElement(cursor, EAENC_DER, dpnTag, dpnContent)
                        && dpnTag.tagClass() == EATAG_CONTEXT_SPECIFIC)
                    {
                        if (dpnTag.value() == 0) {
                            CGeneralName::decodeList(dpnContent, out._fullName);
                        } else if (dpnTag.value() == 1) {
                            out._nameRelativeToCrlIssuer = COctet(dpnContent);
                        }
                    }
                    break;
                }

                case 1: {
                    // --> Decode the BIT STRING once, and only record that reasons were present
                    // once it is known to be well-formed: setting _hasReasons up front meant a
                    // malformed BIT STRING still reported hasReasons() == true with
                    // reasons() == 0 -- a claim the DER never made, and indistinguishable from
                    // "reasons present, none set". Testing bits off the decoded span also drops
                    // the eight redundant re-validations testNamedBit() would do, one per bit.
                    SReadOnlyByteSpan reasonBits;
                    uint8_t reasonUnusedBits = 0;
                    if (!CDecoder::decodeBitString(fieldContent, reasonBits, reasonUnusedBits)) {
                        return false;
                    }

                    out._hasReasons = true;
                    out._reasons = ECRLR_NONE;

                    static constexpr struct { uint32_t bit; uint16_t flag; } NAMED_BITS[] = {
                        { 1, ECRLR_KEY_COMPROMISE },      { 2, ECRLR_CA_COMPROMISE },
                        { 3, ECRLR_AFFILIATION_CHANGED }, { 4, ECRLR_SUPERSEDED },
                        { 5, ECRLR_CESSATION_OF_OPERATION }, { 6, ECRLR_CERTIFICATE_HOLD },
                        { 7, ECRLR_PRIVILEGE_WITHDRAWN }, { 8, ECRLR_AA_COMPROMISE },
                    };

                    for (const auto& namedBit : NAMED_BITS) {
                        size_t byteIndex = namedBit.bit / 8;
                        if (byteIndex >= reasonBits.size) {
                            continue;
                        }

                        uint8_t mask = uint8_t(0x80 >> (namedBit.bit % 8));
                        if ((reasonBits[byteIndex] & mask) != 0) {
                            out._reasons |= namedBit.flag;
                        }
                    }
                    break;
                }

                case 2:
                    CGeneralName::decodeList(fieldContent, out._crlIssuer);
                    break;

                default:
                    break;
            }
        }

        return true;
    }

    /* Encodes this AccessDescription as its own SEQUENCE tag-length-value. */
    bool CAccessDescription::encode(CBuffer& out) const {
        // AccessDescription ::= SEQUENCE { accessMethod OBJECT IDENTIFIER,
        //                                   accessLocation GeneralName }
        size_t needed = CEncoder::encodedOidSize(_accessMethod.raw());
        if (!needed) {
            return false;
        }

        CBuffer oidContent;
        if (!oidContent.resize(needed)) {
            return false;
        }

        size_t written = 0;
        if (!CEncoder::encodeOid(oidContent.toSpan(), _accessMethod.raw(), written)) {
            return false;
        }

        CBuffer body;
        if (!CDer::appendTlv(body, CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), written))) {
            return false;
        }

        if (!_accessLocation.encode(body)) {
            return false;
        }

        return CDer::appendSequence(out, body.toSpan());
    }

    /* Encodes this DistributionPoint as its own SEQUENCE tag-length-value. */
    bool CDistributionPoint::encode(CBuffer& out) const {
        // DistributionPoint ::= SEQUENCE {
        //     distributionPoint [0] DistributionPointName OPTIONAL,
        //     reasons           [1] IMPLICIT ReasonFlags OPTIONAL,
        //     cRLIssuer         [2] IMPLICIT GeneralNames OPTIONAL }
        CBuffer body;

        if (!_fullName.empty()) {
            // distributionPoint [0] EXPLICIT DistributionPointName { fullName [0] IMPLICIT
            // GeneralNames } -- two layers of context tag, mirroring decode()'s two-layer unwrap.
            CBuffer namesContent;
            if (!CGeneralName::encodeList(_fullName, namesContent)) {
                return false;
            }

            CBuffer dpnTlv;
            if (!CDer::appendTlv(dpnTlv, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), namesContent.toSpan())
                || !CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), dpnTlv.toSpan()))
            {
                return false;
            }
        } else if (!_nameRelativeToCrlIssuer.empty()) {
            CBuffer dpnTlv;
            // --> Constructed, like the _fullName branch above: RelativeDistinguishedName is a
            // SET OF, and IMPLICIT tagging keeps the underlying type's constructed bit (X.690
            // 8.14), so this has to be A1 and not 81. decode() accepts either, so emitting the
            // primitive form turned a valid parse into invalid output on re-encode.
            if (!CDer::appendTlv(dpnTlv, CTag(EATAG_CONTEXT_SPECIFIC, 1, true), _nameRelativeToCrlIssuer.toSpan())
                || !CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), dpnTlv.toSpan()))
            {
                return false;
            }
        }

        if (_hasReasons) {
            // ReasonFlags' named-bit numbering already matches ECrlReasons' own flag values
            // (flag == 1u << bit for bit 1-8), so no lookup table is needed here.
            uint8_t packed[2] = { 0, 0 };
            for (uint32_t bit = 1; bit <= 8; ++bit) {
                if (_reasons & (1u << bit)) {
                    packed[bit / 8] |= uint8_t(0x80 >> (bit % 8));
                }
            }

            uint8_t contentBuf[3];
            size_t written = 0;
            if (!CEncoder::encodeNamedBitList(SByteSpan(contentBuf, sizeof(contentBuf)), SReadOnlyByteSpan(packed, sizeof(packed)), 9, written)
                || !CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 1, false), SReadOnlyByteSpan(contentBuf, written)))
            {
                return false;
            }
        }

        if (!_crlIssuer.empty()) {
            CBuffer namesContent;
            if (!CGeneralName::encodeList(_crlIssuer, namesContent)) {
                return false;
            }

            if (!CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 2, true), namesContent.toSpan())) {
                return false;
            }
        }

        return CDer::appendSequence(out, body.toSpan());
    }

} // namespace x509
} // namespace certpp
