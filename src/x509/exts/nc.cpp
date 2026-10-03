#include <certpp/x509/exts/nc.hpp>
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

        /* Decodes a GeneralSubtrees (SEQUENCE OF GeneralSubtree) from its own SEQUENCE's
         * content octets. */
        void CNameConstraintsExtension::decodeGeneralSubtrees(SReadOnlyByteSpan content, TArray<CGeneralSubtree>& out) {
            // GeneralSubtree ::= SEQUENCE {
            //     base     GeneralName,
            //     minimum  [0] IMPLICIT BaseDistance DEFAULT 0,
            //     maximum  [1] IMPLICIT BaseDistance OPTIONAL }
            SReadOnlyByteSpan cursor = content;
            CTag tag;
            SReadOnlyByteSpan gsContent;
            while (CDecoder::readNextElement(cursor, EAENC_DER, tag, gsContent)) {
                if (tag != CTag::SEQ) {
                    continue;
                }

                CReader gsSeq(gsContent, EAENC_DER);
                CTag baseTag;
                SReadOnlyByteSpan baseContent;
                if (!gsSeq.readNextElement(baseTag, baseContent) || baseTag.tagClass() != EATAG_CONTEXT_SPECIFIC) {
                    continue;
                }

                CGeneralName base;
                if (!CGeneralName::decode(baseContent, baseTag.value(), baseTag.isConstructed(), base)) {
                    continue;
                }

                int64_t minimum = 0;
                bool hasMaximum = false;
                int64_t maximum = 0;

                while (!gsSeq.atEnd()) {
                    CTag fieldTag;
                    SReadOnlyByteSpan fieldContent;
                    if (!gsSeq.readNextElement(fieldTag, fieldContent) || fieldTag.tagClass() != EATAG_CONTEXT_SPECIFIC) {
                        break;
                    }

                    int64_t distance = 0;
                    if (!CDecoder::decodeInteger(fieldContent, distance)) {
                        continue;
                    }

                    if (fieldTag.value() == 0) {
                        minimum = distance;
                    } else if (fieldTag.value() == 1) {
                        hasMaximum = true;
                        maximum = distance;
                    }
                }

                out.add(CGeneralSubtree(base, minimum, hasMaximum, maximum));
            }
        }

    /* Parses a NameConstraints extension from its raw extnValue. */
    CNameConstraintsExtension::CNameConstraintsExtension(const COctet& value)
        : IExtension(OID, value)
    {
        // NameConstraints ::= SEQUENCE {
        //     permittedSubtrees [0] IMPLICIT GeneralSubtrees OPTIONAL,
        //     excludedSubtrees  [1] IMPLICIT GeneralSubtrees OPTIONAL }
        CReader wrapper(value.toSpan(), EAENC_DER);
        CReader seq;
        if (!wrapper.readSequence(seq)) {
            return;
        }

        while (!seq.atEnd()) {
            CTag tag;
            SReadOnlyByteSpan content;
            if (!seq.readNextElement(tag, content) || tag.tagClass() != EATAG_CONTEXT_SPECIFIC) {
                break;
            }

            if (tag.value() == 0) {
                decodeGeneralSubtrees(content, _permittedSubtrees);
            } else if (tag.value() == 1) {
                decodeGeneralSubtrees(content, _excludedSubtrees);
            }
        }
    }

    /* Encodes a GeneralSubtrees (SEQUENCE OF GeneralSubtree) list, appending each element's own
     * SEQUENCE TLV to out -- the inverse of CNameConstraintsExtension::decodeGeneralSubtrees(). */
    bool CNameConstraintsExtensionBuilder::encodeGeneralSubtrees(const TArray<CGeneralSubtree>& subtrees, CBuffer& out) {
        for (const CGeneralSubtree& subtree : subtrees) {
            if (!subtree.encode(out)) {
                return false;
            }
        }

        return true;
    }

    /* Encodes this extension, replaying its already-decoded value() bytes. */
    bool CNameConstraintsExtension::encode(CBuffer& out) const {
        return encodeValue(out);
    }

    /* Builds the NameConstraints extension. */
    IExtensionPtr CNameConstraintsExtensionBuilder::build() const {
        // NameConstraints ::= SEQUENCE {
        //     permittedSubtrees [0] IMPLICIT GeneralSubtrees OPTIONAL,
        //     excludedSubtrees  [1] IMPLICIT GeneralSubtrees OPTIONAL }
        CBuffer body;

        if (!_permittedSubtrees.empty()) {
            CBuffer content;
            if (!encodeGeneralSubtrees(_permittedSubtrees, content)
                || !CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), content.toSpan()))
            {
                return nullptr;
            }
        }

        if (!_excludedSubtrees.empty()) {
            CBuffer content;
            if (!encodeGeneralSubtrees(_excludedSubtrees, content)
                || !CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 1, true), content.toSpan()))
            {
                return nullptr;
            }
        }

        CBuffer full;
        if (!CDer::appendSequence(full, body.toSpan())) {
            return nullptr;
        }

        COctet value(full.toSpan());
        return std::make_shared<CNameConstraintsExtension>(value);
    }

} // namespace x509
} // namespace certpp
