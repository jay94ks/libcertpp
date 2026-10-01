#include <certpp/x509/exts/aki.hpp>
#include <certpp/asn1/reader.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/asn1/tag.hpp>

namespace certpp {
namespace x509 {

    using asn1::CReader;
    using asn1::CDer;
    using asn1::CTag;
    using asn1::EAENC_DER;
    using asn1::EATAG_CONTEXT_SPECIFIC;

    /* Parses an AuthorityKeyIdentifier extension from its raw extnValue. */
    CAkiExtension::CAkiExtension(const COctet& value)
        : IExtension(OID, value)
    {
        // AuthorityKeyIdentifier ::= SEQUENCE {
        //     keyIdentifier             [0] IMPLICIT KeyIdentifier OPTIONAL,
        //     authorityCertIssuer       [1] IMPLICIT GeneralNames OPTIONAL,
        //     authorityCertSerialNumber [2] IMPLICIT CertificateSerialNumber OPTIONAL }
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

            switch (tag.value()) {
                case 0:
                    _keyIdentifier = COctet(content);
                    break;

                case 1:
                    CGeneralName::decodeList(content, _authorityCertIssuer);
                    break;

                case 2:
                    _authorityCertSerialNumber = COctet(content);
                    break;

                default:
                    break;
            }
        }
    }

    /* Encodes this extension, replaying its already-decoded value() bytes. */
    bool CAkiExtension::encode(CBuffer& out) const {
        return encodeValue(out);
    }

    /* Builds the AuthorityKeyIdentifier extension. */
    IExtensionPtr CAkiExtensionBuilder::build() const {
        // AuthorityKeyIdentifier ::= SEQUENCE {
        //     keyIdentifier             [0] IMPLICIT KeyIdentifier OPTIONAL,
        //     authorityCertIssuer       [1] IMPLICIT GeneralNames OPTIONAL,
        //     authorityCertSerialNumber [2] IMPLICIT CertificateSerialNumber OPTIONAL }
        CBuffer body;

        if (!_keyIdentifier.empty()) {
            if (!CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 0, false), _keyIdentifier.toSpan())) {
                return nullptr;
            }
        }

        if (!_authorityCertIssuer.empty()) {
            CBuffer namesContent;
            if (!CGeneralName::encodeList(_authorityCertIssuer, namesContent)
                || !CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 1, true), namesContent.toSpan()))
            {
                return nullptr;
            }
        }

        if (!_authorityCertSerialNumber.empty()) {
            if (!CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 2, false), _authorityCertSerialNumber.toSpan())) {
                return nullptr;
            }
        }

        CBuffer full;
        if (!CDer::appendSequence(full, body.toSpan())) {
            return nullptr;
        }

        COctet value(full.toSpan());
        return std::make_shared<CAkiExtension>(value);
    }

}
}
