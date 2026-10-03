#include <certpp/x509/exts/eku.hpp>
#include <certpp/asn1/reader.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/asn1/tag.hpp>

namespace certpp {
namespace x509 {

    using asn1::CReader;
    using asn1::CEncoder;
    using asn1::CDer;
    using asn1::CTag;
    using asn1::EAENC_DER;

    /* Parses an ExtendedKeyUsage extension from its raw extnValue. */
    CEkuExtension::CEkuExtension(const COctet& value)
        : IExtension(OID, value)
    {
        // ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId (OBJECT IDENTIFIER)
        CReader wrapper(value.toSpan(), EAENC_DER);
        CReader seq;
        if (!wrapper.readSequence(seq)) {
            return;
        }

        while (!seq.atEnd()) {
            CString purpose;
            if (!seq.readOidString(purpose)) {
                break;
            }
            _purposes.add(purpose);
        }
    }

    /* Checks whether a specific KeyPurposeId OID is present. */
    bool CEkuExtension::has(const char* purposeOid) const {
        if (!purposeOid) {
            return false;
        }

        for (const CString& purpose : _purposes) {
            if (purpose.compare(purposeOid) == 0) {
                return true;
            }
        }

        return false;
    }

    /* Encodes this extension, replaying its already-decoded value() bytes. */
    bool CEkuExtension::encode(CBuffer& out) const {
        return encodeValue(out);
    }

    /* Builds the ExtendedKeyUsage extension. */
    IExtensionPtr CEkuExtensionBuilder::build() const {
        // ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId (OBJECT IDENTIFIER)
        CBuffer body;

        for (const CString& purpose : _purposes) {
            size_t needed = CEncoder::encodedOidStringSize(purpose);
            if (!needed) {
                return nullptr;
            }

            CBuffer oidContent;
            if (!oidContent.resize(needed)) {
                return nullptr;
            }

            size_t written = 0;
            if (!CEncoder::encodeOidString(oidContent.toSpan(), purpose, written)
                || !CDer::appendTlv(body, CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), written)))
            {
                return nullptr;
            }
        }

        CBuffer full;
        if (!CDer::appendSequence(full, body.toSpan())) {
            return nullptr;
        }

        COctet value(full.toSpan());
        return std::make_shared<CEkuExtension>(value);
    }

} // namespace x509
} // namespace certpp
