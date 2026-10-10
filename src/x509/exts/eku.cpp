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
            SRawOid raw;
            if (!seq.readOid(raw)) {
                break;
            }

            // --> Kept as a COid: has() compares a KeyPurposeId against one of the library's
            // named OIDs, so an arc comparison avoids formatting both sides to text.
            _purposes.add(COid(raw));
        }
    }

    /* Checks whether a specific KeyPurposeId OID is present. */
    bool CEkuExtension::has(const SKnownOid& purposeOid) const {
        const COid target(purposeOid);
        for (const COid& purpose : _purposes) {
            if (purpose == target) {
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

        for (const COid& purpose : _purposes) {
            size_t needed = CEncoder::encodedOidSize(purpose.raw());
            if (!needed) {
                return nullptr;
            }

            CBuffer oidContent;
            if (!oidContent.resize(needed)) {
                return nullptr;
            }

            size_t written = 0;
            if (!CEncoder::encodeOid(oidContent.toSpan(), purpose.raw(), written)
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
