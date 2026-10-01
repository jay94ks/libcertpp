#include <certpp/x509/exts/ku.hpp>
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

    /* Parses a KeyUsage extension from its raw extnValue. */
    CKeyUsagesExtension::CKeyUsagesExtension(const COctet& value)
        : IExtension(OID, value)
    {
        // KeyUsage ::= BIT STRING
        CTag tag;
        SReadOnlyByteSpan content;
        SReadOnlyByteSpan cursor = value.toSpan();
        if (!CDecoder::readNextElement(cursor, EAENC_DER, tag, content) || tag != CTag::STRING_BIT) {
            return;
        }

        // Maps EKeyUsages' own bit positions to KeyUsage's named-bit numbering (0 =
        // digitalSignature ... 8 = decipherOnly, per RFC 5280 4.2.1.3).
        static constexpr struct { uint32_t bit; uint16_t flag; } NAMED_BITS[] = {
            { 0, EKUSE_DIGITAL_SIGNATURE }, { 1, EKUSE_NON_REPUDIATION },
            { 2, EKUSE_KEY_ENCIPHERMENT },  { 3, EKUSE_DATA_ENCIPHERMENT },
            { 4, EKUSE_KEY_AGREEMENT },     { 5, EKUSE_KEY_CERT_SIGN },
            { 6, EKUSE_CRL_SIGN },          { 7, EKUSE_ENCIPHER_ONLY },
            { 8, EKUSE_DECIPHER_ONLY },
        };

        uint16_t result = 0;
        for (const auto& namedBit : NAMED_BITS) {
            if (CDecoder::testNamedBit(content, namedBit.bit)) {
                result |= namedBit.flag;
            }
        }

        _bits = result;
    }

    /* Encodes this extension, replaying its already-decoded value() bytes. */
    bool CKeyUsagesExtension::encode(CBuffer& out) const {
        return encodeValue(out);
    }

    /* Builds the KeyUsage extension. */
    IExtensionPtr CKeyUsagesExtensionBuilder::build() const {
        // KeyUsage ::= BIT STRING
        // Reverses CKeyUsagesExtension's own EKeyUsages -> named-bit mapping.
        static constexpr struct { uint32_t bit; uint16_t flag; } NAMED_BITS[] = {
            { 0, EKUSE_DIGITAL_SIGNATURE }, { 1, EKUSE_NON_REPUDIATION },
            { 2, EKUSE_KEY_ENCIPHERMENT },  { 3, EKUSE_DATA_ENCIPHERMENT },
            { 4, EKUSE_KEY_AGREEMENT },     { 5, EKUSE_KEY_CERT_SIGN },
            { 6, EKUSE_CRL_SIGN },          { 7, EKUSE_ENCIPHER_ONLY },
            { 8, EKUSE_DECIPHER_ONLY },
        };

        uint8_t packed[2] = { 0, 0 };
        for (const auto& namedBit : NAMED_BITS) {
            if (_bits & namedBit.flag) {
                packed[namedBit.bit / 8] |= uint8_t(0x80 >> (namedBit.bit % 8));
            }
        }

        uint8_t contentBuf[3];
        size_t written = 0;
        if (!CEncoder::encodeNamedBitList(SByteSpan(contentBuf, sizeof(contentBuf)), SReadOnlyByteSpan(packed, sizeof(packed)), 9, written)) {
            return nullptr;
        }

        CBuffer full;
        if (!CDer::appendTlv(full, CTag::STRING_BIT, SReadOnlyByteSpan(contentBuf, written))) {
            return nullptr;
        }

        COctet value(full.toSpan());
        return std::make_shared<CKeyUsagesExtension>(value);
    }

}
}
