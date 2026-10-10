#include <certpp/asn1/writer.hpp>
#include <certpp/io/buffer.hpp>
#include <utility>

namespace certpp {
namespace asn1 {

    CWriter::CWriter(IStreamPtr stream, EEncodingRule ruleSet)
        : _stream(std::move(stream)), _ruleSet(ruleSet)
    {
    }

    /* Writes a full tag-length-value to the stream from already-encoded content. */
    bool CWriter::writeElement(const CTag& tag, SReadOnlyByteSpan content) {
        if (!_stream) {
            return false;
        }

        size_t needed = CEncoder::encodedValueSize(tag, content);
        if (!needed) {
            return false;
        }

        CBuffer buf(needed);
        size_t written = 0;

        if (!CEncoder::writeEncodedValue(TSpan<uint8_t>(buf.toPtr(), buf.size()), _ruleSet, tag, content, written)) {
            return false;
        }

        return _stream->write(buf.toPtr(), written) == written;
    }

    /* Writes a SEQUENCE from already-encoded children. */
    bool CWriter::writeSequence(TReadOnlySpan<SReadOnlyByteSpan> children) {
        size_t total = 0;
        for (size_t i = 0; i < children.size; ++i) {
            total += children[i].size;
        }

        CBuffer buf(total);
        size_t written = 0;

        if (!CEncoder::writeSequenceOf(TSpan<uint8_t>(buf.toPtr(), buf.size()), children, written)) {
            return false;
        }

        return writeElement(CTag::SEQ, SReadOnlyByteSpan(buf.toPtr(), written));
    }

    /* Writes a SET from already-encoded children, reordering them into canonical ascending order first. */
    bool CWriter::writeSet(TSpan<SReadOnlyByteSpan> children) {
        size_t total = 0;
        for (size_t i = 0; i < children.size; ++i) {
            total += children[i].size;
        }

        CBuffer buf(total);
        size_t written = 0;

        if (!CEncoder::writeSetOf(TSpan<uint8_t>(buf.toPtr(), buf.size()), children, written)) {
            return false;
        }

        return writeElement(CTag::SET_OF, SReadOnlyByteSpan(buf.toPtr(), written));
    }

    /* Writes a BOOLEAN. */
    bool CWriter::writeBoolean(bool value) {
        uint8_t buf[1];
        size_t written = 0;

        return CEncoder::encodeBoolean(TSpan<uint8_t>(buf, sizeof(buf)), value, written)
            && writeElement(CTag::BOOLEAN, SReadOnlyByteSpan(buf, written));
    }

    /* Writes an INTEGER. */
    bool CWriter::writeInteger(int64_t value) {
        uint8_t buf[9];
        size_t written = 0;

        return CEncoder::encodeInteger(TSpan<uint8_t>(buf, sizeof(buf)), value, written)
            && writeElement(CTag::INTEGER, SReadOnlyByteSpan(buf, written));
    }

    /* Writes an ENUMERATED. */
    bool CWriter::writeEnumerated(uint32_t value) {
        uint8_t buf[9];
        size_t written = 0;

        return CEncoder::encodeEnumerated(TSpan<uint8_t>(buf, sizeof(buf)), value, written)
            && writeElement(CTag::ENUMERATED, SReadOnlyByteSpan(buf, written));
    }

    /* Writes a NULL. */
    bool CWriter::writeNull() {
        size_t written = 0;

        return CEncoder::encodeNull(TSpan<uint8_t>(nullptr, 0), written)
            && writeElement(CTag::NULL_, SReadOnlyByteSpan(nullptr, 0));
    }

    /* Writes an OCTET STRING. */
    bool CWriter::writeOctetString(SReadOnlyByteSpan value) {
        CBuffer buf(value.size);
        size_t written = 0;

        return CEncoder::encodeOctetString(TSpan<uint8_t>(buf.toPtr(), buf.size()), value, written)
            && writeElement(CTag::STRING_OCTET, SReadOnlyByteSpan(buf.toPtr(), written));
    }

    /* Writes an OCTET STRING from an owning COctet. */
    bool CWriter::writeOctetString(const COctet& value) {
        return writeOctetString(value.toSpan());
    }

    /* Writes a BIT STRING. */
    bool CWriter::writeBitString(SReadOnlyByteSpan bits, uint8_t unusedBits) {
        CBuffer buf(1 + bits.size);
        size_t written = 0;

        return CEncoder::encodeBitString(TSpan<uint8_t>(buf.toPtr(), buf.size()), bits, unusedBits, written)
            && writeElement(CTag::STRING_BIT, SReadOnlyByteSpan(buf.toPtr(), written));
    }

    /* Writes a BIT STRING from an owning COctet's packed bit data. */
    bool CWriter::writeBitString(const COctet& bits, uint8_t unusedBits) {
        return writeBitString(bits.toSpan(), unusedBits);
    }

    /* Writes a BIT STRING used as a NamedBitList, trimming trailing zero bits. */
    bool CWriter::writeNamedBitList(SReadOnlyByteSpan bits, uint32_t bitCount) {
        CBuffer buf(1 + bits.size);
        size_t written = 0;

        return CEncoder::encodeNamedBitList(TSpan<uint8_t>(buf.toPtr(), buf.size()), bits, bitCount, written)
            && writeElement(CTag::STRING_BIT, SReadOnlyByteSpan(buf.toPtr(), written));
    }

    /* Writes an OBJECT IDENTIFIER from its arc values. */
    bool CWriter::writeOid(TReadOnlySpan<uint32_t> arcs) {
        size_t needed = CEncoder::encodedOidSize(arcs);
        if (!needed) {
            return false;
        }

        CBuffer buf(needed);
        size_t written = 0;

        return CEncoder::encodeOid(TSpan<uint8_t>(buf.toPtr(), buf.size()), arcs, written)
            && writeElement(CTag::OBJ_ID, SReadOnlyByteSpan(buf.toPtr(), written));
    }

    /* Writes an OBJECT IDENTIFIER from an SRawOid. */
    bool CWriter::writeOid(const SRawOid& oid) {
        size_t needed = CEncoder::encodedOidSize(oid);
        if (!needed) {
            return false;
        }

        CBuffer buf(needed);
        size_t written = 0;

        return CEncoder::encodeOid(TSpan<uint8_t>(buf.toPtr(), buf.size()), oid, written)
            && writeElement(CTag::OBJ_ID, SReadOnlyByteSpan(buf.toPtr(), written));
    }

    /* Writes a character string type's content. */
    bool CWriter::writeText(EUniversalTags kind, SReadOnlyByteSpan text) {
        CTag tag(kind, false);
        if (!tag) {
            return false;
        }

        CBuffer buf(text.size);
        size_t written = 0;

        return CEncoder::encodeText(TSpan<uint8_t>(buf.toPtr(), buf.size()), kind, text, written)
            && writeElement(tag, SReadOnlyByteSpan(buf.toPtr(), written));
    }

    /* Writes a UTCTime. */
    bool CWriter::writeUtcTime(const SDateTime& time) {
        uint8_t buf[13];
        size_t written = 0;

        return CEncoder::encodeUtcTime(TSpan<uint8_t>(buf, sizeof(buf)), time, written)
            && writeElement(CTag::TIME_UTC_, SReadOnlyByteSpan(buf, written));
    }

    /* Writes a GeneralizedTime. */
    bool CWriter::writeGeneralizedTime(const SDateTime& time) {
        size_t needed = CEncoder::encodedGeneralizedTimeSize(time);
        if (!needed) {
            return false;
        }

        CBuffer buf(needed);
        size_t written = 0;

        return CEncoder::encodeGeneralizedTime(TSpan<uint8_t>(buf.toPtr(), buf.size()), time, written)
            && writeElement(CTag::TIME_GENERAL, SReadOnlyByteSpan(buf.toPtr(), written));
    }

    /* Writes a CDistinguishedName. */
    bool CWriter::writeDistinguishedName(const CDistinguishedName& value) {
        size_t needed = CEncoder::encodedDistinguishedNameSize(value);
        CBuffer buf(needed);
        size_t written = 0;

        return CEncoder::encodeDistinguishedName(TSpan<uint8_t>(buf.toPtr(), buf.size()), value, written)
            && writeElement(CTag::SEQ, SReadOnlyByteSpan(buf.toPtr(), written));
    }

} // namespace asn1
} // namespace certpp
