#include <certpp/asn1/encoder.hpp>
#include <certpp/io/buffer.hpp>
#include <algorithm>
#include <cstring>

namespace certpp {
namespace asn1 {

    /* Writes `digitCount` decimal digits of value (assumed to fit) starting at offset. */
    void CEncoder::WriteFixedDigits(TSpan<uint8_t> destination, size_t offset, size_t digitCount, uint32_t value) {
        for (size_t i = digitCount; i > 0; --i) {
            destination.data[offset + i - 1] = uint8_t('0' + (value % 10));
            value /= 10;
        }
    }

    /* Computes the number of octets a length value occupies when encoded in ASN.1 definite-length form. */
    size_t CEncoder::encodedLengthSize(size_t length) {
        if (length < 0x80) {
            return 1;
        }

        size_t octets = 0;
        for (size_t remaining = length; remaining > 0; remaining >>= 8) {
            octets++;
        }

        return 1 + octets;
    }

    /* Encodes a length value into the destination span using ASN.1 definite-length form. */
    bool CEncoder::encodeLength(TSpan<uint8_t> destination, size_t length, size_t& bytesWritten) {
        bytesWritten = 0;

        size_t requiredSize = encodedLengthSize(length);
        if (destination.size < requiredSize) {
            return false;
        }

        if (requiredSize == 1) {
            destination.data[0] = static_cast<uint8_t>(length);
            bytesWritten = 1;
            return true;
        }

        size_t octets = requiredSize - 1;
        destination.data[0] = static_cast<uint8_t>(0x80 | octets);

        for (size_t i = 0; i < octets; ++i) {
            size_t shift = (octets - 1 - i) * 8;
            destination.data[1 + i] = static_cast<uint8_t>((length >> shift) & 0xFF);
        }

        bytesWritten = requiredSize;
        return true;
    }

    /* Computes the minimal number of octets required to encode value as a two's-complement big-endian INTEGER. */
    size_t CEncoder::encodedIntegerSize(int64_t value) {
        uint64_t v = static_cast<uint64_t>(value);
        size_t n = sizeof(int64_t);

        while (n > 1) {
            uint8_t top = uint8_t((v >> ((n - 1) * 8)) & 0xFF);
            uint8_t next = uint8_t((v >> ((n - 2) * 8)) & 0xFF);

            bool redundant = (top == 0x00 && (next & 0x80) == 0) || (top == 0xFF && (next & 0x80) != 0);
            if (!redundant) {
                break;
            }

            n--;
        }

        return n;
    }

    /* Computes the number of octets required to encode value as an ASN.1 base-128 subidentifier. */
    size_t CEncoder::encodedBase128Size(uint32_t value) {
        size_t n = 1;

        for (uint32_t v = value; v >= 0x80; v >>= 7) {
            n++;
        }

        return n;
    }

    /* Encodes value as an ASN.1 base-128 (varint-style) subidentifier. */
    bool CEncoder::encodeBase128(TSpan<uint8_t> destination, uint32_t value, size_t& bytesWritten) {
        bytesWritten = 0;

        size_t n = encodedBase128Size(value);
        if (destination.size < n) {
            return false;
        }

        for (size_t i = 0; i < n; ++i) {
            size_t shift = (n - 1 - i) * 7;
            uint8_t segment = uint8_t((value >> shift) & 0x7F);

            if (i != n - 1) {
                segment |= 0x80;
            }

            destination.data[i] = segment;
        }

        bytesWritten = n;
        return true;
    }

    /* Computes the total number of octets required to encode a tag-length-value with the given tag and content. */
    size_t CEncoder::encodedValueSize(const CTag& tag, SReadOnlyByteSpan content) {
        if (!tag) {
            return 0;
        }

        return tag.encodedSize() + encodedLengthSize(content.size) + content.size;
    }

    /* Writes an ASN.1 tag-length-value into the destination span, using definite-length form. */
    bool CEncoder::writeEncodedValue(
        TSpan<uint8_t> destination,
        EEncodingRule ruleSet,
        const CTag& tag,
        SReadOnlyByteSpan content,
        size_t& bytesWritten
    ) {
        bytesWritten = 0;

        if (!checkEncodingRule(ruleSet) || !tag) {
            return false;
        }

        if (ruleSet == EAENC_CER && exceedsCerSegmentLimit(tag, content.size)) {
            return false;
        }

        size_t tagBytes = 0;
        if (!tag.encode(destination, tagBytes)) {
            return false;
        }

        auto afterTag = destination.slice(tagBytes);
        size_t lengthBytes = 0;
        if (!encodeLength(afterTag, content.size, lengthBytes)) {
            return false;
        }

        auto afterLength = afterTag.slice(lengthBytes);
        if (afterLength.size < content.size) {
            return false;
        }

        TSpan<uint8_t> contentDest = afterLength.slice(0, content.size);
        content.copyTo(contentDest);

        bytesWritten = tagBytes + lengthBytes + content.size;
        return true;
    }

    /* Encodes a BOOLEAN's content octets. */
    bool CEncoder::encodeBoolean(TSpan<uint8_t> destination, bool value, size_t& bytesWritten) {
        bytesWritten = 0;

        if (destination.size < 1) {
            return false;
        }

        destination.data[0] = value ? 0xFF : 0x00;
        bytesWritten = 1;
        return true;
    }

    /* Encodes an INTEGER's content octets. */
    bool CEncoder::encodeInteger(TSpan<uint8_t> destination, int64_t value, size_t& bytesWritten) {
        bytesWritten = 0;

        size_t n = encodedIntegerSize(value);
        if (destination.size < n) {
            return false;
        }

        uint64_t v = static_cast<uint64_t>(value);
        for (size_t i = 0; i < n; ++i) {
            size_t shift = (n - 1 - i) * 8;
            destination.data[i] = uint8_t((v >> shift) & 0xFF);
        }

        bytesWritten = n;
        return true;
    }

    /* Encodes an ENUMERATED's content octets (encoded identically to INTEGER). */
    bool CEncoder::encodeEnumerated(TSpan<uint8_t> destination, uint32_t value, size_t& bytesWritten) {
        return encodeInteger(destination, int64_t(value), bytesWritten);
    }

    /* Encodes a NULL's content octets (always empty). */
    bool CEncoder::encodeNull(TSpan<uint8_t> destination, size_t& bytesWritten) {
        bytesWritten = 0;
        return true;
    }

    /* Encodes an OCTET STRING's content octets. */
    bool CEncoder::encodeOctetString(TSpan<uint8_t> destination, SReadOnlyByteSpan value, size_t& bytesWritten) {
        bytesWritten = 0;

        if (destination.size < value.size) {
            return false;
        }

        TSpan<uint8_t> dest = destination.slice(0, value.size);
        value.copyTo(dest);

        bytesWritten = value.size;
        return true;
    }

    /* Encodes a BIT STRING's content octets. */
    bool CEncoder::encodeBitString(
        TSpan<uint8_t> destination,
        SReadOnlyByteSpan bits,
        uint8_t unusedBits,
        size_t& bytesWritten
    ) {
        bytesWritten = 0;

        if (unusedBits > 7) {
            return false;
        }

        if (bits.empty()) {
            if (unusedBits != 0) {
                return false;
            }
        } else if (unusedBits != 0) {
            // --> The padding bits the caller supplied must already be zero.
            uint8_t mask = uint8_t((1u << unusedBits) - 1);
            if (bits[bits.size - 1] & mask) {
                return false;
            }
        }

        size_t needed = 1 + bits.size;
        if (destination.size < needed) {
            return false;
        }

        destination.data[0] = unusedBits;
        if (!bits.empty()) {
            TSpan<uint8_t> dataDest = destination.slice(1, bits.size);
            bits.copyTo(dataDest);
        }

        bytesWritten = needed;
        return true;
    }

    /* Encodes a BIT STRING used as a NamedBitList, trimming trailing 0 bits per X.690 11.2.2. */
    bool CEncoder::encodeNamedBitList(
        TSpan<uint8_t> destination,
        SReadOnlyByteSpan bits,
        uint32_t bitCount,
        size_t& bytesWritten
    ) {
        bytesWritten = 0;

        size_t requiredBytes = (size_t(bitCount) + 7) / 8;
        if (bits.size < requiredBytes) {
            return false;
        }

        int64_t highestSet = -1;
        for (uint32_t i = 0; i < bitCount; ++i) {
            size_t byteIndex = i / 8;
            uint8_t mask = uint8_t(0x80 >> (i % 8));

            if (bits[byteIndex] & mask) {
                highestSet = int64_t(i);
            }
        }

        if (highestSet < 0) {
            return encodeBitString(destination, SReadOnlyByteSpan(nullptr, 0), 0, bytesWritten);
        }

        size_t trimmedBitCount = size_t(highestSet) + 1;
        size_t trimmedByteCount = (trimmedBitCount + 7) / 8;
        uint8_t unusedBits = uint8_t(trimmedByteCount * 8 - trimmedBitCount);

        size_t needed = 1 + trimmedByteCount;
        if (destination.size < needed) {
            return false;
        }

        destination.data[0] = unusedBits;

        TSpan<uint8_t> dataDest = destination.slice(1, trimmedByteCount);
        bits.slice(0, trimmedByteCount).copyTo(dataDest);

        if (unusedBits != 0) {
            // --> Zero the trailing padding bits; bits beyond bitCount within the same byte are "don't care".
            uint8_t mask = uint8_t((1u << unusedBits) - 1);
            destination.data[needed - 1] = uint8_t(destination.data[needed - 1] & ~mask);
        }

        bytesWritten = needed;
        return true;
    }

    /* Computes the number of content octets required to encode an OBJECT IDENTIFIER's arcs. */
    size_t CEncoder::encodedOidSize(TReadOnlySpan<uint32_t> arcs) {
        if (arcs.size < 2 || arcs[0] > 2) {
            return 0;
        }

        if (arcs[0] < 2 && arcs[1] >= 40) {
            return 0;
        }

        if (arcs[0] == 2 && arcs[1] > 0xFFFFFFFFu - 80) {
            return 0;
        }

        uint32_t combined = arcs[0] * 40 + arcs[1];
        size_t total = encodedBase128Size(combined);

        for (size_t i = 2; i < arcs.size; ++i) {
            total += encodedBase128Size(arcs[i]);
        }

        return total;
    }

    /* Encodes an OBJECT IDENTIFIER's content octets from its arc values. */
    bool CEncoder::encodeOid(TSpan<uint8_t> destination, TReadOnlySpan<uint32_t> arcs, size_t& bytesWritten) {
        bytesWritten = 0;

        size_t needed = encodedOidSize(arcs);
        if (needed == 0 || destination.size < needed) {
            return false;
        }

        uint32_t combined = arcs[0] * 40 + arcs[1];
        size_t offset = 0, n = 0;

        if (!encodeBase128(destination.slice(offset), combined, n)) {
            return false;
        }
        offset += n;

        for (size_t i = 2; i < arcs.size; ++i) {
            if (!encodeBase128(destination.slice(offset), arcs[i], n)) {
                return false;
            }
            offset += n;
        }

        bytesWritten = offset;
        return true;
    }

    /* Encodes/validates a character string type's content octets. */
    bool CEncoder::encodeText(
        TSpan<uint8_t> destination,
        EUniversalTags kind,
        SReadOnlyByteSpan text,
        size_t& bytesWritten
    ) {
        bytesWritten = 0;

        SReadOnlyByteSpan validated;
        if (!CDecoder::decodeText(text, kind, validated)) {
            return false;
        }

        return encodeOctetString(destination, text, bytesWritten);
    }

    /* Encodes a UTCTime's content octets (the DER-canonical "YYMMDDHHMMSSZ" form). */
    bool CEncoder::encodeUtcTime(TSpan<uint8_t> destination, const SDateTime& time, size_t& bytesWritten) {
        bytesWritten = 0;

        if (!time.isUtc || time.year < 1950 || time.year > 2049) {
            return false;
        }

        if (time.month < 1 || time.month > 12 || time.day < 1 || time.day > 31
            || time.hour > 23 || time.minute > 59 || time.second > 59) {
            return false;
        }

        constexpr size_t LENGTH = 13;
        if (destination.size < LENGTH) {
            return false;
        }

        uint32_t yy = time.year >= 2000 ? uint32_t(time.year - 2000) : uint32_t(time.year - 1900);

        WriteFixedDigits(destination, 0, 2, yy);
        WriteFixedDigits(destination, 2, 2, time.month);
        WriteFixedDigits(destination, 4, 2, time.day);
        WriteFixedDigits(destination, 6, 2, time.hour);
        WriteFixedDigits(destination, 8, 2, time.minute);
        WriteFixedDigits(destination, 10, 2, time.second);
        destination.data[12] = 'Z';

        bytesWritten = LENGTH;
        return true;
    }

    /* Computes the number of content octets required to encode a GeneralizedTime. */
    size_t CEncoder::encodedGeneralizedTimeSize(const SDateTime& time) {
        if (!time.isUtc || time.year > 9999) {
            return 0;
        }

        if (time.month < 1 || time.month > 12 || time.day < 1 || time.day > 31
            || time.hour > 23 || time.minute > 59 || time.second > 59 || time.millisecond > 999) {
            return 0;
        }

        size_t length = 15; // YYYYMMDDHHMMSSZ

        if (time.millisecond != 0) {
            size_t digits = 3;
            uint32_t ms = time.millisecond;

            while (digits > 1 && ms % 10 == 0) {
                ms /= 10;
                digits--;
            }

            length += 1 + digits;
        }

        return length;
    }

    /* Encodes a GeneralizedTime's content octets (the "YYYYMMDDHHMMSS[.fff]Z" form). */
    bool CEncoder::encodeGeneralizedTime(TSpan<uint8_t> destination, const SDateTime& time, size_t& bytesWritten) {
        bytesWritten = 0;

        size_t needed = encodedGeneralizedTimeSize(time);
        if (needed == 0 || destination.size < needed) {
            return false;
        }

        WriteFixedDigits(destination, 0, 4, time.year);
        WriteFixedDigits(destination, 4, 2, time.month);
        WriteFixedDigits(destination, 6, 2, time.day);
        WriteFixedDigits(destination, 8, 2, time.hour);
        WriteFixedDigits(destination, 10, 2, time.minute);
        WriteFixedDigits(destination, 12, 2, time.second);

        size_t offset = 14;

        if (time.millisecond != 0) {
            uint8_t digitsBuf[3];
            digitsBuf[0] = uint8_t('0' + (time.millisecond / 100));
            digitsBuf[1] = uint8_t('0' + ((time.millisecond / 10) % 10));
            digitsBuf[2] = uint8_t('0' + (time.millisecond % 10));

            size_t digitCount = 3;
            while (digitCount > 1 && digitsBuf[digitCount - 1] == '0') {
                digitCount--;
            }

            destination.data[offset++] = '.';
            std::memcpy(destination.data + offset, digitsBuf, digitCount);
            offset += digitCount;
        }

        destination.data[offset++] = 'Z';
        bytesWritten = offset;
        return true;
    }

    /* Builds a SEQUENCE/SEQUENCE OF's content octets by concatenating already-encoded children. */
    bool CEncoder::writeSequenceOf(
        TSpan<uint8_t> destination,
        TReadOnlySpan<SReadOnlyByteSpan> children,
        size_t& bytesWritten
    ) {
        bytesWritten = 0;
        size_t offset = 0;

        for (size_t i = 0; i < children.size; ++i) {
            SReadOnlyByteSpan child = children[i];
            auto remaining = destination.slice(offset);

            if (remaining.size < child.size) {
                return false;
            }

            TSpan<uint8_t> dest = remaining.slice(0, child.size);
            child.copyTo(dest);
            offset += child.size;
        }

        bytesWritten = offset;
        return true;
    }

    /* Builds a SET OF's content octets, reordering children into canonical (ascending) order first. */
    bool CEncoder::writeSetOf(TSpan<uint8_t> destination, TSpan<SReadOnlyByteSpan> children, size_t& bytesWritten) {
        std::sort(children.begin(), children.end(), [](SReadOnlyByteSpan a, SReadOnlyByteSpan b) {
            return a.compare(b) < 0;
        });

        return writeSequenceOf(destination, children, bytesWritten);
    }

    /* Builds one AttributeTypeAndValue (SEQUENCE { type OBJECT IDENTIFIER, value ANY }) for a CName. */
    bool CEncoder::buildAttributeTypeAndValue(const CName& name, TArray<uint8_t>& out) {
        out.clear();

        uint32_t arcs[CName::MAX_OID_ARCS];
        size_t arcCount = 0;
        if (!CName::attributeOid(name.type(), TSpan<uint32_t>(arcs, CName::MAX_OID_ARCS), arcCount)) {
            return false;
        }

        size_t oidContentSize = encodedOidSize(TReadOnlySpan<uint32_t>(arcs, arcCount));
        if (!oidContentSize) {
            return false;
        }

        CBuffer oidContent(oidContentSize);
        size_t oidContentWritten = 0;
        if (!encodeOid(TSpan<uint8_t>(oidContent.toPtr(), oidContent.size()),
                TReadOnlySpan<uint32_t>(arcs, arcCount), oidContentWritten)) {
            return false;
        }

        CBuffer oidTlv(encodedValueSize(CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), oidContentWritten)));
        size_t oidTlvWritten = 0;
        if (!writeEncodedValue(TSpan<uint8_t>(oidTlv.toPtr(), oidTlv.size()), EAENC_DER, CTag::OBJ_ID,
                SReadOnlyByteSpan(oidContent.toPtr(), oidContentWritten), oidTlvWritten)) {
            return false;
        }
        oidTlv.resize(oidTlvWritten);

        // Value: the component's unescaped text, as genuine (locale-independent) UTF-8 --
        // preferred as a PrintableString, falling back to a UTF8String if the content isn't
        // within PrintableString's restricted charset. domainComponent is the one exception: RFC
        // 4519 2.4 gives it IA5String as its syntax, with no alternative, so it's written that
        // way (and fails outright rather than falling back) even though its content would almost
        // always fit a PrintableString too.
        const CWideString text = name.toString<wchar_t>(false);

        size_t valueContentSize = encodedStringSize(text);
        if (!valueContentSize) {
            return false;
        }

        CBuffer valueContent(valueContentSize);
        size_t valueContentWritten = 0;
        EUniversalTags kind = name.type() == ENAME_DC ? EAUTAG_STRING_IA5 : EAUTAG_STRING_P;

        if (!encodeString(TSpan<uint8_t>(valueContent.toPtr(), valueContent.size()), kind, text, valueContentWritten)) {
            if (kind == EAUTAG_STRING_IA5) {
                return false;
            }

            kind = EAUTAG_STRING_UTF8;
            if (!encodeString(TSpan<uint8_t>(valueContent.toPtr(), valueContent.size()), kind, text, valueContentWritten)) {
                return false;
            }
        }

        CBuffer valueTlv(
            encodedValueSize(CTag(kind, false), SReadOnlyByteSpan(valueContent.toPtr(), valueContentWritten)));
        size_t valueTlvWritten = 0;
        if (!writeEncodedValue(TSpan<uint8_t>(valueTlv.toPtr(), valueTlv.size()), EAENC_DER, CTag(kind, false),
                SReadOnlyByteSpan(valueContent.toPtr(), valueContentWritten), valueTlvWritten)) {
            return false;
        }
        valueTlv.resize(valueTlvWritten);

        SReadOnlyByteSpan avChildren[2] = {
            SReadOnlyByteSpan(oidTlv.toPtr(), oidTlv.size()),
            SReadOnlyByteSpan(valueTlv.toPtr(), valueTlv.size())
        };

        CBuffer avContent(oidTlv.size() + valueTlv.size());
        size_t avContentWritten = 0;
        if (!writeSequenceOf(TSpan<uint8_t>(avContent.toPtr(), avContent.size()),
                TReadOnlySpan<SReadOnlyByteSpan>(avChildren, 2), avContentWritten)) {
            return false;
        }

        out.resize(encodedValueSize(CTag::SEQ, SReadOnlyByteSpan(avContent.toPtr(), avContentWritten)));
        size_t avTlvWritten = 0;
        if (!writeEncodedValue(TSpan<uint8_t>(out.begin(), out.size()), EAENC_DER, CTag::SEQ,
                SReadOnlyByteSpan(avContent.toPtr(), avContentWritten), avTlvWritten)) {
            out.clear();
            return false;
        }
        out.resize(avTlvWritten);

        return true;
    }

    /* Builds the full RDNSequence content octets (one RDN per component) for a CDistinguishedName. */
    bool CEncoder::buildDistinguishedNameContent(const CDistinguishedName& value, TArray<uint8_t>& out) {
        out.clear();

        TArray<ENameType> keys;
        value.keys(keys); // ascending ENameType order, per std::map's iteration order.

        for (ENameType type : keys) {
            CName name;
            if (!value.tryGet(type, name)) {
                return false;
            }

            TArray<uint8_t> avTlv;
            if (!buildAttributeTypeAndValue(name, avTlv)) {
                out.clear();
                return false;
            }

            // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue -- exactly one element,
            // since CDistinguishedName only ever holds one CName per ENameType.
            SReadOnlyByteSpan avChild(avTlv.begin(), avTlv.size());
            CBuffer rdnContent(avTlv.size());
            size_t rdnContentWritten = 0;
            if (!writeSequenceOf(TSpan<uint8_t>(rdnContent.toPtr(), rdnContent.size()),
                    TReadOnlySpan<SReadOnlyByteSpan>(&avChild, 1), rdnContentWritten)) {
                out.clear();
                return false;
            }

            CBuffer rdnTlv(encodedValueSize(CTag::SET_OF, SReadOnlyByteSpan(rdnContent.toPtr(), rdnContentWritten)));
            size_t rdnTlvWritten = 0;
            if (!writeEncodedValue(TSpan<uint8_t>(rdnTlv.toPtr(), rdnTlv.size()), EAENC_DER, CTag::SET_OF,
                    SReadOnlyByteSpan(rdnContent.toPtr(), rdnContentWritten), rdnTlvWritten)) {
                out.clear();
                return false;
            }

            // --> TArray has no bulk "append a range" method (unlike std::vector::insert), so
            // grow by the new TLV's length first, then copy it into the freshly-grown tail.
            const size_t oldLen = out.size();
            out.resize(oldLen + rdnTlvWritten);
            std::memcpy(out.begin() + oldLen, rdnTlv.toPtr(), rdnTlvWritten);
        }

        return true;
    }

    /* Computes the number of content octets required to encode a CDistinguishedName. */
    size_t CEncoder::encodedDistinguishedNameSize(const CDistinguishedName& value) {
        TArray<uint8_t> content;
        if (!buildDistinguishedNameContent(value, content)) {
            return 0;
        }

        return content.size();
    }

    /* Encodes a CDistinguishedName into a SEQUENCE's content octets. */
    bool CEncoder::encodeDistinguishedName(
        TSpan<uint8_t> destination,
        const CDistinguishedName& value,
        size_t& bytesWritten
    ) {
        bytesWritten = 0;

        TArray<uint8_t> content;
        if (!buildDistinguishedNameContent(value, content)) {
            return false;
        }

        if (destination.size < content.size()) {
            return false;
        }

        if (!content.empty()) {
            TSpan<uint8_t> dest = destination.slice(0, content.size());
            SReadOnlyByteSpan(content.begin(), content.size()).copyTo(dest);
        }

        bytesWritten = content.size();
        return true;
    }

}
}
