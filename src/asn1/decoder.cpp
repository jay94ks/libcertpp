#include <certpp/asn1/decoder.hpp>

namespace certpp {
namespace asn1 {

    /* Decodes the length of an ASN.1 encoded value from the source span. */
    EDecoderStatus CDecoder::decodeLength(
        const TReadOnlySpan<uint8_t>& source,
        EEncodingRule ruleSet,
        size_t& outLength,
        size_t& bytesRead
    ) {
        bytesRead = 0;

        if (!checkEncodingRule(ruleSet)) {
            return EDEC_BAD_ARGS;
        }

        if (source.empty()) {
            return EDEC_NEED_MORE;
        }

        constexpr uint8_t LONG_FORM = 0x80;
        constexpr uint8_t OCTET_COUNT_MASK = 0x7F;

        uint8_t first = source[0];

        // --> Short form: bit 8 is 0, bits 7-1 directly encode the length.
        if ((first & LONG_FORM) == 0) {
            outLength = first;
            bytesRead = 1;
            return EDEC_OK;
        }

        uint8_t octetCount = first & OCTET_COUNT_MASK;

        // --> Indefinite length form: valid under BER/CER, forbidden under DER.
        if (octetCount == 0) {
            if (ruleSet == EAENC_DER) {
                return EDEC_PROHIBITED;
            }

            bytesRead = 1;
            return EDEC_INDEFINITE;
        }

        // --> 0x7F (127 subsequent octets) is reserved by the standard.
        if (octetCount == OCTET_COUNT_MASK) {
            return EDEC_RESERVED;
        }

        if (source.size < size_t(1) + octetCount) {
            return EDEC_NEED_MORE;
        }

        // --> CER/DER require the minimum number of octets (no leading 0x00 padding).
        bool minimal = ruleSet == EAENC_CER || ruleSet == EAENC_DER;
        if (minimal && source[1] == 0) {
            return EDEC_PROHIBITED;
        }

        if (octetCount > sizeof(size_t)) {
            return EDEC_TOO_BIG;
        }

        size_t result = 0;
        for (uint8_t i = 0; i < octetCount; ++i) {
            result = (result << 8) | source[1 + i];
        }

        // --> A definite length below 128 must use the short form under CER/DER.
        if (minimal && result < LONG_FORM) {
            return EDEC_PROHIBITED;
        }

        outLength = result;
        bytesRead = size_t(1) + octetCount;
        return EDEC_OK;
    }

    /* Reads the content octets of an indefinite-length value by skipping nested values until EOC. */
    bool CDecoder::readIndefiniteContent(
        const TReadOnlySpan<uint8_t>& source,
        EEncodingRule ruleSet,
        size_t& outLength,
        size_t& bytesRead,
        size_t depth
    ) {
        size_t offset = 0;

        while (true) {
            auto remaining = source.slice(offset);

            if (remaining.size < EOC_ENC_LEN) {
                return false;
            }

            // --> End-of-contents marker: tag 0x00, length 0x00.
            if (remaining[0] == 0 && remaining[1] == 0) {
                outLength = offset;
                bytesRead = offset + EOC_ENC_LEN;
                return true;
            }

            CTag nestedTag;
            TReadOnlySpan<uint8_t> nestedArea;
            size_t nestedBytesRead = 0;

            if (!readEncodedValue(remaining, ruleSet, nestedTag, nestedArea, nestedBytesRead, depth)) {
                return false;
            }

            offset += nestedBytesRead;
        }
    }

    /* Tries to read an encoded ASN.1 value from the source span, tracking nesting depth. */
    bool CDecoder::readEncodedValue(
        const TReadOnlySpan<uint8_t>& source,
        EEncodingRule ruleSet,
        CTag& outTag,
        TReadOnlySpan<uint8_t>& outArea,
        size_t& bytesRead,
        size_t depth
    ) {
        bytesRead = 0;

        if (!checkEncodingRule(ruleSet)) {
            return false;
        }

        size_t tagLength = 0;
        CTag localTag = CTag::decode(source, tagLength);
        if (!localTag) {
            return false;
        }

        auto afterTag = source.slice(tagLength);
        size_t length = 0, lengthBytes = 0;
        EDecoderStatus status = decodeLength(afterTag, ruleSet, length, lengthBytes);
        size_t headerLength = tagLength + lengthBytes;
        auto afterLength = afterTag.slice(lengthBytes);

        if (status == EDEC_OK) {
            if (ruleSet == EAENC_CER && exceedsCerSegmentLimit(localTag, length)) {
                return false;
            }

            if (afterLength.size < length) {
                return false;
            }

            outTag = localTag;
            outArea = afterLength.slice(0, length);
            bytesRead = headerLength + length;
            return true;
        }

        if (status != EDEC_INDEFINITE) {
            return false;
        }

        // --> Only BER/CER reach here; DER indefinite length is rejected as EDEC_PROHIBITED above.
        if (depth >= MAX_NESTING_DEPTH) {
            return false;
        }

        size_t contentLength = 0, contentBytesRead = 0;
        if (!readIndefiniteContent(afterLength, ruleSet, contentLength, contentBytesRead, depth + 1)) {
            return false;
        }

        outTag = localTag;
        outArea = afterLength.slice(0, contentLength);
        bytesRead = headerLength + contentBytesRead;
        return true;
    }

    /* Tries to read an encoded ASN.1 value from the source span. */
    bool CDecoder::readEncodedValue(
        const TReadOnlySpan<uint8_t>& source,
        EEncodingRule ruleSet,
        CTag& outTag,
        TReadOnlySpan<uint8_t>& outArea,
        size_t& bytesRead
    ) {
        return readEncodedValue(source, ruleSet, outTag, outArea, bytesRead, 0);
    }

    /* Reads the next encoded ASN.1 value from a SEQUENCE/SET's content, advancing the cursor past it. */
    bool CDecoder::readNextElement(
        TReadOnlySpan<uint8_t>& cursor,
        EEncodingRule ruleSet,
        CTag& outTag,
        TReadOnlySpan<uint8_t>& outArea
    ) {
        size_t bytesRead = 0;
        if (!readEncodedValue(cursor, ruleSet, outTag, outArea, bytesRead)) {
            return false;
        }

        cursor = cursor.slice(bytesRead);
        return true;
    }

    /* Decodes one ASN.1 base-128 subidentifier, requiring the minimal encoding. */
    bool CDecoder::decodeBase128(SReadOnlyByteSpan source, uint32_t& outValue, size_t& bytesRead) {
        bytesRead = 0;

        if (source.empty()) {
            return false;
        }

        // --> A leading 0x80 byte would only be valid if a shorter encoding existed, i.e. never.
        if (source[0] == 0x80) {
            return false;
        }

        uint32_t value = 0;
        for (size_t i = 0; i < source.size; ++i) {
            uint8_t b = source[i];

            // --> Reject if the next shift would overflow a uint32_t.
            if (value > (0xFFFFFFFFu >> 7)) {
                return false;
            }

            value = (value << 7) | uint32_t(b & 0x7F);
            bytesRead++;

            if ((b & 0x80) == 0) {
                outValue = value;
                return true;
            }
        }

        bytesRead = 0;
        return false;
    }

    /* Checks whether the given content is a well-formed UTF8String. */
    bool CDecoder::isValidUtf8(SReadOnlyByteSpan content) {
        size_t i = 0;

        while (i < content.size) {
            uint8_t b0 = content[i];

            // --> 1-octet form: 0xxxxxxx.
            if (b0 < 0x80) {
                i += 1;
                continue;
            }

            size_t extra;
            uint32_t codepoint;
            uint32_t minCodepoint;

            if ((b0 & 0xE0) == 0xC0) {
                extra = 1;
                codepoint = b0 & 0x1F;
                minCodepoint = 0x80;
            } else if ((b0 & 0xF0) == 0xE0) {
                extra = 2;
                codepoint = b0 & 0x0F;
                minCodepoint = 0x800;
            } else if ((b0 & 0xF8) == 0xF0) {
                extra = 3;
                codepoint = b0 & 0x07;
                minCodepoint = 0x10000;
            } else {
                return false;
            }

            if (i + extra >= content.size) {
                return false;
            }

            for (size_t k = 1; k <= extra; ++k) {
                uint8_t b = content[i + k];
                if ((b & 0xC0) != 0x80) {
                    return false;
                }

                codepoint = (codepoint << 6) | uint32_t(b & 0x3F);
            }

            // --> Reject overlong encodings, surrogate halves, and codepoints beyond U+10FFFF.
            if (codepoint < minCodepoint || (codepoint >= 0xD800 && codepoint <= 0xDFFF) || codepoint > 0x10FFFF) {
                return false;
            }

            i += extra + 1;
        }

        return true;
    }

    /* Checks whether the given content is a well-formed PrintableString. */
    bool CDecoder::isValidPrintableString(SReadOnlyByteSpan content) {
        for (size_t i = 0; i < content.size; ++i) {
            uint8_t c = content[i];

            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
            if (!ok) {
                switch (c) {
                    case ' ': case '\'': case '(': case ')': case '+': case ',':
                    case '-': case '.': case '/': case ':': case '=': case '?':
                        ok = true;
                        break;
                    default:
                        break;
                }
            }

            if (!ok) {
                return false;
            }
        }

        return true;
    }

    /* Decodes a BOOLEAN's content octets. */
    bool CDecoder::decodeBoolean(SReadOnlyByteSpan content, EEncodingRule ruleSet, bool& outValue) {
        if (!checkEncodingRule(ruleSet) || content.size != 1) {
            return false;
        }

        uint8_t b = content[0];
        bool canonical = ruleSet == EAENC_DER || ruleSet == EAENC_CER;

        if (canonical && b != 0x00 && b != 0xFF) {
            return false;
        }

        outValue = b != 0x00;
        return true;
    }

    /* Decodes an INTEGER's content octets into a 64-bit signed integer. */
    bool CDecoder::decodeInteger(SReadOnlyByteSpan content, int64_t& outValue) {
        if (content.empty() || content.size > sizeof(int64_t)) {
            return false;
        }

        // --> Minimal encoding: the first octet must not be a redundant sign-extension of the second.
        if (content.size > 1) {
            uint8_t first = content[0];
            uint8_t second = content[1];

            bool redundant = (first == 0x00 && (second & 0x80) == 0)
                || (first == 0xFF && (second & 0x80) != 0);

            if (redundant) {
                return false;
            }
        }

        uint64_t magnitude = (content[0] & 0x80) ? ~uint64_t(0) : 0;
        for (size_t i = 0; i < content.size; ++i) {
            magnitude = (magnitude << 8) | uint64_t(content[i]);
        }

        outValue = static_cast<int64_t>(magnitude);
        return true;
    }

    /* Decodes an ENUMERATED's content octets into a 32-bit unsigned integer. */
    bool CDecoder::decodeEnumerated(SReadOnlyByteSpan content, uint32_t& outValue) {
        int64_t value = 0;
        if (!decodeInteger(content, value)) {
            return false;
        }

        if (value < 0 || value > int64_t(0xFFFFFFFFu)) {
            return false;
        }

        outValue = uint32_t(value);
        return true;
    }

    /* Validates a NULL's content octets. */
    bool CDecoder::decodeNull(SReadOnlyByteSpan content) {
        return content.empty();
    }

    /* Decodes an OCTET STRING's content octets. */
    bool CDecoder::decodeOctetString(SReadOnlyByteSpan content, SReadOnlyByteSpan& outValue) {
        outValue = content;
        return true;
    }

    /* Decodes an OCTET STRING's content octets into an owning COctet. */
    bool CDecoder::decodeOctetString(SReadOnlyByteSpan content, COctet& outValue) {
        if (content.empty()) {
            outValue.clear();
            return true;
        }

        return outValue.store(content.data, content.size);
    }

    /* Decodes a BIT STRING's content octets. */
    bool CDecoder::decodeBitString(SReadOnlyByteSpan content, SReadOnlyByteSpan& outBits, uint8_t& outUnusedBits) {
        if (content.empty()) {
            return false;
        }

        uint8_t unusedBits = content[0];
        if (unusedBits > 7) {
            return false;
        }

        SReadOnlyByteSpan bits = content.slice(1);

        if (bits.empty()) {
            if (unusedBits != 0) {
                return false;
            }
        } else if (unusedBits != 0) {
            // --> Padding bits (the low unusedBits bits of the last octet) must be zero.
            uint8_t mask = uint8_t((1u << unusedBits) - 1);
            if (bits[bits.size - 1] & mask) {
                return false;
            }
        }

        outBits = bits;
        outUnusedBits = unusedBits;
        return true;
    }

    /* Decodes a BIT STRING's content octets into an owning COctet. */
    bool CDecoder::decodeBitString(SReadOnlyByteSpan content, COctet& outBits, uint8_t& outUnusedBits) {
        SReadOnlyByteSpan bits;
        if (!decodeBitString(content, bits, outUnusedBits)) {
            return false;
        }

        if (bits.empty()) {
            outBits.clear();
            return true;
        }

        return outBits.store(bits.data, bits.size);
    }

    /* Tests a single named bit of a BIT STRING used as a NamedBitList. */
    bool CDecoder::testNamedBit(SReadOnlyByteSpan content, uint32_t bitIndex) {
        SReadOnlyByteSpan bits;
        uint8_t unusedBits = 0;

        if (!decodeBitString(content, bits, unusedBits)) {
            return false;
        }

        size_t byteIndex = bitIndex / 8;
        if (byteIndex >= bits.size) {
            return false;
        }

        uint8_t mask = uint8_t(0x80 >> (bitIndex % 8));
        return (bits[byteIndex] & mask) != 0;
    }

    /* Counts the number of subidentifiers an OBJECT IDENTIFIER's content decodes to. */
    size_t CDecoder::countOidArcs(SReadOnlyByteSpan content) {
        if (content.empty()) {
            return 0;
        }

        size_t offset = 0;
        size_t count = 0;
        bool first = true;

        while (offset < content.size) {
            uint32_t value = 0;
            size_t bytesRead = 0;

            if (!decodeBase128(content.slice(offset), value, bytesRead)) {
                return 0;
            }

            offset += bytesRead;
            count += first ? 2 : 1;
            first = false;
        }

        return count;
    }

    /* Decodes an OBJECT IDENTIFIER's content octets into its arc values. */
    bool CDecoder::decodeOid(SReadOnlyByteSpan content, TSpan<uint32_t> outArcs, size_t& outArcCount) {
        outArcCount = 0;

        if (content.empty()) {
            return false;
        }

        size_t offset = 0;
        bool first = true;

        while (offset < content.size) {
            uint32_t value = 0;
            size_t bytesRead = 0;

            if (!decodeBase128(content.slice(offset), value, bytesRead)) {
                return false;
            }

            offset += bytesRead;

            if (first) {
                uint32_t arc0, arc1;
                if (value < 40) {
                    arc0 = 0;
                    arc1 = value;
                } else if (value < 80) {
                    arc0 = 1;
                    arc1 = value - 40;
                } else {
                    arc0 = 2;
                    arc1 = value - 80;
                }

                if (outArcs.size < 2) {
                    return false;
                }

                outArcs[0] = arc0;
                outArcs[1] = arc1;
                outArcCount = 2;
                first = false;
            } else {
                if (outArcCount >= outArcs.size) {
                    return false;
                }

                outArcs[outArcCount++] = value;
            }
        }

        return true;
    }

    /* Decodes/validates a character string type's content octets. */
    bool CDecoder::decodeText(SReadOnlyByteSpan content, EUniversalTags kind, SReadOnlyByteSpan& outText) {
        switch (kind) {
            case EAUTAG_STRING_UTF8:
                if (!isValidUtf8(content)) {
                    return false;
                }
                break;

            case EAUTAG_STRING_P:
                if (!isValidPrintableString(content)) {
                    return false;
                }
                break;

            case EAUTAG_STRING_IA5:
                for (size_t i = 0; i < content.size; ++i) {
                    if (content[i] & 0x80) {
                        return false;
                    }
                }
                break;

            case EAUTAG_STRING_N:
                for (size_t i = 0; i < content.size; ++i) {
                    uint8_t c = content[i];
                    if (!((c >= '0' && c <= '9') || c == ' ')) {
                        return false;
                    }
                }
                break;

            default:
                break;
        }

        outText = content;
        return true;
    }

    /* Parses `digitCount` ASCII digits from source, starting at offset. */
    bool CDecoder::ParseFixedDigits(SReadOnlyByteSpan source, size_t offset, size_t digitCount, uint32_t& outValue) {
        if (offset + digitCount > source.size) {
            return false;
        }

        uint32_t value = 0;
        for (size_t i = 0; i < digitCount; ++i) {
            uint8_t c = source[offset + i];
            if (c < '0' || c > '9') {
                return false;
            }

            value = value * 10 + uint32_t(c - '0');
        }

        outValue = value;
        return true;
    }

    /* Validates the calendar fields of an SDateTime, independent of how they were parsed. */
    bool CDecoder::ValidateTimeFields(const SDateTime& time) {
        constexpr uint8_t DAYS_IN_MONTH[12] = { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

        if (time.month < 1 || time.month > 12) {
            return false;
        }

        bool isLeapYear = (time.year % 4 == 0 && time.year % 100 != 0) || (time.year % 400 == 0);
        uint8_t maxDay = DAYS_IN_MONTH[time.month - 1];
        if (time.month == 2 && !isLeapYear) {
            maxDay = 28;
        }

        if (time.day < 1 || time.day > maxDay) {
            return false;
        }

        return time.hour <= 23 && time.minute <= 59 && time.second <= 59;
    }

    /* Decodes a UTCTime's content octets (the DER-canonical "YYMMDDHHMMSSZ" form). */
    bool CDecoder::decodeUtcTime(SReadOnlyByteSpan content, SDateTime& outTime) {
        constexpr size_t LENGTH = 13;

        if (content.size != LENGTH || content[LENGTH - 1] != 'Z') {
            return false;
        }

        uint32_t yy, month, day, hour, minute, second;
        if (!ParseFixedDigits(content, 0, 2, yy)
            || !ParseFixedDigits(content, 2, 2, month)
            || !ParseFixedDigits(content, 4, 2, day)
            || !ParseFixedDigits(content, 6, 2, hour)
            || !ParseFixedDigits(content, 8, 2, minute)
            || !ParseFixedDigits(content, 10, 2, second)) {
            return false;
        }

        SDateTime time;
        time.year = uint16_t((yy >= 50 ? 1900 : 2000) + yy);
        time.month = uint8_t(month);
        time.day = uint8_t(day);
        time.hour = uint8_t(hour);
        time.minute = uint8_t(minute);
        time.second = uint8_t(second);
        time.millisecond = 0;
        time.isUtc = true;

        if (!ValidateTimeFields(time)) {
            return false;
        }

        outTime = time;
        return true;
    }

    /* Decodes a GeneralizedTime's content octets (the "YYYYMMDDHHMMSS[.fff]Z" form). */
    bool CDecoder::decodeGeneralizedTime(SReadOnlyByteSpan content, SDateTime& outTime) {
        constexpr size_t MIN_LENGTH = 15; // YYYYMMDDHHMMSSZ

        if (content.size < MIN_LENGTH || content[content.size - 1] != 'Z') {
            return false;
        }

        uint32_t year, month, day, hour, minute, second;
        if (!ParseFixedDigits(content, 0, 4, year)
            || !ParseFixedDigits(content, 4, 2, month)
            || !ParseFixedDigits(content, 6, 2, day)
            || !ParseFixedDigits(content, 8, 2, hour)
            || !ParseFixedDigits(content, 10, 2, minute)
            || !ParseFixedDigits(content, 12, 2, second)) {
            return false;
        }

        size_t fractionStart = 14;
        size_t fractionEnd = content.size - 1; // exclude trailing 'Z'
        uint32_t millisecond = 0;

        if (fractionStart != fractionEnd) {
            if (content[fractionStart] != '.') {
                return false;
            }

            size_t digitsStart = fractionStart + 1;
            size_t digitCount = fractionEnd - digitsStart;

            // --> DER forbids an empty or trailing-zero fractional part.
            if (digitCount == 0 || content[fractionEnd - 1] == '0') {
                return false;
            }

            uint32_t fraction = 0;
            for (size_t i = 0; i < digitCount; ++i) {
                uint8_t c = content[digitsStart + i];
                if (c < '0' || c > '9') {
                    return false;
                }

                // --> Only the first 3 fractional digits are kept (millisecond precision).
                if (i < 3) {
                    fraction = fraction * 10 + uint32_t(c - '0');
                }
            }

            for (size_t i = digitCount; i < 3; ++i) {
                fraction *= 10;
            }

            millisecond = fraction;
        }

        SDateTime time;
        time.year = uint16_t(year);
        time.month = uint8_t(month);
        time.day = uint8_t(day);
        time.hour = uint8_t(hour);
        time.minute = uint8_t(minute);
        time.second = uint8_t(second);
        time.millisecond = uint16_t(millisecond);
        time.isUtc = true;

        if (!ValidateTimeFields(time)) {
            return false;
        }

        outTime = time;
        return true;
    }

    /* Decodes a CDistinguishedName (X.501 Name/RDNSequence) from a SEQUENCE's content octets. */
    bool CDecoder::decodeDistinguishedName(SReadOnlyByteSpan content, CDistinguishedName& outValue) {
        CDistinguishedName result;
        TReadOnlySpan<uint8_t> cursor = content;

        while (!cursor.empty()) {
            CTag rdnTag;
            TReadOnlySpan<uint8_t> rdnContent;

            if (!readNextElement(cursor, EAENC_DER, rdnTag, rdnContent) || rdnTag != CTag::SET_OF) {
                return false; // Not a well-formed RelativeDistinguishedName (SET).
            }

            // RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue -- this
            // library's CDistinguishedName only ever holds one value per attribute type, so a
            // multi-valued RDN isn't representable and is rejected outright, rather than
            // silently keeping only the first AttributeTypeAndValue and dropping the rest.
            TReadOnlySpan<uint8_t> rdnCursor = rdnContent;

            CTag avTag;
            TReadOnlySpan<uint8_t> avContent;

            if (!readNextElement(rdnCursor, EAENC_DER, avTag, avContent) || avTag != CTag::SEQ) {
                return false; // Not a well-formed AttributeTypeAndValue (SEQUENCE).
            }

            if (!rdnCursor.empty()) {
                return false; // Multi-valued RDN; unsupported.
            }

            // AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY }
            TReadOnlySpan<uint8_t> avCursor = avContent;

            CTag oidTag;
            TReadOnlySpan<uint8_t> oidContent;

            if (!readNextElement(avCursor, EAENC_DER, oidTag, oidContent) || oidTag != CTag::OBJ_ID) {
                return false;
            }

            const size_t oidArcs = countOidArcs(oidContent);
            if (!oidArcs || oidArcs > CName::MAX_OID_ARCS) {
                return false; // Longer than any DN attribute OID CName::attributeTypeOf() knows.
            }

            uint32_t arcs[CName::MAX_OID_ARCS];
            size_t arcCount = 0;

            if (!decodeOid(oidContent, TSpan<uint32_t>(arcs, CName::MAX_OID_ARCS), arcCount)
                || arcCount != oidArcs)
            {
                return false;
            }

            ENameType type = CName::attributeTypeOf(TReadOnlySpan<uint32_t>(arcs, arcCount));
            if (type == ENAME_NONE) {
                return false; // Unrecognized attribute type OID.
            }

            CTag valueTag;
            TReadOnlySpan<uint8_t> valueContent;

            if (!readNextElement(avCursor, EAENC_DER, valueTag, valueContent) || !avCursor.empty()) {
                return false; // Missing value, or trailing content after it.
            }

            // Only accept the three kinds CEncoder::encodeDistinguishedName() ever writes:
            // PrintableString/UTF8String for every attribute, plus IA5String, which is
            // domainComponent's own mandatory syntax (RFC 4519 2.4).
            if (valueTag != CTag(EAUTAG_STRING_P, false)
                && valueTag != CTag(EAUTAG_STRING_UTF8, false)
                && valueTag != CTag(EAUTAG_STRING_IA5, false))
            {
                return false;
            }

            CWideString text;
            if (!decodeString(valueContent, EUniversalTags(valueTag.value()), text)) {
                return false;
            }

            const CString narrow = text.convertTo<char>();
            CName name(type, narrow.toPtr(), narrow.size());

            if (name.empty() || !result.trySet(name, true)) {
                return false;
            }
        }

        outValue = std::move(result);
        return true;
    }

}
}
