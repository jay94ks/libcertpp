#ifndef __INCLUDE_CERTPP_ASN1_DECODER_HPP__
#define __INCLUDE_CERTPP_ASN1_DECODER_HPP__

#include <certpp/common.hpp>
#include <certpp/time.hpp>
#include <certpp/string.hpp>
#include <certpp/oid.hpp>
#include <certpp/name.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/asn1/tag.hpp>
#include <utility>

namespace certpp {
namespace asn1 {

    /**
     * Represents the ASN.1 encoding rules.
     * EAENC_BER: Basic Encoding Rules
     * EAENC_DER: Distinguished Encoding Rules
     * EAENC_CER: Canonical Encoding Rules
     */
    enum EEncodingRule {
        EAENC_BER = 0,
        EAENC_DER,
        EAENC_CER,
    };

    /**
     * Checks if the given encoding rule is valid.
     * @param ruleSet The encoding rule to check.
     * @return True if the encoding rule is valid; otherwise, false.
     */
    static inline bool checkEncodingRule(EEncodingRule ruleSet) {
        return ruleSet == EAENC_BER || ruleSet == EAENC_DER || ruleSet == EAENC_CER;
    }

    /**
     * The maximum number of content octets a primitive OCTET STRING may have
     * before Canonical Encoding Rules (CER) require it to be re-encoded as a
     * constructed, segmented value instead.
     */
    static constexpr size_t CER_MAX_SEGMENT = 1000;

    /**
     * Checks whether a primitive encoding of the given tag and content length
     * would violate the CER maximum single-segment length. Only meaningful
     * when the active rule set is EAENC_CER.
     * @param tag The tag of the value being encoded/decoded.
     * @param length The content length of the value, in octets.
     * @return True if a CER primitive encoding of this length is prohibited.
     */
    static inline bool exceedsCerSegmentLimit(const CTag& tag, size_t length) {
        return !tag.isConstructed()
            && tag.tagClass() == EATAG_UNIVERSAL
            && tag.value() == uint32_t(EAUTAG_STRING_OCTET)
            && length > CER_MAX_SEGMENT;
    }

    /**
     * Represents the status of the ASN.1 decoder.
     */
    enum EDecoderStatus {
        EDEC_OK = 0,
        EDEC_NEED_MORE,
        EDEC_BAD_ARGS,
        EDEC_INDEFINITE,
        EDEC_RESERVED,
        EDEC_TOO_BIG,
        EDEC_PROHIBITED
    };

    /**
     * Represents an ASN.1 decoder.
     * This provides static methods for decoding ASN.1 data.
     */
    class CERTPP_API CDecoder {
    private:
        /* End-of-contents marker length, in octets, used to terminate an indefinite-length value. */
        static constexpr size_t EOC_ENC_LEN = 2;

        /* Maximum indefinite-length nesting depth, guarding against stack exhaustion on malicious input. */
        static constexpr size_t MAX_NESTING_DEPTH = 64;

        /* Maximum arc count decodeOidString() works with, bounding its fixed-size stack buffer --
         * generous for any realistic OID (X.509 OIDs rarely exceed a dozen arcs). CEncoder's
         * encodeOidString() mirrors this with its own identically-valued constant. */
        static constexpr size_t MAX_OID_TEXT_ARCS = 32;

    private:
        /**
         * Decodes the length of an ASN.1 encoded value from the source span.
         * @param source The source span containing ASN.1 encoded data.
         * @param ruleSet The ASN.1 encoding rule set to use.
         * @param outLength The output length of the encoded value. Only meaningful when the return value is EDEC_OK.
         * @param bytesRead The number of bytes consumed from the source span.
         * @return The status of the decoding operation.
         */
        static EDecoderStatus decodeLength(
            const TReadOnlySpan<uint8_t>& source,
            EEncodingRule ruleSet,
            size_t& outLength,
            size_t& bytesRead
        );

        /**
         * Reads the content octets of an indefinite-length value, by skipping nested
         * encoded values until the end-of-contents (EOC) marker is reached.
         * @param source The source span containing the value's content, starting right after its length octet.
         * @param ruleSet The ASN.1 encoding rule set to use.
         * @param outLength The number of content octets read, excluding the EOC marker.
         * @param bytesRead The total number of bytes consumed, including the EOC marker.
         * @param depth The current indefinite-length nesting depth.
         * @return EDEC_OK if the end-of-contents marker was found; EDEC_NEED_MORE if the source
         *         ran out before it, so that a streaming caller sees a short nested value as
         *         short rather than as malformed; otherwise whatever the nested value failed
         *         with.
         */
        static EDecoderStatus readIndefiniteContent(
            const TReadOnlySpan<uint8_t>& source,
            EEncodingRule ruleSet,
            size_t& outLength,
            size_t& bytesRead,
            size_t depth
        );

        /**
         * Tries to read an encoded ASN.1 value from the source span, tracking nesting depth.
         * @param source The source span containing ASN.1 encoded data.
         * @param ruleSet The ASN.1 encoding rule set to use.
         * @param outTag The output tag of the encoded value.
         * @param outArea The output span containing the encoded value.
         * @param bytesRead The number of bytes consumed from the source span.
         * @param depth The current indefinite-length nesting depth.
         * @return The status of the read; see tryReadEncodedValue().
         */
        static EDecoderStatus readEncodedValue(
            const TReadOnlySpan<uint8_t>& source,
            EEncodingRule ruleSet,
            CTag& outTag,
            TReadOnlySpan<uint8_t>& outArea,
            size_t& bytesRead,
            size_t depth
        );

        /**
         * Decodes one ASN.1 base-128 (varint-style) subidentifier, as used by OBJECT
         * IDENTIFIER content octets, requiring the minimal encoding (no leading all-continuation
         * padding byte).
         * @param source The source span to decode from.
         * @param outValue The decoded subidentifier value.
         * @param bytesRead The number of bytes consumed from the source span.
         * @return True if a subidentifier was successfully decoded; otherwise, false.
         */
        static bool decodeBase128(SReadOnlyByteSpan source, uint32_t& outValue, size_t& bytesRead);

        /**
         * Checks whether the given content is a well-formed UTF8String.
         * @param content The content octets to validate.
         * @return True if content is valid UTF-8; otherwise, false.
         */
        static bool isValidUtf8(SReadOnlyByteSpan content);

        /**
         * Checks whether the given content is a well-formed PrintableString
         * (letters, digits, space, and the ' ( ) + , - . / : = ? characters).
         * @param content The content octets to validate.
         * @return True if every octet is in the PrintableString character set; otherwise, false.
         */
        static bool isValidPrintableString(SReadOnlyByteSpan content);

        /**
         * Parses digitCount ASCII digits from source, starting at offset.
         */
        static bool parseFixedDigits(SReadOnlyByteSpan source, size_t offset, size_t digitCount, uint32_t& outValue);

        /**
         * Validates the calendar fields of an SDateTime, independent of how they were parsed.
         */
        static bool validateTimeFields(const SDateTime& time);

    public:
        /**
         * Tries to read an encoded ASN.1 value from the source span.
         * @param source The source span containing ASN.1 encoded data.
         * @param ruleSet The ASN.1 encoding rule set to use.
         * @param outTag The output tag of the encoded value.
         * @param outArea The output span containing the encoded value.
         * @param bytesRead The number of bytes consumed from the source span.
         * @return True if an encoded value was successfully read; otherwise, false.
         */
        static bool readEncodedValue(
            const TReadOnlySpan<uint8_t>& source,
            EEncodingRule ruleSet,
            CTag& outTag,
            TReadOnlySpan<uint8_t>& outArea,
            size_t& bytesRead
        );

        /**
         * Reads an encoded ASN.1 value, reporting *why* a read did not succeed.
         *
         * The same operation as readEncodedValue() above, which is this call compared against
         * EDEC_OK. It exists because the distinction between a value that is merely incomplete
         * and one that is malformed cannot be recovered from a bool, and a caller feeding bytes
         * in as they arrive -- off a socket, or a stream -- has to make exactly that decision:
         * EDEC_NEED_MORE means read more and call again with a longer span, and every other
         * non-OK status means this input will never parse no matter how much is appended.
         *
         * Note what EDEC_NEED_MORE does not tell you: how many more bytes. The length octets may
         * themselves be the part that is truncated, in which case the total is not yet knowable.
         * @param source The source span containing ASN.1 encoded data.
         * @param ruleSet The ASN.1 encoding rule set to use.
         * @param outTag The output tag of the encoded value. Only meaningful on EDEC_OK.
         * @param outArea The output span containing the encoded value's content. Only meaningful
         *        on EDEC_OK. Note this is the *content*, while bytesRead covers tag, length and
         *        content -- iterating by the span descends into a constructed value, iterating by
         *        bytesRead steps over it.
         * @param bytesRead The number of bytes consumed from the source span. Only meaningful on
         *        EDEC_OK.
         * @return EDEC_OK on success. EDEC_BAD_ARGS for an unknown ruleSet or a tag that cannot
         *         be decoded at all. EDEC_NEED_MORE if the source ends before the value does.
         *         EDEC_RESERVED for the reserved 0xFF length form, EDEC_TOO_BIG for a length (or
         *         an indefinite-length nesting depth) beyond what this decoder will process, and
         *         EDEC_PROHIBITED for an encoding the chosen rule set forbids -- an indefinite
         *         length under DER, or a CER segment over its own limit.
         */
        static EDecoderStatus tryReadEncodedValue(
            const TReadOnlySpan<uint8_t>& source,
            EEncodingRule ruleSet,
            CTag& outTag,
            TReadOnlySpan<uint8_t>& outArea,
            size_t& bytesRead
        );

        /**
         * Reads the next encoded ASN.1 value from a SEQUENCE/SET's content, advancing
         * the cursor past it. Used to iterate a constructed value's members: pass the
         * outArea of an outer readEncodedValue() call, then call this repeatedly until
         * cursor is empty.
         * @param cursor The remaining content to read from; advanced past the value read on success.
         * @param ruleSet The ASN.1 encoding rule set to use.
         * @param outTag The output tag of the encoded value.
         * @param outArea The output span containing the encoded value's content.
         * @return True if a value was successfully read; false on a parse error or if cursor was empty.
         */
        static bool readNextElement(
            TReadOnlySpan<uint8_t>& cursor,
            EEncodingRule ruleSet,
            CTag& outTag,
            TReadOnlySpan<uint8_t>& outArea
        );

        /**
         * Decodes a BOOLEAN's content octets.
         * @param content The content octets (exactly 1 octet).
         * @param ruleSet The ASN.1 encoding rule set to use; EAENC_DER/EAENC_CER require the
         * canonical 0x00 (false) / 0xFF (true) values, while EAENC_BER accepts any octet.
         * @param outValue The decoded value.
         * @return True if content was a valid BOOLEAN encoding; otherwise, false.
         */
        static bool decodeBoolean(SReadOnlyByteSpan content, EEncodingRule ruleSet, bool& outValue);

        /**
         * Decodes an INTEGER's content octets into a 64-bit signed integer.
         * @param content The content octets (a minimal-length two's-complement big-endian integer).
         * @param outValue The decoded value.
         * @return True if content was a valid INTEGER encoding representable in an int64_t; otherwise, false.
         */
        static bool decodeInteger(SReadOnlyByteSpan content, int64_t& outValue);

        /**
         * Decodes an ENUMERATED's content octets into a 32-bit unsigned integer.
         * @param content The content octets (encoded identically to INTEGER).
         * @param outValue The decoded value.
         * @return True if content was a valid, non-negative ENUMERATED encoding representable in a uint32_t; otherwise, false.
         */
        static bool decodeEnumerated(SReadOnlyByteSpan content, uint32_t& outValue);

        /**
         * Validates a NULL's content octets.
         * @param content The content octets (must be empty).
         * @return True if content was a valid NULL encoding; otherwise, false.
         */
        static bool decodeNull(SReadOnlyByteSpan content);

        /**
         * Decodes an OCTET STRING's content octets. Any byte sequence is valid, so this
         * is a validating pass-through, provided for symmetry with the other decode*() methods.
         * @param content The content octets.
         * @param outValue The decoded value (aliases content).
         * @return Always true.
         */
        static bool decodeOctetString(SReadOnlyByteSpan content, SReadOnlyByteSpan& outValue);

        /**
         * Decodes an OCTET STRING's content octets into an owning COctet, copying the content
         * rather than aliasing it like the SReadOnlyByteSpan overload does.
         * @param content The content octets.
         * @param outValue The decoded value, replacing any content it previously held.
         * @return True if content was successfully copied into outValue; otherwise, false.
         */
        static bool decodeOctetString(SReadOnlyByteSpan content, COctet& outValue);

        /**
         * Decodes a BIT STRING's content octets.
         * @param content The content octets (an unused-bit count octet followed by the packed bits).
         * @param outBits The packed bit data octets (aliases content, excluding the unused-bit count octet).
         * @param outUnusedBits The number of unused (padding) bits in the last octet of outBits (0-7).
         * @return True if content was a valid BIT STRING encoding (including that any padding bits are zero); otherwise, false.
         */
        static bool decodeBitString(SReadOnlyByteSpan content, SReadOnlyByteSpan& outBits, uint8_t& outUnusedBits);

        /**
         * Decodes a BIT STRING's content octets into an owning COctet, copying the packed bit
         * data rather than aliasing it like the SReadOnlyByteSpan overload does.
         * @param content The content octets (an unused-bit count octet followed by the packed bits).
         * @param outBits The decoded packed bit data, replacing any content it previously held.
         * @param outUnusedBits The number of unused (padding) bits in the last octet of outBits (0-7).
         * @return True if content was a valid BIT STRING encoding and was successfully copied
         * into outBits; otherwise, false.
         */
        static bool decodeBitString(SReadOnlyByteSpan content, COctet& outBits, uint8_t& outUnusedBits);

        /**
         * Tests a single named bit of a BIT STRING used as a NamedBitList (e.g. X.509's
         * KeyUsage). A bit beyond the encoded content is implicitly unset, per X.690 22.5.
         * @param content The BIT STRING's content octets.
         * @param bitIndex The zero-based named bit position to test.
         * @return True if content was a valid BIT STRING and bitIndex is set; otherwise, false.
         */
        static bool testNamedBit(SReadOnlyByteSpan content, uint32_t bitIndex);

        /**
         * Counts the number of subidentifiers (arcs) an OBJECT IDENTIFIER's content
         * decodes to, so a caller can size the buffer passed to decodeOid().
         * @param content The content octets.
         * @return The arc count, or 0 if content is not a valid OBJECT IDENTIFIER encoding.
         */
        static size_t countOidArcs(SReadOnlyByteSpan content);

        /**
         * Decodes an OBJECT IDENTIFIER's content octets into its arc values.
         * @param content The content octets.
         * @param outArcs The destination for the decoded arc values; must be at least countOidArcs(content) long.
         * @param outArcCount The number of arcs written to outArcs.
         * @return True if content was a valid OBJECT IDENTIFIER encoding that fit in outArcs; otherwise, false.
         */
        static bool decodeOid(SReadOnlyByteSpan content, TSpan<uint32_t> outArcs, size_t& outArcCount);

        /**
         * Decodes an OBJECT IDENTIFIER's content octets into an SRawOid.
         *
         * This is the form the rest of the library should reach for. SRawOid carries both the
         * arcs and, on demand, their dotted-decimal text, so a caller that keeps an OID as a
         * COid can decode straight into it without the text detour that decodeOidString()
         * forces -- and without a second formatter that could drift from SRawOid::toString().
         * @param content The content octets.
         * @param outOid Receives the decoded OID. Left empty if this returns false.
         * @return True if content was a valid OBJECT IDENTIFIER encoding that fit in
         * SRawOid::MAX_OID_ARCS arcs; otherwise, false.
         */
        static bool decodeOid(SReadOnlyByteSpan content, SRawOid& outOid);

        /**
         * Decodes an OBJECT IDENTIFIER's content octets directly into its dotted-decimal text
         * form (e.g. "1.2.840.113549.1.1.1"), rather than a raw arc array. Only ever produces
         * ASCII digits and '.' separators, so unlike decodeString() this is locale-independent
         * for both TChar=char and TChar=wchar_t -- it never goes through TUtf8Encoding.
         *
         * Formatted by SRawOid::toString() rather than by a loop of its own. This used to carry
         * one, and having two formatters for the same value is exactly how they come to disagree
         * about the same OID -- which is what happened between CName's DN table and the OID it
         * was supposed to be describing.
         * @tparam TChar The destination TString's character type (char or wchar_t).
         * @param content The content octets.
         * @param outValue The decoded dotted-decimal text. Left unchanged if this returns false.
         * @return True if content was a valid OBJECT IDENTIFIER encoding with at most
         * SRawOid::MAX_OID_ARCS arcs and was successfully formatted; otherwise, false.
         */
        template<typename TChar>
        static bool decodeOidString(SReadOnlyByteSpan content, TString<TChar>& outValue) {
            SRawOid oid;
            if (!decodeOid(content, oid)) {
                return false;
            }

            // --> SRawOid::toString() always produces ASCII digits and '.', so for either
            // character type the answer is the narrow string widened if necessary -- and going
            // through the one formatter is the point, since this used to carry a second copy of
            // the digit loop that could disagree with it about the same OID.
            CString narrow;
            oid.toString(narrow);

            outValue.clear();
            outValue.append(narrow);
            return true;
        }

        /**
         * Decodes/validates a character string type's content octets.
         * @param content The content octets.
         * @param kind The universal string tag (EAUTAG_STRING_UTF8, EAUTAG_STRING_P, EAUTAG_STRING_IA5,
         * or EAUTAG_STRING_N get their character set validated; any other tag is passed through unvalidated).
         * @param outText The decoded text (aliases content).
         * @return True if content is valid for kind's character set; otherwise, false.
         */
        static bool decodeText(SReadOnlyByteSpan content, EUniversalTags kind, SReadOnlyByteSpan& outText);

        /**
         * Decodes/validates a character string type's content octets directly into a TString,
         * rather than a raw byte span. Validates via decodeText() (so the same kinds get their
         * character set checked), then transcodes the validated bytes into TChar through
         * TUtf8Encoding<TChar> -- valid for any kind, since a kind whose charset decodeText()
         * restricts to plain ASCII (PrintableString, IA5String, NumericString) is inherently
         * already valid UTF-8 too (ASCII is a byte-identical subset of UTF-8).
         *
         * TChar=wchar_t transcodes genuine UTF-8 regardless of the process locale. TChar=char
         * instead goes through TUtf8Encoding<char>, which treats char as native-locale text (not
         * raw UTF-8) -- so non-ASCII content only round-trips correctly under a UTF-8-compatible
         * locale; under "C", only the ASCII subset decodes as expected.
         * @tparam TChar The destination TString's character type (char or wchar_t).
         * @param content The content octets.
         * @param kind The universal string tag; see decodeText() for which kinds get validated.
         * @param outValue The decoded string. Left unchanged if this returns false.
         * @return True if content is valid for kind's character set and was successfully
         * transcoded to TChar; otherwise, false.
         */
        template<typename TChar>
        static bool decodeString(SReadOnlyByteSpan content, EUniversalTags kind, TString<TChar>& outValue) {
            SReadOnlyByteSpan validated;
            if (!decodeText(content, kind, validated)) {
                return false;
            }

            if (validated.empty()) {
                outValue.clear();
                return true;
            }

            // --> Upper bound: decoding never produces more TChar units than input octets, since
            // every TUtf8Encoding<TChar> specialization consumes at least 1 octet per output unit.
            TString<TChar> result;
            if (!result.resize(validated.size)) {
                return false;
            }

            TSpan<TChar> dst = result.toSpan();
            size_t decoded = TUtf8Encoding<TChar>::get().decodeFrom(dst, validated);
            if (!decoded) {
                return false;
            }

            if (!result.resize(decoded)) {
                return false;
            }

            outValue = std::move(result);
            return true;
        }

        /**
         * Decodes a UTCTime's content octets (the DER-canonical "YYMMDDHHMMSSZ" form).
         * @param content The content octets (exactly 13 bytes).
         * @param outTime The decoded time.
         * @return True if content was a valid UTCTime encoding; otherwise, false.
         */
        static bool decodeUtcTime(SReadOnlyByteSpan content, SDateTime& outTime);

        /**
         * Decodes a GeneralizedTime's content octets (the "YYYYMMDDHHMMSS[.fff]Z" form).
         * @param content The content octets.
         * @param outTime The decoded time.
         * @return True if content was a valid GeneralizedTime encoding; otherwise, false.
         */
        static bool decodeGeneralizedTime(SReadOnlyByteSpan content, SDateTime& outTime);

        /**
         * Decodes a CDistinguishedName (X.501 Name/RDNSequence) from a SEQUENCE's content
         * octets, i.e. the content of an outer SEQUENCE tag-length-value (see CReader's
         * readDistinguishedName() for reading that outer tag from a stream too).
         *
         * Each content element must be a SET (RelativeDistinguishedName) containing exactly one
         * AttributeTypeAndValue -- a multi-valued RDN is rejected, since CDistinguishedName only
         * ever holds one CName per ENameType. Each AttributeTypeAndValue's type must be one of
         * the X.520 OIDs CName::attributeTypeOf() recognizes, and its value must be a
         * PrintableString or UTF8String (the two kinds CEncoder::encodeDistinguishedName() ever
         * writes); any other structure or value kind fails the decode.
         *
         * Always applies DER's encoding rules, regardless of the enclosing document's rule set
         * -- in practice, X.501 Names are encoded with DER even inside a BER/CER document.
         * @param content The content octets of the outer SEQUENCE (RDNSequence).
         * @param outValue The decoded distinguished name, replacing any content it previously
         * held. Left unchanged if this returns false.
         * @return True if content was a valid, supported RDNSequence encoding; otherwise, false.
         */
        static bool decodeDistinguishedName(SReadOnlyByteSpan content, CDistinguishedName& outValue);
    };

} // namespace asn1
} // namespace certpp

#endif
