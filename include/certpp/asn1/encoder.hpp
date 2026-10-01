#ifndef __INCLUDE_CERTPP_ASN1_ENCODER_HPP__
#define __INCLUDE_CERTPP_ASN1_ENCODER_HPP__

#include <certpp/common.hpp>
#include <certpp/time.hpp>
#include <certpp/string.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/io/array.hpp>
#include <certpp/asn1/tag.hpp>
#include <certpp/asn1/decoder.hpp>

namespace certpp {
namespace asn1 {

    /**
     * Represents an ASN.1 encoder.
     * This provides static methods for encoding ASN.1 data using definite-length form.
     */
    class CERTPP_API CEncoder {
    private:
        /**
         * Writes digitCount decimal digits of value (assumed to fit) starting at offset.
         */
        static void WriteFixedDigits(TSpan<uint8_t> destination, size_t offset, size_t digitCount, uint32_t value);

        /**
         * Computes the number of octets a length value occupies when encoded in ASN.1 definite-length form.
         * @param length The length value to measure.
         * @return The number of octets required to encode the length.
         */
        static size_t encodedLengthSize(size_t length);

        /**
         * Encodes a length value into the destination span using ASN.1 definite-length form.
         * @param destination The destination span to write the encoded length into.
         * @param length The length value to encode.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if the length was successfully encoded; otherwise, false.
         */
        static bool encodeLength(
            TSpan<uint8_t> destination,
            size_t length,
            size_t& bytesWritten
        );

        /**
         * Computes the minimal number of octets required to encode value as a
         * two's-complement big-endian INTEGER.
         * @param value The value to measure.
         * @return The number of octets required (1-8).
         */
        static size_t encodedIntegerSize(int64_t value);

        /**
         * Computes the number of octets required to encode value as an ASN.1
         * base-128 subidentifier.
         * @param value The value to measure.
         * @return The number of octets required (1-5).
         */
        static size_t encodedBase128Size(uint32_t value);

        /**
         * Encodes value as an ASN.1 base-128 (varint-style) subidentifier, as used by
         * OBJECT IDENTIFIER content octets.
         * @param destination The destination span to write into.
         * @param value The value to encode.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if value was successfully encoded; otherwise, false.
         */
        static bool encodeBase128(TSpan<uint8_t> destination, uint32_t value, size_t& bytesWritten);

        /* Maximum arc count encodeOidString()/encodedOidStringSize() work with, bounding
         * parseOidArcs()'s fixed-size stack buffer -- generous for any realistic OID (X.509
         * OIDs rarely exceed a dozen arcs). Mirrors CDecoder::MAX_OID_TEXT_ARCS. */
        static constexpr size_t MAX_OID_TEXT_ARCS = 32;

        /**
         * Parses a dotted-decimal OID string (e.g. "1.2.840.113549.1.1.1") into its arc values.
         * @tparam TChar The source TString's character type (char or wchar_t).
         * @param text The dotted-decimal OID text to parse.
         * @param outArcs The destination for the parsed arc values.
         * @param outArcCount The number of arcs written to outArcs.
         * @return True if text was a well-formed dotted-decimal OID (at least one '.'-separated
         * component, every component a minimal-length decimal number fitting in a uint32_t, and
         * no more arcs than outArcs can hold); otherwise, false.
         */
        template<typename TChar>
        static bool parseOidArcs(const TString<TChar>& text, TSpan<uint32_t> outArcs, size_t& outArcCount) {
            outArcCount = 0;

            const size_t len = text.size();
            if (!len) {
                return false;
            }

            size_t i = 0;
            while (i < len) {
                if (outArcCount >= outArcs.size) {
                    return false;
                }

                if (text[i] < TChar('0') || text[i] > TChar('9')) {
                    return false;
                }

                uint64_t value = 0;
                size_t start = i;

                while (i < len && text[i] >= TChar('0') && text[i] <= TChar('9')) {
                    value = value * 10 + uint64_t(text[i] - TChar('0'));
                    if (value > 0xFFFFFFFFull) {
                        return false; // doesn't fit in a uint32_t arc
                    }

                    ++i;
                }

                if (i - start > 1 && text[start] == TChar('0')) {
                    return false; // non-minimal encoding, e.g. "01"
                }

                outArcs[outArcCount++] = uint32_t(value);

                if (i < len) {
                    if (text[i] != TChar('.')) {
                        return false;
                    }

                    if (++i >= len) {
                        return false; // trailing '.'
                    }
                }
            }

            return true;
        }

    public:
        /**
         * Computes the total number of octets required to encode a tag-length-value with the given tag and content.
         * @param tag The tag of the value to encode.
         * @param content The content octets of the value to encode.
         * @return The number of octets the encoded value will occupy, or 0 if the tag is invalid.
         */
        static size_t encodedValueSize(const CTag& tag, SReadOnlyByteSpan content);

        /**
         * Writes an ASN.1 tag-length-value into the destination span, using definite-length form.
         * @param destination The destination span to write the encoded value into.
         * @param ruleSet The ASN.1 encoding rule set to use.
         * @param tag The tag of the value to encode.
         * @param content The content octets of the value to encode.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if the value was successfully encoded; otherwise, false.
         */
        static bool writeEncodedValue(
            TSpan<uint8_t> destination,
            EEncodingRule ruleSet,
            const CTag& tag,
            SReadOnlyByteSpan content,
            size_t& bytesWritten
        );

        /**
         * Reads the next encoded ASN.1 value from a SEQUENCE/SET's content, advancing the cursor
         * past it. Thin re-export of CDecoder::readNextElement() so a caller building up a
         * SEQUENCE/SET OF from freshly-encoded children doesn't need to also name CDecoder.
         * @param cursor The remaining content to read from; advanced past the value read on success.
         * @param ruleSet The ASN.1 encoding rule set to use.
         * @param outTag The output tag of the encoded value.
         * @param outArea The output span containing the encoded value's content.
         * @return True if a value was successfully read; false on a parse error or if cursor was empty.
         */
        static inline bool readNextElement(
            TReadOnlySpan<uint8_t>& cursor,
            EEncodingRule ruleSet,
            CTag& outTag,
            TReadOnlySpan<uint8_t>& outArea
        ) {
            return CDecoder::readNextElement(cursor, ruleSet, outTag, outArea);
        }

        /**
         * Encodes a BOOLEAN's content octets. Always writes the canonical 1-octet form
         * (0x00 / 0xFF), which is valid under all three rule sets.
         * @param destination The destination span to write into.
         * @param value The value to encode.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if value was successfully encoded; otherwise, false.
         */
        static bool encodeBoolean(TSpan<uint8_t> destination, bool value, size_t& bytesWritten);

        /**
         * Encodes an INTEGER's content octets: a minimal-length two's-complement big-endian integer.
         * @param destination The destination span to write into.
         * @param value The value to encode.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if value was successfully encoded; otherwise, false.
         */
        static bool encodeInteger(TSpan<uint8_t> destination, int64_t value, size_t& bytesWritten);

        /**
         * Encodes an ENUMERATED's content octets (encoded identically to INTEGER).
         * @param destination The destination span to write into.
         * @param value The value to encode.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if value was successfully encoded; otherwise, false.
         */
        static bool encodeEnumerated(TSpan<uint8_t> destination, uint32_t value, size_t& bytesWritten);

        /**
         * Encodes a NULL's content octets (always empty).
         * @param destination The destination span to write into.
         * @param bytesWritten The number of bytes written to the destination span (always 0).
         * @return Always true.
         */
        static bool encodeNull(TSpan<uint8_t> destination, size_t& bytesWritten);

        /**
         * Encodes an OCTET STRING's content octets (a direct copy of value).
         * @param destination The destination span to write into.
         * @param value The octets to encode.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if destination had enough room; otherwise, false.
         */
        static bool encodeOctetString(TSpan<uint8_t> destination, SReadOnlyByteSpan value, size_t& bytesWritten);

        /**
         * Encodes an OCTET STRING's content octets from an owning COctet. Thin wrapper over the
         * SReadOnlyByteSpan overload via COctet::toSpan().
         * @param destination The destination span to write into.
         * @param value The octets to encode.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if destination had enough room; otherwise, false.
         */
        static inline bool encodeOctetString(TSpan<uint8_t> destination, const COctet& value, size_t& bytesWritten) {
            return encodeOctetString(destination, value.toSpan(), bytesWritten);
        }

        /**
         * Encodes a BIT STRING's content octets.
         * @param destination The destination span to write into.
         * @param bits The packed bit data octets.
         * @param unusedBits The number of unused (padding) bits in the last octet of bits (0-7); the
         * corresponding low bits of destination's last written octet are forced to zero.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if the arguments were valid and destination had enough room; otherwise, false.
         */
        static bool encodeBitString(
            TSpan<uint8_t> destination,
            SReadOnlyByteSpan bits,
            uint8_t unusedBits,
            size_t& bytesWritten
        );

        /**
         * Encodes a BIT STRING's content octets from an owning COctet's packed bit data. Thin
         * wrapper over the SReadOnlyByteSpan overload via COctet::toSpan().
         * @param destination The destination span to write into.
         * @param bits The packed bit data octets.
         * @param unusedBits The number of unused (padding) bits in the last octet of bits (0-7); the
         * corresponding low bits of destination's last written octet are forced to zero.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if the arguments were valid and destination had enough room; otherwise, false.
         */
        static inline bool encodeBitString(
            TSpan<uint8_t> destination,
            const COctet& bits,
            uint8_t unusedBits,
            size_t& bytesWritten
        ) {
            return encodeBitString(destination, bits.toSpan(), unusedBits, bytesWritten);
        }

        /**
         * Encodes a BIT STRING used as a NamedBitList (e.g. X.509's KeyUsage), trimming
         * trailing 0 bits per X.690 11.2.2 (an all-zero bit set encodes as the empty BIT STRING).
         * @param destination The destination span to write into.
         * @param bits The packed named bits, MSB-first (bit 0 is the MSB of bits[0]); must cover at
         * least bitCount bits.
         * @param bitCount The number of named bit positions in bits.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if destination had enough room for the trimmed encoding; otherwise, false.
         */
        static bool encodeNamedBitList(
            TSpan<uint8_t> destination,
            SReadOnlyByteSpan bits,
            uint32_t bitCount,
            size_t& bytesWritten
        );

        /**
         * Computes the number of content octets required to encode an OBJECT IDENTIFIER's arcs.
         * @param arcs The arc values (at least 2; arcs[0] must be 0-2, and if arcs[0] < 2, arcs[1] must be < 40).
         * @return The number of octets required, or 0 if arcs is not a valid arc sequence.
         */
        static size_t encodedOidSize(TReadOnlySpan<uint32_t> arcs);

        /**
         * Encodes an OBJECT IDENTIFIER's content octets from its arc values.
         * @param destination The destination span to write into.
         * @param arcs The arc values (see encodedOidSize() for the constraints on arcs[0]/arcs[1]).
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if arcs was valid and destination had enough room; otherwise, false.
         */
        static bool encodeOid(TSpan<uint8_t> destination, TReadOnlySpan<uint32_t> arcs, size_t& bytesWritten);

        /**
         * Computes the number of content octets required to encode a dotted-decimal OID string
         * via encodeOidString().
         * @tparam TChar The source TString's character type (char or wchar_t).
         * @param text The dotted-decimal OID text to measure (e.g. "1.2.840.113549.1.1.1").
         * @return The number of octets required, or 0 if text is not a well-formed dotted-decimal
         * OID (see parseOidArcs()) or doesn't form a valid arc sequence (see encodedOidSize()).
         */
        template<typename TChar>
        static size_t encodedOidStringSize(const TString<TChar>& text) {
            uint32_t arcs[MAX_OID_TEXT_ARCS];
            size_t arcCount = 0;

            if (!parseOidArcs(text, TSpan<uint32_t>(arcs, MAX_OID_TEXT_ARCS), arcCount)) {
                return 0;
            }

            return encodedOidSize(TReadOnlySpan<uint32_t>(arcs, arcCount));
        }

        /**
         * Encodes an OBJECT IDENTIFIER's content octets from its dotted-decimal text form (e.g.
         * "1.2.840.113549.1.1.1"), the inverse of CDecoder::decodeOidString(). Parses text via
         * parseOidArcs(), then encodes the resulting arc values exactly like encodeOid().
         * @tparam TChar The source TString's character type (char or wchar_t).
         * @param destination The destination span to write into.
         * @param text The dotted-decimal OID text to encode.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if text was a well-formed dotted-decimal OID forming a valid arc sequence
         * and destination had enough room; otherwise, false.
         */
        template<typename TChar>
        static bool encodeOidString(TSpan<uint8_t> destination, const TString<TChar>& text, size_t& bytesWritten) {
            bytesWritten = 0;

            uint32_t arcs[MAX_OID_TEXT_ARCS];
            size_t arcCount = 0;

            if (!parseOidArcs(text, TSpan<uint32_t>(arcs, MAX_OID_TEXT_ARCS), arcCount)) {
                return false;
            }

            return encodeOid(destination, TReadOnlySpan<uint32_t>(arcs, arcCount), bytesWritten);
        }

        /**
         * Encodes/validates a character string type's content octets.
         * @param destination The destination span to write into.
         * @param kind The universal string tag (see CDecoder::decodeText() for which kinds get their
         * character set validated).
         * @param text The text to encode.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if text is valid for kind's character set and destination had enough room; otherwise, false.
         */
        static bool encodeText(
            TSpan<uint8_t> destination,
            EUniversalTags kind,
            SReadOnlyByteSpan text,
            size_t& bytesWritten
        );

        /**
         * Computes the number of UTF-8 content octets required to encode text via encodeString().
         * TChar=wchar_t measures genuine UTF-8, locale-independent; TChar=char goes through
         * TUtf8Encoding<char>, which treats char as native-locale text -- see encodeString()'s
         * doc comment for the same locale caveat.
         * @tparam TChar The source TString's character type (char or wchar_t).
         * @param text The text to measure.
         * @return The number of content octets required, or 0 if text is empty or not encodable
         * (e.g. text contains a wide character not representable in the current locale, for
         * TChar=char).
         */
        template<typename TChar>
        static size_t encodedStringSize(const TString<TChar>& text) {
            if (text.empty()) {
                return 0;
            }

            return TUtf8Encoding<TChar>::get().measure(text.toSpan());
        }

        /**
         * Encodes a TString directly into a character string type's content octets, the inverse
         * of CDecoder::decodeString(). Transcodes text to UTF-8 via TUtf8Encoding<TChar>, then
         * validates the result via CDecoder::decodeText() against kind's character set -- so
         * encoding a TString whose content doesn't fit kind (e.g. non-ASCII text as IA5String)
         * fails rather than silently writing invalid content.
         *
         * TChar=wchar_t encodes genuine UTF-8 regardless of the process locale. TChar=char
         * instead goes through TUtf8Encoding<char>, which treats char as native-locale text (not
         * raw UTF-8) -- so non-ASCII text only produces valid UTF-8 content under a
         * UTF-8-compatible locale; under "C", only ASCII text encodes successfully.
         * @tparam TChar The source TString's character type (char or wchar_t).
         * @param destination The destination span to write into.
         * @param kind The universal string tag; see CDecoder::decodeText() for which kinds get
         * validated.
         * @param text The text to encode.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if text was successfully transcoded to UTF-8, the result is valid for
         * kind's character set, and destination had enough room; otherwise, false.
         */
        template<typename TChar>
        static bool encodeString(
            TSpan<uint8_t> destination,
            EUniversalTags kind,
            const TString<TChar>& text,
            size_t& bytesWritten
        ) {
            bytesWritten = 0;

            if (text.empty()) {
                SReadOnlyByteSpan validated;
                return CDecoder::decodeText(SReadOnlyByteSpan(nullptr, 0), kind, validated);
            }

            IStringEncoding<TChar>& enc = TUtf8Encoding<TChar>::get();
            TReadOnlySpan<TChar> src = text.toSpan();

            size_t needed = enc.measure(src);
            if (!needed || destination.size < needed) {
                return false;
            }

            TSpan<uint8_t> dst = destination.slice(0, needed);
            size_t written = enc.encodeTo(dst, src);
            if (written != needed) {
                return false;
            }

            SReadOnlyByteSpan validated;
            if (!CDecoder::decodeText(SReadOnlyByteSpan(destination.data, written), kind, validated)) {
                return false;
            }

            bytesWritten = written;
            return true;
        }

        /**
         * Encodes a UTCTime's content octets (the DER-canonical "YYMMDDHHMMSSZ" form; always 13 octets).
         * @param destination The destination span to write into.
         * @param time The time to encode; time.isUtc must be true and time.year must be in [1950, 2049].
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if time was encodable and destination had enough room; otherwise, false.
         */
        static bool encodeUtcTime(TSpan<uint8_t> destination, const SDateTime& time, size_t& bytesWritten);

        /**
         * Computes the number of content octets required to encode a GeneralizedTime.
         * @param time The time to measure.
         * @return The number of octets required, or 0 if time is not encodable (time.isUtc must be true).
         */
        static size_t encodedGeneralizedTimeSize(const SDateTime& time);

        /**
         * Encodes a GeneralizedTime's content octets (the "YYYYMMDDHHMMSS[.fff]Z" form; a trailing
         * ".fff" fractional-seconds part is included only when time.millisecond != 0, with trailing
         * zero digits trimmed per DER).
         * @param destination The destination span to write into.
         * @param time The time to encode; time.isUtc must be true.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if time was encodable and destination had enough room; otherwise, false.
         */
        static bool encodeGeneralizedTime(TSpan<uint8_t> destination, const SDateTime& time, size_t& bytesWritten);

        /**
         * Builds a SEQUENCE/SEQUENCE OF's content octets by concatenating already-encoded
         * child tag-length-values, in the order given.
         * @param destination The destination span to write into.
         * @param children The already-encoded children, in encoding order.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if destination had enough room for all children; otherwise, false.
         */
        static bool writeSequenceOf(
            TSpan<uint8_t> destination,
            TReadOnlySpan<SReadOnlyByteSpan> children,
            size_t& bytesWritten
        );

        /**
         * Builds a SET OF's content octets from already-encoded child tag-length-values. Reorders
         * children in place into ascending order by encoded octets (X.690 11.6), the canonical order
         * CER/DER require and that remains valid under BER, before concatenating them.
         * @param destination The destination span to write into.
         * @param children The already-encoded children; reordered by this call.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if destination had enough room for all children; otherwise, false.
         */
        static bool writeSetOf(
            TSpan<uint8_t> destination,
            TSpan<SReadOnlyByteSpan> children,
            size_t& bytesWritten
        );

        /**
         * Computes the number of content octets required to encode a CDistinguishedName via
         * encodeDistinguishedName(), i.e. the size of the resulting SEQUENCE's content (the
         * RDNSequence content, not including the outer SEQUENCE tag-length).
         * @param value The distinguished name to measure.
         * @return The number of octets required; 0 both for an empty (no-component) value and
         * for one that can't be encoded (see encodeDistinguishedName()) -- as with
         * encodedStringSize(), callers that need to tell the two apart should call
         * encodeDistinguishedName() directly and check its return value.
         */
        static size_t encodedDistinguishedNameSize(const CDistinguishedName& value);

        /**
         * Encodes a CDistinguishedName (X.501 Name/RDNSequence) into a SEQUENCE's content
         * octets, the inverse of CDecoder::decodeDistinguishedName(). One RelativeDistinguishedName
         * (SET) is written per component, in the CDistinguishedName's ascending ENameType order,
         * each containing exactly one AttributeTypeAndValue (SEQUENCE { type, value }): type is
         * the component's X.520 attribute OID (CName::attributeOid()), and value is the
         * component's unescaped text (CName::toString<wchar_t>()) encoded as a PrintableString
         * where possible, falling back to a UTF8String otherwise.
         *
         * Always applies DER's encoding rules; see CDecoder::decodeDistinguishedName() for why.
         * @param destination The destination span to write into.
         * @param value The distinguished name to encode.
         * @param bytesWritten The number of bytes written to the destination span.
         * @return True if every component has a recognized X.520 OID and encodable text, and
         * destination had enough room; otherwise, false. Vacuously true (bytesWritten = 0) for
         * an empty (no-component) value.
         */
        static bool encodeDistinguishedName(
            TSpan<uint8_t> destination,
            const CDistinguishedName& value,
            size_t& bytesWritten
        );

    private:
        /**
         * Builds the full DER encoding of a single AttributeTypeAndValue (SEQUENCE { type, value })
         * for one CName, appending it to out (which is cleared first).
         * @param name The name component to encode; must not be empty.
         * @param out The destination buffer, replacing any content it previously held.
         * @return True on success; otherwise, false (out is left empty).
         */
        static bool buildAttributeTypeAndValue(const CName& name, TArray<uint8_t>& out);

        /**
         * Builds the full RDNSequence content octets (one RelativeDistinguishedName per
         * component) for a CDistinguishedName, appending each in turn to out (which is cleared
         * first). The shared implementation behind encodedDistinguishedNameSize() and
         * encodeDistinguishedName(), so the two can never disagree on what gets encoded.
         * @param value The distinguished name to encode.
         * @param out The destination buffer, replacing any content it previously held.
         * @return True on success (including the vacuous empty-value case); otherwise, false
         * (out is left empty).
         */
        static bool buildDistinguishedNameContent(const CDistinguishedName& value, TArray<uint8_t>& out);
    };

}
}

#endif
