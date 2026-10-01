#ifndef __INCLUDE_CERTPP_ASN1_WRITER_HPP__
#define __INCLUDE_CERTPP_ASN1_WRITER_HPP__

#include <certpp/common.hpp>
#include <certpp/time.hpp>
#include <certpp/string.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/stream.hpp>
#include <certpp/asn1/tag.hpp>
#include <certpp/asn1/encoder.hpp>

namespace certpp {
namespace asn1 {

    /**
     * Sequentially writes ASN.1 tag-length-values to an IStream, pairing CEncoder's
     * content-level encode*() methods with stream writing. The write-side counterpart to
     * CReader.
     *
     * Every typed write*() method encodes its value's content into a scratch buffer via the
     * matching CEncoder::encode*(), then writes the full tag-length-value to the stream via
     * writeElement() (CEncoder::writeEncodedValue() under the hood), always under the plain
     * UNIVERSAL tag for that type. For an IMPLICIT-tagged or otherwise non-universal-tagged
     * value, encode the content with CEncoder directly and pass the custom CTag to
     * writeElement().
     *
     * writeSequence()/writeSet() build a constructed value's content from already-encoded
     * children, exactly like CEncoder::writeSequenceOf()/writeSetOf() -- build each child (e.g.
     * with a nested CWriter over its own memory stream, or directly via CEncoder) before calling
     * either.
     */
    class CERTPP_API CWriter {
    private:
        IStreamPtr _stream;
        EEncodingRule _ruleSet;

    public:
        /**
         * Constructs a CWriter that writes to the given stream.
         * @param stream The stream to write to.
         * @param ruleSet The ASN.1 encoding rule set to use.
         */
        explicit CWriter(IStreamPtr stream, EEncodingRule ruleSet = EAENC_DER);

    public:
        /**
         * Writes a full tag-length-value to the stream from already-encoded content. The
         * low-level primitive every other write*() method builds on.
         * @param tag The tag of the value to write.
         * @param content The already-encoded content octets of the value.
         * @return True if the value was successfully encoded and written to the stream in full;
         * otherwise, false.
         */
        bool writeElement(const CTag& tag, SReadOnlyByteSpan content);

        /**
         * Writes a SEQUENCE from already-encoded children, exactly like
         * CEncoder::writeSequenceOf().
         * @param children The already-encoded children, in encoding order.
         * @return True on success; otherwise, false.
         */
        bool writeSequence(TReadOnlySpan<SReadOnlyByteSpan> children);

        /**
         * Writes a SET from already-encoded children, reordering them into CER/DER's canonical
         * ascending order first, exactly like CEncoder::writeSetOf().
         * @param children The already-encoded children; reordered by this call.
         * @return True on success; otherwise, false.
         */
        bool writeSet(TSpan<SReadOnlyByteSpan> children);

        /**
         * Writes a BOOLEAN.
         * @param value The value to write.
         * @return True on success; otherwise, false.
         */
        bool writeBoolean(bool value);

        /**
         * Writes an INTEGER.
         * @param value The value to write.
         * @return True on success; otherwise, false.
         */
        bool writeInteger(int64_t value);

        /**
         * Writes an ENUMERATED.
         * @param value The value to write.
         * @return True on success; otherwise, false.
         */
        bool writeEnumerated(uint32_t value);

        /**
         * Writes a NULL.
         * @return True on success; otherwise, false.
         */
        bool writeNull();

        /**
         * Writes an OCTET STRING.
         * @param value The octets to write.
         * @return True on success; otherwise, false.
         */
        bool writeOctetString(SReadOnlyByteSpan value);

        /**
         * Writes an OCTET STRING from an owning COctet.
         * @param value The octets to write.
         * @return True on success; otherwise, false.
         */
        bool writeOctetString(const COctet& value);

        /**
         * Writes a BIT STRING.
         * @param bits The packed bit data octets.
         * @param unusedBits The number of unused (padding) bits in the last octet of bits (0-7).
         * @return True on success; otherwise, false.
         */
        bool writeBitString(SReadOnlyByteSpan bits, uint8_t unusedBits);

        /**
         * Writes a BIT STRING from an owning COctet's packed bit data.
         * @param bits The packed bit data octets.
         * @param unusedBits The number of unused (padding) bits in the last octet of bits (0-7).
         * @return True on success; otherwise, false.
         */
        bool writeBitString(const COctet& bits, uint8_t unusedBits);

        /**
         * Writes a BIT STRING used as a NamedBitList (e.g. X.509's KeyUsage), trimming trailing
         * 0 bits per X.690 11.2.2.
         * @param bits The packed named bits, MSB-first (bit 0 is the MSB of bits[0]); must cover
         * at least bitCount bits.
         * @param bitCount The number of named bit positions in bits.
         * @return True on success; otherwise, false.
         */
        bool writeNamedBitList(SReadOnlyByteSpan bits, uint32_t bitCount);

        /**
         * Writes an OBJECT IDENTIFIER from its arc values.
         * @param arcs The arc values (see CEncoder::encodedOidSize() for the constraints).
         * @return True on success; otherwise, false.
         */
        bool writeOid(TReadOnlySpan<uint32_t> arcs);

        /**
         * Writes an OBJECT IDENTIFIER from its dotted-decimal text form (e.g.
         * "1.2.840.113549.1.1.1"); see CEncoder::encodeOidString().
         * @tparam TChar The source TString's character type (char or wchar_t).
         * @param text The dotted-decimal OID text to write.
         * @return True on success; otherwise, false.
         */
        template<typename TChar>
        bool writeOidString(const TString<TChar>& text) {
            size_t needed = CEncoder::encodedOidStringSize(text);
            if (!needed) {
                return false;
            }

            TArray<uint8_t> buf;
            buf.resize(needed);
            size_t written = 0;

            return CEncoder::encodeOidString(TSpan<uint8_t>(buf.begin(), buf.size()), text, written)
                && writeElement(CTag::OBJ_ID, SReadOnlyByteSpan(buf.begin(), written));
        }

        /**
         * Writes a character string type's content; see CEncoder::encodeText() for which kinds
         * get their character set validated.
         * @param kind The universal string tag to write.
         * @param text The text to write.
         * @return True on success; otherwise, false.
         */
        bool writeText(EUniversalTags kind, SReadOnlyByteSpan text);

        /**
         * Writes a character string type's content directly from a TString; see
         * CEncoder::encodeString().
         * @tparam TChar The source TString's character type (char or wchar_t).
         * @param kind The universal string tag to write.
         * @param text The text to write.
         * @return True on success; otherwise, false.
         */
        template<typename TChar>
        bool writeString(EUniversalTags kind, const TString<TChar>& text) {
            CTag tag(kind, false);
            if (!tag) {
                return false;
            }

            size_t needed = CEncoder::encodedStringSize(text);
            TArray<uint8_t> buf;
            buf.resize(needed);
            size_t written = 0;

            return CEncoder::encodeString(TSpan<uint8_t>(buf.begin(), buf.size()), kind, text, written)
                && writeElement(tag, SReadOnlyByteSpan(buf.begin(), written));
        }

        /**
         * Writes a UTCTime.
         * @param time The time to write; see CEncoder::encodeUtcTime() for the constraints.
         * @return True on success; otherwise, false.
         */
        bool writeUtcTime(const SDateTime& time);

        /**
         * Writes a GeneralizedTime.
         * @param time The time to write; see CEncoder::encodeGeneralizedTime() for the constraints.
         * @return True on success; otherwise, false.
         */
        bool writeGeneralizedTime(const SDateTime& time);

        /**
         * Writes a CDistinguishedName; see CEncoder::encodeDistinguishedName() for the exact
         * structure written.
         * @param value The distinguished name to write.
         * @return True on success; otherwise, false.
         */
        bool writeDistinguishedName(const CDistinguishedName& value);
    };

}
}

#endif
