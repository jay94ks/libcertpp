#ifndef __INCLUDE_CERTPP_ASN1_DER_HPP__
#define __INCLUDE_CERTPP_ASN1_DER_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/buffer.hpp>
#include <certpp/asn1/tag.hpp>
#include <certpp/utils/bignum.hpp>

namespace certpp {
namespace asn1 {

    /**
     * DER encode/decode helpers for arbitrary-precision integers and already-encoded child
     * values -- the CBigNum-sized equivalent of CEncoder::encodeInteger()/
     * CDecoder::decodeInteger(), which only handle a plain int64_t. Used by every
     * crypto::IAsymmetric implementation (RSA/DSA/EC/...) to DER-encode/decode its keys and
     * signatures, so it lives alongside CEncoder/CDecoder rather than under crypto/.
     */
    class CERTPP_API CDer {
    public:
        /**
         * Appends a full DER tag-length-value to out, given an already-built tag and content
         * octets.
         * @param out The destination array; the encoded TLV is appended to whatever it already holds.
         * @param tag The tag to encode.
         * @param content The content octets to encode.
         * @return true on success; false if tag was invalid.
         */
        static bool appendTlv(TArray<uint8_t>& out, const CTag& tag, SReadOnlyByteSpan content);

        /**
         * Appends a full DER tag-length-value to out, given an already-built tag and content
         * octets. Same as the TArray<uint8_t> overload; used by the x509 extension encoders,
         * which build into a CBuffer instead.
         * @param out The destination buffer; the encoded TLV is appended to whatever it already holds.
         * @param tag The tag to encode.
         * @param content The content octets to encode.
         * @return true on success; false if tag was invalid.
         */
        static bool appendTlv(CBuffer& out, const CTag& tag, SReadOnlyByteSpan content);

        /**
         * Appends a DER INTEGER TLV encoding value's magnitude, in two's-complement big-endian
         * form (a leading 0x00 pad byte is added whenever value's top bit would otherwise read
         * as negative).
         * @param out The destination array; the encoded TLV is appended to whatever it already holds.
         * @param value The non-negative value to encode.
         * @return true on success; false on failure.
         */
        static bool appendBigInteger(TArray<uint8_t>& out, const CBigNum& value);

        /**
         * Appends a DER INTEGER TLV encoding value's magnitude. Same as the TArray<uint8_t>
         * overload; used by the x509 extension encoders, which build into a CBuffer instead.
         * @param out The destination buffer; the encoded TLV is appended to whatever it already holds.
         * @param value The non-negative value to encode.
         * @return true on success; false on failure.
         */
        static bool appendBigInteger(CBuffer& out, const CBigNum& value);

        /**
         * Appends a DER SEQUENCE TLV wrapping innerContent (the already-encoded concatenation of
         * the SEQUENCE's members).
         * @param out The destination array; the encoded TLV is appended to whatever it already holds.
         * @param innerContent The SEQUENCE's content octets.
         * @return true on success; false on failure.
         */
        static bool appendSequence(TArray<uint8_t>& out, SReadOnlyByteSpan innerContent);

        /**
         * Appends a DER SEQUENCE TLV wrapping innerContent. Same as the TArray<uint8_t> overload;
         * used by the x509 extension encoders, which build into a CBuffer instead.
         * @param out The destination buffer; the encoded TLV is appended to whatever it already holds.
         * @param innerContent The SEQUENCE's content octets.
         * @return true on success; false on failure.
         */
        static bool appendSequence(CBuffer& out, SReadOnlyByteSpan innerContent);

        /**
         * Appends bytes verbatim -- already the caller's own complete, independently-encoded TLV
         * (or concatenation of several) -- to out, with no further tag/length wrapping, unlike
         * appendTlv()/appendSequence(), which each build one new TLV around their content. Used
         * to splice a shared sub-structure (e.g. one AlgorithmIdentifier reused byte-for-byte in
         * two different places of the same document) into more than one destination.
         * @param out The destination buffer; bytes is appended to whatever it already holds.
         * @param bytes The already-encoded bytes to append.
         * @return true on success; false if out couldn't be grown.
         */
        static bool appendRaw(CBuffer& out, SReadOnlyByteSpan bytes);

        /**
         * Reads one DER INTEGER element from cursor, advancing it past the element.
         * @param cursor The remaining content to read from; advanced past the value read on success.
         * @param out Receives the decoded value.
         * @return true if cursor started with a well-formed, non-negative INTEGER; false otherwise.
         */
        static bool readBigInteger(TReadOnlySpan<uint8_t>& cursor, CBigNum& out);

        /**
         * Reads a DER document's outer SEQUENCE tag-length-value, giving back its content octets.
         * @param der The full DER-encoded document.
         * @param outContent Receives the outer SEQUENCE's content octets.
         * @return true if der was a well-formed SEQUENCE; false otherwise.
         */
        static bool readOuterSequence(SReadOnlyByteSpan der, TReadOnlySpan<uint8_t>& outContent);

        /**
         * @param contentBytes The content length, in bytes, of a DER INTEGER TLV.
         * @return A safe upper bound on that TLV's total encoded size (tag + length + content).
         */
        static size_t maxIntegerSize(size_t contentBytes);

        /**
         * Safe upper bound for the size of `SEQUENCE { INTEGER r, INTEGER s }` -- the
         * Dss-Sig-Value/Ecdsa-Sig-Value shape RFC 3279/SEC 1 define for DSA/ECDSA signatures --
         * where each of r/s is derived from a value up to orderByteLen bytes long (plus a
         * possible leading 0x00 pad, which the actual encoded signature frequently omits; this
         * is only the buffer size to allocate up front, not the exact signature length).
         * @param orderByteLen The signing key's subgroup order, in bytes.
         * @return A safe upper bound on the DER-encoded signature's size.
         */
        static size_t maxSignatureSize(size_t orderByteLen);
    };

} // namespace asn1
} // namespace certpp

#endif
