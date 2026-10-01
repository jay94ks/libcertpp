#ifndef __SRC_X509_OCSPCODEC_HPP__
#define __SRC_X509_OCSPCODEC_HPP__

#include <certpp/common.hpp>
#include <certpp/time.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/io/buffer.hpp>
#include <certpp/asn1/reader.hpp>

namespace certpp {
namespace x509 {

    /**
     * Shared encode/decode helpers for the OCSP (RFC 6960) request/response wire format, used
     * across COcspRequest/COcspRequestBuilder/COcspResponse/COcspResponseBuilder -- the parts of
     * the format (the Nonce extension, RFC 8954; the GeneralizedTime-only time fields RFC 6960's
     * own ASN.1 module uses) that aren't specific to any single one of those classes.
     */
    class OcspCodec {
    public:
        static constexpr const char* OID_NONCE = "1.3.6.1.5.5.7.48.1.2";          // id-pkix-ocsp-nonce
        static constexpr const char* OID_BASIC_RESPONSE = "1.3.6.1.5.5.7.48.1.1"; // id-pkix-ocsp-basic

        /**
         * Appends one Extension { extnID = oid, extnValue = extnValue } SEQUENCE OF Extension
         * (i.e. the complete, single-entry Extensions structure id-pkix-ocsp-nonce occupies in
         * both requestExtensions and responseExtensions) to out.
         * @return true on success; false otherwise.
         */
        static bool appendSingleExtensionList(CBuffer& out, const char* oid, SReadOnlyByteSpan extnValue);

        /**
         * Builds the Nonce extension's own extnValue: an OCTET STRING wrapping nonce's raw bytes
         * (RFC 8954) -- so the extension's extnValue (itself always an OCTET STRING, per the
         * generic Extension shape) ends up double-OCTET-STRING-wrapped, same as RFC 8410's
         * CurvePrivateKey quirk elsewhere in this library.
         * @return true on success; false otherwise.
         */
        static bool buildNonceExtnValue(SReadOnlyByteSpan nonce, CBuffer& out);

        /**
         * Scans extList (an already-descended-into SEQUENCE OF Extension reader) for the Nonce
         * extension and, if found, unwraps its own double-OCTET-STRING into outNonce.
         */
        static void scanForNonce(asn1::CReader& extList, COctet& outNonce);

        /**
         * Encodes time as a plain GeneralizedTime TLV. RFC 6960's ASN.1 module types
         * producedAt/thisUpdate/nextUpdate/revocationTime as plain GeneralizedTime -- unlike
         * X.509's own Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime } that
         * CCert::encodeTime()/readTime() implement (and would pick UTCTime for any year in
         * [1950, 2049], which is wrong here regardless of year).
         * @return true on success; false otherwise (e.g. time.isUtc wasn't set).
         */
        static bool encodeGeneralizedTime(const SDateTime& time, CBuffer& out);
    };

} // namespace x509
} // namespace certpp

#endif
