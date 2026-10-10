#ifndef __INCLUDE_CERTPP_X509_ACCESS_HPP__
#define __INCLUDE_CERTPP_X509_ACCESS_HPP__

#include <certpp/common.hpp>
#include <certpp/string.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/buffer.hpp>
#include <certpp/oid.hpp>
#include <certpp/x509/generalname.hpp>

namespace certpp {
namespace x509 {

    /**
     * @brief One AccessDescription (RFC 5280 4.2.2.1): how to reach one service (e.g. an OCSP
     * responder, or the issuing CA's own certificate) related to the issuing CA.
     */
    class CERTPP_API CAccessDescription {
    private:
        COid _accessMethod;
        CGeneralName _accessLocation;

    public:
        /**
         * @brief Constructs an empty AccessDescription.
         */
        CAccessDescription() = default;

        /**
         * @brief Constructs an AccessDescription from its decoded fields.
         * @param accessMethod The access method OID's dotted-decimal text.
         * @param accessLocation The decoded access location.
         */
        CAccessDescription(const COid& accessMethod, const CGeneralName& accessLocation)
            : _accessMethod(accessMethod), _accessLocation(accessLocation)
        {
        }

        /**
         * @brief The access method OID's dotted-decimal text (e.g.
         * CAiaExtension::OID_OCSP_METHOD).
         * @return The access method OID.
         */
        inline const COid& accessMethod() const { return _accessMethod; }

        /**
         * @brief Where to reach the service (typically a uniformResourceIdentifier).
         * @return The access location.
         */
        inline const CGeneralName& accessLocation() const { return _accessLocation; }

        /**
         * @brief Encodes this AccessDescription as its own SEQUENCE tag-length-value, appending
         * it to out.
         * @param out The destination array; the encoded TLV is appended to whatever it already holds.
         * @return true on success; false if accessMethod() or accessLocation() can't be encoded.
         */
        bool encode(CBuffer& out) const;
    };

    /**
     * @brief Named bits of a DistributionPoint's reasons field (RFC 5280 4.2.1.13), in the
     * ReasonFlags BIT STRING's own named-bit numbering (bit 0, "unused", is reserved and has no
     * flag here).
     */
    enum ECrlReasons : uint16_t {
        ECRLR_NONE = 0,
        ECRLR_KEY_COMPROMISE            = (1u << 1),
        ECRLR_CA_COMPROMISE             = (1u << 2),
        ECRLR_AFFILIATION_CHANGED       = (1u << 3),
        ECRLR_SUPERSEDED                = (1u << 4),
        ECRLR_CESSATION_OF_OPERATION    = (1u << 5),
        ECRLR_CERTIFICATE_HOLD          = (1u << 6),
        ECRLR_PRIVILEGE_WITHDRAWN       = (1u << 7),
        ECRLR_AA_COMPROMISE             = (1u << 8),
    };

    /**
     * @brief One DistributionPoint (RFC 5280 4.2.1.13): where to find the CRL(s) covering (all
     * or part of) a certificate's revocation reasons.
     */
    class CERTPP_API CDistributionPoint {
    private:
        TArray<CGeneralName> _fullName;
        COctet _nameRelativeToCrlIssuer; // --> raw RDN content; rarely used, not deeply parsed.
        bool _hasReasons = false;
        uint16_t _reasons = ECRLR_NONE;
        TArray<CGeneralName> _crlIssuer;

    public:
        /**
         * @brief Constructs an empty (all fields absent) DistributionPoint.
         */
        CDistributionPoint() = default;

        /**
         * @brief Constructs a DistributionPoint from its decoded fields.
         * @param fullName The CRL issuer's own alternative names to fetch the CRL from (mutually
         * exclusive with nameRelativeToCrlIssuer -- pass an empty array to use the latter instead).
         * @param nameRelativeToCrlIssuer The raw, still-DER-encoded RelativeDistinguishedName
         * content, used only when fullName is empty.
         * @param hasReasons Whether reasons is present.
         * @param reasons Which revocation reasons the CRL(s) at this distribution point cover;
         * only meaningful when hasReasons is true.
         * @param crlIssuer The CRL issuer, if different from the certificate's own issuer.
         */
        CDistributionPoint(
            const TArray<CGeneralName>& fullName,
            const COctet& nameRelativeToCrlIssuer,
            bool hasReasons,
            uint16_t reasons,
            const TArray<CGeneralName>& crlIssuer
        )
            : _fullName(fullName), _nameRelativeToCrlIssuer(nameRelativeToCrlIssuer),
              _hasReasons(hasReasons), _reasons(reasons), _crlIssuer(crlIssuer)
        {
        }

        /**
         * @brief The CRL issuer's own alternative names to fetch the CRL from, given as a full
         * DistributionPointName (the fullName CHOICE alternative -- by far the one seen in
         * practice). Empty if absent, or if nameRelativeToCrlIssuer() was used instead.
         * @return The names.
         */
        inline const TArray<CGeneralName>& fullName() const { return _fullName; }

        /**
         * @brief The raw, still-DER-encoded RelativeDistinguishedName content, for the
         * nameRelativeToCRLIssuer CHOICE alternative (relative to the certificate's own issuer)
         * -- not deeply parsed, since it's rarely used in practice. Empty if absent, or if
         * fullName() was used instead.
         * @return The raw RDN content.
         */
        inline const COctet& nameRelativeToCrlIssuer() const { return _nameRelativeToCrlIssuer; }

        /**
         * @brief Whether reasons() is present. Its absence means the CRL(s) at this
         * distribution point cover every revocation reason.
         * @return true if present.
         */
        inline bool hasReasons() const { return _hasReasons; }

        /**
         * @brief Which revocation reasons the CRL(s) at this distribution point cover: a
         * bitwise combination of ECrlReasons flags. Only meaningful when hasReasons() is true.
         * @return The reasons.
         */
        inline uint16_t reasons() const { return _reasons; }

        /**
         * @brief The CRL issuer, if different from the certificate's own issuer. Empty in the
         * overwhelmingly common case (the certificate's own issuer also issues its CRL).
         * @return The names.
         */
        inline const TArray<CGeneralName>& crlIssuer() const { return _crlIssuer; }

        /**
         * @brief Decodes one DistributionPoint from its own SEQUENCE's content octets.
         * @param content The DistributionPoint SEQUENCE's own content octets.
         * @param out Receives the decoded DistributionPoint.
         * @return true on success (every field is OPTIONAL, so an empty SEQUENCE succeeds too).
         */
        static bool decode(SReadOnlyByteSpan content, CDistributionPoint& out);

        /**
         * @brief Encodes this DistributionPoint as its own SEQUENCE tag-length-value, the
         * inverse of decode(), appending it to out.
         * @param out The destination array; the encoded TLV is appended to whatever it already holds.
         * @return true on success; false if fullName()/crlIssuer() contains a GeneralName that
         * can't be encoded.
         */
        bool encode(CBuffer& out) const;
    };

} // namespace x509
} // namespace certpp

#endif
