#ifndef __INCLUDE_CERTPP_X509_GENERALNAME_HPP__
#define __INCLUDE_CERTPP_X509_GENERALNAME_HPP__

#include <certpp/common.hpp>
#include <certpp/string.hpp>
#include <certpp/oid.hpp>
#include <certpp/name.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/buffer.hpp>

namespace certpp {
namespace x509 {

    /**
     * @brief The alternative GeneralName (RFC 5280 4.2.1.6) actually holds, mirroring its
     * CHOICE tags 0-8.
     */
    enum EGeneralNameType : uint8_t {
        EGNAME_OTHER            = 0, // --> otherName [0]: type-id/value pair, value unparsed.
        EGNAME_RFC822           = 1, // --> rfc822Name [1]: an email address (IA5String).
        EGNAME_DNS              = 2, // --> dNSName [2]: a DNS domain name (IA5String).
        EGNAME_X400_ADDRESS     = 3, // --> x400Address [3]: unparsed.
        EGNAME_DIRECTORY        = 4, // --> directoryName [4]: an X.501 Name.
        EGNAME_EDI_PARTY        = 5, // --> ediPartyName [5]: unparsed.
        EGNAME_URI              = 6, // --> uniformResourceIdentifier [6] (IA5String).
        EGNAME_IP_ADDRESS       = 7, // --> iPAddress [7]: 4 (IPv4) or 16 (IPv6) raw address octets.
        EGNAME_REGISTERED_ID    = 8, // --> registeredID [8]: an OBJECT IDENTIFIER.
    };

    /**
     * @brief One GeneralName (RFC 5280 4.2.1.6), as used by SubjectAltName,
     * AuthorityKeyIdentifier.authorityCertIssuer, CRLDistributionPoints' fullName,
     * AuthorityInformationAccess's accessLocation, and NameConstraints' GeneralSubtree.base.
     *
     * Only the alternatives realistically seen in commercial certificates are given a typed
     * accessor (text()/directoryName()); otherName/x400Address/ediPartyName are structurally
     * rare enough in practice that this class keeps only their raw, still-DER-encoded content
     * (raw()) rather than modeling OtherName/ORAddress/EDIPartyName in full.
     */
    class CERTPP_API CGeneralName {
    private:
        EGeneralNameType _type;
        CString _text;                  // --> rfc822Name/dNSName/URI, or registeredID's text.
        COid _registeredId;             // --> registeredID only; empty for every other type.
        COctet _raw;                     // --> iPAddress, or the unparsed content for other/x400/ediParty.
        CDistinguishedName _directoryName; // --> directoryName only.

    public:
        /**
         * @brief Constructs an empty (otherName-typed, all-default) GeneralName.
         */
        CGeneralName() : _type(EGNAME_OTHER) { }

        /**
         * @brief Constructs a text-valued GeneralName (rfc822Name/dNSName/URI/registeredID).
         *
         * For EGNAME_REGISTERED_ID the text must be dotted-decimal OID text; it is parsed here
         * so registeredId() has the arcs to answer with, and a text that does not parse leaves
         * registeredId() empty rather than half-built. Prefer the COid overload when the caller
         * already has an OID.
         * @param type The alternative this holds.
         * @param text The decoded text.
         */
        CGeneralName(EGeneralNameType type, const CString& text) : _type(type), _text(text) {
            if (type == EGNAME_REGISTERED_ID) {
                _registeredId = text;
                if (!_registeredId) {
                    _text.clear();
                }
            }
        }

        /**
         * @brief Constructs a registeredID-valued GeneralName from a COid.
         * @param oid The registered OID.
         */
        CGeneralName(const COid& oid) : _type(EGNAME_REGISTERED_ID), _registeredId(oid) {
            _registeredId.toString(_text);
        }

        /**
         * @brief Constructs a directoryName-valued GeneralName.
         * @param name The decoded X.501 Name.
         */
        explicit CGeneralName(const CDistinguishedName& name) : _type(EGNAME_DIRECTORY), _directoryName(name) { }

        /**
         * @brief Constructs a raw-valued GeneralName (iPAddress, or an unparsed alternative).
         * @param type The alternative this holds.
         * @param raw The raw content octets.
         */
        CGeneralName(EGeneralNameType type, const COctet& raw) : _type(type), _raw(raw) { }

        /**
         * @brief Gets which alternative this GeneralName holds.
         * @return The alternative.
         */
        inline EGeneralNameType type() const { return _type; }

        /**
         * @brief Gets the decoded text, for EGNAME_RFC822/EGNAME_DNS/EGNAME_URI (the string
         * itself) or EGNAME_REGISTERED_ID (the OID's dotted-decimal text). Empty for every
         * other alternative.
         * @return The decoded text.
         */
        inline const CString& text() const { return _text; }

        /**
         * @brief Gets the OID, for EGNAME_REGISTERED_ID only. Empty for every other alternative.
         *
         * The accessor to compare against when a caller wants to know whether two
         * GeneralNames name the same registered ID: the comparison is on the arcs. text() gives
         * the same OID as dotted-decimal text, which is the right thing to display and the wrong
         * thing to compare.
         * @return The registered OID, or an empty COid if this is not a registeredID.
         */
        inline const COid& registeredId() const { return _registeredId; }

        /**
         * @brief Gets the decoded directory name, for EGNAME_DIRECTORY only. Empty for every
         * other alternative.
         * @return The decoded name.
         */
        inline const CDistinguishedName& directoryName() const { return _directoryName; }

        /**
         * @brief Gets the raw content octets, for EGNAME_IP_ADDRESS (4 or 16 raw address bytes)
         * or an alternative this class doesn't otherwise interpret (EGNAME_OTHER/
         * EGNAME_X400_ADDRESS/EGNAME_EDI_PARTY -- their content, still DER-encoded). Empty for
         * every other alternative.
         * @return The raw content octets.
         */
        inline const COctet& raw() const { return _raw; }

        /**
         * @brief Decodes one GeneralName from its outer context-specific tag-length-value.
         * Best-effort like every other extension parser in this module: false on a malformed or
         * unrecognized (tag value not 0-8) encoding, leaving out unchanged.
         * @param content The GeneralName's own content octets (i.e. one element read from a
         * GeneralNames SEQUENCE OF GeneralName, via the caller's own asn1::CReader/
         * asn1::CDecoder::readNextElement()) plus that element's tag.
         * @param tagValue The context-specific tag value (0-8) identifying which alternative.
         * @param constructed Whether that tag was encoded as constructed.
         * @param out Receives the decoded GeneralName.
         * @return true on success; false otherwise.
         */
        static bool decode(SReadOnlyByteSpan content, uint32_t tagValue, bool constructed, CGeneralName& out);

        /**
         * @brief Decodes a GeneralNames (SEQUENCE OF GeneralName) from its outer SEQUENCE's
         * content octets. Best-effort: an individual GeneralName this class can't decode is
         * skipped rather than aborting the whole list.
         * @param content The GeneralNames SEQUENCE's own content octets.
         * @param out Receives the decoded list, replacing any content it previously held.
         */
        static void decodeList(SReadOnlyByteSpan content, TArray<CGeneralName>& out);

        /**
         * @brief Encodes this GeneralName as its own context-specific tag-length-value (the
         * inverse of decode()), appending it to out. otherName/x400Address/ediPartyName encode
         * raw()'s content back out verbatim under a constructed tag, since it was never parsed
         * further; every other alternative is genuinely re-encoded.
         * @param out The destination array; the encoded TLV is appended to whatever it already holds.
         * @return true on success; false if this GeneralName's content can't be encoded (e.g. an
         * OID-shaped text() that isn't well-formed dotted-decimal, or IA5 text containing
         * non-ASCII characters).
         */
        bool encode(CBuffer& out) const;

        /**
         * @brief Encodes a GeneralNames (SEQUENCE OF GeneralName) list, the inverse of
         * decodeList(), by appending each element's own encode() in order to out. Unlike
         * decodeList()'s best-effort skipping, a single unencodable element fails the whole call.
         * @param names The names to encode.
         * @param out The destination array; the encoded TLVs are appended to whatever it already holds.
         * @return true on success; false if any element failed to encode.
         */
        static bool encodeList(const TArray<CGeneralName>& names, CBuffer& out);
    };

    /**
     * @brief One GeneralSubtree (RFC 5280 4.2.1.10): a name (and, for hierarchical name forms,
     * everything subordinate to it) a CA is permitted or excluded from certifying.
     */
    class CERTPP_API CGeneralSubtree {
    private:
        CGeneralName _base;
        int64_t _minimum = 0;
        bool _hasMaximum = false;
        int64_t _maximum = 0;

    public:
        /**
         * @brief Constructs an empty GeneralSubtree.
         */
        CGeneralSubtree() = default;

        /**
         * @brief Constructs a GeneralSubtree from its decoded fields.
         * @param base The base name.
         * @param minimum The minimum distance (0 if absent, its DER default).
         * @param hasMaximum Whether a maximum distance is present.
         * @param maximum The maximum distance, if hasMaximum is true.
         */
        CGeneralSubtree(const CGeneralName& base, int64_t minimum, bool hasMaximum, int64_t maximum)
            : _base(base), _minimum(minimum), _hasMaximum(hasMaximum), _maximum(maximum)
        {
        }

        /**
         * @brief The base name this subtree is rooted at.
         * @return The base name.
         */
        inline const CGeneralName& base() const { return _base; }

        /**
         * @brief The minimum distance below base() this constraint applies from (0, the DER
         * default, if absent -- meaning it applies starting at base() itself).
         *
         * RFC 5280 4.2.1.10 does not merely make a non-zero value rare, it forbids one:
         * "within this profile, the minimum and maximum fields are not used with any name
         * forms, thus minimum MUST be zero". A validator that honours a non-zero minimum
         * narrows the subtree the constraint covers, which lets through exactly the names the
         * constraint was there to exclude -- so a non-zero value here is grounds to reject the
         * certificate, not to apply the offset.
         * @return The minimum distance, which a conforming certificate states as 0 or omits.
         */
        inline int64_t minimum() const { return _minimum; }

        /**
         * @brief Whether maximum() is present.
         * @return true if present.
         */
        inline bool hasMaximum() const { return _hasMaximum; }

        /**
         * @brief The maximum distance below base() this constraint applies to. Only meaningful
         * when hasMaximum() is true.
         *
         * As with minimum(), RFC 5280 4.2.1.10 forbids the field outright -- "maximum MUST be
         * absent" -- so hasMaximum() returning true is a non-conformance to reject rather than
         * a bound to enforce. It is reported rather than dropped so the caller can see that the
         * certificate carried it.
         * @return The maximum distance, meaningful only when hasMaximum() is true.
         */
        inline int64_t maximum() const { return _maximum; }

        /**
         * @brief Encodes this GeneralSubtree as its own SEQUENCE tag-length-value, the inverse of
         * NameConstraints' decodeGeneralSubtrees(), appending it to out.
         * @param out The destination array; the encoded TLV is appended to whatever it already holds.
         * @return true on success; false if base() can't be encoded (see CGeneralName::encode()).
         */
        bool encode(CBuffer& out) const;
    };

} // namespace x509
} // namespace certpp

#endif
