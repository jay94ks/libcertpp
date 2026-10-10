#ifndef __INCLUDE_CERTPP_X509_CSR_HPP__
#define __INCLUDE_CERTPP_X509_CSR_HPP__

#include <certpp/common.hpp>
#include <certpp/string.hpp>
#include <certpp/name.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/io/array.hpp>
#include <certpp/io/buffer.hpp>
#include <certpp/crypto/asym.hpp>
#include <certpp/crypto/hasher.hpp>
#include <certpp/x509/ext.hpp>
#include <certpp/x509/cert.hpp>

namespace certpp {
namespace x509 {

    /**
     * @brief One PKCS#10 Attribute (RFC 2986 4.1) out of a certification request's
     * `attributes [0] IMPLICIT Attributes` field:
     *
     *     Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET OF ANY }
     *
     * Deliberately holds `values` as raw bytes rather than modelling each attribute type: the
     * one attribute that matters for certificate issuance is PKCS#9's extensionRequest, and
     * CCertRequest already decodes that one into its own extension list (see
     * CCertRequest::extensionOf()). Everything else -- challengePassword, unstructuredName, a
     * vendor's own private arc -- is handed back verbatim for a caller that knows what it is.
     *
     * The same struct is both what CCertRequest hands back and what CCertRequestBuilder takes,
     * with `values` meaning exactly the same bytes in each direction, so a parsed attribute can
     * be fed straight back into a builder without reshaping it.
     */
    struct SCertRequestAttribute {
        /* The attribute's type OID. */
        COid oid;

        /* The content octets of the attribute's `values SET OF ANY` field -- i.e. the
         * concatenated DER elements inside that SET, *without* the SET's own tag and length.
         * Usually exactly one element (RFC 2985 defines a single-valued SET for every attribute
         * it specifies), but the ASN.1 permits any number, so this is not unwrapped further. */
        COctet values;

        /**
         * @brief Constructs an empty attribute.
         */
        SCertRequestAttribute() = default;

        /**
         * @brief Constructs an attribute from its type OID and raw values content.
         * @param oid The attribute's type OID.
         * @param values The content octets of the attribute's values SET.
         */
        SCertRequestAttribute(const COid& oid, const COctet& values)
            : oid(oid), values(values)
        {
        }
    };

    /**
     * @brief A PKCS#10 certification request (RFC 2986) -- a CSR -- as parsed from DER or PEM.
     *
     *     CertificationRequest ::= SEQUENCE {
     *         certificationRequestInfo CertificationRequestInfo,
     *         signatureAlgorithm       AlgorithmIdentifier,
     *         signature                BIT STRING }
     *
     *     CertificationRequestInfo ::= SEQUENCE {
     *         version       INTEGER { v1(0) },
     *         subject       Name,
     *         subjectPKInfo SubjectPublicKeyInfo,
     *         attributes    [0] IMPLICIT Attributes }
     *
     * **importDer()/importPem() verify the self-signature before reporting success.** A CSR is
     * signed by the very key it carries, and that self-signature is the *only* thing a CSR
     * attests: proof that whoever produced it holds the private half of subjectPKInfo. A request
     * whose signature doesn't check proves nothing at all, so there is no "parsed but
     * unverified" state to get into here -- unlike a certificate, whose fields are still
     * meaningful to a caller that can't reach the issuer's key, every field of a CSR is an
     * unauthenticated claim without that signature. For the same reason a request signed with an
     * algorithm this library cannot verify is rejected (ERET_NOTSUP) rather than imported
     * unchecked. verify() is public as well, for a caller that wants to re-run the check by hand
     * or over certificationRequestInfo() itself.
     *
     * What a verified CSR does **not** establish is that any of its content should be granted:
     * see CCertBuilder::subjectFrom() for the CA-side half of that.
     */
    class CERTPP_API CCertRequest {
    public:
        /**
         * @brief PKCS#9's extensionRequest attribute OID (RFC 2985 5.4.2) -- the attribute whose
         * single value is an `Extensions` SEQUENCE, i.e. the mechanism by which a requester asks
         * for a SubjectAlternativeName, a KeyUsage and so on. Its contents are decoded into this
         * object's own extension list, reachable through extensionOf()/extension().
         */
        static constexpr SKnownOid OID_EXTENSION_REQUEST = COid::EXT_EXTENSION_REQUEST;

    private:
        COctet _rawData;        // --> Raw certification request data, DER-encoded.

        uint32_t _version = 0;

        CDistinguishedName _subject;
        CString _subjectStr;

        CString _keyAlgo;
        COctet _keyAlgoParams;
        COctet _publicKey;
        bool _keyAlgoIsDsa = false; // --> Whether publicKey()'s lazy build needs DSA's SPKI re-encoding.

        CString _signAlgo;
        crypto::EHashers _sigHashAlgo = crypto::EHASH_UNKNOWN;
        COctet _signature;

        /* Whether signatureAlgorithm is id-RSASSA-PSS *and* its RSASSA-PSS-params parsed, in
         * exactly the sense CCert's own identically-named pair carries. */
        bool _sigIsRsaPss = false;
        SRsaPssParams _sigPssParams;

        /* cached cryptographic objects, the same lazily-built-once shape CCert uses */
        crypto::IAsymmetricPtr _asym;
        mutable crypto::IPublicKeyPtr _cachedPub;

        std::vector<IExtensionPtr> _extensions;
        TArray<SCertRequestAttribute> _attributes;

        // --> Copy/move are left implicit on purpose, unlike CCert's and CCrlReader's
        // hand-written ones: every member here is already correctly copyable and movable on its
        // own, and a hand-written set would be four more places that have to list every field
        // and silently drop one when a field is added later.

    private:
        /* Reads the `attributes [0] IMPLICIT Attributes` field via attrs, a reader positioned
         * inside that implicitly-tagged SET, into outAttributes -- and, for the one
         * extensionRequest attribute, additionally decodes its Extensions value into
         * outExtensions (via CCert::parseExtensions(), so a requested extension surfaces as
         * exactly the same concrete IExtension type it would on a certificate). False for a
         * malformed Attribute; a *repeated* OID is likewise rejected rather than accumulating an
         * ambiguous pair, since attributeOf() returns the first match and a caller iterating
         * attributes() directly would see both. An empty SET is perfectly valid and yields
         * nothing. */
        static bool parseAttributes(
            asn1::CReader& attrs,
            TArray<SCertRequestAttribute>& outAttributes,
            std::vector<IExtensionPtr>& outExtensions
        );

    public:
        /**
         * @brief Constructs an empty certification request.
         */
        CCertRequest() = default;

        /**
         * @brief Imports the certification request from DER-encoded raw data, verifying its
         * self-signature before reporting success (see this class's own doc comment on why that
         * isn't optional). Always parsed as DER.
         *
         * `version` must be v1 (0), the only version RFC 2986 defines, and the
         * `attributes [0]` field must be present -- it is not OPTIONAL, so a request that omits
         * it entirely is malformed even when it has no attributes to carry (the empty case is
         * encoded as a present-but-empty SET). This object is left empty on any failure.
         *
         * @param data The raw DER certification request data.
         * @return ERET_OK on success; ERET_INVAL if data is empty; ERET_BADREQ if data isn't a
         * well-formed PKCS#10 CertificationRequest; ERET_KEY_EMPTY if subjectPKInfo doesn't
         * yield a usable public key; ERET_NOTSUP if the signature algorithm isn't one this
         * library can verify; otherwise whatever the verification itself reported, a plain
         * signature mismatch included.
         */
        ERetCode importDer(const COctet& data);

        /**
         * @brief Imports the certification request from PEM-encoded raw data. The first
         * "CERTIFICATE REQUEST" or "NEW CERTIFICATE REQUEST" block found (RFC 7468 specifies the
         * former; the latter is an older label still emitted by some tooling) is decoded via
         * importDer(); any other block is ignored, unlike CCert::importPem(), which tries a
         * second block as its own private key -- a CSR's private key is by definition not part
         * of the request and has no field here to attach to.
         *
         * @param data The raw PEM certification request data.
         * @return ERET_OK on success; ERET_INVAL if data is empty; ERET_BADREQ if no
         * certification-request block is found or it isn't well-formed; otherwise importDer()'s
         * own codes.
         */
        ERetCode importPem(const COctet& data);

        /**
         * @brief Imports the certification request from raw data in the specified format. With
         * the default ECERT_AUTO the format is detected from data itself (the presence of PEM's
         * own "-----BEGIN " marker), exactly as CCert::importFrom() detects it.
         *
         * @param data The raw certification request data.
         * @param format The format of the data (default is AUTO).
         * @return ERET_OK on success; otherwise importDer()/importPem()'s own codes.
         */
        ERetCode importFrom(const SReadOnlyByteSpan& data, ECertFormat format = ECERT_AUTO);

        /**
         * @brief Resets this certification request to an empty state.
         */
        void reset();

        /**
         * @brief Checks if this certification request is empty.
         * @return True if it is empty, false otherwise.
         */
        inline bool empty() const { return _rawData.empty(); }

        /**
         * @brief Checks if this certification request holds a request.
         * @return True if it is not empty, false otherwise.
         */
        inline operator bool() const { return !empty(); }

        /**
         * @brief Checks if this certification request is empty.
         * @return True if it is empty, false otherwise.
         */
        inline bool operator!() const { return empty(); }

        /**
         * @brief Gets the raw DER certification request data, exactly as imported.
         * @return The raw data.
         */
        inline const COctet& rawData() const { return _rawData; }

        /**
         * @brief Gets the request's version. Always 0 (v1) -- importDer() rejects anything else,
         * since RFC 2986 defines no other value.
         * @return The version.
         */
        inline uint32_t version() const { return _version; }

        /**
         * @brief Gets the subject name the request asks to be certified under.
         * @return The subject name.
         */
        inline const CDistinguishedName& subject() const { return _subject; }

        /**
         * @brief Gets the subject name as a string.
         * @return The subject name as a string.
         */
        inline const CString& subjectStr() const { return _subjectStr; }

        /**
         * @brief Gets the public-key algorithm's display name, falling back to the OID's own
         * dotted-decimal text for an algorithm this library doesn't implement.
         * @return The key algorithm.
         */
        inline const CString& keyAlgo() const { return _keyAlgo; }

        /**
         * @brief Gets the signature algorithm's display name, falling back to the OID's own
         * dotted-decimal text for an algorithm this library doesn't implement.
         * @return The signature algorithm.
         */
        inline const CString& signAlgo() const { return _signAlgo; }

        /**
         * @brief Gets the content octets of subjectPKInfo.algorithm.parameters (e.g. an EC key's
         * namedCurve OID content, a DSA key's Dss-Parms {p, q, g} content), not including that
         * field's own tag/length. Empty when the parameters are NULL (RSA) or absent (RFC 8410).
         * @return The key algorithm parameters.
         */
        inline const COctet& keyAlgoParams() const { return _keyAlgoParams; }

        /**
         * @brief Gets the content octets of subjectPKInfo.subjectPublicKey -- the BIT STRING's
         * packed bits, with its unused-bits count already stripped, in exactly the sense
         * CCert::rawPublicKey() means it.
         * @return The raw public key bits.
         */
        inline const COctet& rawPublicKey() const { return _publicKey; }

        /**
         * @brief Gets the raw signature bits from CertificationRequest.signature, with the BIT
         * STRING wrapper and its unused-bit count stripped. Its internal format is the signature
         * algorithm's own, exactly as with CCert::signature().
         * @return The signature value.
         */
        inline const COctet& signature() const { return _signature; }

        /**
         * @brief Gets the requested public key as a live key object, built lazily from
         * rawPublicKey()/keyAlgoParams() on first call and cached afterwards.
         * @return A pointer to the public key, or null if its algorithm isn't one this library
         * implements (in which case importDer() would already have refused the request).
         */
        crypto::IPublicKeyPtr publicKey() const;

        /**
         * @brief Gets the RSASSA-PSS parameters (RFC 4055 3.1) this request's own signature was
         * produced with, for an id-RSASSA-PSS signatureAlgorithm whose parameters parsed -- the
         * same contract CCert::rsaPssParams() documents, defaults included.
         * @param outValue Receives the parameters. Left untouched if this returns false.
         * @return true if the signature algorithm is RSASSA-PSS and its parameters were parsed.
         */
        inline bool rsaPssParams(SRsaPssParams& outValue) const {
            if (!_sigIsRsaPss) {
                return false;
            }

            outValue = _sigPssParams;
            return true;
        }

        /**
         * @brief Returns the exact CertificationRequestInfo element the signature was computed
         * over: its complete TLV (tag and length included), as it appears inside rawData().
         *
         * These are deliberately the original requester-produced bytes rather than a re-encoding
         * of the parsed fields, for the same reason CCert::tbsCertificate() is -- a re-encode
         * would silently "repair" any encoding quirk the requester actually signed, and so would
         * reject a perfectly valid request whose DER this library's own encoder happens to spell
         * differently.
         * @return The CertificationRequestInfo's complete DER element, or an empty span if
         * nothing has been imported or the outer structure cannot be walked.
         */
        SReadOnlyByteSpan certificationRequestInfo() const;

        /**
         * @brief Verifies this request's self-signature against the very public key it carries,
         * i.e. answers "does whoever produced this request hold the private half of the key it
         * asks to have certified?" -- which is the entire content of a CSR's assurance.
         *
         * importDer() already calls this and refuses to report success without it, so a
         * non-empty CCertRequest has always passed; this is exposed for a caller that wants to
         * re-check by hand, or after mutating nothing but still wanting the statement in its own
         * code. It says nothing about whether the request *should* be granted.
         * @return ERET_OK if the signature verifies; ERET_INVAL if nothing has been imported or
         * there is no signature/CertificationRequestInfo to check; ERET_KEY_EMPTY if the
         * requested key isn't usable; ERET_NOTSUP if the signature algorithm isn't one this
         * library can verify; ERET_HASH_PIPE if hashing failed; otherwise whatever the
         * algorithm's own verify() reported, with a plain mismatch distinguishable from an error.
         */
        ERetCode verify() const;

        /**
         * @brief Gets every attribute the request carries, in the order they appeared. Empty for
         * a request with no attributes, which is both legal and common.
         * @return The attributes.
         */
        inline const TArray<SCertRequestAttribute>& attributes() const { return _attributes; }

        /**
         * @brief Looks up one attribute's raw `values` content by its type OID.
         * @param oid The attribute type OID to look for.
         * @param out Receives the content octets of that attribute's values SET.
         * @return ERET_OK if found; ERET_INVAL if oid is null or no such attribute is present.
         */
        ERetCode attributeOf(const char* oid, COctet& out) const;

        /**
         * @brief Looks up one attribute's raw `values` content by one of the library's known OIDs.
         *
         * Preferred over the const char* form, which is kept for a caller holding an OID it
         * parsed rather than one the library names: this one takes the SKnownOid itself, so the
         * comparison is on the arcs rather than on formatted OID text.
         * @param oid The attribute type OID to look for.
         * @param out Receives the content octets of that attribute's values SET.
         * @return ERET_OK if found; ERET_INVAL if no such attribute is present.
         */
        ERetCode attributeOf(const SKnownOid& oid, COctet& out) const;

        /**
         * @brief Gets every extension the request *asks for*, decoded out of its PKCS#9
         * extensionRequest attribute (OID_EXTENSION_REQUEST). Empty when the request carries no
         * such attribute.
         *
         * These are requests, not facts. A CA must decide each one on its own policy rather than
         * copying them -- see CCertBuilder::subjectFrom()'s own doc comment.
         * @return The requested extensions.
         */
        inline const std::vector<IExtensionPtr>& extensions() const { return _extensions; }

        /**
         * @brief Looks up one requested extension by its OID.
         * @param oid The OID of the extension to retrieve.
         * @param out Receives the extension.
         * @return ERET_OK if found; ERET_INVAL if oid is null or no such extension was requested.
         */
        ERetCode extensionOf(const char* oid, IExtensionPtr& out) const;

        /**
         * @brief Looks up one requested extension by one of the library's known OIDs.
         * @param oid The OID of the extension to retrieve.
         * @param out Receives the extension.
         * @return ERET_OK if found; ERET_INVAL if no such extension was requested.
         */
        ERetCode extensionOf(const SKnownOid& oid, IExtensionPtr& out) const;

        /**
         * @brief Looks up one requested extension by its OID.
         * @param oid The OID of the extension to retrieve.
         * @param out Receives the extension.
         * @return ERET_OK if found; ERET_INVAL if oid is null or no such extension was requested.
         */
        ERetCode extensionOf(const wchar_t* oid, IExtensionPtr& out) const;

        /**
         * @brief Looks up one requested extension by its OID.
         * @param oid The OID of the extension to retrieve.
         * @param out Receives the extension.
         * @return ERET_OK if found; ERET_INVAL if no such extension was requested.
         */
        template<typename T>
        inline ERetCode extensionOf(const TString<T>& oid, IExtensionPtr& out) const {
            return extensionOf(oid.toPtr(), out);
        }

        /**
         * @brief Gets a specific requested extension by its concrete IExtension subclass (e.g.
         * CSanExtension), looked up by that class's own OID and downcast to it -- so a requested
         * SubjectAlternativeName is read exactly the way one carried by a certificate is.
         * @tparam TExtension A concrete IExtension subclass exposing a static OID member.
         * @return A shared pointer to the extension, or null if the request didn't ask for it.
         */
        template<typename TExtension>
        inline std::shared_ptr<TExtension> extension() const {
            IExtensionPtr raw;
            if (extensionOf(TExtension::OID, raw) != ERET_OK) {
                return nullptr;
            }
            return std::dynamic_pointer_cast<TExtension>(raw);
        }

        /**
         * @brief Compares this request with another for equality.
         * @param other The other request to compare with.
         * @return True if they are byte-identical DER encodings, false otherwise.
         */
        bool equals(const CCertRequest& other) const;

        /**
         * @brief Exports the request in DER format -- the exact raw bytes imported or built.
         * @param output Receives the DER-encoded request.
         * @return ERET_OK on success; ERET_INVAL if this request is empty.
         */
        ERetCode exportDer(COctet& output) const;

        /**
         * @brief Exports the request as a PEM "CERTIFICATE REQUEST" block (RFC 7468).
         * @param output Receives the PEM text.
         * @return ERET_OK on success; ERET_INVAL if this request is empty; ERET_NOMEM if the
         * Base64 encoding failed.
         */
        ERetCode exportPem(COctet& output) const;

        /**
         * @brief Exports the request in the specified format.
         * @note Named exportAs() for the same reason CCert::exportAs() is -- `export` is a
         * reserved C++ keyword.
         * @param output Receives the request in the specified format.
         * @param format The format to export in (ECERT_DER or ECERT_PEM; ECERT_AUTO is not a
         * meaningful export format and returns ERET_NOTSUP).
         * @return ERET_OK on success; otherwise exportDer()/exportPem()'s own codes.
         */
        ERetCode exportAs(COctet& output, ECertFormat format = ECERT_DER) const;
    };

    /**
     * @brief A builder for PKCS#10 certification requests, mirroring CCertBuilder's own
     * public-field shape.
     *
     * The requester's key is supplied as a whole `crypto::SKeyPair` and nothing else: there is
     * deliberately no way to set a public key to be certified separately from the private key
     * that signs the request, because a CSR's only purpose is to prove those two are halves of
     * one pair. build() additionally re-derives the public half from the private one and
     * compares, so a mismatched pair is refused rather than producing a request that claims a
     * key it cannot prove -- and since build() always signs, there is no path to an unsigned
     * request either.
     */
    class CERTPP_API CCertRequestBuilder {
    public:
        CDistinguishedName subject;             ///< The subject's distinguished name.

        /**
         * The requester's own key pair: `publicKey` becomes subjectPKInfo and `privateKey`
         * signs the request, proving possession of it. Both halves are required, and build()
         * checks they actually match.
         */
        crypto::SKeyPair subjectKeyPair;

        /**
         * The extensions to *ask* the CA for, encoded as the single value of a PKCS#9
         * extensionRequest attribute (CCertRequest::OID_EXTENSION_REQUEST). Left empty, no such
         * attribute is written at all, rather than one carrying an empty Extensions SEQUENCE.
         */
        TArray<IExtensionPtr> extensions;

        /**
         * Any further attributes to carry, beyond the extensionRequest one `extensions` itself
         * produces -- e.g. challengePassword (RFC 2985 5.4.1). Each entry's `values` field is
         * the content octets of that attribute's own `values SET OF ANY`, exactly as
         * CCertRequest hands them back, so a parsed attribute can be copied straight across.
         * An entry with CCertRequest::OID_EXTENSION_REQUEST as its OID is rejected when
         * `extensions` is also non-empty, rather than writing the attribute twice.
         */
        TArray<SCertRequestAttribute> attributes;

        /**
         * The digest algorithm to sign the CertificationRequestInfo with. Defaults to
         * EHASH_SHA256; EHASH_UNKNOWN falls back to it. Ignored entirely for a self-hashing
         * subjectKeyPair (Ed25519/Ed448/ML-DSA). Not every (algorithm, digestAlgo) combination
         * has a defined signature OID -- see build()'s own @return.
         */
        crypto::EHashers digestAlgo = crypto::EHASH_SHA256;

        /**
         * Signs with RSASSA-PSS (RFC 8017) instead of EMSA-PKCS1-v1_5. Only meaningful (and only
         * accepted by build()) when subjectKeyPair is RSA; the salt length is always digestAlgo's
         * own digest length, and MGF1 always uses digestAlgo as its own underlying hash.
         */
        bool rsaPss = false;

    public:
        /**
         * @brief Builds and self-signs a certification request from this builder's fields,
         * handing the result to CCertRequest::importDer() -- so `out` ends up populated exactly
         * the way a real parse would populate it, *including that parse's own signature
         * verification*. A request this method reports success for has therefore already been
         * checked end to end, by the same code path an externally-produced one goes through.
         *
         * `out` is left empty on any failure.
         * @param out Receives the built request.
         * @return ERET_OK on success; ERET_INVAL if subject or subjectKeyPair is missing, or an
         * `extensions`/`attributes` entry is unusable (a null extension, an attribute whose OID
         * can't be encoded, a duplicate extensionRequest); ERET_KEY_ERROR if subjectKeyPair's
         * two halves don't match; ERET_NOTSUP if subjectKeyPair can't sign at all (X25519), or
         * (its algorithm, digestAlgo, rsaPss) isn't a combination this library defines a
         * signature OID for; another ERetCode for other failures.
         */
        ERetCode build(CCertRequest& out) const;
    };

} // namespace x509
} // namespace certpp

#endif
