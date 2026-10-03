#ifndef __INCLUDE_CERTPP_X509_CERT_HPP__
#define __INCLUDE_CERTPP_X509_CERT_HPP__

#include <certpp/common.hpp>
#include <certpp/io/octet.hpp>
#include <certpp/io/span.hpp>
#include <certpp/io/buffer.hpp>
#include <certpp/string.hpp>
#include <certpp/name.hpp>
#include <certpp/time.hpp>
#include <certpp/crypto/hasher.hpp>
#include <certpp/crypto/asym.hpp>
#include <certpp/x509/ext.hpp>
#include <certpp/x509/exts/ku.hpp>

namespace certpp {
namespace asn1 {
    // --> Forward declaration: only used by-reference in CCert's private helper declarations,
    // so a full #include <certpp/asn1/reader.hpp> here would be an unnecessary public dependency.
    class CReader;
} // namespace asn1
} // namespace certpp

namespace certpp {
namespace x509 {

    /**
     * @brief The RSASSA-PSS-params (RFC 4055 3.1) carried in an id-RSASSA-PSS signature
     * AlgorithmIdentifier's "parameters" field, as parsed out of a certificate.
     *
     * All four ASN.1 fields are DEFAULTed, and DER omits a field that equals its default, so a
     * value this struct reports isn't necessarily one the certificate spelled out -- a
     * default-constructed instance already holds exactly the four defaults an empty
     * RSASSA-PSS-params SEQUENCE means (SHA-1, MGF1 with SHA-1, a 20-byte salt, trailerFieldBC).
     */
    struct SRsaPssParams {
        /* hashAlgorithm [0]: the digest the signature is computed over. */
        crypto::EHashers hashAlgo;

        /* maskGenAlgorithm [1]: the hash id-mgf1 is parameterized with. RFC 8017 recommends,
         * and practice universally uses, the same hash as hashAlgo -- but the encoding allows
         * them to differ, so it's reported separately rather than assumed. */
        crypto::EHashers mgfHashAlgo;

        /* saltLength [2]: the length, in bytes, of the salt embedded in the PSS encoding. */
        size_t saltLength;

        /* trailerField [3]: trailerFieldBC (1) is its only value defined by RFC 4055. */
        uint32_t trailerField;

        /**
         * @brief Constructs an SRsaPssParams holding RSASSA-PSS-params' own DER defaults.
         */
        SRsaPssParams()
            : hashAlgo(crypto::EHASH_SHA1), mgfHashAlgo(crypto::EHASH_SHA1),
              saltLength(20), trailerField(1)
        {
        }
    };

    // --> Forward declaration: CCert::subjectFrom() takes one by reference, and csr.hpp itself
    // includes this header (it reuses CCert's own encode/decode/sign/verify helpers), so the
    // dependency can only run this way round.
    class CCertRequest;

    /* Certificate formats. */
    enum ECertFormat {
        ECERT_AUTO = 0,     /*< Automatically detect the certificate format. */
        ECERT_DER,          /*< DER-encoded certificate. */
        ECERT_PEM,          /*< PEM-encoded certificate. */
    };

    /**
     * Forward declaration of the PEM container format, which owns this library's PEM handling
     * (see `x509/chain/pem.hpp`) and is a friend of CCert -- declared rather than included,
     * since chain/pem.hpp itself includes this header.
     */
    class CPemChainFormat;

    /**
     * @brief Represents an X.509 certificate.
     */
    class CERTPP_API CCert {
        friend class CCertBuilder;
        friend class CCrlReader;
        friend class CCrlWriter;
        friend class CCrlRevokationInfo;
        friend class COcspCertId;
        friend class COcspEntry;
        friend class COcspResponse;
        friend class COcspResponseBuilder;
        friend class COcspRequest;
        friend class COcspRequestBuilder;
        friend class CCertRequest;
        friend class CCertRequestBuilder;

        /* The PEM container format reads and writes certificates, and needs two things this
         * class keeps to itself: _asym (the already-resolved algorithm a candidate private key
         * block has to parse under) and lookupKeyAlgoOid() (KEY_ALGOS's own OID for a key
         * algorithm name, so the OID a PKCS#8 key block carries and the one importDer()
         * resolved come from one table rather than two). Everything else it needs is public. */
        friend class CPemChainFormat;

    private:
        /**
         * @brief Represents the key algorithm information for the certificate.
         */
        struct SKeyAlgo {
            const char* oid;
            const char* name;
            crypto::EAsymmetrics which;
        };

        /**
         * @brief Represents the signature algorithm information for the certificate.
         */
        struct SSigAlgo {
            const char* oid;
            const char* name;
            crypto::EHashers which;
        };

        /**
         * @brief The SubjectPublicKeyInfo fields decodeSubjectPublicKeyInfo() reads out of an
         * encoded SPKI -- grouped into one struct rather than five out-parameters because both
         * CCert::importDer() and CCertRequest::decode() want the whole set, and a five-argument
         * call is exactly where two call sites quietly end up passing them in different orders.
         */
        struct SSpkiFields {
            /* algorithm's display name: KEY_ALGOS's own name, "EC" for id-ecPublicKey, or the
             * OID's own dotted-decimal text for an algorithm this library doesn't implement. */
            CString algoName;

            /* algorithm.parameters' content octets (an EC namedCurve OID's content, a DSA
             * Dss-Parms {p, q, g}'s content); empty for NULL (RSA) or absent (RFC 8410). */
            COctet algoParams;

            /* subjectPublicKey BIT STRING's packed bits, unused-bit count already stripped. */
            COctet publicKey;

            /* The algorithm resolved, meaningful only when `resolved` is true. */
            crypto::EAsymmetrics which;

            /* Whether `which` was actually resolved -- false for an algorithm this library
             * doesn't implement, which still leaves algoName/algoParams/publicKey usable. */
            bool resolved;

            /**
             * @brief Constructs an SSpkiFields holding nothing resolved yet.
             */
            SSpkiFields()
                : which(crypto::EASYM_RSA), resolved(false)
            {
            }
        };

    private:
        static const SKeyAlgo KEY_ALGOS[];
        static const SSigAlgo SIG_ALGOS[];

        /* RFC 5480/SEC2/RFC 5639 namedCurve OIDs, for id-ecPublicKey's ECParameters CHOICE (the
         * { namedCurve OBJECT IDENTIFIER } alternative -- the only one any of this library's own
         * encoders ever produce, and by far the only one seen in practice). Reuses SKeyAlgo's
         * shape ({oid, name, which}) since a named curve is itself just another EAsymmetrics. */
        static const SKeyAlgo EC_CURVES[];

        static constexpr const char* OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";    // --> id-ecPublicKey

        /**
         * @brief One (hash, OID) pair in a signature-OID-by-family lookup table.
         */
        struct SSigHashOid {
            crypto::EHashers hash;
            const char* oid;
        };

        /* Signature-OID lookup tables for resolveSigAlgoForSigning(), one per hash-then-sign
         * family -- separate from SIG_ALGOS (which is indexed by OID, for parsing) since here the
         * lookup runs the other way (family + hash -> OID). Every OID here also appears in
         * SIG_ALGOS, except the two ecdsa-with-SHA224/dsa-with-sha224 entries (RFC 5758), which
         * importDer()'s own resolveSigAlgo() doesn't yet recognize for display purposes -- a gap
         * in parsing/display, not in signing. */
        static const SSigHashOid RSA_SIG_OIDS[];
        static const SSigHashOid DSA_SIG_OIDS[];
        static const SSigHashOid ECDSA_SIG_OIDS[];

        /* Linear lookup of hash within one of the *_SIG_OIDS tables above (table/count identify
         * which one), used 3x by resolveSigAlgoForSigning() (once each for RSA/DSA/ECDSA). */
        static bool lookupSigOid(const SSigHashOid* table, size_t count, crypto::EHashers hash, CString& outOid);

        /* KEY_ALGOS's own OID for a keyAlgo() display name -- the reverse of the lookup
         * importDer()'s resolveKeyAlgo() does. Exists for CPemChainFormat, which needs the OID
         * to write a PKCS#8 PrivateKeyInfo and must not reach it from a second table of its own
         * that could drift out of step with this one. False for a name KEY_ALGOS doesn't list,
         * including the dotted-decimal OID text resolveKeyAlgo() falls back to. */
        static bool lookupKeyAlgoOid(const CString& name, CString& outOid);

    private:
        COctet _rawData;        // --> Raw certificate data, DER-encoded.

        CDistinguishedName _subject;
        CDistinguishedName _issuer;

        CString _subjectStr;
        CString _issuerStr;

        COctet _thumbprint;
        CString _keyAlgo;
        CString _signAlgo;
        crypto::EHashers _sigHashAlgo;

        COctet _keyAlgoParams;
        COctet _publicKey;
        COctet _privateKey;
        COctet _serialNumber;
        COctet _signature;

        SDateTime _notBefore;
        SDateTime _notAfter;

        /* cached cryptographic objects */
        crypto::IAsymmetricPtr _asym;
        mutable crypto::IPublicKeyPtr _cachedPub;
        mutable crypto::IPrivateKeyPtr _cachedPvt;

        std::vector<IExtensionPtr> _extensions;
        bool _keyAlgoIsDsa = false; // --> Whether publicKey()'s lazy build needs DSA's SPKI re-encoding.

        /* Whether signatureAlgorithm is id-RSASSA-PSS *and* its RSASSA-PSS-params parsed, i.e.
         * whether verifyBy() has to go through verifyPss() rather than PKCS#1 v1.5's verify().
         * Only meaningful together with _sigPssParams, which is otherwise left at its defaults. */
        bool _sigIsRsaPss = false;
        SRsaPssParams _sigPssParams;

    public:
        /**
         * @brief Constructs an empty X.509 certificate.
         */
        CCert()
            : _sigHashAlgo(crypto::EHASH_UNKNOWN)
        {
        }

        /**
         * @brief Copy constructor for the X.509 certificate.
         * @param other The certificate to copy from.
         */
        CCert(const CCert& other);

        /**
         * @brief Move constructor for the X.509 certificate.
         * @param other The certificate to move from.
         */
        CCert(CCert&& other);

        /**
         * @brief Copy assignment operator for the X.509 certificate.
         * @param other The certificate to copy from.
         * @return A reference to the assigned certificate.
         */
        CCert& operator=(const CCert& other);

        /**
         * @brief Move assignment operator for the X.509 certificate.
         * @param other The certificate to move from.
         * @return A reference to the assigned certificate.
         */
        CCert& operator=(CCert&& other);

    private:
        /* Resolves an id-ecPublicKey key's namedCurve OID content (keyAlgoParams(), i.e. the
         * OBJECT IDENTIFIER's own content octets, not including its tag/length) to the specific
         * curve EAsymmetrics this library implements it as. */
        static bool resolveEcCurve(SReadOnlyByteSpan namedCurveContent, crypto::EAsymmetrics& outWhich);

        /* Resolves SubjectPublicKeyInfo.algorithm's OID (+ parameters, for id-ecPublicKey) to a
         * display name and, where this library implements the algorithm, an EAsymmetrics.
         * Always sets outName (falling back to the OID's own dotted-decimal text when
         * unrecognized); returns whether outWhich was actually set. */
        static bool resolveKeyAlgo(
            const CString& oid,
            const COctet& params,
            crypto::EAsymmetrics& outWhich,
            CString& outName
        );

        /* Resolves Certificate.signatureAlgorithm's OID to a display name and, for a
         * hash-then-sign scheme (everything but EdDSA), the digest algorithm it signs (left at
         * outHash's caller-supplied default -- EHASH_UNKNOWN -- for EdDSA or an unrecognized
         * OID). Always sets outName, falling back to the OID's own dotted-decimal text when
         * unrecognized. */
        static void resolveSigAlgo(const CString& oid, crypto::EHashers& outHash, CString& outName);

        /* Reads an X.509 Time CHOICE (UTCTime | GeneralizedTime); either read*Time() call rolls
         * the reader back on failure, so trying UTCTime first is safe regardless of which one
         * content actually is. */
        static bool readTime(asn1::CReader& reader, SDateTime& outValue);

        /* Walks the TBSCertificate's extensions [3] EXPLICIT Extensions field (extensionsRaw:
         * the complete encoded Extensions SEQUENCE OF Extension, tag+length+content), populating
         * _extensions (extensionOf()'s own backing store) with one IExtension::create()-built
         * instance per Extension entry -- clearing any previous contents first. Best-effort: a
         * malformed individual Extension entry is skipped rather than aborting the whole scan
         * (extList's cursor has already moved past it regardless of what's inside its own
         * SEQUENCE). Static, with an out-parameter, so CCertRequest can reuse it for the
         * extensionRequest attribute's own Extensions value -- importDer() still only calls it
         * once every other fallible read has already succeeded (see importDer()'s own comment on
         * why), passing _extensions as `out`. */
        static void parseExtensions(const COctet& extensionsRaw, std::vector<IExtensionPtr>& out);

        /* Encodes one AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters
         * ANY DEFINED BY algorithm OPTIONAL } tag-length-value, appending it to out. params is
         * that parameters field already TLV-encoded (as resolveSigAlgoForSigning() hands it
         * back); empty omits the field entirely. Shared by CCertBuilder::build() (which needs
         * one for TBSCertificate.signature/Certificate.signatureAlgorithm) and
         * CCertRequestBuilder::build() (CertificationRequest.signatureAlgorithm). */
        static bool encodeAlgorithmIdentifier(const CString& oid, const COctet& params, CBuffer& out);

        /* Encodes a complete SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
         * subjectPublicKey BIT STRING } tag-length-value for key, appending it to out --
         * including the per-algorithm parameters field (an EC namedCurve OID, a DSA Dss-Parms
         * SEQUENCE split back out of key's own serialize() by splitDsaPublicKeyBlob(), an
         * explicit NULL for RSA, nothing at all for RFC 8410/ML-DSA). The exact inverse of
         * decodeSubjectPublicKeyInfo(). Shared by CCertBuilder::build() and
         * CCertRequestBuilder::build(), which embed a byte-identical SPKI.
         *
         * @param key The public key to encode. Must be non-null.
         * @param out The destination buffer; the SPKI is appended to whatever it already holds.
         * @return ERET_OK on success; ERET_NOTSUP if key's algorithm has no SPKI OID this
         * library knows; ERET_KEY_ERROR if key can't be serialized; ERET_KEY_FORMAT if a DSA
         * key's serialization can't be split into X.509's own representation; ERET_UNKNOWN for
         * an encoding failure.
         */
        static ERetCode encodeSubjectPublicKeyInfo(const crypto::IPublicKeyPtr& key, CBuffer& out);

        /* Reads a SubjectPublicKeyInfo's fields via spkiSeq, a reader positioned inside the SPKI
         * SEQUENCE, into out -- the exact inverse of encodeSubjectPublicKeyInfo(), and shared by
         * CCert::importDer() and CCertRequest::decode(). An algorithm this library doesn't
         * implement is not a failure (out.resolved is simply left false, out.algoName falling
         * back to the OID's own text); false means the encoding itself was malformed, out then
         * being left in an unspecified partially-filled state. */
        static bool decodeSubjectPublicKeyInfo(asn1::CReader& spkiSeq, SSpkiFields& out);

        /* Builds a live public key from decodeSubjectPublicKeyInfo()'s raw output -- the one
         * place that knows DSA's X.509 representation has to go back through
         * buildDsaPublicKeyBlob() first, so CCert::publicKey() and CCertRequest::publicKey()
         * can't drift apart on it. Null if asym is null (an unresolved algorithm) or the bytes
         * don't parse under it. */
        static crypto::IPublicKeyPtr makePublicKey(
            const crypto::IAsymmetricPtr& asym,
            bool isDsa,
            const COctet& params,
            const COctet& publicKey
        );

        /* Encodes an Extensions ::= SEQUENCE OF Extension tag-length-value from extensions,
         * appending it to out: one Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT
         * FALSE, extnValue OCTET STRING } per entry, with critical DER-canonically omitted when
         * false. Deliberately the bare Extensions SEQUENCE and not TBSCertificate's own
         * `[3] EXPLICIT` wrapper, because PKCS#9's extensionRequest attribute carries the
         * SEQUENCE unwrapped -- CCertBuilder::build() adds the [3] layer itself.
         *
         * @param extensions The extensions to encode. Must hold no null entry, and must not be
         * empty (an empty Extensions SEQUENCE is illegal under RFC 5280 4.1.2.9; both callers
         * omit the field entirely instead).
         * @param out The destination buffer; the SEQUENCE is appended to whatever it holds.
         * @return ERET_OK on success; ERET_INVAL if extensions is empty or holds a null entry;
         * ERET_UNKNOWN for an encoding failure.
         */
        static ERetCode encodeExtensions(const TArray<IExtensionPtr>& extensions, CBuffer& out);

        /* Signs toBeSigned with keyPair, producing the bytes a signatureValue/signature BIT
         * STRING carries. sigHash is the digest resolveSigAlgoForSigning() picked, and
         * EHASH_UNKNOWN there means the scheme hashes the message itself (EdDSA, ML-DSA) and
         * toBeSigned is handed to sign() whole; rsaPss selects signPss() and is only meaningful
         * for an RSA keyPair. Shared by CCertBuilder::build() and CCertRequestBuilder::build().
         *
         * @param keyPair The key pair to sign with. Must be non-empty.
         * @param toBeSigned The exact bytes to sign (a TBSCertificate/CertificationRequestInfo).
         * @param sigHash The digest to hash toBeSigned with first, or EHASH_UNKNOWN for a
         * self-hashing scheme.
         * @param rsaPss Whether to sign with RSASSA-PSS rather than EMSA-PKCS1-v1_5.
         * @param outSignature Receives the raw signature bytes.
         * @return ERET_OK on success; ERET_HASH_PIPE if hashing failed; ERET_NOMEM if the
         * signature buffer couldn't be sized; ERET_UNKNOWN if no context could be created;
         * otherwise whatever the algorithm's own sign() reported.
         */
        static ERetCode signTbs(
            const crypto::SKeyPair& keyPair,
            SReadOnlyByteSpan toBeSigned,
            crypto::EHashers sigHash,
            bool rsaPss,
            COctet& outSignature
        );

        /* Checks `signature` over `signedBytes` with ctx -- the shared body behind
         * CCert::verifyBy() and CCertRequest::verify(). keyWhich is the *verifying key's* own
         * algorithm, which is what decides whether signedBytes is hashed first or handed over
         * whole (see signsMessageDirectly()'s own comment on why this must never be inferred
         * from sigHash == EHASH_UNKNOWN instead). isRsaPss/pssParams route an id-RSASSA-PSS
         * signature through verifyPss(), and are ignored otherwise.
         *
         * @param ctx A context already bound to the verifying public key. Must be non-null.
         * @param keyWhich The verifying key's own algorithm.
         * @param signedBytes The exact bytes the signature covers.
         * @param signature The signature to check.
         * @param sigHash The digest the signature algorithm names, or EHASH_UNKNOWN if none.
         * @param isRsaPss Whether the signature is RSASSA-PSS.
         * @param pssParams The RSASSA-PSS parameters; only read when isRsaPss.
         * @return ERET_OK if the signature verifies; ERET_NOTSUP for a hash-then-sign algorithm
         * whose digest never resolved, or an RSASSA-PSS whose maskGenAlgorithm/trailerField
         * verifyPss() can't express; ERET_HASH_PIPE if hashing failed; otherwise whatever the
         * algorithm's own verify() reported.
         */
        static ERetCode verifySignedBlob(
            const crypto::IAsymmetricContextPtr& ctx,
            crypto::EAsymmetrics keyWhich,
            SReadOnlyByteSpan signedBytes,
            SReadOnlyByteSpan signature,
            crypto::EHashers sigHash,
            bool isRsaPss,
            const SRsaPssParams& pssParams
        );

        /* Builds the standalone DER SEQUENCE { p, q, g, y } DSA::createPublicKey() expects, from
         * X.509's split representation: keyAlgoParams() is Dss-Parms { p, q, g }'s own content,
         * and rawPublicKey() is the DER INTEGER y content -- every other builtin algorithm's
         * X.509 wire format already matches its own createPublicKey() input directly, but DSA's
         * domain parameters and public value are split across two different SPKI fields. */
        static bool buildDsaPublicKeyBlob(const COctet& params, const COctet& publicKey, CBuffer& out);

        /* The inverse of buildDsaPublicKeyBlob(): splits a DSA public key's own
         * createPublicKey()-compatible SEQUENCE { p, q, g, y } (crypto::IPublicKey::serialize()'s
         * output for DSA) back into X.509's split SubjectPublicKeyInfo representation --
         * outParams receiving Dss-Parms { p, q, g }'s own content (no outer SEQUENCE
         * tag/length), and outPublicKey the complete DER INTEGER y TLV (RFC 3279 2.3.2's own
         * quirk -- see buildDsaPublicKeyBlob()'s comment). Used by CCertBuilder::build() when
         * subjectKey is a DSA key. */
        static bool splitDsaPublicKeyBlob(const COctet& serialized, COctet& outParams, COctet& outPublicKey);

        /* Resolves a crypto::EAsymmetrics to the SubjectPublicKeyInfo.algorithm fields
         * CCertBuilder::build() needs to embed: outOid is always set (KEY_ALGOS's own OID, or
         * OID_EC_PUBLIC_KEY for any EC/EC2 curve); outIsDsa/outIsEc flag which further handling
         * the caller needs (DSA's Dss-Parms split, EC's namedCurve parameter -- outEcCurveOid --
         * respectively); neither is set for RSA/Ed25519/Ed448/X25519. The exact inverse of
         * resolveKeyAlgo(), built from the same KEY_ALGOS/EC_CURVES tables so the two can never
         * disagree. False if which isn't a value this library implements (shouldn't happen for
         * an EAsymmetrics a real IKeyBase::algorithm() reported).
         */
        static bool resolveKeyAlgoForBuild(
            crypto::EAsymmetrics which,
            CString& outOid,
            bool& outIsDsa,
            bool& outIsEc,
            CString& outEcCurveOid
        );

        /* Picks a signature algorithm OID (+ digest algorithm, EHASH_UNKNOWN for the
         * self-hashing EdDSA schemes) to sign with, for CCertBuilder::build()'s issuerKeyPair,
         * honoring the builder's own digestAlgo/rsaPss fields. hash is the caller's requested
         * digest algorithm (EHASH_UNKNOWN falls back to EHASH_SHA256); it's ignored entirely
         * for Ed25519/Ed448, which are always self-hashing regardless. rsaPss selects RSASSA-PSS
         * (RFC 8017) instead of EMSA-PKCS1-v1_5 -- only meaningful (and only accepted) when
         * which is EASYM_RSA.
         *
         * outOid is always the signature AlgorithmIdentifier's OID; outHash is the digest
         * algorithm actually used (EHASH_UNKNOWN for EdDSA); outParams is that
         * AlgorithmIdentifier's own "parameters" field, already TLV-encoded and ready to splice
         * in as-is -- empty means the parameters field is omitted entirely (DSA/ECDSA/EdDSA), a
         * two-byte NULL TLV for RSA PKCS#1 v1.5, or the full RSASSA-PSS-params SEQUENCE for PSS.
         *
         * False for X25519 (no signing capability at all), rsaPss with a non-RSA which, a hash
         * this library can't produce, a hash with no defined OID for which's family (e.g.
         * ecdsa-with-SHA224 exists but dsa-with-sha384 doesn't), or an EAsymmetrics this
         * library doesn't implement. */
        static bool resolveSigAlgoForSigning(
            crypto::EAsymmetrics which,
            crypto::EHashers hash,
            bool rsaPss,
            CString& outOid,
            crypto::EHashers& outHash,
            COctet& outParams
        );

        /* Builds RSASSA-PSS-params (RFC 8017 A.2.3) for hash: SEQUENCE { hashAlgorithm [0],
         * maskGenAlgorithm [1] (id-mgf1 with hash as its own parameters), saltLength [2] (always
         * hash's own digest length -- this library's own signPss()/verifyPss() convention) };
         * trailerField [3] is always DER's own default (trailerFieldBC) and so is omitted. False
         * if hash has no defined id-sha2-family OID for this purpose (e.g. MD5, SHAKE256, or
         * EHASH_UNKNOWN). Used by resolveSigAlgoForSigning() when rsaPss is requested. */
        static bool buildRsaPssParams(crypto::EHashers hash, COctet& outParams);

        /* The inverse of buildRsaPssParams(): reads an RSASSA-PSS-params SEQUENCE's content (via
         * params, a reader positioned inside it) into an SRsaPssParams. Every field is OPTIONAL
         * by virtue of being DEFAULTed, so any the encoding omits is left at outValue's own
         * constructor default -- an empty SEQUENCE legitimately means "all four defaults". False
         * for a field out of order or repeated, an unknown context tag, a maskGenAlgorithm that
         * isn't id-mgf1, a hash OID this library can't produce, or any malformed TLV; outValue
         * is then left untouched. */
        static bool parseRsaPssParams(asn1::CReader& params, SRsaPssParams& outValue);

        /* Resolves one of RSASSA-PSS-params' HashAlgorithm AlgorithmIdentifiers (via algo, a
         * reader positioned inside the AlgorithmIdentifier SEQUENCE) to the digest it names.
         * Accepts both encodings seen in practice for the parameters field: absent (RFC 5754's
         * SHOULD, what buildRsaPssParams() writes) and an explicit NULL. False for an OID outside
         * the SHA-1/SHA-2 families, a parameters field that's anything but those two, or a
         * malformed TLV. */
        static bool parsePssHashAlgo(asn1::CReader& algo, crypto::EHashers& outHash);

        /* Encodes an X.509 Time CHOICE (UTCTime | GeneralizedTime) from time, appending it to
         * out -- the inverse of readTime(). UTCTime for time.year in [1950, 2049] (RFC 5280
         * 4.1.2.5's own boundary), GeneralizedTime otherwise. False if time.isUtc is false (both
         * CEncoder::encodeUtcTime()/encodeGeneralizedTime() require it) or otherwise unencodable. */
        static bool encodeTime(const SDateTime& time, CBuffer& out);

        /* Encodes a CDistinguishedName as a full Name (SEQUENCE) tag-length-value, appending it
         * to out -- used by CCertBuilder::build() for both issuer and subject. */
        static bool encodeName(const CDistinguishedName& name, CBuffer& out);

        /* SHA-1 digest of the whole raw DER certificate -- the conventional meaning of a
         * certificate "thumbprint"/"fingerprint" in most tooling. */
        static bool computeThumbprint(const COctet& rawData, COctet& out);

        /* Detects whether data is DER or PEM, for importFrom()'s ECERT_AUTO -- by asking
         * IChainFormat::detect(), which sniffs exactly the same "-----BEGIN" encapsulation
         * boundary marker (RFC 7468) for the same reason, and is where that knowledge lives now
         * that CPemChainFormat owns this library's PEM handling. Anything that isn't PEM is
         * reported as ECERT_DER (a DER Certificate's own first byte, 0x30 for its outer
         * SEQUENCE, isn't distinctive enough on its own to be worth checking, unlike PEM's
         * unmistakable text marker). */
        static ECertFormat detectCertFormat(SReadOnlyByteSpan data);

    public:
        /**
         * @brief Whether an algorithm's sign()/verify() take the message itself rather than a
         * pre-computed digest -- Ed25519/Ed448 (which hash internally, twice, with different
         * prefixes) and all three ML-DSA parameter sets (which derive mu from the message and
         * then hash a lattice commitment).
         *
         * This exists as one function rather than four copies of the predicate because four
         * places have to agree about it -- CCert::verifyBy(), CCrlReader::verifyBy() and both
         * OCSP verifySignature()s -- and a site that misses an entry does not fail to compile or
         * fail loudly: it hands the raw TBS bytes to a hash-then-sign verify as though they were
         * a digest, or hands a digest to ML-DSA and signs that 32-byte string instead of the
         * message. Both were real bugs in this library's own history (see verifyBy()'s comment
         * on OCSP), and both are invisible to a self-signed round trip.
         *
         * Note what it is deliberately not: a test of _sigHashAlgo == EHASH_UNKNOWN. That value
         * is also what resolveSigAlgo() leaves behind for an OID absent from SIG_ALGOS, so the
         * two cases are indistinguishable there and an unrecognized algorithm must fail closed
         * instead. The decision is made from the verifying key's own algorithm().
         *
         * Public because a caller signing or verifying through this library faces the same
         * choice and must not reimplement the predicate -- see the paragraph above on what
         * happens to the site that gets it wrong.
         * @param which The algorithm of the key that will sign or verify.
         * @return True if sign()/verify() take the message, false if they take a digest.
         */
        static bool signsMessageDirectly(crypto::EAsymmetrics which);

    public:
        /**
         * @brief Imports the X.509 certificate from DER-encoded raw data (a ".cer"/".crt"/".der"
         * file's contents -- a bare Certificate, not PEM text and not a PKCS#7/PKCS#12
         * container). Always parsed as DER, per the X.509 profile.
         *
         * Only fields this class exposes a getter for are populated. issuerUniqueID/
         * subjectUniqueID and the TBSCertificate-embedded copy of the signature algorithm are
         * read past but not retained. Every extension's raw extnValue is kept (see
         * extensionOf()); KeyUsage (id-ce-keyUsage) is additionally interpreted into keyUsages().
         * keyAlgo()/signAlgo() fall back to the dotted-decimal OID text (and the algorithm
         * identifiers publicKey()/createHasher() resolve against internally stay unresolved) for
         * an algorithm this library doesn't implement -- that alone does not fail the importDer,
         * since the rest of the certificate's data is still valid. publicKey() itself isn't
         * built until first called (see its own doc comment); any private key previously
         * attached via privateKey(IPrivateKeyPtr&) is cleared, since it was for whatever
         * certificate was imported before this call, not this one.
         *
         * @param data The raw DER certificate data.
         * @return ERET_OK on success; ERET_INVAL if data is empty; ERET_BADREQ if data isn't a
         * well-formed X.509 Certificate.
         */
        ERetCode importDer(const COctet& data);

        /**
         * @brief Imports the X.509 certificate from PEM-encoded raw data (a ".pem" file's
         * contents). The file may hold more than one "-----BEGIN ... -----" block -- the first
         * CERTIFICATE block found becomes this certificate; any other block (typically a private
         * key, e.g. "RSA PRIVATE KEY"/"PRIVATE KEY"/"EC PRIVATE KEY") is tried as this
         * certificate's own private key afterward, best-effort -- a key block that's absent,
         * unsupported, or simply isn't this certificate's own key pair just leaves privateKey()
         * unset rather than failing the importFrom.
         *
         * @note This is a convenience over CPemChainFormat (x509/chain/pem.hpp), which owns this
         * library's PEM handling: the file is loaded as the container it is, and the first entry
         * is taken. One consequence is worth knowing: a PEM file is read whole, so a *structurally
         * broken* block anywhere in it (a missing "-----END", a body that isn't base64) fails the
         * import, where an earlier version of this method stopped scanning at that point and
         * silently reported success with whatever it had already found.
         *
         * @param data The raw PEM certificate data.
         * @return ERET_OK on success; ERET_INVAL if data is empty; ERET_BADREQ if no CERTIFICATE
         * block is found, a block is structurally broken, or a CERTIFICATE block isn't a
         * well-formed X.509 Certificate; ERET_NOTSUP if the file carries a password-encrypted
         * private-key block (which has no password to be opened with here).
         */
        ERetCode importPem(const COctet& data);

        /**
         * @brief Imports the X.509 certificate from raw data in the specified format. With the
         * default ECERT_AUTO, the format is detected from data itself (see detectCertFormat()'s
         * own doc comment) -- ECERT_DER/ECERT_PEM can still be passed explicitly to skip that
         * detection.
         *
         * @param data The raw certificate data.
         * @param format The format of the certificate data (default is AUTO).
         * @return ERET_OK on success; ERET_INVAL if data is empty; ERET_BADREQ if data isn't a
         * well-formed X.509 Certificate.
         */
        ERetCode importFrom(const SReadOnlyByteSpan& data, ECertFormat format = ECERT_AUTO);

        /**
         * @brief Resets the X.509 certificate to an empty state.
         */
        void reset();

        /**
         * @brief Checks if the certificate is empty.
         * @return True if the certificate is empty, false otherwise.
         */
        inline bool empty() const { return _rawData.empty(); }

        /**
         * @brief Checks if the certificate is valid.
         * @return True if the certificate is valid, false otherwise.
         */
        inline operator bool() const { return !empty(); }

        /**
         * @brief Checks if the certificate is not valid.
         * @return True if the certificate is not valid, false otherwise.
         */
        inline bool operator!() const { return empty(); }

        /**
         * @brief Gets the raw certificate data.
         * @return The raw certificate data.
         */
        inline const COctet& rawData() const { return _rawData; }

        /**
         * @brief Gets the subject name of the certificate.
         * @return The subject name.
         */
        inline const CDistinguishedName& subject() const { return _subject; }

        /**
         * @brief Gets the subject name of the certificate as a string.
         * @return The subject name as a string.
         */
        inline const CString& subjectStr() const { return _subjectStr; }

        /**
         * @brief Gets the issuer name of the certificate.
         * @return The issuer name.
         */
        inline const CDistinguishedName& issuer() const { return _issuer; }

        /**
         * @brief Gets the issuer name of the certificate as a string.
         * @return The issuer name as a string.
         */
        inline const CString& issuerStr() const { return _issuerStr; }

        /**
         * @brief Gets the thumbprint of the certificate: the SHA-1 digest of the whole raw DER
         * certificate (rawData()), matching the conventional meaning of "thumbprint"/
         * "fingerprint" in most certificate tooling.
         * @return The thumbprint.
         */
        inline const COctet& thumbprint() const { return _thumbprint; }

        /**
         * @brief Gets the raw signature bits from Certificate.signatureValue -- the signature
         * itself, with the BIT STRING wrapper and its unused-bit count already stripped. Its
         * internal format is the signature algorithm's own: a bare big-endian integer for RSA,
         * a DER Dss-Sig-Value/Ecdsa-Sig-Value SEQUENCE for DSA/ECDSA, R||S for EdDSA.
         * @return The signature value, or an empty COctet if this certificate was never imported.
         */
        inline const COctet& signature() const { return _signature; }

        /**
         * @brief Returns the exact TBSCertificate element the signature was computed over: its
         * complete TLV (tag and length included), as it appears inside rawData().
         *
         * This is the span to hash when verifying by hand. It is deliberately the original bytes
         * rather than a re-encoding of the parsed fields -- re-encoding would silently "repair"
         * any encoding quirk the issuer actually signed, and the signature covers the issuer's
         * bytes, not this library's idea of them.
         * @return The TBSCertificate's complete DER element, or an empty span if this certificate
         * was never imported or its outer structure cannot be walked.
         */
        SReadOnlyByteSpan tbsCertificate() const;

        /**
         * @brief Verifies this certificate's own signature against an issuer certificate's public
         * key -- i.e. answers "did this issuer sign this certificate?".
         *
         * This is a single-link check and nothing more: it does not walk a chain, match issuer
         * and subject names, check validity dates, or enforce BasicConstraints/KeyUsage. A caller
         * building a validator supplies all of that itself; see docs/architecture.md's scope note.
         * Pass *this as the issuer to check a self-signed certificate.
         * @param issuer The certificate whose public key is expected to have signed this one.
         * @return ERET_OK if the signature verifies; ERET_INVAL if either certificate is empty or
         * this one carries no signature/TBS to check; ERET_KEY_EMPTY if the issuer exposes no
         * usable public key; ERET_NOTSUP if this certificate's signature algorithm isn't one this
         * library can verify (an unregistered OID, an id-RSASSA-PSS whose parameters didn't
         * parse, or an RSASSA-PSS whose maskGenAlgorithm/trailerField this library's verifyPss()
         * can't express -- see rsaPssParams()); ERET_HASH_PIPE if hashing failed; otherwise
         * whatever the algorithm's own verify() reported, with a plain mismatch distinguishable
         * from an error.
         */
        ERetCode verifyBy(const CCert& issuer) const;

        /**
         * @brief Gets the key algorithm of the certificate.
         * @return The key algorithm.
         */
        inline const CString& keyAlgo() const { return _keyAlgo; }

        /**
         * @brief Gets the signature algorithm of the certificate.
         * @return The signature algorithm.
         */
        inline const CString& signAlgo() const { return _signAlgo; }

        /**
         * @brief Gets the RSASSA-PSS parameters (RFC 4055 3.1) this certificate's own signature
         * was produced with, for an id-RSASSA-PSS signatureAlgorithm whose parameters parsed.
         *
         * A field the DER omitted because it equals its ASN.1 default is reported as that
         * default, not as "absent": under DER a field equal to its default has to be left out,
         * so the two are the same statement. verifyBy() already applies these itself; this is for
         * a caller that wants to inspect or re-verify by hand.
         * @param outValue Receives the parameters. Left untouched if this returns false.
         * @return true if this certificate's signature algorithm is RSASSA-PSS and its
         * parameters were parsed; false for any other algorithm (including an id-RSASSA-PSS
         * whose parameters were malformed, which leaves signAlgo() resolved but the signature
         * unverifiable).
         */
        inline bool rsaPssParams(SRsaPssParams& outValue) const {
            if (!_sigIsRsaPss) {
                return false;
            }

            outValue = _sigPssParams;
            return true;
        }

        /**
         * @brief Gets the key algorithm parameters of the certificate: the content octets of
         * SubjectPublicKeyInfo.algorithm.parameters (e.g. an EC key's namedCurve OID content, or
         * a DSA key's Dss-Parms {p, q, g} content), not including that field's own tag/length.
         * Empty when the algorithm's parameters are NULL (RSA) or absent (Ed25519/Ed448/X25519).
         * @return The key algorithm parameters.
         */
        inline const COctet& keyAlgoParams() const { return _keyAlgoParams; }

        /**
         * @brief Gets the public key of the certificate: the content octets of
         * SubjectPublicKeyInfo.subjectPublicKey (the BIT STRING's packed bits, not including its
         * unused-bits count octet) -- e.g. an RSA key's DER RSAPublicKey SEQUENCE, an EC key's
         * raw point encoding, or a DSA key's DER INTEGER y.
         * @return The public key.
         */
        inline const COctet& rawPublicKey() const { return _publicKey; }

        /**
         * @brief Gets the private key of the certificate.
         * @return The private key.
         * @note to check the certificate has private key, check this returns non-empty.
         */
        inline const COctet& rawPrivateKey() const { return _privateKey; }

        /**
         * @brief Gets the public key of the certificate as an IPublicKeyPtr.
         * @return A pointer to the public key.
         */
        crypto::IPublicKeyPtr publicKey() const;

        /**
         * @brief Gets the private key of the certificate as an IPrivateKeyPtr.
         * @return A pointer to the private key.
         * @note to check the certificate has private key, check this returns non-null.
         */
        crypto::IPrivateKeyPtr privateKey() const;

        /**
         * @brief Sets the private key of the certificate.
         * @param inKey A pointer to the private key to set.
         * @return The result code of the operation.
         * @note The private key must be compatible with the certificate's public key.
         */
        ERetCode privateKey(crypto::IPrivateKeyPtr& inKey);

        /**
         * @brief Gets the serial number of the certificate.
         * @return The serial number.
         */
        inline const COctet& serialNumber() const { return _serialNumber; }

        /**
         * @brief Gets the not before date of the certificate.
         * @return The not before date.
         */
        inline const SDateTime& notBefore() const { return _notBefore; }

        /**
         * @brief Gets the not after date of the certificate.
         * @return The not after date.
         */
        inline const SDateTime& notAfter() const { return _notAfter; }

        /**
         * @brief Gets the certificate's key usages: a bitwise combination of EKeyUsages flags,
         * decoded from the KeyUsage extension (id-ce-keyUsage) if present. EKUSE_NONE if the
         * certificate has no KeyUsage extension (or none of its bits are set).
         * @return The key usages.
         */
        inline uint16_t keyUsages() const {
            auto ext = extension<CKeyUsagesExtension>();
            return ext ? ext->bits() : EKUSE_NONE;
        }

        /**
         * @brief Gets the subject key identifier of the certificate.
         * @param out The output subject key identifier.
         * @return The result code of the operation.
         */
        ERetCode subjectKeyIdentifier(COctet& out) const;

        /**
         * @brief Gets the authority key identifier of the certificate.
         * @param out The output authority key identifier.
         * @return The result code of the operation.
         */
        ERetCode authorityKeyIdentifier(COctet& out) const;

        /**
         * @brief Gets the extension of the certificate by its OID.
         * @param oid The OID of the extension to retrieve.
         * @param out The octet of the extension value in DER format.
         * @return The result code of the operation.
         */
        ERetCode extensionOf(const char* oid, IExtensionPtr& out) const;

        /**
         * @brief Gets the extension of the certificate by its OID.
         * @param oid The OID of the extension to retrieve.
         * @param out The octet of the extension value in DER format.
         * @return The result code of the operation.
         */
        ERetCode extensionOf(const wchar_t* oid, IExtensionPtr& out) const;

        /**
         * @brief Gets the extension of the certificate by its OID.
         * @param oid The OID of the extension to retrieve.
         * @param out The output buffer for the extension value.
         * @return The result code of the operation.
         */
        template<typename T>
        inline ERetCode extensionOf(const TString<T>& oid, IExtensionPtr& out) const {
            return extensionOf(oid.toPtr(), out);
        }

        /**
         * @brief Gets a specific extension by its concrete IExtension subclass (e.g.
         * CBasicConstraintsExtension), looked up by that class's own OID and downcast to it.
         * @tparam TExtension A concrete IExtension subclass exposing a static OID member.
         * @return A shared pointer to the extension, or null if the certificate has no
         * extension with that OID.
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
         * @brief Compares this certificate with another for equality.
         * @param other The other certificate to compare with.
         * @return True if the certificates are equal, false otherwise.
         */
        bool equals(const CCert& other) const;

        /**
         * @brief Creates a hasher for the digest algorithm this certificate's signature
         * algorithm (signAlgo()) uses -- push the data to be signed/verified through it, then
         * pass the result to createAsymmetricContext()'s sign()/verify(). Null if signAlgo()
         * wasn't resolved to a supported digest (an algorithm this library doesn't implement, or
         * a hash-less/self-hashing scheme like Ed25519/Ed448).
         * @return A pointer to the hasher, or null.
         */
        crypto::IHasherPtr createHasher() const;

        /**
         * @brief Creates an asymmetric context for the certificate's public key, and its
         * attached private key (privateKey()) if one has been set via
         * privateKey(IPrivateKeyPtr&) -- ready for sign() as well as verify() in that case.
         * @return A pointer to the asymmetric context.
         */
        crypto::IAsymmetricContextPtr createAsymmetricContext() const;

        /**
         * @brief Signs the given digest using the certificate's private key.
         * @param digest The digest to sign.
         * @param signature The output buffer for the signature.
         * @return The result code of the operation.
         */
        ERetCode sign(const SReadOnlyByteSpan& digest, SByteSpan& signature) const;

        /**
         * @brief Verifies the given digest against the provided signature using the certificate's public key.
         * @param digest The digest to verify.
         * @param signature The signature to verify.
         * @return The result code of the operation.
         */
        ERetCode verify(const SReadOnlyByteSpan& digest, const SReadOnlyByteSpan& signature) const;

        /**
         * @brief Signs the given data using the certificate's private key.
         * @param data The data to sign.
         * @param signature The output buffer for the signature.
         * @return The result code of the operation.
         */
        ERetCode signData(const SReadOnlyByteSpan& data, SByteSpan& signature) const;

        /**
         * @brief Verifies the given signature against the provided data using the certificate's public key.
         * @param data The data that was signed.
         * @param signature The signature to verify.
         * @return The result code of the operation.
         */
        ERetCode verifyData(const SReadOnlyByteSpan& data, const SReadOnlyByteSpan& signature) const;

        /**
         * @brief Exports the certificate in DER format.
         * @param output The output buffer for the DER-encoded certificate.
         * @return The result code of the operation.
         * @note This does not export private key.
         */
        ERetCode exportDer(COctet& output) const;

        /**
         * @brief Exports the certificate in PEM format.
         * @note A convenience over CPemChainFormat (x509/chain/pem.hpp), which owns this
         * library's PEM handling: this certificate is saved as a one-entry container.
         * @param output The output buffer for the PEM-encoded certificate.
         * @param includePrivateKey Whether to also include privateKey() (if attached), as a
         * "<ALGO> PRIVATE KEY" block -- works for every algorithm this library implements (see
         * CPemChainFormat::appendPrivateKeyBlock() for which label each one gets, and the
         * interoperability caveat for Ed25519/Ed448/X25519, which have no traditional-format PEM
         * convention of their own). **The key is written in the clear**; PEM has no encryption.
         * @return The result code of the operation.
         */
        ERetCode exportPem(COctet& output, bool includePrivateKey = false) const;

        /**
         * @brief Exports the certificate in the specified format (DER or PEM).
         * @note Named exportAs(), not export() -- `export` is a reserved C++ keyword (still
         * reserved even after the export-template feature it originally named was removed, and
         * reused by C++20 modules), so it can't be used as a method name here.
         * @param output The output buffer for the certificate in the specified format.
         * @param includePrivateKey Whether to include the private key in the output.
         * @param format The format to export the certificate in (ECERT_DER or ECERT_PEM;
         * ECERT_AUTO is not a meaningful export format and returns ERET_NOTSUP).
         */
        ERetCode exportAs(COctet& output, bool includePrivateKey = false, ECertFormat format = ECERT_DER) const;
    };

    /**
     * @brief A builder class for constructing X.509 certificates.
     */
    class CERTPP_API CCertBuilder {
    public:
        CDistinguishedName issuer;          ///< The issuer's distinguished name.
        CDistinguishedName subject;         ///< The subject's distinguished name.

        COctet serialNumber;                ///< The certificate's serial number.
        SDateTime notBefore;                ///< The start of the certificate's validity period.
        SDateTime notAfter;                 ///< The end of the certificate's validity period.

        TArray<IExtensionPtr> extensions;   ///< The certificate's extensions.

        crypto::IPublicKeyPtr subjectKey;   ///< The subject key.
        crypto::SKeyPair issuerKeyPair;     ///< The issuer's key pair.

        /**
         * The digest algorithm to sign the TBSCertificate with. Defaults to EHASH_SHA256, a
         * reasonable, secure default matching most CA tooling's own default today;
         * EHASH_UNKNOWN also falls back to it. Ignored entirely for an Ed25519/Ed448
         * issuerKeyPair, which is always self-hashing regardless of this field. Not every
         * (issuerKeyPair algorithm, digestAlgo) combination has a defined signature OID -- see
         * build()'s own @return for which ERetCode a mismatch (e.g. EHASH_MD5 with an EC key)
         * produces.
         */
        crypto::EHashers digestAlgo = crypto::EHASH_SHA256;

        /**
         * Signs with RSASSA-PSS (RFC 8017) instead of EMSA-PKCS1-v1_5. Only meaningful (and only
         * accepted by build()) when issuerKeyPair is RSA; the salt length is always digestAlgo's
         * own digest length, and MGF1 always uses digestAlgo as its own underlying hash.
         */
        bool rsaPss = false;

    public:
        /**
         * @brief Builds and returns the X.509 certificate based on the provided information.
         * @param out The output parameter that will hold the constructed X.509 certificate.
         * @return ERET_OK on success; ERET_INVAL if a required field (subjectKey,
         * issuerKeyPair, issuer, subject, serialNumber) is missing or notBefore/notAfter
         * isn't UTC; ERET_NOTSUP if issuerKeyPair can't sign at all (X25519), or
         * (issuerKeyPair's algorithm, digestAlgo, rsaPss) isn't a combination this library
         * defines a signature OID for; another ERetCode for other failures (e.g. ERET_KEY_ERROR
         * if subjectKey can't be serialized).
         */
        ERetCode build(CCert& out) const;

        /**
         * @brief Takes `subject` and `subjectKey` from a PKCS#10 certification request -- the
         * CA-side half of a CSR exchange: the requester proved possession of subjectKey by
         * self-signing the request, and this copies over exactly the two things that proof
         * covers.
         *
         * It deliberately copies **nothing else**, and in particular not the request's
         * requested extensions. A CSR is an unauthenticated wish-list from whoever generated it:
         * a request's self-signature proves possession of a private key and says nothing
         * whatsoever about whether its subject name or its requested BasicConstraints/KeyUsage/
         * SubjectAlternativeName are ones this CA should be willing to certify. Copying
         * `request.extensions()` into `extensions` wholesale is how a CA issues a CA certificate,
         * or a certificate for a domain the requester doesn't control, because the requester
         * asked it to. So there is no method here that does that: a CA that wants a requested
         * extension reads the specific one it is prepared to grant (via
         * `request.extension<CSanExtension>()` and friends), validates it against its own policy,
         * and pushes it onto `extensions` itself -- one explicit decision per extension. The
         * subject name itself still needs the same scrutiny; this method copies it because a
         * certificate cannot be issued without one, not because it is trustworthy.
         *
         * @param request The certification request to take the subject name and key from. Its
         * self-signature must already have been verified -- CCertRequest::decode() does that
         * before it ever reports success, so any non-empty CCertRequest has been.
         * @return ERET_OK on success; ERET_INVAL if request is empty; ERET_KEY_EMPTY if it
         * exposes no usable public key (an algorithm this library doesn't implement).
         */
        ERetCode subjectFrom(const CCertRequest& request);
    };
} // namespace x509
} // namespace certpp

#endif
