#include <certpp/x509/cert.hpp>
// --> For CCertBuilder::subjectFrom()'s own definition, which needs CCertRequest complete.
// csr.hpp includes cert.hpp rather than the other way round, so this include can only sit here
// in the .cpp, which is also where the declaration's matching definition belongs.
#include <certpp/x509/csr.hpp>
#include <certpp/x509/chain/pem.hpp>
#include <certpp/x509/exts/ski.hpp>
#include <certpp/x509/exts/aki.hpp>
#include <certpp/crypto/asyms/mldsa.hpp>
#include <certpp/asn1/reader.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/utils/bignum.hpp>
#include <certpp/utils/secure.hpp>
#include <certpp/io/buffer.hpp>
#include <cstring>

namespace certpp {
namespace x509 {

    using asn1::CReader;
    using asn1::CDecoder;
    using asn1::CEncoder;
    using asn1::CDer;
    using asn1::CTag;
    using asn1::EAENC_DER;
    using asn1::EATAG_CONTEXT_SPECIFIC;

    namespace {

        /* Wipes a COctet's or CBuffer's bytes when it leaves scope.
         *
         * The PKCS#8 conversions below hold a private key in half a dozen locals across twenty
         * return statements, and a wipe written out beside each one is a wipe that is wrong the
         * first time a branch is added. Neither COctet nor CBuffer clears on destruction, so
         * without this the key stays in freed heap for whatever allocates next.
         *
         * It does *not* reach the intermediate states of a buffer that grew: CBuffer::resize()
         * reallocates per append and frees the previous block unwiped, which is a property of the
         * buffer type -- shared with exportPem()'s own key paths -- rather than of these methods. */
        template<typename T>
        class ScopedWipe {
        private:
            T& _target;

        public:
            explicit ScopedWipe(T& target) : _target(target) { }

            ScopedWipe(const ScopedWipe&) = delete;
            ScopedWipe& operator=(const ScopedWipe&) = delete;

            ~ScopedWipe() {
                CSecure::zero(SByteSpan(
                    const_cast<uint8_t*>(_target.toPtr()), _target.size()));
            }
        };

    } // namespace

    /* Public-key algorithm OIDs whose EAsymmetrics doesn't depend on any further
     * parameters -- id-ecPublicKey is deliberately excluded here (its EAsymmetrics
     * depends on the namedCurve OID carried in the AlgorithmIdentifier's parameters) and handled
     * separately via EC_CURVES below. */
    const CCert::SKeyAlgo CCert::KEY_ALGOS[] = {
        { COid::RSA, "RSA",     crypto::EASYM_RSA },
        { COid::DSA,    "DSA",     crypto::EASYM_DSA },
        { COid::X25519,          "X25519",  crypto::EASYM_X25519 },
        { COid::ED25519,          "Ed25519", crypto::EASYM_ED25519 },
        { COid::ED448,          "Ed448",   crypto::EASYM_ED448 },

        // NIST CSOR's ML-DSA arc, as RFC 9881 2 profiles it for X.509. The three OIDs run 17/18/
        // 19 for ML-DSA-44/65/87 -- consecutive, so an off-by-one here resolves a certificate to
        // the wrong parameter set, and since every parameter set has a different public-key
        // length that shows up as createPublicKey() refusing the key rather than as a wrong
        // answer. The IdenTrust pilot root in tests/x509/certs/implemented/ carries .19, and its
        // 2592-byte key and 4627-byte signature are ML-DSA-87's own sizes.
        { COid::MLDSA44, "ML-DSA-44", crypto::EASYM_MLDSA44 },
        { COid::MLDSA65, "ML-DSA-65", crypto::EASYM_MLDSA65 },
        { COid::MLDSA87, "ML-DSA-87", crypto::EASYM_MLDSA87 },
    };

    const CCert::SKeyAlgo CCert::EC_CURVES[] = {
        { COid::CURVE_P192, "P-192",       crypto::EASYM_P192 },
        { COid::CURVE_P224,        "P-224",       crypto::EASYM_P224 },
        { COid::CURVE_P256, "P-256",       crypto::EASYM_P256 },
        { COid::CURVE_P384,        "P-384",       crypto::EASYM_P384 },
        { COid::CURVE_P521,        "P-521",       crypto::EASYM_P521 },
        { COid::CURVE_SECP256K1,        "secp256k1",   crypto::EASYM_SECP256K1 },
        { COid::CURVE_BRAINPOOL_P160R1,  "brainpoolP160r1", crypto::EASYM_BPOOL160R1 },
        { COid::CURVE_BRAINPOOL_P160T1,  "brainpoolP160t1", crypto::EASYM_BPOOL160T1 },
        { COid::CURVE_BRAINPOOL_P192R1,  "brainpoolP192r1", crypto::EASYM_BPOOL192R1 },
        { COid::CURVE_BRAINPOOL_P192T1,  "brainpoolP192t1", crypto::EASYM_BPOOL192T1 },
        { COid::CURVE_BRAINPOOL_P224R1,  "brainpoolP224r1", crypto::EASYM_BPOOL224R1 },
        { COid::CURVE_BRAINPOOL_P224T1,  "brainpoolP224t1", crypto::EASYM_BPOOL224T1 },
        { COid::CURVE_BRAINPOOL_P256R1,  "brainpoolP256r1", crypto::EASYM_BPOOL256R1 },
        { COid::CURVE_BRAINPOOL_P256T1,  "brainpoolP256t1", crypto::EASYM_BPOOL256T1 },
        { COid::CURVE_BRAINPOOL_P320R1,  "brainpoolP320r1", crypto::EASYM_BPOOL320R1 },
        { COid::CURVE_BRAINPOOL_P320T1, "brainpoolP320t1", crypto::EASYM_BPOOL320T1 },
        { COid::CURVE_BRAINPOOL_P384R1, "brainpoolP384r1", crypto::EASYM_BPOOL384R1 },
        { COid::CURVE_BRAINPOOL_P384T1, "brainpoolP384t1", crypto::EASYM_BPOOL384T1 },
        { COid::CURVE_BRAINPOOL_P512R1, "brainpoolP512r1", crypto::EASYM_BPOOL512R1 },
        { COid::CURVE_BRAINPOOL_P512T1, "brainpoolP512t1", crypto::EASYM_BPOOL512T1 },
        { COid::CURVE_K163,  "K-163", crypto::EASYM_K163 },
        { COid::CURVE_B163, "B-163", crypto::EASYM_B163 },
        { COid::CURVE_K233, "K-233", crypto::EASYM_K233 },
        { COid::CURVE_B233, "B-233", crypto::EASYM_B233 },
        { COid::CURVE_K283, "K-283", crypto::EASYM_K283 },
        { COid::CURVE_B283, "B-283", crypto::EASYM_B283 },
        { COid::CURVE_K409, "K-409", crypto::EASYM_K409 },
        { COid::CURVE_B409, "B-409", crypto::EASYM_B409 },
        { COid::CURVE_K571, "K-571", crypto::EASYM_K571 },
        { COid::CURVE_B571, "B-571", crypto::EASYM_B571 },
    };

    /* Signature algorithm OIDs. EBASYM isn't recorded here -- unlike the public-key algorithm
     * above, a signature OID like ecdsa-with-SHA256 doesn't name a specific curve (any EC key
     * can use it), so the signature's own asymmetric family is never needed separately from
     * keyAlgo()'s. */
    const CCert::SSigAlgo CCert::SIG_ALGOS[] = {
        { COid::MD5_RSA,   "md5WithRSAEncryption",    crypto::EHASH_MD5 },
        { COid::SHA1_RSA,   "sha1WithRSAEncryption",   crypto::EHASH_SHA1 },
        { COid::SHA224_RSA,  "sha224WithRSAEncryption", crypto::EHASH_SHA224 },
        { COid::SHA256_RSA,  "sha256WithRSAEncryption", crypto::EHASH_SHA256 },
        { COid::SHA384_RSA,  "sha384WithRSAEncryption", crypto::EHASH_SHA384 },
        { COid::SHA512_RSA,  "sha512WithRSAEncryption", crypto::EHASH_SHA512 },
        { COid::SHA1_DSA,      "dsa-with-sha1",           crypto::EHASH_SHA1 },
        { COid::SHA224_DSA, "dsa-with-sha224",         crypto::EHASH_SHA224 },
        { COid::SHA256_DSA, "dsa-with-sha256",         crypto::EHASH_SHA256 },
        { COid::SHA1_ECDSA,      "ecdsa-with-SHA1",         crypto::EHASH_SHA1 },
        { COid::SHA224_ECDSA,    "ecdsa-with-SHA224",       crypto::EHASH_SHA224 },
        { COid::SHA256_ECDSA,    "ecdsa-with-SHA256",       crypto::EHASH_SHA256 },
        { COid::SHA384_ECDSA,    "ecdsa-with-SHA384",       crypto::EHASH_SHA384 },
        { COid::SHA512_ECDSA,    "ecdsa-with-SHA512",       crypto::EHASH_SHA512 },
        { COid::ED25519,            "Ed25519",                 crypto::EHASH_UNKNOWN },
        { COid::ED448,            "Ed448",                   crypto::EHASH_UNKNOWN },
        // --> id-RSASSA-PSS (RFC 4055) names no digest of its own: the hash lives in the
        // AlgorithmIdentifier's parameters, which importDer() reads separately via
        // parseRsaPssParams() and then uses to set _sigHashAlgo. EHASH_UNKNOWN here keeps
        // resolveSigAlgo() from claiming a digest this OID genuinely doesn't carry.
        { COid::RSASSA_PSS,  "rsassaPss",               crypto::EHASH_UNKNOWN },

        // --> The same three OIDs as KEY_ALGOS above, which is correct and not a copy/paste
        // slip: RFC 9881 uses one identifier for both the key type and the signature, the way
        // Ed25519/Ed448 do and unlike ecdsa-with-SHA256. EHASH_UNKNOWN because there is no
        // separate digest -- see signsMessageDirectly(), which is what verifyBy() actually
        // branches on; EHASH_UNKNOWN here is ambiguous with "OID not in this table at all" and
        // must never be read as "self-hashing" on its own.
        { COid::MLDSA44, "ML-DSA-44",              crypto::EHASH_UNKNOWN },
        { COid::MLDSA65, "ML-DSA-65",              crypto::EHASH_UNKNOWN },
        { COid::MLDSA87, "ML-DSA-87",              crypto::EHASH_UNKNOWN },
    };

    /* Whether an algorithm signs the message itself rather than a caller-supplied digest. */
    bool CCert::signsMessageDirectly(crypto::EAsymmetrics which) {
        return which == crypto::EASYM_ED25519
            || which == crypto::EASYM_ED448
            || crypto::CMlDsa::isMlDsa(which);
    }

    /* Copy constructor for the X.509 certificate. */
    CCert::CCert(const CCert& other) {
        _rawData = other._rawData;
        _subject = other._subject;
        _issuer = other._issuer;
        _subjectStr = other._subjectStr;
        _issuerStr = other._issuerStr;
        _thumbprint = other._thumbprint;
        _keyAlgo = other._keyAlgo;
        _signAlgo = other._signAlgo;
        _keyAlgoParams = other._keyAlgoParams;
        _publicKey = other._publicKey;
        _privateKey = other._privateKey;
        _serialNumber = other._serialNumber;
        _signature = other._signature;
        _notBefore = other._notBefore;
        _notAfter = other._notAfter;
        _asym = other._asym;
        _cachedPub = other._cachedPub;
        _cachedPvt = other._cachedPvt;
        _sigHashAlgo = other._sigHashAlgo;
        _sigIsRsaPss = other._sigIsRsaPss;
        _sigPssParams = other._sigPssParams;
        _keyAlgoIsDsa = other._keyAlgoIsDsa;
        _extensions = other._extensions;
    }

    /* Move constructor for the X.509 certificate. */
    CCert::CCert(CCert&& other) {
        _rawData = move(other._rawData);
        _subject = move(other._subject);
        _issuer = move(other._issuer);
        _subjectStr = move(other._subjectStr);
        _issuerStr = move(other._issuerStr);
        _thumbprint = move(other._thumbprint);
        _keyAlgo = move(other._keyAlgo);
        _signAlgo = move(other._signAlgo);
        _keyAlgoParams = move(other._keyAlgoParams);
        _publicKey = move(other._publicKey);
        _privateKey = move(other._privateKey);
        _serialNumber = move(other._serialNumber);
        _signature = move(other._signature);
        _notBefore = move(other._notBefore);
        _notAfter = move(other._notAfter);
        _asym = move(other._asym);
        _cachedPub = move(other._cachedPub);
        _cachedPvt = move(other._cachedPvt);
        _sigHashAlgo = other._sigHashAlgo;
        _sigIsRsaPss = other._sigIsRsaPss;
        _sigPssParams = other._sigPssParams;
        _keyAlgoIsDsa = other._keyAlgoIsDsa;
        _extensions = move(other._extensions);
    }

    /* Copy assignment operator for the X.509 certificate. */
    CCert& CCert::operator=(const CCert& other) {
        if (this != &other) {
            _rawData = other._rawData;
            _subject = other._subject;
            _issuer = other._issuer;
            _subjectStr = other._subjectStr;
            _issuerStr = other._issuerStr;
            _thumbprint = other._thumbprint;
            _keyAlgo = other._keyAlgo;
            _signAlgo = other._signAlgo;
            _keyAlgoParams = other._keyAlgoParams;
            _publicKey = other._publicKey;
            _privateKey = other._privateKey;
            _serialNumber = other._serialNumber;
            _signature = other._signature;
            _notBefore = other._notBefore;
            _notAfter = other._notAfter;
            _asym = other._asym;
            _cachedPub = other._cachedPub;
            _cachedPvt = other._cachedPvt;
            _sigHashAlgo = other._sigHashAlgo;
            _sigIsRsaPss = other._sigIsRsaPss;
            _sigPssParams = other._sigPssParams;
            _keyAlgoIsDsa = other._keyAlgoIsDsa;
            _extensions = other._extensions;
        }
        return *this;
    }

    /* Move assignment operator for the X.509 certificate. */
    CCert& CCert::operator=(CCert&& other) {
        if (this != &other) {
            swap(_rawData, other._rawData);
            swap(_subject, other._subject);
            swap(_issuer, other._issuer);
            swap(_subjectStr, other._subjectStr);
            swap(_issuerStr, other._issuerStr);
            swap(_thumbprint, other._thumbprint);
            swap(_keyAlgo, other._keyAlgo);
            swap(_signAlgo, other._signAlgo);
            swap(_keyAlgoParams, other._keyAlgoParams);
            swap(_publicKey, other._publicKey);
            swap(_privateKey, other._privateKey);
            swap(_serialNumber, other._serialNumber);
            swap(_signature, other._signature);
            swap(_notBefore, other._notBefore);
            swap(_notAfter, other._notAfter);
            swap(_asym, other._asym);
            swap(_cachedPub, other._cachedPub);
            swap(_cachedPvt, other._cachedPvt);
            swap(_sigHashAlgo, other._sigHashAlgo);
            swap(_sigIsRsaPss, other._sigIsRsaPss);
            swap(_sigPssParams, other._sigPssParams);
            swap(_keyAlgoIsDsa, other._keyAlgoIsDsa);
            swap(_extensions, other._extensions);
        }

        return *this;
    }

    /* Resolves an id-ecPublicKey key's namedCurve OID content (keyAlgoParams(), i.e. the OBJECT
     * IDENTIFIER's own content octets, not including its tag/length) to the specific curve
     * EAsymmetrics this library implements it as. */
    bool CCert::resolveEcCurve(SReadOnlyByteSpan namedCurveContent, crypto::EAsymmetrics& outWhich) {
        SRawOid curveOid;
        if (!CDecoder::decodeOid(namedCurveContent, curveOid)) {
            return false;
        }

        const COid oid(curveOid);
        for (const SKeyAlgo& entry : EC_CURVES) {
            if (oid == COid(entry.oid)) {
                outWhich = entry.which;
                return true;
            }
        }

        return false;
    }

    /* Resolves SubjectPublicKeyInfo.algorithm's OID (+ parameters, for id-ecPublicKey) to a
     * display name and, where this library implements the algorithm, an EAsymmetrics.
     * Always sets outName (falling back to the OID's own dotted-decimal text when unrecognized);
     * returns whether outWhich was actually set. */
    bool CCert::resolveKeyAlgo(
        const COid& oid,
        const COctet& params,
        crypto::EAsymmetrics& outWhich,
        CString& outName
    ) {
        for (const SKeyAlgo& entry : KEY_ALGOS) {
            if (oid == COid(entry.oid)) {
                outWhich = entry.which;
                outName = entry.name;
                return true;
            }
        }

        if (oid == COid(OID_EC_PUBLIC_KEY)) {
            outName = "EC";
            return resolveEcCurve(params.toSpan(), outWhich);
        }

        // --> The unrecognized case hands back the OID's own text as the display name, which is
        // why this returns a COid rather than keeping the text around: the text is only wanted
        // here, at the point where the library admits it has no name for this OID.
        outName = oid.toString();
        return false;
    }

    /* Resolves a crypto::EAsymmetrics to the SubjectPublicKeyInfo.algorithm fields
     * CCertBuilder::build() needs -- the inverse of resolveKeyAlgo(), built from the same tables. */
    bool CCert::resolveKeyAlgoForBuild(
        crypto::EAsymmetrics which,
        COid& outOid,
        bool& outIsDsa,
        bool& outIsEc,
        COid& outEcCurveOid
    ) {
        outIsDsa = false;
        outIsEc = false;

        for (const SKeyAlgo& entry : KEY_ALGOS) {
            if (entry.which == which) {
                outOid = entry.oid;
                outIsDsa = (which == crypto::EASYM_DSA);
                return true;
            }
        }

        for (const SKeyAlgo& entry : EC_CURVES) {
            if (entry.which == which) {
                outOid = OID_EC_PUBLIC_KEY;
                outIsEc = true;
                outEcCurveOid = entry.oid;
                return true;
            }
        }

        return false;
    }

    /* Resolves Certificate.signatureAlgorithm's OID to a display name and, for a hash-then-sign
     * scheme (everything but EdDSA), the digest algorithm it signs (left at outHash's
     * caller-supplied default -- EHASH_UNKNOWN -- for EdDSA or an unrecognized OID). Always
     * sets outName, falling back to the OID's own dotted-decimal text when unrecognized. */
    void CCert::resolveSigAlgo(const COid& oid, crypto::EHashers& outHash, CString& outName) {
        for (const SSigAlgo& entry : SIG_ALGOS) {
            if (oid == COid(entry.oid)) {
                outName = entry.name;
                if (entry.which != crypto::EHASH_UNKNOWN) {
                    outHash = entry.which;
                }
                return;
            }
        }

        // --> Unrecognized: the OID's own text becomes the display name, formatted only here
        // where the library is admitting it has no better one.
        outName = oid.toString();
    }

    const CCert::SSigHashOid CCert::RSA_SIG_OIDS[] = {
        { crypto::EHASH_MD5,    COid::MD5_RSA    }, // md5WithRSAEncryption
        { crypto::EHASH_SHA1,   COid::SHA1_RSA   }, // sha1WithRSAEncryption
        { crypto::EHASH_SHA224, COid::SHA224_RSA }, // sha224WithRSAEncryption
        { crypto::EHASH_SHA256, COid::SHA256_RSA }, // sha256WithRSAEncryption
        { crypto::EHASH_SHA384, COid::SHA384_RSA }, // sha384WithRSAEncryption
        { crypto::EHASH_SHA512, COid::SHA512_RSA }, // sha512WithRSAEncryption
    };

    const CCert::SSigHashOid CCert::DSA_SIG_OIDS[] = {
        { crypto::EHASH_SHA1,   COid::SHA1_DSA   }, // dsa-with-sha1
        { crypto::EHASH_SHA224, COid::SHA224_DSA }, // dsa-with-sha224
        { crypto::EHASH_SHA256, COid::SHA256_DSA }, // dsa-with-sha256
    };

    const CCert::SSigHashOid CCert::ECDSA_SIG_OIDS[] = {
        { crypto::EHASH_SHA1,   COid::SHA1_ECDSA   }, // ecdsa-with-SHA1
        { crypto::EHASH_SHA224, COid::SHA224_ECDSA }, // ecdsa-with-SHA224
        { crypto::EHASH_SHA256, COid::SHA256_ECDSA }, // ecdsa-with-SHA256
        { crypto::EHASH_SHA384, COid::SHA384_ECDSA }, // ecdsa-with-SHA384
        { crypto::EHASH_SHA512, COid::SHA512_ECDSA }, // ecdsa-with-SHA512
    };

    /* Linear lookup of hash within one of the *_SIG_OIDS tables above. */
    bool CCert::lookupSigOid(const SSigHashOid* table, size_t count, crypto::EHashers hash, COid& outOid) {
        for (size_t i = 0; i < count; ++i) {
            if (table[i].hash == hash) {
                outOid = table[i].oid;
                return true;
            }
        }
        return false;
    }

    /* Builds RSASSA-PSS-params (RFC 8017 A.2.3) -- see its own doc comment in cert.hpp. */
    bool CCert::buildRsaPssParams(crypto::EHashers hash, COctet& outParams) {
        const SKnownOid* hashOid = nullptr;
        switch (hash) {
            case crypto::EHASH_SHA1:   hashOid = &COid::SHA1;   break;
            case crypto::EHASH_SHA224: hashOid = &COid::SHA224; break;
            case crypto::EHASH_SHA256: hashOid = &COid::SHA256; break;
            case crypto::EHASH_SHA384: hashOid = &COid::SHA384; break;
            case crypto::EHASH_SHA512: hashOid = &COid::SHA512; break;
            default: return false; // --> MD5/SHAKE256/UNKNOWN: no defined RSASSA-PSS mapping.
        }

        crypto::IHasherPtr hasher;
        if (crypto::IHasher::create(hash, hasher) != ERET_OK || !hasher) {
            return false;
        }
        size_t hLen = hasher->byteWidth();

        // HashAlgorithm ::= AlgorithmIdentifier { OID, parameters ABSENT } -- built once, reused
        // both as the top-level hashAlgorithm field and, nested, as id-mgf1's own parameters
        // (RFC 8017 A.2.3: MGF1's parameters ARE the hash's own AlgorithmIdentifier).
        CBuffer hashAlgIdTlv;
        {
            const COid hashId(*hashOid);
            size_t needed = CEncoder::encodedOidSize(hashId.raw());
            if (!needed) {
                return false;
            }

            CBuffer oidContent;
            size_t written = 0;
            if (!oidContent.resize(needed) || !CEncoder::encodeOid(oidContent.toSpan(), hashId.raw(), written)) {
                return false;
            }

            CBuffer body;
            if (!CDer::appendTlv(body, CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), written))) {
                return false;
            }
            if (!CDer::appendSequence(hashAlgIdTlv, body.toSpan())) {
                return false;
            }
        }

        // maskGenAlgorithm ::= AlgorithmIdentifier { id-mgf1, parameters HashAlgorithm }.
        CBuffer mgfAlgIdTlv;
        {
            const COid mgf1(COid::MGF1);
            size_t needed = CEncoder::encodedOidSize(mgf1.raw());
            if (!needed) {
                return false;
            }

            CBuffer oidContent;
            size_t written = 0;
            if (!oidContent.resize(needed) || !CEncoder::encodeOid(oidContent.toSpan(), mgf1.raw(), written)) {
                return false;
            }

            CBuffer body;
            if (!CDer::appendTlv(body, CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), written))
                || !CDer::appendRaw(body, hashAlgIdTlv.toSpan()))
            {
                return false;
            }
            if (!CDer::appendSequence(mgfAlgIdTlv, body.toSpan())) {
                return false;
            }
        }

        // saltLength INTEGER -- this library's signPss()/verifyPss() always use hash's own
        // digest length, the RFC 8017-recommended value.
        CBigNum saltLen(static_cast<uint64_t>(hLen));

        CBuffer paramsBody;

        // [0] EXPLICIT hashAlgorithm.
        {
            CBuffer inner;
            if (!CDer::appendRaw(inner, hashAlgIdTlv.toSpan())) {
                return false;
            }
            if (!CDer::appendTlv(paramsBody, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), inner.toSpan())) {
                return false;
            }
        }

        // [1] EXPLICIT maskGenAlgorithm.
        {
            CBuffer inner;
            if (!CDer::appendRaw(inner, mgfAlgIdTlv.toSpan())) {
                return false;
            }
            if (!CDer::appendTlv(paramsBody, CTag(EATAG_CONTEXT_SPECIFIC, 1, true), inner.toSpan())) {
                return false;
            }
        }

        // [2] EXPLICIT saltLength.
        {
            CBuffer inner;
            if (!CDer::appendBigInteger(inner, saltLen)) {
                return false;
            }
            if (!CDer::appendTlv(paramsBody, CTag(EATAG_CONTEXT_SPECIFIC, 2, true), inner.toSpan())) {
                return false;
            }
        }

        // trailerField [3] is always omitted: its only defined value (trailerFieldBC = 1) is
        // this field's own DER default.

        CBuffer paramsSeq;
        if (!CDer::appendSequence(paramsSeq, paramsBody.toSpan())) {
            return false;
        }

        outParams = COctet(paramsSeq.toSpan());
        return true;
    }

    /* Resolves one of RSASSA-PSS-params' HashAlgorithm AlgorithmIdentifiers to the digest it
     * names -- see its own doc comment in cert.hpp. */
    bool CCert::parsePssHashAlgo(CReader& algo, crypto::EHashers& outHash) {
        // --> Decoded to a COid, not to the OID's text: every comparison below this function is
        // against one of the library's own hash OIDs, so the arcs are what is wanted.
        SRawOid rawOid;
        if (!algo.readOid(rawOid)) {
            return false;
        }

        const COid oid(rawOid);

        // parameters ANY DEFINED BY algorithm OPTIONAL -- NULL or absent for every hash here
        // (RFC 5754 2: SHOULD be absent, but real encoders write both, and this library's own
        // buildRsaPssParams() writes it absent).
        if (!algo.atEnd()) {
            if (!algo.readNull() || !algo.atEnd()) {
                return false;
            }
        }

        // --> id-sha1 lives under a different arc (1.3.14.3.2.26) than the id-sha2 family, which
        // is why this isn't a single prefix test.
        if (oid == COid(COid::SHA1))   { outHash = crypto::EHASH_SHA1;   return true; }
        if (oid == COid(COid::SHA224)) { outHash = crypto::EHASH_SHA224; return true; }
        if (oid == COid(COid::SHA256)) { outHash = crypto::EHASH_SHA256; return true; }
        if (oid == COid(COid::SHA384)) { outHash = crypto::EHASH_SHA384; return true; }
        if (oid == COid(COid::SHA512)) { outHash = crypto::EHASH_SHA512; return true; }

        return false;
    }

    /* Reads an RSASSA-PSS-params SEQUENCE's content -- see its own doc comment in cert.hpp. */
    bool CCert::parseRsaPssParams(CReader& params, SRsaPssParams& outValue) {
        // --> Starts from the four ASN.1 DEFAULTs, which SRsaPssParams' own constructor already
        // holds: under DER a field equal to its default MUST be omitted, so every field this
        // loop never sees is a field that was defaulted, not one that was missing.
        SRsaPssParams result;
        int32_t lastField = -1;

        while (!params.atEnd()) {
            CTag tag;
            CReader field;

            // --> Every one of the four is [n] EXPLICIT (RFC 4055's module is EXPLICIT TAGS), so
            // each is a constructed context-specific wrapper around its own single element --
            // including saltLength/trailerField, whose INTEGER sits inside the wrapper.
            if (!params.readConstructed(tag, field) || tag.tagClass() != EATAG_CONTEXT_SPECIFIC) {
                return false;
            }

            // --> SEQUENCE, not SET: DER fixes the field order, so a repeated or out-of-order
            // tag is malformed rather than merely unusual, and silently taking the last one
            // would let a second saltLength override the first.
            if (int32_t(tag.value()) <= lastField) {
                return false;
            }
            lastField = int32_t(tag.value());

            switch (tag.value()) {
                case 0: { // hashAlgorithm [0] EXPLICIT AlgorithmIdentifier DEFAULT sha1
                    CReader hashAlgo;
                    if (!field.readSequence(hashAlgo) || !parsePssHashAlgo(hashAlgo, result.hashAlgo)) {
                        return false;
                    }
                    break;
                }

                case 1: { // maskGenAlgorithm [1] EXPLICIT AlgorithmIdentifier DEFAULT mgf1SHA1
                    CReader mgfAlgo;
                    SRawOid rawMgfOid;
                    if (!field.readSequence(mgfAlgo) || !mgfAlgo.readOid(rawMgfOid)) {
                        return false;
                    }

                    const COid mgfOid(rawMgfOid);

                    // --> id-mgf1 is the only mask generation function RFC 4055 defines, and its
                    // parameters ARE a HashAlgorithm (RFC 8017 A.2.3) -- not optional here,
                    // since mgf1SHA1's "absent parameters" form is the DEFAULT, which DER would
                    // have encoded by omitting this whole field.
                    if (mgfOid != COid(COid::MGF1)) {
                        return false;
                    }

                    CReader mgfHashAlgo;
                    if (!mgfAlgo.readSequence(mgfHashAlgo)
                        || !parsePssHashAlgo(mgfHashAlgo, result.mgfHashAlgo)
                        || !mgfAlgo.atEnd())
                    {
                        return false;
                    }
                    break;
                }

                case 2: { // saltLength [2] EXPLICIT INTEGER DEFAULT 20
                    int64_t saltLength = 0;
                    if (!field.readInteger(saltLength) || saltLength < 0 || saltLength > 0xffff) {
                        // --> A PSS salt can't exceed emLen - hLen - 2, so 64 KiB is already far
                        // past any real RSA modulus; bounding it here keeps a hostile value from
                        // reaching verifyPss() as a size_t at all.
                        return false;
                    }
                    result.saltLength = size_t(saltLength);
                    break;
                }

                case 3: { // trailerField [3] EXPLICIT INTEGER DEFAULT 1
                    int64_t trailerField = 0;
                    if (!field.readInteger(trailerField) || trailerField < 0 || trailerField > 0xffffffffll) {
                        return false;
                    }
                    result.trailerField = uint32_t(trailerField);
                    break;
                }

                default:
                    return false; // --> RSASSA-PSS-params has exactly four fields.
            }

            if (!field.atEnd()) {
                return false; // --> Trailing content inside an EXPLICIT wrapper.
            }
        }

        outValue = result;
        return true;
    }

    /* Picks a signature algorithm OID (+ digest algorithm + AlgorithmIdentifier parameters) to
     * sign with, for CCertBuilder::build()'s issuerKeyPair/digestAlgo/rsaPss -- see its own doc
     * comment in cert.hpp. */
    bool CCert::resolveSigAlgoForSigning(
        crypto::EAsymmetrics which,
        crypto::EHashers hash,
        bool rsaPss,
        COid& outOid,
        crypto::EHashers& outHash,
        COctet& outParams
    ) {
        outParams = COctet();

        if (which == crypto::EASYM_ED25519) {
            outOid = COid::ED25519;
            outHash = crypto::EHASH_UNKNOWN; // --> self-hashing: sign() gets the message directly
            return true;
        }

        if (which == crypto::EASYM_ED448) {
            outOid = COid::ED448;
            outHash = crypto::EHASH_UNKNOWN;
            return true;
        }

        if (which == crypto::EASYM_X25519) {
            return false; // --> Diffie-Hellman only; no signing capability at all.
        }

        if (crypto::CMlDsa::isMlDsa(which)) {
            // RFC 9881 2: the signature AlgorithmIdentifier is the same OID as the key's, with
            // `parameters` absent -- so outParams stays empty, exactly as for EdDSA. The
            // requested digest is ignored for the same reason it is for Ed25519.
            COid oid;
            bool unusedIsDsa = false;
            bool unusedIsEc = false;
            COid unusedCurve;
            if (!resolveKeyAlgoForBuild(which, oid, unusedIsDsa, unusedIsEc, unusedCurve)) {
                return false;
            }

            outOid = oid;
            outHash = crypto::EHASH_UNKNOWN; // --> self-hashing: sign() gets the message directly
            return true;
        }

        if (rsaPss && which != crypto::EASYM_RSA) {
            return false; // --> RSASSA-PSS only makes sense for an RSA key.
        }

        crypto::EHashers useHash = (hash == crypto::EHASH_UNKNOWN) ? crypto::EHASH_SHA256 : hash;

        if (which == crypto::EASYM_RSA && rsaPss) {
            if (!buildRsaPssParams(useHash, outParams)) {
                return false; // --> e.g. useHash is MD5/SHAKE256, which PSS has no OID mapping for.
            }
            outOid = COid::RSASSA_PSS;
            outHash = useHash;
            return true;
        }

        if (which == crypto::EASYM_RSA) {
            if (!lookupSigOid(RSA_SIG_OIDS, sizeof(RSA_SIG_OIDS) / sizeof(RSA_SIG_OIDS[0]), useHash, outOid)) {
                return false;
            }
            // RSA PKCS#1 v1.5 signature AlgorithmIdentifiers always carry an explicit NULL.
            static const uint8_t NULL_TLV[] = { 0x05, 0x00 };
            outParams = COctet(SReadOnlyByteSpan(NULL_TLV, sizeof(NULL_TLV)));
            outHash = useHash;
            return true;
        }

        if (which == crypto::EASYM_DSA) {
            if (!lookupSigOid(DSA_SIG_OIDS, sizeof(DSA_SIG_OIDS) / sizeof(DSA_SIG_OIDS[0]), useHash, outOid)) {
                return false;
            }
            outHash = useHash; // --> outParams stays empty: DSA signature AlgorithmIdentifiers carry none.
            return true;
        }

        // Every other EAsymmetrics value this library implements is an EC/EC2 curve
        // (prime or binary) -- these OIDs apply uniformly to any of them.
        if (!lookupSigOid(ECDSA_SIG_OIDS, sizeof(ECDSA_SIG_OIDS) / sizeof(ECDSA_SIG_OIDS[0]), useHash, outOid)) {
            return false;
        }
        outHash = useHash; // --> outParams stays empty: ECDSA signature AlgorithmIdentifiers carry none.
        return true;
    }

    /* Reads an X.509 Time CHOICE (UTCTime | GeneralizedTime); either read*Time() call rolls the
     * reader back on failure, so trying UTCTime first is safe regardless of which one content
     * actually is. */
    bool CCert::readTime(CReader& reader, SDateTime& outValue) {
        return reader.readUtcTime(outValue) || reader.readGeneralizedTime(outValue);
    }

    /* Encodes an X.509 Time CHOICE from time, the inverse of readTime(). */
    bool CCert::encodeTime(const SDateTime& time, CBuffer& out) {
        if (time.year >= 1950 && time.year <= 2049) {
            uint8_t buf[13];
            size_t written = 0;
            if (!CEncoder::encodeUtcTime(SByteSpan(buf, sizeof(buf)), time, written)) {
                return false;
            }

            return CDer::appendTlv(out, CTag::TIME_UTC_, SReadOnlyByteSpan(buf, written));
        }

        size_t needed = CEncoder::encodedGeneralizedTimeSize(time);
        if (!needed) {
            return false;
        }

        CBuffer content;
        if (!content.resize(needed)) {
            return false;
        }

        size_t written = 0;
        if (!CEncoder::encodeGeneralizedTime(content.toSpan(), time, written)) {
            return false;
        }

        return CDer::appendTlv(out, CTag::TIME_GENERAL, SReadOnlyByteSpan(content.toPtr(), written));
    }

    /* Encodes one AlgorithmIdentifier SEQUENCE { algorithm, parameters OPTIONAL }. */
    bool CCert::encodeAlgorithmIdentifier(const COid& oid, const COctet& params, CBuffer& out) {
        // --> Straight from the arcs: the OID arrives already parsed as a COid, so formatting it
        // to dotted-decimal here only to have encodeOidString() parse it straight back would undo
        // whatever the caller did to get it here.
        size_t needed = CEncoder::encodedOidSize(oid.raw());
        if (!needed) {
            return false;
        }

        CBuffer oidContent;
        size_t written = 0;
        if (!oidContent.resize(needed) || !CEncoder::encodeOid(oidContent.toSpan(), oid.raw(), written)) {
            return false;
        }

        CBuffer body;
        if (!CDer::appendTlv(body, CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), written))) {
            return false;
        }

        // --> params arrives already TLV-encoded (resolveSigAlgoForSigning()'s own contract), so
        // it splices in verbatim; empty means the whole OPTIONAL field is omitted, which is what
        // DSA/ECDSA/EdDSA/ML-DSA signature AlgorithmIdentifiers want.
        if (!params.empty() && !CDer::appendRaw(body, params.toSpan())) {
            return false;
        }

        return CDer::appendSequence(out, body.toSpan());
    }

    /* Encodes a complete SubjectPublicKeyInfo SEQUENCE { algorithm, subjectPublicKey BIT
     * STRING } for key -- see its own doc comment in cert.hpp. */
    ERetCode CCert::encodeSubjectPublicKeyInfo(const crypto::IPublicKeyPtr& key, CBuffer& out) {
        if (!key) {
            return ERET_KEY_EMPTY;
        }

        crypto::EAsymmetrics which = key->algorithm();

        COid keyOid, ecCurveOid;
        bool keyIsDsa = false, keyIsEc = false;
        if (!resolveKeyAlgoForBuild(which, keyOid, keyIsDsa, keyIsEc, ecCurveOid)) {
            return ERET_NOTSUP; // --> key's algorithm has no SPKI OID this library knows.
        }

        COctet serialized;
        if (key->serialize(serialized) != ERET_OK) {
            return ERET_KEY_ERROR;
        }

        // DSA alone splits across the two SPKI fields: its serialize() hands back the whole
        // SEQUENCE { p, q, g, y } createPublicKey() takes, and X.509 wants {p, q, g} in
        // algorithm.parameters with y alone in the BIT STRING (RFC 3279 2.3.2).
        COctet spkiParams, spkiPublicKey;
        if (keyIsDsa) {
            if (!splitDsaPublicKeyBlob(serialized, spkiParams, spkiPublicKey)) {
                return ERET_KEY_FORMAT;
            }
        } else {
            spkiPublicKey = move(serialized);
        }

        // algorithm.parameters, built as its own complete TLV so encodeAlgorithmIdentifier() can
        // splice it in the same way it splices a signature algorithm's.
        COctet algoParams;
        {
            CBuffer paramsTlv;

            if (keyIsEc) {
                // ECParameters ::= CHOICE { namedCurve OBJECT IDENTIFIER, ... } -- the only
                // alternative this library produces (and effectively the only one in practice).
                size_t curveNeeded = CEncoder::encodedOidSize(ecCurveOid.raw());
                CBuffer curveOidContent;
                size_t curveWritten = 0;
                if (!curveNeeded || !curveOidContent.resize(curveNeeded)
                    || !CEncoder::encodeOid(curveOidContent.toSpan(), ecCurveOid.raw(), curveWritten)
                    || !CDer::appendTlv(paramsTlv, CTag::OBJ_ID, SReadOnlyByteSpan(curveOidContent.toPtr(), curveWritten)))
                {
                    return ERET_UNKNOWN;
                }
            } else if (keyIsDsa) {
                if (!CDer::appendSequence(paramsTlv, spkiParams.toSpan())) {
                    return ERET_UNKNOWN;
                }
            } else if (which == crypto::EASYM_RSA) {
                if (!CDer::appendTlv(paramsTlv, CTag::NULL_, SReadOnlyByteSpan())) {
                    return ERET_UNKNOWN;
                }
            }
            // Ed25519/Ed448/X25519 (RFC 8410) and ML-DSA (RFC 9881) carry no parameters at all,
            // which leaves paramsTlv empty and so omits the field entirely.

            algoParams = COctet(paramsTlv.toSpan());
        }

        CBuffer body;
        if (!encodeAlgorithmIdentifier(keyOid, algoParams, body)) {
            return ERET_UNKNOWN;
        }

        CBuffer bitContent;
        size_t written = 0;
        if (!bitContent.resize(1 + spkiPublicKey.size())
            || !CEncoder::encodeBitString(bitContent.toSpan(), spkiPublicKey.toSpan(), 0, written))
        {
            return ERET_UNKNOWN;
        }

        if (!CDer::appendTlv(body, CTag::STRING_BIT, SReadOnlyByteSpan(bitContent.toPtr(), written))
            || !CDer::appendSequence(out, body.toSpan()))
        {
            return ERET_UNKNOWN;
        }

        return ERET_OK;
    }

    /* Reads a SubjectPublicKeyInfo's fields -- the inverse of encodeSubjectPublicKeyInfo(). */
    bool CCert::decodeSubjectPublicKeyInfo(CReader& spkiSeq, SSpkiFields& out) {
        CReader keyAlgoSeq;
        if (!spkiSeq.readSequence(keyAlgoSeq)) {
            return false;
        }

        // --> As a COid: it is resolved against KEY_ALGOS and EC_CURVES immediately below,
        // and both of those compare arcs.
        SRawOid rawKeyAlgoOid;
        if (!keyAlgoSeq.readOid(rawKeyAlgoOid)) {
            return false;
        }

        const COid keyAlgoOid(rawKeyAlgoOid);

        // parameters ANY DEFINED BY algorithm OPTIONAL
        if (!keyAlgoSeq.atEnd()) {
            CTag paramTag;
            SReadOnlyByteSpan paramContent;
            if (!keyAlgoSeq.readNextElement(paramTag, paramContent)) {
                return false;
            }
            out.algoParams = COctet(paramContent);
        }

        out.resolved = resolveKeyAlgo(keyAlgoOid, out.algoParams, out.which, out.algoName);

        SReadOnlyByteSpan pkBits;
        uint8_t pkUnusedBits = 0;
        if (!spkiSeq.readBitString(pkBits, pkUnusedBits) || pkUnusedBits != 0) {
            // --> A valid SubjectPublicKeyInfo is always byte-aligned; a nonzero unused-bit
            // count here means malformed input, not a key format this library doesn't support.
            return false;
        }
        out.publicKey = COctet(pkBits);

        return true;
    }

    /* Builds a live public key from decodeSubjectPublicKeyInfo()'s raw output. */
    crypto::IPublicKeyPtr CCert::makePublicKey(
        const crypto::IAsymmetricPtr& asym,
        bool isDsa,
        const COctet& params,
        const COctet& publicKey
    ) {
        if (!asym) {
            return nullptr;
        }

        if (isDsa) {
            CBuffer blob;
            if (!buildDsaPublicKeyBlob(params, publicKey, blob)) {
                return nullptr;
            }

            return asym->createPublicKey(blob.toSpan());
        }

        return asym->createPublicKey(publicKey);
    }

    /* Encodes an Extensions SEQUENCE OF Extension -- see its own doc comment in cert.hpp. */
    ERetCode CCert::encodeExtensions(const TArray<IExtensionPtr>& extensions, CBuffer& out) {
        if (extensions.empty()) {
            return ERET_INVAL;
        }

        CBuffer extList;

        for (const IExtensionPtr& ext : extensions) {
            if (!ext) {
                return ERET_INVAL;
            }

            CBuffer extnValue;
            if (!ext->encode(extnValue)) {
                return ERET_UNKNOWN;
            }

            size_t needed = CEncoder::encodedOidSize(ext->oid().raw());
            if (!needed) {
                return ERET_UNKNOWN;
            }

            CBuffer oidContent;
            size_t written = 0;
            if (!oidContent.resize(needed) || !CEncoder::encodeOid(oidContent.toSpan(), ext->oid().raw(), written)) {
                return ERET_UNKNOWN;
            }

            // Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue
            // OCTET STRING } -- critical is DER-canonically omitted when false (the
            // default) and written only when ext->critical() is true.
            CBuffer extBody;
            if (!CDer::appendTlv(extBody, CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), written))) {
                return ERET_UNKNOWN;
            }

            if (ext->critical()) {
                uint8_t boolContent = 0;
                size_t boolWritten = 0;
                if (!CEncoder::encodeBoolean(SByteSpan(&boolContent, 1), true, boolWritten)
                    || !CDer::appendTlv(extBody, CTag::BOOLEAN, SReadOnlyByteSpan(&boolContent, boolWritten)))
                {
                    return ERET_UNKNOWN;
                }
            }

            if (!CDer::appendTlv(extBody, CTag::STRING_OCTET, extnValue.toSpan())
                || !CDer::appendSequence(extList, extBody.toSpan()))
            {
                return ERET_UNKNOWN;
            }
        }

        if (!CDer::appendSequence(out, extList.toSpan())) {
            return ERET_UNKNOWN;
        }

        return ERET_OK;
    }

    /* Signs toBeSigned with keyPair -- see its own doc comment in cert.hpp. */
    ERetCode CCert::signTbs(
        const crypto::SKeyPair& keyPair,
        SReadOnlyByteSpan toBeSigned,
        crypto::EHashers sigHash,
        bool rsaPss,
        COctet& outSignature
    ) {
        if (keyPair.empty()) {
            return ERET_KEY_EMPTY;
        }

        crypto::EAsymmetrics which = keyPair.privateKey->algorithm();

        crypto::IAsymmetricPtr asym = crypto::IAsymmetric::builtIn(which);
        crypto::IAsymmetricContextPtr ctx = asym ? asym->createContext() : nullptr;
        if (!ctx) {
            return ERET_UNKNOWN;
        }

        ctx->keyPair(keyPair);

        // --> EHASH_UNKNOWN is resolveSigAlgoForSigning()'s own marker for a self-hashing scheme
        // (EdDSA, ML-DSA), which takes the message itself rather than a digest.
        COctet toSign;
        if (sigHash == crypto::EHASH_UNKNOWN) {
            toSign = COctet(toBeSigned);
        } else {
            crypto::IHasherPtr hasher;
            if (crypto::IHasher::create(sigHash, hasher) != ERET_OK || !hasher) {
                return ERET_HASH_PIPE;
            }

            CBuffer digest;
            if (!digest.resize(hasher->byteWidth())
                || !hasher->push(toBeSigned)
                || !hasher->finish(SByteSpan(digest.toPtr(), digest.size())))
            {
                return ERET_HASH_PIPE;
            }

            toSign = COctet(digest.toSpan());
        }

        CBuffer sigBuf;
        if (!sigBuf.resize(ctx->sizeOfSign())) {
            return ERET_NOMEM;
        }

        SByteSpan sigOut(sigBuf.toPtr(), sigBuf.size());
        ERetCode signRc = (which == crypto::EASYM_RSA && rsaPss)
            ? ctx->signPss(toSign.toSpan(), sigHash, toSign.size(), sigOut)
            : ctx->sign(toSign.toSpan(), sigOut);
        if (signRc != ERET_OK) {
            return signRc;
        }

        outSignature = COctet(SReadOnlyByteSpan(sigOut.data, sigOut.size));
        return ERET_OK;
    }

    /* Checks signature over signedBytes with ctx -- see its own doc comment in cert.hpp. */
    ERetCode CCert::verifySignedBlob(
        const crypto::IAsymmetricContextPtr& ctx,
        crypto::EAsymmetrics keyWhich,
        SReadOnlyByteSpan signedBytes,
        SReadOnlyByteSpan signature,
        crypto::EHashers sigHash,
        bool isRsaPss,
        const SRsaPssParams& pssParams
    ) {
        if (!ctx) {
            return ERET_NOTSUP;
        }

        // --> Whether to hash first is decided by the verifying key's algorithm, never by
        // sigHash == EHASH_UNKNOWN. That value is ambiguous: resolveSigAlgo() leaves it
        // untouched for an OID absent from SIG_ALGOS, which is indistinguishable from EdDSA's
        // legitimate "no separate hash" -- and reading it as EdDSA would hand the raw signed
        // bytes to an ECDSA/DSA verify as though they were a digest, which truncates them to the
        // order's bit length and leaves the signature covering a prefix of the plaintext rather
        // than a hash of the message. OCSP's own verifySignature() had exactly that bug.
        if (signsMessageDirectly(keyWhich)) {
            // --> The signature BIT STRING's content is handed over whole. ML-DSA's signature is
            // one opaque blob (c-tilde || z || h) with no internal ASN.1, exactly like EdDSA's
            // R || S -- unlike ECDSA's SEQUENCE { r, s }, which createPublicKey()'s algorithm
            // unpacks itself.
            return ctx->verify(signedBytes, signature);
        }

        if (sigHash == crypto::EHASH_UNKNOWN) {
            return ERET_NOTSUP;
        }

        crypto::IHasherPtr hasher;
        if (crypto::IHasher::create(sigHash, hasher) != ERET_OK || !hasher) {
            return ERET_HASH_PIPE;
        }

        CBuffer digest;
        if (!digest.resize(hasher->byteWidth())
            || !hasher->push(signedBytes)
            || !hasher->finish(SByteSpan(digest.toPtr(), digest.size())))
        {
            return ERET_HASH_PIPE;
        }

        if (isRsaPss) {
            // --> verifyPss() takes a single hash algorithm and uses it for both the message
            // digest and MGF1's own mask generation, which is the only pairing RFC 8017
            // recommends and the only one any real issuer encodes. A signature whose
            // maskGenAlgorithm genuinely names a different hash than hashAlgorithm -- or whose
            // trailerField isn't trailerFieldBC, the single value RFC 4055 defines and the only
            // one EMSA-PSS-VERIFY implements -- therefore cannot be checked here, and must fail
            // closed: verifying it with the wrong MGF1 hash would reject every valid signature,
            // which is indistinguishable from a forgery.
            if (pssParams.mgfHashAlgo != pssParams.hashAlgo || pssParams.trailerField != 1) {
                return ERET_NOTSUP;
            }

            return ctx->verifyPss(digest.toSpan(), sigHash, pssParams.saltLength, signature);
        }

        return ctx->verify(digest.toSpan(), signature);
    }

    /* Encodes a CDistinguishedName as a full Name (SEQUENCE) tag-length-value. */
    bool CCert::encodeName(const CDistinguishedName& name, CBuffer& out) {
        size_t needed = CEncoder::encodedDistinguishedNameSize(name);

        CBuffer content;
        size_t written = 0;
        if (needed) {
            if (!content.resize(needed)) {
                return false;
            }

            if (!CEncoder::encodeDistinguishedName(content.toSpan(), name, written)) {
                return false;
            }
        }

        return CDer::appendSequence(out, SReadOnlyByteSpan(content.toPtr(), written));
    }

    /* Walks the TBSCertificate's extensions [3] EXPLICIT Extensions field (extensionsRaw: the
     * complete encoded Extensions SEQUENCE OF Extension, tag+length+content), populating
     * _extensions (extensionOf()'s own backing store) with one IExtension::create()-built
     * instance per Extension entry -- clearing any previous contents first. Best-effort: a
     * malformed individual Extension entry is skipped rather than aborting the whole scan
     * (extList's cursor has already moved past it regardless of what's inside its own
     * SEQUENCE). RFC 5280 4.2 requires a certificate to include at most one instance of any
     * given extension; a repeated OID is likewise skipped (keeping only the first occurrence)
     * rather than silently accumulating an ambiguous pair that extensionOf() (first match) and a
     * caller iterating the list directly (which would see both) could disagree about. */
    void CCert::parseExtensions(const COctet& extensionsRaw, std::vector<IExtensionPtr>& out) {
        out.clear();

        if (extensionsRaw.empty()) {
            return;
        }

        CReader wrapper(extensionsRaw.toSpan(), EAENC_DER);
        CReader extList;
        if (!wrapper.readSequence(extList)) {
            return;
        }

        while (!extList.atEnd()) {
            CReader extSeq;
            if (!extList.readSequence(extSeq)) {
                break;
            }

            // --> As a COid: it is compared against the extensions already parsed and then
            // handed to IExtension::create(), both of which want the arcs. The duplicate check
            // below was a CString::compare() against another extension's COid formatted to
            // text, which is the round trip this whole change exists to remove.
            SRawOid rawExtnOid;
            if (!extSeq.readOid(rawExtnOid)) {
                continue;
            }

            const COid extnOid(rawExtnOid);

            bool critical = false;
            extSeq.readBoolean(critical); // OPTIONAL DEFAULT FALSE -- absent leaves it false

            COctet extnValue;
            if (!extSeq.readOctetString(extnValue)) {
                continue;
            }

            bool duplicate = false;
            for (const IExtensionPtr& existing : out) {
                if (existing && existing->oid() == extnOid) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) {
                continue;
            }

            IExtensionPtr ext = IExtension::create(extnOid, extnValue);
            if (ext) {
                ext->critical(critical);
            }
            out.push_back(std::move(ext));
        }
    }

    /* Builds the standalone DER SEQUENCE { p, q, g, y } DSA::createPublicKey() expects, from
     * X.509's split representation: keyAlgoParams() is Dss-Parms { p, q, g }'s own content, and
     * rawPublicKey() is the complete DER INTEGER y TLV (RFC 3279 2.3.2: unlike every other
     * built-in algorithm, whose SubjectPublicKeyInfo.subjectPublicKey BIT STRING already matches
     * its own createPublicKey() input directly, DSA's BIT STRING content is itself a full DER
     * INTEGER encoding, tag and length included, not just y's bare magnitude -- so it must be
     * unwrapped here before re-encoding it into this SEQUENCE). DSA's domain parameters and
     * public value are split across two different SPKI fields, hence this reassembly at all. */
    bool CCert::buildDsaPublicKeyBlob(const COctet& params, const COctet& publicKey, CBuffer& out) {
        SReadOnlyByteSpan cursor = params.toSpan();

        CBigNum p, q, g;
        if (!CDer::readBigInteger(cursor, p) || !CDer::readBigInteger(cursor, q) || !CDer::readBigInteger(cursor, g)) {
            return false;
        }

        CTag yTag;
        SReadOnlyByteSpan yContent;
        SReadOnlyByteSpan yCursor = publicKey.toSpan();
        if (!CDecoder::readNextElement(yCursor, EAENC_DER, yTag, yContent) || yTag != CTag::INTEGER) {
            return false;
        }
        CBigNum y = CBigNum::fromBigEndian(yContent);

        CBuffer inner;
        if (!CDer::appendBigInteger(inner, p) || !CDer::appendBigInteger(inner, q)
            || !CDer::appendBigInteger(inner, g) || !CDer::appendBigInteger(inner, y))
        {
            return false;
        }

        return CDer::appendSequence(out, inner.toSpan());
    }

    /* The inverse of buildDsaPublicKeyBlob(): splits a DSA public key's own SEQUENCE { p, q, g,
     * y } (crypto::IPublicKey::serialize()'s output for DSA) back into X.509's split
     * SubjectPublicKeyInfo representation. */
    bool CCert::splitDsaPublicKeyBlob(const COctet& serialized, COctet& outParams, COctet& outPublicKey) {
        SReadOnlyByteSpan cursor;
        if (!CDer::readOuterSequence(serialized.toSpan(), cursor)) {
            return false;
        }

        CBigNum p, q, g, y;
        if (!CDer::readBigInteger(cursor, p) || !CDer::readBigInteger(cursor, q)
            || !CDer::readBigInteger(cursor, g) || !CDer::readBigInteger(cursor, y))
        {
            return false;
        }

        CBuffer params;
        if (!CDer::appendBigInteger(params, p) || !CDer::appendBigInteger(params, q) || !CDer::appendBigInteger(params, g)) {
            return false;
        }

        CBuffer publicKeyTlv;
        if (!CDer::appendBigInteger(publicKeyTlv, y)) {
            return false;
        }

        outParams = COctet(params.toSpan());
        outPublicKey = COctet(publicKeyTlv.toSpan());
        return true;
    }

    /* SHA-1 digest of the whole raw DER certificate -- the conventional meaning of a certificate
     * "thumbprint"/"fingerprint" in most tooling. */
    bool CCert::computeThumbprint(const COctet& rawData, COctet& out) {
        crypto::IHasherPtr hasher;
        if (crypto::IHasher::create(crypto::EHASH_SHA1, hasher) != ERET_OK || !hasher) {
            return false;
        }

        hasher->push(rawData.toSpan());

        uint8_t digest[20];
        SByteSpan digestSpan(digest, sizeof(digest));
        if (!hasher->finish(digestSpan)) {
            return false;
        }

        out = COctet(SReadOnlyByteSpan(digest, digestSpan.size));
        return true;
    }

    /* Loads the X.509 certificate from raw DER data. */
    ERetCode CCert::importDer(const COctet& data) {
        if (data.empty()) {
            return ERET_INVAL;
        }

        // --> Parsed into locals first, and only committed to *this at the very end, so a
        // failure partway through never leaves this object in a partially-populated state.
        CDistinguishedName issuer, subject;
        SDateTime notBefore, notAfter;
        COctet serialNumber, keyAlgoParams, publicKey;
        CString keyAlgoName, signAlgoName;
        crypto::EAsymmetrics keyAlgoWhich = crypto::EASYM_RSA;
        crypto::EHashers sigAlgoHash = crypto::EHASH_UNKNOWN;
        bool haveKeyAlgo = false;

        CReader outer(data.toSpan(), EAENC_DER);
        CReader certSeq;
        if (!outer.readSequence(certSeq)) {
            return ERET_BADREQ;
        }

        // --> The Certificate SEQUENCE must be the whole input. Accepting a suffix is not a
        // harmless leniency here: _rawData keeps whatever was handed in, so thumbprint() -- the
        // SHA-1 over rawData() that callers use as a certificate's identity -- changes with every
        // byte appended, which hands an attacker unlimited distinct fingerprints for one
        // certificate and breaks any blocklist or dedupe keyed on it. exportDer() would also
        // re-emit the non-DER suffix to whoever asked.
        if (!outer.atEnd()) {
            return ERET_BADREQ;
        }

        CReader tbsSeq;
        if (!certSeq.readSequence(tbsSeq)) {
            return ERET_BADREQ;
        }

        // version [0] EXPLICIT INTEGER DEFAULT v1 (OPTIONAL) -- not exposed by this class, so
        // its value (if present) is simply discarded rather than stored.
        CTag tag;
        SReadOnlyByteSpan content;
        if (!tbsSeq.readNextElement(tag, content)) {
            return ERET_BADREQ;
        }

        if (tag.tagClass() == EATAG_CONTEXT_SPECIFIC && tag.value() == 0 && tag.isConstructed()) {
            if (!tbsSeq.readNextElement(tag, content)) {
                return ERET_BADREQ;
            }
        }

        // serialNumber CertificateSerialNumber (INTEGER) -- kept as its raw two's-complement
        // big-endian content, since a serial number can be up to 20 octets (RFC 5280), well
        // past what an int64_t can hold.
        if (tag != CTag::INTEGER) {
            return ERET_BADREQ;
        }
        serialNumber = COctet(content);

        // signature AlgorithmIdentifier -- TBSCertificate's own copy. RFC 5280 4.1.1.2 requires
        // it to match Certificate.signatureAlgorithm, and that match is load-bearing rather than
        // decorative: this inner copy is inside the signed bytes, the outer one is not, yet it is
        // the outer one that signAlgo()/createHasher()/verifyBy() act on. Leaving them unchecked
        // let an unauthenticated field choose the digest used to verify the authenticated ones.
        // Only the OID is compared; the parameters are deliberately not, since a few real-world
        // issuers differ between the two copies on absent-vs-NULL for the same algorithm.
        COid tbsSigAlgoOid;
        {
            CReader tbsSigAlgoSeq;
            if (!tbsSeq.readSequence(tbsSigAlgoSeq)) {
                return ERET_BADREQ;
            }

            SRawOid rawTbsSigAlgoOid;
            if (!tbsSigAlgoSeq.readOid(rawTbsSigAlgoOid)) {
                return ERET_BADREQ;
            }

            tbsSigAlgoOid = COid(rawTbsSigAlgoOid);
        }

        // issuer Name
        if (!tbsSeq.readDistinguishedName(issuer)) {
            return ERET_BADREQ;
        }

        // validity Validity ::= SEQUENCE { notBefore Time, notAfter Time }
        CReader validitySeq;
        if (!tbsSeq.readSequence(validitySeq)) {
            return ERET_BADREQ;
        }
        if (!readTime(validitySeq, notBefore) || !readTime(validitySeq, notAfter)) {
            return ERET_BADREQ;
        }

        // subject Name
        if (!tbsSeq.readDistinguishedName(subject)) {
            return ERET_BADREQ;
        }

        // subjectPublicKeyInfo SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
        CReader spkiSeq;
        if (!tbsSeq.readSequence(spkiSeq)) {
            return ERET_BADREQ;
        }

        SSpkiFields spki;
        if (!decodeSubjectPublicKeyInfo(spkiSeq, spki)) {
            return ERET_BADREQ;
        }

        keyAlgoName = move(spki.algoName);
        keyAlgoParams = move(spki.algoParams);
        publicKey = move(spki.publicKey);
        keyAlgoWhich = spki.which;
        haveKeyAlgo = spki.resolved;

        // issuerUniqueID [1] IMPLICIT BIT STRING OPTIONAL, subjectUniqueID [2] IMPLICIT BIT
        // STRING OPTIONAL (v2/v3), extensions [3] EXPLICIT Extensions OPTIONAL (v3) -- in that
        // order, all optional; neither uniqueID is exposed by this class, so only extensions'
        // raw bytes are kept (to pull KeyUsage out of below). A v1 certificate (or a v2/v3 one
        // with none of these present) simply exhausts tbsSeq here, which readNextElement()
        // reports as "no more to read" rather than a parse error.
        COctet extensionsRaw;
        {
            CTag tag;
            SReadOnlyByteSpan content;

            // --> "Nothing left to read" and "the next element doesn't parse" must not be
            // conflated. readNextElement() reports both as false, and treating the pair as
            // "no optional fields present" was fail-open: a [3] wrapper whose declared length
            // ran past the TBSCertificate made the read fail, and the certificate then imported
            // ERET_OK with every extension missing. Checking atEnd() first separates the two.
            auto readOptional = [&tbsSeq, &tag, &content](bool& outHave) -> bool {
                if (tbsSeq.atEnd()) {
                    outHave = false;
                    return true;
                }

                outHave = tbsSeq.readNextElement(tag, content);
                return outHave;
            };

            bool have = false;
            if (!readOptional(have)) {
                return ERET_BADREQ;
            }

            if (have && tag.tagClass() == EATAG_CONTEXT_SPECIFIC && tag.value() == 1) {
                if (!readOptional(have)) { // issuerUniqueID -- skip
                    return ERET_BADREQ;
                }
            }
            if (have && tag.tagClass() == EATAG_CONTEXT_SPECIFIC && tag.value() == 2) {
                if (!readOptional(have)) { // subjectUniqueID -- skip
                    return ERET_BADREQ;
                }
            }
            if (have && tag.tagClass() == EATAG_CONTEXT_SPECIFIC && tag.value() == 3) {
                // --> A primitive [3] has to be rejected, not skipped. `extensions [3] EXPLICIT
                // Extensions` wraps a SEQUENCE, so the tag is always constructed (X.690 8.14);
                // treating `0x83` as "no extensions present" instead meant a single flipped bit
                // turned a constrained certificate into an unconstrained one that still imported
                // ERET_OK -- BasicConstraints, KeyUsage, SAN and the rest all silently absent,
                // and indistinguishable from a certificate that genuinely carries none.
                if (!tag.isConstructed()) {
                    return ERET_BADREQ;
                }

                extensionsRaw = COctet(content);
            }
        }

        // Certificate.signatureAlgorithm AlgorithmIdentifier
        CReader sigAlgoSeq;
        if (!certSeq.readSequence(sigAlgoSeq)) {
            return ERET_BADREQ;
        }

        // --> A COid rather than the OID's text. It is compared against id-RSASSA-PSS below
        // and against tbsSigAlgoOid above, and only this form answers either question: a
        // CString compared against a COid does not compare the two OIDs at all.
        SRawOid rawSigAlgoOid;
        if (!sigAlgoSeq.readOid(rawSigAlgoOid)) {
            return ERET_BADREQ;
        }

        const COid sigAlgoOid(rawSigAlgoOid);

        // --> RFC 5280 4.1.1.2: the two copies must name the same algorithm. See the
        // tbsSigAlgoOid read above for why this is a security check and not a formality.
        if (sigAlgoOid != tbsSigAlgoOid) {
            return ERET_BADREQ;
        }

        resolveSigAlgo(sigAlgoOid, sigAlgoHash, signAlgoName);

        // parameters ANY DEFINED BY algorithm OPTIONAL -- only id-RSASSA-PSS's are read: it's
        // the one signature algorithm here whose parameters carry information the verifier needs
        // (the digest, the MGF1 hash and the salt length) rather than a NULL placeholder, so
        // without them signAlgo()'s OID alone doesn't say what was signed.
        //
        // Best-effort, exactly like resolveSigAlgo() above: parameters that don't parse leave
        // sigIsRsaPss false and sigAlgoHash at EHASH_UNKNOWN, so verifyBy() reports ERET_NOTSUP
        // instead of falling back to RSASSA-PSS-params' SHA-1 defaults -- which would be a guess
        // at what a signature covers, and the rest of the certificate is still perfectly usable.
        bool sigIsRsaPss = false;
        SRsaPssParams sigPssParams;

        if (sigAlgoOid == COid(COid::RSASSA_PSS)) {
            CReader pssParams;

            if (sigAlgoSeq.atEnd()) {
                // --> No parameters field at all. RFC 4055 3.3 requires one here, but an empty
                // RSASSA-PSS-params SEQUENCE (all four fields defaulted) is legal and means
                // exactly what sigPssParams already holds, so the two are treated alike.
                sigIsRsaPss = true;
            }
            else if (sigAlgoSeq.readSequence(pssParams)
                && parseRsaPssParams(pssParams, sigPssParams)
                && sigAlgoSeq.atEnd())
            {
                sigIsRsaPss = true;
            }

            if (sigIsRsaPss) {
                sigAlgoHash = sigPssParams.hashAlgo;
            }
        }

        // signatureValue BIT STRING
        SReadOnlyByteSpan sigBits;
        uint8_t sigUnusedBits = 0;
        // --> A signature is a whole number of octets, so its BIT STRING carries no unused bits.
        // The SubjectPublicKeyInfo BIT STRING above already required this; leaving it off here
        // gave every signature up to eight extra encodings of the same bits.
        if (!certSeq.readBitString(sigBits, sigUnusedBits) || sigUnusedBits != 0) {
            return ERET_BADREQ;
        }

        // --> Structural parse succeeded; every remaining step (algorithm resolution, the
        // thumbprint) is best-effort and never fails the importDer -- an unsupported algorithm
        // still leaves the rest of the certificate's data usable. publicKey() itself is left to
        // build lazily on first call (see its own doc comment) rather than eagerly here, so
        // _cachedPub genuinely serves as a cache instead of always being populated up front.
        COctet thumbprint;
        computeThumbprint(data, thumbprint);

        crypto::IAsymmetricPtr asym;
        if (haveKeyAlgo) {
            asym = crypto::IAsymmetric::builtIn(keyAlgoWhich);
        }

        _rawData = data;
        _issuer = move(issuer);
        _subject = move(subject);
        _issuer.toString(_issuerStr);
        _subject.toString(_subjectStr);
        _thumbprint = move(thumbprint);
        _keyAlgo = move(keyAlgoName);
        _signAlgo = move(signAlgoName);
        _keyAlgoParams = move(keyAlgoParams);
        _publicKey = move(publicKey);
        _privateKey.clear(); // --> A bare X.509 certificate never embeds a private key; any
                              // previously privateKey()-attached one is no longer this cert's own.
        _serialNumber = move(serialNumber);
        _signature = COctet(sigBits);
        _notBefore = notBefore;
        _notAfter = notAfter;
        _asym = move(asym);
        _keyAlgoIsDsa = haveKeyAlgo && keyAlgoWhich == crypto::EASYM_DSA;
        _cachedPub.reset(); // --> Rebuilt lazily by publicKey() on first call.
        _cachedPvt.reset();
        _sigHashAlgo = sigAlgoHash;
        _sigIsRsaPss = sigIsRsaPss;
        _sigPssParams = sigPssParams;

        // --> Writes directly into member state (_extensions), so it's called last, only once
        // every fallible read above has already succeeded.
        parseExtensions(extensionsRaw, _extensions);

        return ERET_OK;
    }

    /* KEY_ALGOS's own OID for a keyAlgo() display name -- the reverse of resolveKeyAlgo()'s
     * lookup. */
    bool CCert::lookupKeyAlgoOid(const CString& name, COid& outOid) {
        for (const SKeyAlgo& entry : KEY_ALGOS) {
            if (name.compare(entry.name) == 0) {
                // --> The table's own SKnownOid, not a re-parse of its text: the row already
                // names the OID, and copying the constant is what keeps the name-based and
                // OID-based lookups pointing at one entry.
                outOid = entry.oid;
                return true;
            }
        }

        return false;
    }

    /* Unwraps one OCTET STRING TLV, giving back its content. */
    bool CCert::unwrapOctetString(const COctet& data, COctet& outContent) {
        CTag tag;
        SReadOnlyByteSpan content;
        SReadOnlyByteSpan cursor = data.toSpan();
        if (!CDecoder::readNextElement(cursor, EAENC_DER, tag, content)
            || tag != CTag::STRING_OCTET)
        {
            return false;
        }

        outContent = COctet(content);
        return true;
    }

    /* Parses a standard SEC1 ECPrivateKey blob into this library's own native EC wire format. */
    bool CCert::convertSec1ToNative(const COctet& data, COctet& outNative) {
        CReader wrapper(data.toSpan(), EAENC_DER);
        CReader seq;
        if (!wrapper.readSequence(seq)) {
            return false;
        }

        int64_t version = 0;
        if (!seq.readInteger(version)) {
            return false;
        }

        COctet dOctet;
        if (!seq.readOctetString(dOctet)) {
            return false;
        }

        COctet pubPoint;
        bool havePub = false;

        while (!seq.atEnd()) {
            CTag tag;
            SReadOnlyByteSpan content;
            if (!seq.readNextElement(tag, content) || tag.tagClass() != EATAG_CONTEXT_SPECIFIC) {
                break;
            }

            if (tag.value() == 1) {
                // [1] EXPLICIT BIT STRING publicKey -- unwrap the EXPLICIT layer, then the BIT
                // STRING itself (its first content byte is the unused-bits count, always 0 for a
                // byte-aligned EC point).
                CTag innerTag;
                SReadOnlyByteSpan innerContent;
                SReadOnlyByteSpan innerCursor = content;
                if (CDecoder::readNextElement(innerCursor, EAENC_DER, innerTag, innerContent)
                    && innerTag == CTag::STRING_BIT && !innerContent.empty()
                    && innerContent.data[0] == 0)
                {
                    pubPoint = COctet(innerContent.slice(1));
                    havePub = true;
                }
            }
            // [0] parameters (curve OID) isn't needed here -- the certificate's own curve is
            // already known from importDer()'s own resolveKeyAlgo() result.
        }

        if (!havePub) {
            return false; // this library's own native format has no OPTIONAL public key field.
        }

        CBigNum d = CBigNum::fromBigEndian(dOctet.toSpan());

        CBuffer body;
        CBigNum zero;
        if (!CDer::appendBigInteger(body, zero) || !CDer::appendBigInteger(body, d)
            || !CDer::appendTlv(body, CTag::STRING_OCTET, pubPoint.toSpan()))
        {
            return false;
        }

        CBuffer full;
        if (!CDer::appendSequence(full, body.toSpan())) {
            return false;
        }

        outNative = COctet(full.toSpan());
        return true;
    }

    /* Assembles this library's own traditional DSAPrivateKey wire format from Dss-Parms content,
     * a public value y and PKCS#8's inner INTEGER x TLV. */
    bool CCert::buildDsaNative(
        SReadOnlyByteSpan dssParmsContent, const CBigNum& y,
        const COctet& innerX, COctet& outNative
    ) {
        SReadOnlyByteSpan paramsCursor = dssParmsContent;
        CBigNum p, q, g;
        if (!CDer::readBigInteger(paramsCursor, p) || !CDer::readBigInteger(paramsCursor, q)
            || !CDer::readBigInteger(paramsCursor, g))
        {
            return false;
        }

        CTag xTag;
        SReadOnlyByteSpan xContent;
        SReadOnlyByteSpan xCursor = innerX.toSpan();
        if (!CDecoder::readNextElement(xCursor, EAENC_DER, xTag, xContent) || xTag != CTag::INTEGER) {
            return false;
        }
        CBigNum x = CBigNum::fromBigEndian(xContent);

        CBuffer body;
        CBigNum zero;
        if (!CDer::appendBigInteger(body, zero) || !CDer::appendBigInteger(body, p)
            || !CDer::appendBigInteger(body, q) || !CDer::appendBigInteger(body, g)
            || !CDer::appendBigInteger(body, y) || !CDer::appendBigInteger(body, x))
        {
            return false;
        }

        CBuffer full;
        if (!CDer::appendSequence(full, body.toSpan())) {
            return false;
        }

        outNative = COctet(full.toSpan());
        return true;
    }

    /* Imports the X.509 certificate from PEM-encoded raw data (a ".pem" file's contents), by
     * loading it as the container it is -- CPemChainFormat owns this library's PEM handling --
     * and keeping the first entry. The loaded certificate already carries whichever key block in
     * the file (if any) proved to be its own pair, since the format attaches it through
     * privateKey(IPrivateKeyPtr&), so there is nothing left to re-attach here. */
    ERetCode CCert::importPem(const COctet& data) {
        if (data.empty()) {
            return ERET_INVAL;
        }

        CPemChainFormat format;
        CCertCollection loaded;

        const ERetCode rc = format.load(data.toSpan(), SReadOnlyByteSpan(), loaded);
        if (rc != ERET_OK) {
            return rc;
        }

        SCertEntry entry;
        if (loaded.at(0, entry) != ERET_OK) {
            return ERET_BADREQ; // --> unreachable: load() reports ERET_OK only with an entry.
        }

        *this = move(entry.cert);
        return ERET_OK;
    }

    /* Detects whether data is DER or PEM, by asking the PEM container format's own sniffer. */
    ECertFormat CCert::detectCertFormat(SReadOnlyByteSpan data) {
        return (IChainFormat::detect(data) == ECHAINFMT_PEM) ? ECERT_PEM : ECERT_DER;
    }

    /* Imports the X.509 certificate from raw data in the specified format. */
    ERetCode CCert::importFrom(const SReadOnlyByteSpan& data, ECertFormat format) {
        if (format == ECERT_AUTO) {
            format = detectCertFormat(data);
        }

        if (format == ECERT_DER) {
            return importDer(COctet(data));
        }

        if (format == ECERT_PEM) {
            return importPem(COctet(data));
        }

        return ERET_NOTIMPL;
    }

    /* Resets the X.509 certificate to an empty state. */
    void CCert::reset() {
        _rawData.clear();
        _subject = CDistinguishedName();
        _issuer = CDistinguishedName();
        _subjectStr.clear();
        _issuerStr.clear();
        _thumbprint.clear();
        _keyAlgo.clear();
        _signAlgo.clear();
        _keyAlgoParams.clear();
        _publicKey.clear();
        _privateKey.clear();
        _serialNumber.clear();
        _signature.clear();
        _notBefore = SDateTime();
        _notAfter = SDateTime();
        _asym.reset();
        _cachedPub.reset();
        _cachedPvt.reset();
        _sigHashAlgo = crypto::EHASH_UNKNOWN;
        _sigIsRsaPss = false;
        _sigPssParams = SRsaPssParams();
        _keyAlgoIsDsa = false;
        _extensions.clear();
    }

    /* Lazily builds and caches this certificate's public key from its raw SubjectPublicKeyInfo
     * bytes (rawPublicKey()/keyAlgoParams()) the first time it's needed, rather than eagerly
     * during importDer() -- _cachedPub genuinely serves as a cache (checked first, filled once,
     * reused after) rather than always being populated whether or not a caller ever asks for it.
     * Null if _asym was never resolved (an algorithm this library doesn't implement) or the key
     * bytes don't parse under it; that failure isn't cached, so a later call can retry (e.g.
     * after the certificate's underlying algorithm gains support in a future version of this
     * library). */
    crypto::IPublicKeyPtr CCert::publicKey() const {
        if (!_cachedPub && _asym) {
            _cachedPub = makePublicKey(_asym, _keyAlgoIsDsa, _keyAlgoParams, _publicKey);
        }

        return _cachedPub;
    }

    /* Lazily builds and caches this certificate's private key from its raw bytes
     * (rawPrivateKey(), set via the privateKey(IPrivateKeyPtr&) setter -- a bare X.509
     * certificate never embeds one itself), the same on-first-use-only shape as publicKey().
     * Null if no private key has been attached, or _asym was never resolved. */
    crypto::IPrivateKeyPtr CCert::privateKey() const {
        if (!_cachedPvt && _asym && !_privateKey.empty()) {
            _cachedPvt = _asym->createPrivateKey(_privateKey);
        }

        return _cachedPvt;
    }

    /* Attaches a private key to this certificate, after checking it's actually this
     * certificate's own key (its derived public key must match publicKey() exactly) --
     * serialized into rawPrivateKey() and cached in _cachedPvt immediately, rather than
     * deferred, since the caller already handed over a live key object here (there's no raw
     * bytes to lazily reparse the way publicKey()/privateKey() do from importDer()). */
    ERetCode CCert::privateKey(crypto::IPrivateKeyPtr& inKey) {
        if (!inKey) {
            return ERET_KEY_EMPTY;
        }

        crypto::IPublicKeyPtr ownPub = publicKey();
        if (!ownPub) {
            return ERET_KEY_EMPTY; // this certificate's own public key isn't available
        }

        crypto::IPublicKeyPtr candidatePub = inKey->publicKey();
        if (!candidatePub || ownPub->compare(candidatePub) != 0) {
            return ERET_KEY_ERROR; // not this certificate's own key pair
        }

        COctet serialized;
        if (inKey->serialize(serialized) != ERET_OK) {
            return ERET_UNKNOWN;
        }

        _privateKey = move(serialized);
        _cachedPvt = inKey;
        return ERET_OK;
    }

    /* Gets the SubjectKeyIdentifier extension's key identifier bytes. ERET_INVAL if the
     * certificate has no such extension. */
    ERetCode CCert::subjectKeyIdentifier(COctet& out) const {
        auto ext = extension<CSkiExtension>();
        if (!ext) {
            return ERET_INVAL;
        }

        out = ext->keyIdentifier();
        return ERET_OK;
    }

    /* Gets the AuthorityKeyIdentifier extension's keyIdentifier [0] component -- the piece used
     * to match a chain-building candidate issuer's own subjectKeyIdentifier() -- rather than the
     * whole AuthorityKeyIdentifier SEQUENCE (which can also carry authorityCertIssuer/
     * authorityCertSerialNumber, neither exposed by this method). ERET_INVAL if the certificate
     * has no such extension, or it has one but without a keyIdentifier component (both are
     * legitimate per RFC 5280 -- every field of AuthorityKeyIdentifier is OPTIONAL). */
    ERetCode CCert::authorityKeyIdentifier(COctet& out) const {
        auto ext = extension<CAkiExtension>();
        if (!ext || !ext->hasKeyIdentifier()) {
            return ERET_INVAL;
        }

        out = ext->keyIdentifier();
        return ERET_OK;
    }

    /* Looks up a certificate extension by one of the library's known OIDs.
     *
     * Identical to the const char* overload's walk except for the comparison: this one is on
     * the arcs, so the extension's OID is not formatted to text on every extension in the
     * certificate to be compared against a string. */
    ERetCode CCert::extensionOf(const SKnownOid& oid, IExtensionPtr& out) const {
        const COid target(oid);
        if (!target) {
            return ERET_INVAL;
        }

        for (const IExtensionPtr& ext : _extensions) {
            if (ext && ext->oid() == target) {
                out = ext;
                return ERET_OK;
            }
        }

        return ERET_INVAL;
    }

    /* Looks up a certificate extension by its OID, from the list importDer() populated. ERET_INVAL
     * if oid is null or the certificate has no such extension. */
    ERetCode CCert::extensionOf(const char* oid, IExtensionPtr& out) const {
        if (!oid) {
            return ERET_INVAL;
        }

        for (const IExtensionPtr& ext : _extensions) {
            if (ext && ext->oid().compare(oid) == 0) {
                out = ext;
                return ERET_OK;
            }
        }

        return ERET_INVAL;
    }

    /* Wide-character overload of extensionOf(const char*, IExtensionPtr&) -- an OID's
     * dotted-decimal text is always plain ASCII, so the narrowing conversion is lossless
     * regardless of locale. */
    ERetCode CCert::extensionOf(const wchar_t* oid, IExtensionPtr& out) const {
        if (!oid) {
            return ERET_INVAL;
        }

        CString narrowOid = CWideString(oid).convertTo<char>();
        return extensionOf(narrowOid.toPtr(), out);
    }

    /* Two certificates are equal iff they're byte-identical DER encodings. */
    bool CCert::equals(const CCert& other) const {
        return _rawData.toSpan().sequencialEqual(other._rawData.toSpan());
    }

    /* Creates a fresh hasher for signAlgo()'s own digest algorithm (_sigHashAlgo, resolved
     * during importDer() from Certificate.signatureAlgorithm's OID) -- unrelated to thumbprint(),
     * which is always SHA-1 regardless of this certificate's actual signature algorithm. Null
     * when _sigHashAlgo is EHASH_UNKNOWN (an algorithm this library doesn't implement, or a
     * hash-less/self-hashing scheme like Ed25519/Ed448). */
    crypto::IHasherPtr CCert::createHasher() const {
        crypto::IHasherPtr hasher;
        crypto::IHasher::create(_sigHashAlgo, hasher);
        return hasher;
    }

    /* Returns the TBSCertificate's complete TLV, the bytes the signature covers. */
    SReadOnlyByteSpan CCert::tbsCertificate() const {
        if (_rawData.empty()) {
            return SReadOnlyByteSpan(nullptr, 0);
        }

        // --> Certificate ::= SEQUENCE { tbsCertificate TBSCertificate, signatureAlgorithm, ... }.
        // What gets signed is the first element's whole TLV, header included, so the length comes
        // from readEncodedValue()'s own bytesRead rather than from pointer arithmetic over the
        // content span: an empty content span can carry a null data pointer (TSpan::slice()
        // returns {nullptr, 0} once it reaches the end), which would make
        // `content.data + content.size - start` meaningless. Re-walked from _rawData on demand
        // rather than recorded during importDer(), which reads through CReader and so never sees
        // raw offsets -- two header decodes, and only when asked.
        SReadOnlyByteSpan outer = _rawData.toSpan();

        CTag tag;
        SReadOnlyByteSpan outerContent;
        size_t outerRead = 0;
        if (!CDecoder::readEncodedValue(outer, EAENC_DER, tag, outerContent, outerRead)
            || tag != CTag::SEQ || outerContent.empty())
        {
            return SReadOnlyByteSpan(nullptr, 0);
        }

        SReadOnlyByteSpan tbsContent;
        size_t tbsRead = 0;
        if (!CDecoder::readEncodedValue(outerContent, EAENC_DER, tag, tbsContent, tbsRead)
            || tag != CTag::SEQ)
        {
            return SReadOnlyByteSpan(nullptr, 0);
        }

        return SReadOnlyByteSpan(outerContent.data, tbsRead);
    }

    /* Verifies this certificate's signature against an issuer certificate's public key. */
    ERetCode CCert::verifyBy(const CCert& issuer) const {
        if (empty() || issuer.empty() || _signature.empty()) {
            return ERET_INVAL;
        }

        SReadOnlyByteSpan tbs = tbsCertificate();
        if (tbs.empty()) {
            return ERET_INVAL;
        }

        crypto::IPublicKeyPtr issuerKey = issuer.publicKey();
        if (!issuerKey) {
            return ERET_KEY_EMPTY;
        }

        crypto::IAsymmetricContextPtr ctx = issuer.createAsymmetricContext();
        if (!ctx) {
            return ERET_NOTSUP;
        }

        // --> The whole decision (hash-then-sign vs. sign-the-message, PKCS#1 v1.5 vs. PSS)
        // lives in verifySignedBlob(), shared with CCertRequest::verify() so a CSR's
        // self-signature can never be checked by subtly different rules than a certificate's.
        return verifySignedBlob(
            ctx, issuerKey->algorithm(), tbs, _signature.toSpan(),
            _sigHashAlgo, _sigIsRsaPss, _sigPssParams
        );
    }

    /* Creates a context bound to this certificate's public key, and its attached private key
     * (privateKey()) if one has been set via privateKey(IPrivateKeyPtr&) -- ready for sign() as
     * well as verify() in that case. Null if the certificate is empty or its public-key
     * algorithm isn't one this library implements -- see importDer()'s doc comment on keyAlgo()/
     * rawPublicKey() falling back to the raw OID text in that case. */
    crypto::IAsymmetricContextPtr CCert::createAsymmetricContext() const {
        crypto::IPublicKeyPtr pub = publicKey();
        if (!_asym || !pub) {
            return nullptr;
        }

        crypto::IAsymmetricContextPtr ctx = _asym->createContext();
        if (ctx) {
            ctx->keyPair(pub, privateKey());
        }

        return ctx;
    }

    /* Signs the given digest using the certificate's private key. */
    ERetCode CCert::sign(const SReadOnlyByteSpan& digest, SByteSpan& signature) const {
        if (crypto::IAsymmetricContextPtr ctx = createAsymmetricContext()) {
            return ctx->sign(digest, signature);
        }

        return ERET_NOTSUP;
    }

    /* Verifies the given digest against the provided signature using the certificate's public key. */
    ERetCode CCert::verify(const SReadOnlyByteSpan& digest, const SReadOnlyByteSpan& signature) const {
        if (crypto::IAsymmetricContextPtr ctx = createAsymmetricContext()) {
            return ctx->verify(digest, signature);
        }

        return ERET_NOTSUP;
    }

    /* Signs the given data using the certificate's private key. */
    ERetCode CCert::signData(const SReadOnlyByteSpan& data, SByteSpan& signature) const {
        if (crypto::IHasherPtr hasher = createHasher()) {
            CBuffer buffer;

            if (!buffer.resize(hasher->byteWidth())) {
                return ERET_NOMEM;
            }

            if (!hasher->push(data)) {
                return ERET_HASH_PIPE;
            }

            if (!hasher->finish(SByteSpan(buffer.toPtr(), buffer.size()))) {
                return ERET_HASH_PIPE;
            }

            return sign(SReadOnlyByteSpan(buffer.toPtr(), buffer.size()), signature);
        }

        return ERET_NOTSUP;
    }

    /* Verifies the given data against the provided signature using the certificate's public key. */
    ERetCode CCert::verifyData(const SReadOnlyByteSpan& data, const SReadOnlyByteSpan& signature) const {
        if (crypto::IHasherPtr hasher = createHasher()) {
            CBuffer buffer;

            if (!buffer.resize(hasher->byteWidth())) {
                return ERET_NOMEM;
            }

            if (!hasher->push(data)) {
                return ERET_HASH_PIPE;
            }

            if (!hasher->finish(SByteSpan(buffer.toPtr(), buffer.size()))) {
                return ERET_HASH_PIPE;
            }

            return verify(SReadOnlyByteSpan(buffer.toPtr(), buffer.size()), signature);
        }

        return ERET_NOTSUP;
    }

    /* Exports the certificate in DER format: this class has no from-scratch Certificate encoder
     * (see docs/architecture.md's "Where this will grow" -- parsing only, so far), so this simply
     * hands back the exact raw DER bytes importDer()/importPem() themselves parsed. */
    ERetCode CCert::exportDer(COctet& output) const {
        if (empty()) {
            return ERET_INVAL;
        }

        output = _rawData;
        return ERET_OK;
    }

    /* The body of buildSec1PrivateKey(), with its three inputs passed in. */
    bool CCert::buildSec1FromNative(
        const COctet& native, const COctet& curveOidContent,
        SReadOnlyByteSpan publicPoint, COctet& out
    ) {
        if (native.empty() || !publicPoint.data || publicPoint.size == 0
            || (publicPoint.size % 2) == 0)
        {
            return false; // the point must be a SEC1 uncompressed one (0x04 || X || Y).
        }

        // Extract d from this library's own SEQUENCE { INTEGER 0, INTEGER d, OCTET STRING point }.
        CReader wrapper(native.toSpan(), EAENC_DER);
        CReader seq;
        if (!wrapper.readSequence(seq)) {
            return false;
        }

        int64_t version = 0;
        if (!seq.readInteger(version)) {
            return false;
        }

        CTag dTag;
        SReadOnlyByteSpan dContent;
        if (!seq.readNextElement(dTag, dContent) || dTag != CTag::INTEGER) {
            return false;
        }

        size_t fieldLen = (publicPoint.size - 1) / 2;

        CBigNum d = CBigNum::fromBigEndian(dContent);
        CBuffer dPadded;
        if (!dPadded.resize(fieldLen) || !d.toBigEndian(dPadded.toSpan())) {
            return false; // d doesn't fit in the curve's own field width -- shouldn't happen.
        }

        CBuffer body;
        uint8_t versionContent = 0x01; // SEC1's ecPrivkeyVer1.
        if (!CDer::appendTlv(body, CTag::INTEGER, SReadOnlyByteSpan(&versionContent, 1))
            || !CDer::appendTlv(body, CTag::STRING_OCTET, dPadded.toSpan()))
        {
            return false;
        }

        if (!curveOidContent.empty()) {
            // parameters [0] EXPLICIT OBJECT IDENTIFIER (namedCurve) -- this certificate's own,
            // already resolved by importDer().
            CBuffer oidTlv;
            if (!CDer::appendTlv(oidTlv, CTag::OBJ_ID, curveOidContent.toSpan())
                || !CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), oidTlv.toSpan()))
            {
                return false;
            }
        }

        // publicKey [1] EXPLICIT BIT STRING (0 unused bits, content = the SEC1 uncompressed point).
        CBuffer bitStringContent;
        if (!bitStringContent.resize(1 + publicPoint.size)) {
            return false;
        }
        uint8_t* bitStringContentPtr = bitStringContent.toPtr();
        bitStringContentPtr[0] = 0x00;
        std::memcpy(bitStringContentPtr + 1, publicPoint.data, publicPoint.size);

        CBuffer bitStringTlv;
        if (!CDer::appendTlv(bitStringTlv, CTag::STRING_BIT, bitStringContent.toSpan())
            || !CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 1, true), bitStringTlv.toSpan()))
        {
            return false;
        }

        CBuffer full;
        if (!CDer::appendSequence(full, body.toSpan())) {
            return false;
        }

        out = COctet(full.toSpan());
        return true;
    }

    /* Exports the certificate in PEM format, by saving it as a one-entry container --
     * CPemChainFormat owns this library's PEM handling, including which label and which standard
     * encoding each key algorithm's own block gets. includePrivateKey selects the form of that
     * format which writes a key block at all; the key goes out in the clear, because PEM has no
     * other way to carry one. */

    ERetCode CCert::exportPem(COctet& output, bool includePrivateKey) const {
        if (empty()) {
            return ERET_INVAL; // --> the same answer exportDer() gives, before building anything.
        }

        CCertCollection one;
        size_t index = 0;

        const ERetCode addRc = one.add(*this, index);
        if (addRc != ERET_OK) {
            return addRc;
        }

        // --> add() copied this certificate whole, rawPrivateKey() included, so the collection
        // entry already carries the key the format is about to write (if it was asked to).
        CPemChainFormat format(includePrivateKey);
        CBuffer buffer;

        const ERetCode rc = format.save(one, SReadOnlyByteSpan(), buffer);
        if (rc != ERET_OK) {
            return rc;
        }

        output = COctet(SReadOnlyByteSpan(buffer.toPtr(), buffer.size()));
        return ERET_OK;
    }

    /* Exports the certificate in the specified format -- see exportAs()'s own doc comment on
     * why it isn't named export(). */
    ERetCode CCert::exportAs(COctet& output, bool includePrivateKey, ECertFormat format) const {
        if (format == ECERT_DER) {
            return exportDer(output);
        }

        if (format == ECERT_PEM) {
            return exportPem(output, includePrivateKey);
        }

        return ERET_NOTSUP; // --> ECERT_AUTO isn't a meaningful export format.
    }

    /* Wraps a private key as a PKCS#8 PrivateKeyInfo (RFC 5208 5). */
    ERetCode CCert::exportPkcs8PrivateKey(const crypto::IPrivateKeyPtr& key, COctet& out) {
        out = COctet();

        if (!key) {
            return ERET_INVAL;
        }

        const crypto::EAsymmetrics which = key->algorithm();

        // --> ML-DSA's PKCS#8 form is a CHOICE between a 32-byte seed and the full expanded key
        // (and the drafts disagreed about it for years). This library's own key blob is neither
        // shape, so writing one here would be guessing at an encoding nothing else reads.
        if (which == crypto::EASYM_MLDSA44 || which == crypto::EASYM_MLDSA65
            || which == crypto::EASYM_MLDSA87)
        {
            return ERET_NOTSUP;
        }

        COid keyOid, ecCurveOid;
        bool keyIsDsa = false, keyIsEc = false;
        if (!resolveKeyAlgoForBuild(which, keyOid, keyIsDsa, keyIsEc, ecCurveOid)) {
            return ERET_NOTSUP;
        }

        COctet native;
        ScopedWipe<COctet> wipeNative(native);
        if (key->serialize(native) != ERET_OK || native.empty()) {
            return ERET_KEY_ERROR;
        }

        // --- The AlgorithmIdentifier's "parameters", and the "privateKey OCTET STRING"'s
        // content, both of which mean something different per algorithm. ---
        CBuffer algoParams;     // --> the complete parameters TLV, or empty for "absent".
        COctet innerKey;        // --> what goes inside the privateKey OCTET STRING.
        ScopedWipe<COctet> wipeInner(innerKey);

        if (keyIsEc) {
            // EC: parameters is the namedCurve OID, and the inner blob is a SEC1 ECPrivateKey.
            // The point comes out of the native blob, which embeds it -- there is no certificate
            // here to take rawPublicKey() from.
            size_t needed = CEncoder::encodedOidSize(ecCurveOid.raw());
            CBuffer oidContent;
            size_t written = 0;
            if (!needed || !oidContent.resize(needed)
                || !CEncoder::encodeOid(oidContent.toSpan(), ecCurveOid.raw(), written))
            {
                return ERET_UNKNOWN;
            }

            if (!CDer::appendTlv(algoParams, CTag::OBJ_ID,
                                 SReadOnlyByteSpan(oidContent.toPtr(), written)))
            {
                return ERET_NOMEM;
            }

            CReader wrapper(native.toSpan(), EAENC_DER);
            CReader seq;
            int64_t version = 0;
            CTag dTag;
            SReadOnlyByteSpan dContent;
            COctet point;
            if (!wrapper.readSequence(seq) || !seq.readInteger(version)
                || !seq.readNextElement(dTag, dContent) || dTag != CTag::INTEGER
                || !seq.readOctetString(point))
            {
                return ERET_KEY_FORMAT;
            }

            if (!buildSec1FromNative(
                    native, COctet(SReadOnlyByteSpan(oidContent.toPtr(), written)),
                    point.toSpan(), innerKey))
            {
                return ERET_KEY_FORMAT;
            }
        } else if (keyIsDsa) {
            // DSA: parameters is Dss-Parms { p, q, g } and the inner blob is a bare INTEGER x --
            // both pulled out of the native { version, p, q, g, y, x } SEQUENCE.
            SReadOnlyByteSpan cursor;
            if (!CDer::readOuterSequence(native.toSpan(), cursor)) {
                return ERET_KEY_FORMAT;
            }

            CBigNum version, p, q, g, y, x;
            if (!CDer::readBigInteger(cursor, version) || !CDer::readBigInteger(cursor, p)
                || !CDer::readBigInteger(cursor, q) || !CDer::readBigInteger(cursor, g)
                || !CDer::readBigInteger(cursor, y) || !CDer::readBigInteger(cursor, x))
            {
                return ERET_KEY_FORMAT;
            }

            CBuffer parmsBody;
            if (!CDer::appendBigInteger(parmsBody, p) || !CDer::appendBigInteger(parmsBody, q)
                || !CDer::appendBigInteger(parmsBody, g)
                || !CDer::appendSequence(algoParams, parmsBody.toSpan()))
            {
                return ERET_NOMEM;
            }

            CBuffer xTlv;
            if (!CDer::appendBigInteger(xTlv, x)) {
                return ERET_NOMEM;
            }

            innerKey = COctet(xTlv.toSpan());
        } else if (which == crypto::EASYM_ED25519 || which == crypto::EASYM_ED448
                   || which == crypto::EASYM_X25519)
        {
            // RFC 8410 7: no parameters at all, and the inner blob is itself a DER OCTET STRING
            // around the raw seed. The double wrapping is not a mistake in the RFC.
            CBuffer seedTlv;
            if (!CDer::appendTlv(seedTlv, CTag::STRING_OCTET, native.toSpan())) {
                return ERET_NOMEM;
            }

            innerKey = COctet(seedTlv.toSpan());
        } else {
            // RSA: parameters is an explicit NULL (not absent -- RFC 3447 A.1 requires it), and
            // the inner blob is the PKCS#1 RSAPrivateKey directly.
            if (!CDer::appendTlv(algoParams, CTag::NULL_, SReadOnlyByteSpan(nullptr, 0))) {
                return ERET_NOMEM;
            }

            innerKey = native;
        }

        // --- PrivateKeyInfo ::= SEQUENCE { version INTEGER 0, privateKeyAlgorithm
        // AlgorithmIdentifier, privateKey OCTET STRING } ---
        size_t oidNeeded = CEncoder::encodedOidSize(keyOid.raw());
        CBuffer oidBuf;
        size_t oidWritten = 0;
        if (!oidNeeded || !oidBuf.resize(oidNeeded)
            || !CEncoder::encodeOid(oidBuf.toSpan(), keyOid.raw(), oidWritten))
        {
            return ERET_UNKNOWN;
        }

        CBuffer algoIdContent;
        if (!CDer::appendTlv(algoIdContent, CTag::OBJ_ID,
                             SReadOnlyByteSpan(oidBuf.toPtr(), oidWritten)))
        {
            return ERET_NOMEM;
        }
        if (!algoParams.empty() && !CDer::appendRaw(algoIdContent, algoParams.toSpan())) {
            return ERET_NOMEM;
        }

        CBuffer body, full;
        ScopedWipe<CBuffer> wipeBody(body);
        ScopedWipe<CBuffer> wipeFull(full);

        uint8_t versionContent = 0x00;
        if (!CDer::appendTlv(body, CTag::INTEGER, SReadOnlyByteSpan(&versionContent, 1))
            || !CDer::appendSequence(body, algoIdContent.toSpan())
            || !CDer::appendTlv(body, CTag::STRING_OCTET, innerKey.toSpan()))
        {
            return ERET_NOMEM;
        }

        if (!CDer::appendSequence(full, body.toSpan())) {
            return ERET_NOMEM;
        }

        // `out` is the caller's copy and is deliberately not wiped; everything else goes out
        // through ScopedWipe, on this path and on the nineteen failure paths above.
        out = COctet(full.toSpan());
        return ERET_OK;
    }

    /* Reads a PKCS#8 PrivateKeyInfo back into a key. */
    ERetCode CCert::importPkcs8PrivateKey(
        const SReadOnlyByteSpan& data, crypto::IPrivateKeyPtr& out
    ) {
        out.reset();

        if (!data.data || data.size == 0) {
            return ERET_BADREQ;
        }

        CReader wrapper(data, EAENC_DER);
        CReader seq;
        int64_t version = 0;
        if (!wrapper.readSequence(seq) || !seq.readInteger(version)) {
            return ERET_BADREQ;
        }

        CReader algoSeq;
        if (!seq.readSequence(algoSeq)) {
            return ERET_BADREQ;
        }

        SRawOid rawAlgoOid;
        if (!algoSeq.readOid(rawAlgoOid)) {
            return ERET_BADREQ;
        }

        // --> As a COid, not as the OID's text: what this function does next is compare the OID
        // against KEY_ALGOS and id-ecPublicKey, and it later stores it as CCert::_keyAlgo. Both
        // want the arcs, so formatting it to dotted-decimal here would be a round trip
        // re-parsed by every one of them.
        const COid algoOid(rawAlgoOid);

        // The parameters are read now because EC needs them to resolve the curve before it knows
        // which algorithm it even is. They are OPTIONAL, so an absent one is not an error.
        CTag paramsTag;
        SReadOnlyByteSpan paramsContent;
        bool haveParams = algoSeq.readNextElement(paramsTag, paramsContent);

        COctet inner;
        ScopedWipe<COctet> wipeInner(inner);
        if (!seq.readOctetString(inner)) {
            return ERET_BADREQ;
        }

        // --- Resolve the algorithm from the PrivateKeyInfo's own OID, which is the whole point
        // of this method as against tryAttachPrivateKey()'s guessing. ---
        crypto::EAsymmetrics which = crypto::EASYM_RSA;
        bool resolved = false, isEc = false;

        if (algoOid == COid(OID_EC_PUBLIC_KEY)) {
            if (!haveParams || paramsTag != CTag::OBJ_ID
                || !resolveEcCurve(paramsContent, which))
            {
                return ERET_NOTSUP; // an unnamed or unimplemented curve.
            }

            resolved = true;
            isEc = true;
        } else {
            for (const SKeyAlgo& entry : KEY_ALGOS) {
                if (algoOid == COid(entry.oid)) {
                    which = entry.which;
                    resolved = true;
                    break;
                }
            }
        }

        if (!resolved) {
            return ERET_NOTSUP;
        }
        if (which == crypto::EASYM_MLDSA44 || which == crypto::EASYM_MLDSA65
            || which == crypto::EASYM_MLDSA87)
        {
            return ERET_NOTSUP; // see exportPkcs8PrivateKey()'s own comment.
        }

        crypto::IAsymmetricPtr algo = crypto::IAsymmetric::builtIn(which);
        if (!algo) {
            return ERET_NOTSUP;
        }

        ERetCode result = ERET_KEY_FORMAT;
        COctet native;
        ScopedWipe<COctet> wipeNative(native);

        if (isEc) {
            // EC's inner blob is a SEC1 ECPrivateKey, which carries the public point this
            // library's own native format needs.
            if (convertSec1ToNative(inner, native)) {
                out = algo->createPrivateKey(native);
                result = out ? ERET_OK : ERET_KEY_FORMAT;
            }
        } else if (which == crypto::EASYM_DSA) {
            // DSA's inner blob is a bare INTEGER x, and PKCS#8 carries no y at all -- so y has
            // to be recovered as g^x mod p before this library's native blob can be assembled.
            SReadOnlyByteSpan parmsCursor = paramsContent;
            CBigNum p, q, g;
            if (haveParams && paramsTag == CTag::SEQ
                && CDer::readBigInteger(parmsCursor, p) && CDer::readBigInteger(parmsCursor, q)
                && CDer::readBigInteger(parmsCursor, g))
            {
                CTag xTag;
                SReadOnlyByteSpan xContent;
                SReadOnlyByteSpan xCursor = inner.toSpan();
                if (CDecoder::readNextElement(xCursor, EAENC_DER, xTag, xContent)
                    && xTag == CTag::INTEGER)
                {
                    const CBigNum x = CBigNum::fromBigEndian(xContent);
                    const CBigNum y = CBigNum::modExp(g, x, p);

                    if (buildDsaNative(paramsContent, y, inner, native)) {
                        out = algo->createPrivateKey(native);
                        result = out ? ERET_OK : ERET_KEY_FORMAT;
                    }
                }
            }
        } else if (which == crypto::EASYM_ED25519 || which == crypto::EASYM_ED448
                   || which == crypto::EASYM_X25519)
        {
            // RFC 8410's double OCTET STRING: one more unwrap reaches the raw seed.
            COctet seed;
            ScopedWipe<COctet> wipeSeed(seed);
            if (unwrapOctetString(inner, seed)) {
                out = algo->createPrivateKey(seed);
                result = out ? ERET_OK : ERET_KEY_FORMAT;
            }
        } else {
            // RSA: the inner blob is already the final PKCS#1 RSAPrivateKey.
            out = algo->createPrivateKey(inner);
            result = out ? ERET_OK : ERET_KEY_FORMAT;
        }

        // --> `inner`, `native` and the EdDSA branch's `seed` are all plaintext private key
        // material, on the failing paths as much as this one, which is why each goes out through
        // a ScopedWipe rather than a wipe written beside one `return`.
        if (result != ERET_OK) {
            out.reset();
        }

        return result;
    }

    /* Builds and signs a fresh X.509 certificate from this builder's fields. Assembles the
     * TBSCertificate/Certificate DER from scratch, signs it with issuerKeyPair, and hands the
     * result to CCert::importDer() -- so out ends up populated exactly the way a real parse
     * would populate it (including importDer()'s own clearing of any private key, matching this
     * method's own documented "no private key attached" guarantee) rather than by separately
     * duplicating CCert's field-population logic here. out is left empty on any failure. */
    ERetCode CCertBuilder::build(CCert& out) const {
        out = CCert();

        if (!subjectKey || issuerKeyPair.empty() || issuer.empty() || subject.empty() || serialNumber.empty()) {
            return ERET_INVAL;
        }

        // --- signature: resolve issuerKeyPair's algorithm + digestAlgo/rsaPss to a signature
        // OID + digest + AlgorithmIdentifier parameters. ---
        crypto::EAsymmetrics issuerWhich = issuerKeyPair.privateKey->algorithm();

        COid sigOid;
        crypto::EHashers sigHash = crypto::EHASH_UNKNOWN;
        COctet sigAlgoParams;
        if (!CCert::resolveSigAlgoForSigning(issuerWhich, digestAlgo, rsaPss, sigOid, sigHash, sigAlgoParams)) {
            return ERET_NOTSUP; // --> e.g. issuerKeyPair is X25519, or digestAlgo has no OID for it.
        }

        // AlgorithmIdentifier ::= SEQUENCE { OID, parameters ANY OPTIONAL } -- built once, since
        // TBSCertificate.signature and Certificate.signatureAlgorithm must be byte-identical.
        CBuffer sigAlgoIdTlv;
        if (!CCert::encodeAlgorithmIdentifier(sigOid, sigAlgoParams, sigAlgoIdTlv)) {
            return ERET_UNKNOWN;
        }

        // --- Assemble TBSCertificate. ---
        CBuffer tbsBody;

        // version [0] EXPLICIT INTEGER { v3(2) } -- always v3, the universal modern default.
        static constexpr uint8_t VERSION_V3_INNER[] = { 0x02, 0x01, 0x02 };
        if (!CDer::appendTlv(tbsBody, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), SReadOnlyByteSpan(VERSION_V3_INNER, sizeof(VERSION_V3_INNER)))) {
            return ERET_UNKNOWN;
        }

        // serialNumber -- already this builder's own raw two's-complement big-endian content.
        if (!CDer::appendTlv(tbsBody, CTag::INTEGER, serialNumber.toSpan())) {
            return ERET_UNKNOWN;
        }

        // signature AlgorithmIdentifier -- TBSCertificate's own copy of sigAlgoIdTlv.
        if (!CDer::appendRaw(tbsBody, sigAlgoIdTlv.toSpan())) {
            return ERET_UNKNOWN;
        }

        // issuer Name.
        if (!CCert::encodeName(issuer, tbsBody)) {
            return ERET_UNKNOWN;
        }

        // validity SEQUENCE { notBefore Time, notAfter Time }.
        {
            CBuffer body;
            if (!CCert::encodeTime(notBefore, body) || !CCert::encodeTime(notAfter, body)) {
                return ERET_INVAL; // --> e.g. notBefore/notAfter.isUtc wasn't set to true.
            }

            if (!CDer::appendSequence(tbsBody, body.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        // subject Name.
        if (!CCert::encodeName(subject, tbsBody)) {
            return ERET_UNKNOWN;
        }

        // subjectPublicKeyInfo SEQUENCE { algorithm, subjectPublicKey BIT STRING }.
        {
            ERetCode rc = CCert::encodeSubjectPublicKeyInfo(subjectKey, tbsBody);
            if (rc != ERET_OK) {
                return rc; // --> ERET_NOTSUP/ERET_KEY_ERROR/ERET_KEY_FORMAT, see its own contract.
            }
        }

        // extensions [3] EXPLICIT Extensions OPTIONAL (SEQUENCE OF Extension) -- omitted
        // entirely when empty, rather than encoded as an empty SEQUENCE.
        if (!extensions.empty()) {
            CBuffer extListSeq;
            ERetCode rc = CCert::encodeExtensions(extensions, extListSeq);
            if (rc != ERET_OK) {
                return rc;
            }

            if (!CDer::appendTlv(tbsBody, CTag(EATAG_CONTEXT_SPECIFIC, 3, true), extListSeq.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        CBuffer tbsFull;
        if (!CDer::appendSequence(tbsFull, tbsBody.toSpan())) {
            return ERET_UNKNOWN;
        }

        // --- Sign the TBSCertificate: a digest for a hash-then-sign family, or the raw
        // TBSCertificate bytes directly for the self-hashing schemes (EdDSA, ML-DSA). ---
        COctet signature;
        {
            ERetCode rc = CCert::signTbs(issuerKeyPair, tbsFull.toSpan(), sigHash, rsaPss, signature);
            if (rc != ERET_OK) {
                return rc;
            }
        }

        // --- Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }. ---
        CBuffer certBody;
        if (!CDer::appendRaw(certBody, tbsFull.toSpan()) || !CDer::appendRaw(certBody, sigAlgoIdTlv.toSpan())) {
            return ERET_UNKNOWN;
        }

        {
            CBuffer bitContent;
            size_t written = 0;
            if (!bitContent.resize(1 + signature.size())
                || !CEncoder::encodeBitString(bitContent.toSpan(), signature.toSpan(), 0, written))
            {
                return ERET_UNKNOWN;
            }

            if (!CDer::appendTlv(certBody, CTag::STRING_BIT, SReadOnlyByteSpan(bitContent.toPtr(), written))) {
                return ERET_UNKNOWN;
            }
        }

        CBuffer certFull;
        if (!CDer::appendSequence(certFull, certBody.toSpan())) {
            return ERET_UNKNOWN;
        }

        return out.importDer(COctet(certFull.toSpan()));
    }

    /* Takes `subject` and `subjectKey` from a PKCS#10 certification request -- and deliberately
     * nothing else, extensions least of all. See its own doc comment in cert.hpp for why there
     * is no method here that copies a request's requested extensions wholesale. */
    ERetCode CCertBuilder::subjectFrom(const CCertRequest& request) {
        if (request.empty()) {
            return ERET_INVAL;
        }

        crypto::IPublicKeyPtr requestedKey = request.publicKey();
        if (!requestedKey) {
            return ERET_KEY_EMPTY;
        }

        subject = request.subject();
        subjectKey = move(requestedKey);
        return ERET_OK;
    }

} // namespace x509
} // namespace certpp
