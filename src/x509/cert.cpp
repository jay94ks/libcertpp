#include <certpp/x509/cert.hpp>
#include <certpp/x509/exts/ski.hpp>
#include <certpp/x509/exts/aki.hpp>
#include <certpp/asn1/reader.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/utils/bignum.hpp>
#include <certpp/utils/base64.hpp>
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

    /* Public-key algorithm OIDs whose EAsymmetrics doesn't depend on any further
     * parameters -- id-ecPublicKey is deliberately excluded here (its EAsymmetrics
     * depends on the namedCurve OID carried in the AlgorithmIdentifier's parameters) and handled
     * separately via EC_CURVES below. */
    const CCert::SKeyAlgo CCert::KEY_ALGOS[] = {
        { "1.2.840.113549.1.1.1", "RSA",     crypto::EASYM_RSA },
        { "1.2.840.10040.4.1",    "DSA",     crypto::EASYM_DSA },
        { "1.3.101.110",          "X25519",  crypto::EASYM_X25519 },
        { "1.3.101.112",          "Ed25519", crypto::EASYM_ED25519 },
        { "1.3.101.113",          "Ed448",   crypto::EASYM_ED448 },
    };

    const CCert::SKeyAlgo CCert::EC_CURVES[] = {
        { "1.2.840.10045.3.1.1", "P-192",       crypto::EASYM_P192 },
        { "1.3.132.0.33",        "P-224",       crypto::EASYM_P224 },
        { "1.2.840.10045.3.1.7", "P-256",       crypto::EASYM_P256 },
        { "1.3.132.0.34",        "P-384",       crypto::EASYM_P384 },
        { "1.3.132.0.35",        "P-521",       crypto::EASYM_P521 },
        { "1.3.132.0.10",        "secp256k1",   crypto::EASYM_SECP256K1 },
        { "1.3.36.3.3.2.8.1.1.1",  "brainpoolP160r1", crypto::EASYM_BPOOL160R1 },
        { "1.3.36.3.3.2.8.1.1.2",  "brainpoolP160t1", crypto::EASYM_BPOOL160T1 },
        { "1.3.36.3.3.2.8.1.1.3",  "brainpoolP192r1", crypto::EASYM_BPOOL192R1 },
        { "1.3.36.3.3.2.8.1.1.4",  "brainpoolP192t1", crypto::EASYM_BPOOL192T1 },
        { "1.3.36.3.3.2.8.1.1.5",  "brainpoolP224r1", crypto::EASYM_BPOOL224R1 },
        { "1.3.36.3.3.2.8.1.1.6",  "brainpoolP224t1", crypto::EASYM_BPOOL224T1 },
        { "1.3.36.3.3.2.8.1.1.7",  "brainpoolP256r1", crypto::EASYM_BPOOL256R1 },
        { "1.3.36.3.3.2.8.1.1.8",  "brainpoolP256t1", crypto::EASYM_BPOOL256T1 },
        { "1.3.36.3.3.2.8.1.1.9",  "brainpoolP320r1", crypto::EASYM_BPOOL320R1 },
        { "1.3.36.3.3.2.8.1.1.10", "brainpoolP320t1", crypto::EASYM_BPOOL320T1 },
        { "1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1", crypto::EASYM_BPOOL384R1 },
        { "1.3.36.3.3.2.8.1.1.12", "brainpoolP384t1", crypto::EASYM_BPOOL384T1 },
        { "1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1", crypto::EASYM_BPOOL512R1 },
        { "1.3.36.3.3.2.8.1.1.14", "brainpoolP512t1", crypto::EASYM_BPOOL512T1 },
        { "1.3.132.0.1",  "K-163", crypto::EASYM_K163 },
        { "1.3.132.0.15", "B-163", crypto::EASYM_B163 },
        { "1.3.132.0.26", "K-233", crypto::EASYM_K233 },
        { "1.3.132.0.27", "B-233", crypto::EASYM_B233 },
        { "1.3.132.0.16", "K-283", crypto::EASYM_K283 },
        { "1.3.132.0.17", "B-283", crypto::EASYM_B283 },
        { "1.3.132.0.36", "K-409", crypto::EASYM_K409 },
        { "1.3.132.0.37", "B-409", crypto::EASYM_B409 },
        { "1.3.132.0.38", "K-571", crypto::EASYM_K571 },
        { "1.3.132.0.39", "B-571", crypto::EASYM_B571 },
    };

    /* Signature algorithm OIDs. EBASYM isn't recorded here -- unlike the public-key algorithm
     * above, a signature OID like ecdsa-with-SHA256 doesn't name a specific curve (any EC key
     * can use it), so the signature's own asymmetric family is never needed separately from
     * keyAlgo()'s. */
    const CCert::SSigAlgo CCert::SIG_ALGOS[] = {
        { "1.2.840.113549.1.1.4",   "md5WithRSAEncryption",    crypto::EHASH_MD5 },
        { "1.2.840.113549.1.1.5",   "sha1WithRSAEncryption",   crypto::EHASH_SHA1 },
        { "1.2.840.113549.1.1.14",  "sha224WithRSAEncryption", crypto::EHASH_SHA224 },
        { "1.2.840.113549.1.1.11",  "sha256WithRSAEncryption", crypto::EHASH_SHA256 },
        { "1.2.840.113549.1.1.12",  "sha384WithRSAEncryption", crypto::EHASH_SHA384 },
        { "1.2.840.113549.1.1.13",  "sha512WithRSAEncryption", crypto::EHASH_SHA512 },
        { "1.2.840.10040.4.3",      "dsa-with-sha1",           crypto::EHASH_SHA1 },
        { "2.16.840.1.101.3.4.3.1", "dsa-with-sha224",         crypto::EHASH_SHA224 },
        { "2.16.840.1.101.3.4.3.2", "dsa-with-sha256",         crypto::EHASH_SHA256 },
        { "1.2.840.10045.4.1",      "ecdsa-with-SHA1",         crypto::EHASH_SHA1 },
        { "1.2.840.10045.4.3.1",    "ecdsa-with-SHA224",       crypto::EHASH_SHA224 },
        { "1.2.840.10045.4.3.2",    "ecdsa-with-SHA256",       crypto::EHASH_SHA256 },
        { "1.2.840.10045.4.3.3",    "ecdsa-with-SHA384",       crypto::EHASH_SHA384 },
        { "1.2.840.10045.4.3.4",    "ecdsa-with-SHA512",       crypto::EHASH_SHA512 },
        { "1.3.101.112",            "Ed25519",                 crypto::EHASH_UNKNOWN },
        { "1.3.101.113",            "Ed448",                   crypto::EHASH_UNKNOWN },
        // --> id-RSASSA-PSS (RFC 4055) names no digest of its own: the hash lives in the
        // AlgorithmIdentifier's parameters, which importDer() reads separately via
        // parseRsaPssParams() and then uses to set _sigHashAlgo. EHASH_UNKNOWN here keeps
        // resolveSigAlgo() from claiming a digest this OID genuinely doesn't carry.
        { "1.2.840.113549.1.1.10",  "rsassaPss",               crypto::EHASH_UNKNOWN },
    };

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
        CString oidText;
        if (!CDecoder::decodeOidString(namedCurveContent, oidText)) {
            return false;
        }

        for (const SKeyAlgo& entry : EC_CURVES) {
            if (oidText.compare(entry.oid) == 0) {
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
        const CString& oid,
        const COctet& params,
        crypto::EAsymmetrics& outWhich,
        CString& outName
    ) {
        for (const SKeyAlgo& entry : KEY_ALGOS) {
            if (oid.compare(entry.oid) == 0) {
                outWhich = entry.which;
                outName = entry.name;
                return true;
            }
        }

        if (oid.compare(OID_EC_PUBLIC_KEY) == 0) {
            outName = "EC";
            return resolveEcCurve(params.toSpan(), outWhich);
        }

        outName = oid;
        return false;
    }

    /* Resolves a crypto::EAsymmetrics to the SubjectPublicKeyInfo.algorithm fields
     * CCertBuilder::build() needs -- the inverse of resolveKeyAlgo(), built from the same tables. */
    bool CCert::resolveKeyAlgoForBuild(
        crypto::EAsymmetrics which,
        CString& outOid,
        bool& outIsDsa,
        bool& outIsEc,
        CString& outEcCurveOid
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
    void CCert::resolveSigAlgo(const CString& oid, crypto::EHashers& outHash, CString& outName) {
        for (const SSigAlgo& entry : SIG_ALGOS) {
            if (oid.compare(entry.oid) == 0) {
                outName = entry.name;
                if (entry.which != crypto::EHASH_UNKNOWN) {
                    outHash = entry.which;
                }
                return;
            }
        }

        outName = oid;
    }

    const CCert::SSigHashOid CCert::RSA_SIG_OIDS[] = {
        { crypto::EHASH_MD5,    "1.2.840.113549.1.1.4" },  // md5WithRSAEncryption
        { crypto::EHASH_SHA1,   "1.2.840.113549.1.1.5" },  // sha1WithRSAEncryption
        { crypto::EHASH_SHA224, "1.2.840.113549.1.1.14" }, // sha224WithRSAEncryption
        { crypto::EHASH_SHA256, "1.2.840.113549.1.1.11" }, // sha256WithRSAEncryption
        { crypto::EHASH_SHA384, "1.2.840.113549.1.1.12" }, // sha384WithRSAEncryption
        { crypto::EHASH_SHA512, "1.2.840.113549.1.1.13" }, // sha512WithRSAEncryption
    };

    const CCert::SSigHashOid CCert::DSA_SIG_OIDS[] = {
        { crypto::EHASH_SHA1,   "1.2.840.10040.4.3" },      // dsa-with-sha1
        { crypto::EHASH_SHA224, "2.16.840.1.101.3.4.3.1" }, // dsa-with-sha224
        { crypto::EHASH_SHA256, "2.16.840.1.101.3.4.3.2" }, // dsa-with-sha256
    };

    const CCert::SSigHashOid CCert::ECDSA_SIG_OIDS[] = {
        { crypto::EHASH_SHA1,   "1.2.840.10045.4.1" },   // ecdsa-with-SHA1
        { crypto::EHASH_SHA224, "1.2.840.10045.4.3.1" }, // ecdsa-with-SHA224
        { crypto::EHASH_SHA256, "1.2.840.10045.4.3.2" }, // ecdsa-with-SHA256
        { crypto::EHASH_SHA384, "1.2.840.10045.4.3.3" }, // ecdsa-with-SHA384
        { crypto::EHASH_SHA512, "1.2.840.10045.4.3.4" }, // ecdsa-with-SHA512
    };

    /* Linear lookup of hash within one of the *_SIG_OIDS tables above. */
    bool CCert::lookupSigOid(const SSigHashOid* table, size_t count, crypto::EHashers hash, CString& outOid) {
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
        const char* hashOid = nullptr;
        switch (hash) {
            case crypto::EHASH_SHA1:   hashOid = "1.3.14.3.2.26";          break;
            case crypto::EHASH_SHA224: hashOid = "2.16.840.1.101.3.4.2.4"; break;
            case crypto::EHASH_SHA256: hashOid = "2.16.840.1.101.3.4.2.1"; break;
            case crypto::EHASH_SHA384: hashOid = "2.16.840.1.101.3.4.2.2"; break;
            case crypto::EHASH_SHA512: hashOid = "2.16.840.1.101.3.4.2.3"; break;
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
            size_t needed = CEncoder::encodedOidStringSize(CString(hashOid));
            if (!needed) {
                return false;
            }

            CBuffer oidContent;
            size_t written = 0;
            if (!oidContent.resize(needed) || !CEncoder::encodeOidString(oidContent.toSpan(), CString(hashOid), written)) {
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
            static const char* MGF1_OID = "1.2.840.113549.1.1.8";
            size_t needed = CEncoder::encodedOidStringSize(CString(MGF1_OID));
            if (!needed) {
                return false;
            }

            CBuffer oidContent;
            size_t written = 0;
            if (!oidContent.resize(needed) || !CEncoder::encodeOidString(oidContent.toSpan(), CString(MGF1_OID), written)) {
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
        CString oid;
        if (!algo.readOidString(oid)) {
            return false;
        }

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
        if (oid.compare("1.3.14.3.2.26") == 0)          { outHash = crypto::EHASH_SHA1;   return true; }
        if (oid.compare("2.16.840.1.101.3.4.2.4") == 0) { outHash = crypto::EHASH_SHA224; return true; }
        if (oid.compare("2.16.840.1.101.3.4.2.1") == 0) { outHash = crypto::EHASH_SHA256; return true; }
        if (oid.compare("2.16.840.1.101.3.4.2.2") == 0) { outHash = crypto::EHASH_SHA384; return true; }
        if (oid.compare("2.16.840.1.101.3.4.2.3") == 0) { outHash = crypto::EHASH_SHA512; return true; }

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
                    CString mgfOid;
                    if (!field.readSequence(mgfAlgo) || !mgfAlgo.readOidString(mgfOid)) {
                        return false;
                    }

                    // --> id-mgf1 is the only mask generation function RFC 4055 defines, and its
                    // parameters ARE a HashAlgorithm (RFC 8017 A.2.3) -- not optional here,
                    // since mgf1SHA1's "absent parameters" form is the DEFAULT, which DER would
                    // have encoded by omitting this whole field.
                    if (mgfOid.compare("1.2.840.113549.1.1.8") != 0) {
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
        CString& outOid,
        crypto::EHashers& outHash,
        COctet& outParams
    ) {
        outParams = COctet();

        if (which == crypto::EASYM_ED25519) {
            outOid = "1.3.101.112";
            outHash = crypto::EHASH_UNKNOWN; // --> self-hashing: sign() gets the message directly
            return true;
        }

        if (which == crypto::EASYM_ED448) {
            outOid = "1.3.101.113";
            outHash = crypto::EHASH_UNKNOWN;
            return true;
        }

        if (which == crypto::EASYM_X25519) {
            return false; // --> Diffie-Hellman only; no signing capability at all.
        }

        if (rsaPss && which != crypto::EASYM_RSA) {
            return false; // --> RSASSA-PSS only makes sense for an RSA key.
        }

        crypto::EHashers useHash = (hash == crypto::EHASH_UNKNOWN) ? crypto::EHASH_SHA256 : hash;

        if (which == crypto::EASYM_RSA && rsaPss) {
            if (!buildRsaPssParams(useHash, outParams)) {
                return false; // --> e.g. useHash is MD5/SHAKE256, which PSS has no OID mapping for.
            }
            outOid = "1.2.840.113549.1.1.10"; // id-RSASSA-PSS
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
     * caller iterating _extensions directly (which would see both) could disagree about. */
    void CCert::parseExtensions(const COctet& extensionsRaw) {
        _extensions.clear();

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

            CString extnOid;
            if (!extSeq.readOidString(extnOid)) {
                continue;
            }

            bool critical = false;
            extSeq.readBoolean(critical); // OPTIONAL DEFAULT FALSE -- absent leaves it false

            COctet extnValue;
            if (!extSeq.readOctetString(extnValue)) {
                continue;
            }

            bool duplicate = false;
            for (const IExtensionPtr& existing : _extensions) {
                if (existing && existing->oid().compare(extnOid) == 0) {
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
            _extensions.push_back(std::move(ext));
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
        CString tbsSigAlgoOid;
        {
            CReader tbsSigAlgoSeq;
            if (!tbsSeq.readSequence(tbsSigAlgoSeq)) {
                return ERET_BADREQ;
            }
            if (!tbsSigAlgoSeq.readOidString(tbsSigAlgoOid)) {
                return ERET_BADREQ;
            }
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

        CReader keyAlgoSeq;
        if (!spkiSeq.readSequence(keyAlgoSeq)) {
            return ERET_BADREQ;
        }

        CString keyAlgoOid;
        if (!keyAlgoSeq.readOidString(keyAlgoOid)) {
            return ERET_BADREQ;
        }

        // parameters ANY DEFINED BY algorithm OPTIONAL
        if (!keyAlgoSeq.atEnd()) {
            CTag paramTag;
            SReadOnlyByteSpan paramContent;
            if (!keyAlgoSeq.readNextElement(paramTag, paramContent)) {
                return ERET_BADREQ;
            }
            keyAlgoParams = COctet(paramContent);
        }

        haveKeyAlgo = resolveKeyAlgo(keyAlgoOid, keyAlgoParams, keyAlgoWhich, keyAlgoName);

        SReadOnlyByteSpan pkBits;
        uint8_t pkUnusedBits = 0;
        if (!spkiSeq.readBitString(pkBits, pkUnusedBits) || pkUnusedBits != 0) {
            // --> A valid SubjectPublicKeyInfo is always byte-aligned; a nonzero unused-bit
            // count here means malformed input, not a key format this library doesn't support.
            return ERET_BADREQ;
        }
        publicKey = COctet(pkBits);

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

        CString sigAlgoOid;
        if (!sigAlgoSeq.readOidString(sigAlgoOid)) {
            return ERET_BADREQ;
        }

        // --> RFC 5280 4.1.1.2: the two copies must name the same algorithm. See the
        // tbsSigAlgoOid read above for why this is a security check and not a formality.
        if (sigAlgoOid.compare(tbsSigAlgoOid) != 0) {
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

        if (sigAlgoOid.compare("1.2.840.113549.1.1.10") == 0) {
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
        parseExtensions(extensionsRaw);

        return ERET_OK;
    }

    /* Finds the next PEM block in text at or after cursor, decoding its Base64 body into outDer. */
    bool CCert::findNextPemBlock(const CString& text, size_t& cursor, CString& outLabel, COctet& outDer) {
        static constexpr const char* BEGIN_MARKER = "-----BEGIN ";
        static constexpr const char* DASHES = "-----";
        static constexpr const char* END_PREFIX = "-----END ";

        auto beginPos = text.find(BEGIN_MARKER, cursor);
        if (beginPos < 0) {
            return false; // --> No more blocks.
        }

        size_t labelStart = static_cast<size_t>(beginPos) + std::strlen(BEGIN_MARKER);
        auto labelEnd = text.find(DASHES, labelStart);
        if (labelEnd < 0) {
            return false;
        }

        outLabel = text.subString(labelStart, static_cast<size_t>(labelEnd) - labelStart);

        auto bodyStart = text.find('\n', static_cast<size_t>(labelEnd));
        if (bodyStart < 0) {
            return false;
        }
        size_t bodyPos = static_cast<size_t>(bodyStart) + 1;

        CString endMarker(END_PREFIX);
        endMarker.append(outLabel);

        auto endPos = text.find(endMarker.toPtr(), bodyPos);
        if (endPos < 0) {
            return false;
        }

        CString body = text.subString(bodyPos, static_cast<size_t>(endPos) - bodyPos);

        auto afterEnd = text.find('\n', static_cast<size_t>(endPos));
        cursor = (afterEnd < 0) ? text.size() : static_cast<size_t>(afterEnd) + 1;

        CBuffer decoded;
        if (!CBase64::decode(decoded, body)) {
            return false;
        }

        outDer = COctet(SReadOnlyByteSpan(decoded.toPtr(), decoded.size()));
        return true;
    }

    /* Unwraps a PKCS#8 PrivateKeyInfo, reaching the algorithm-specific key blob inside. */
    bool CCert::unwrapPkcs8PrivateKey(const COctet& data, COctet& outInner) {
        CReader wrapper(data.toSpan(), EAENC_DER);
        CReader seq;
        if (!wrapper.readSequence(seq)) {
            return false;
        }

        int64_t version = 0;
        if (!seq.readInteger(version)) {
            return false;
        }

        // privateKeyAlgorithm AlgorithmIdentifier -- read past, not resolved (see this method's
        // own doc comment on why: only whether the inner blob happens to match this certificate's
        // algorithm's own wire format matters, not which OID PKCS#8 itself names).
        CReader algoSeq;
        if (!seq.readSequence(algoSeq)) {
            return false;
        }

        COctet inner;
        if (!seq.readOctetString(inner)) {
            return false;
        }

        outInner = move(inner);
        return true;
    }

    /* Unwraps one OCTET STRING TLV, giving back its content. */
    bool CCert::unwrapOctetString(const COctet& data, COctet& outContent) {
        CTag tag;
        SReadOnlyByteSpan content;
        SReadOnlyByteSpan cursor = data.toSpan();
        if (!CDecoder::readNextElement(cursor, EAENC_DER, tag, content) || tag != CTag::STRING_OCTET) {
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
                    && innerTag == CTag::STRING_BIT && !innerContent.empty() && innerContent.data[0] == 0)
                {
                    pubPoint = COctet(innerContent.slice(1));
                    havePub = true;
                }
            }
            // [0] parameters (curve OID) isn't needed here -- this certificate's own curve is
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

    /* Converts a PKCS#8-wrapped DSA private key's inner blob (a bare INTEGER x) into this
     * library's own traditional DSAPrivateKey wire format. */
    bool CCert::convertPkcs8DsaInnerToNative(const COctet& innerX, COctet& outNative) const {
        if (_keyAlgoParams.empty() || _publicKey.empty()) {
            return false;
        }

        // keyAlgoParams() is Dss-Parms { p, q, g }'s own content.
        SReadOnlyByteSpan paramsCursor = _keyAlgoParams.toSpan();
        CBigNum p, q, g;
        if (!CDer::readBigInteger(paramsCursor, p) || !CDer::readBigInteger(paramsCursor, q)
            || !CDer::readBigInteger(paramsCursor, g))
        {
            return false;
        }

        // rawPublicKey() is the complete DER INTEGER y TLV (see buildDsaPublicKeyBlob()'s own
        // comment on why), not just its bare magnitude -- unwrap it first.
        CTag yTag;
        SReadOnlyByteSpan yContent;
        SReadOnlyByteSpan yCursor = _publicKey.toSpan();
        if (!CDecoder::readNextElement(yCursor, EAENC_DER, yTag, yContent) || yTag != CTag::INTEGER) {
            return false;
        }
        CBigNum y = CBigNum::fromBigEndian(yContent);

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

    /* Tries candidate as this certificate's own private key, attempting every shape it might be
     * in until one both parses under this certificate's own algorithm and matches its public
     * key. */
    bool CCert::tryAttachPrivateKey(const COctet& candidate) {
        if (!_asym) {
            return false;
        }

        crypto::IPrivateKeyPtr pvt = _asym->createPrivateKey(candidate);

        // A traditional (non-PKCS#8) "EC PRIVATE KEY" block: standard SEC1, not this library's
        // own native EC format (see convertSec1ToNative()'s own doc comment).
        if (!pvt) {
            COctet native;
            if (convertSec1ToNative(candidate, native)) {
                pvt = _asym->createPrivateKey(native);
            }
        }

        if (!pvt) {
            COctet inner;
            if (unwrapPkcs8PrivateKey(candidate, inner)) {
                // RSA's PKCS#8 form: the inner blob is the final PKCS#1 RSAPrivateKey directly.
                pvt = _asym->createPrivateKey(inner);

                if (!pvt) {
                    // RFC 8410 (Ed25519/Ed448/X25519): the inner blob is itself a separately
                    // DER-encoded OCTET STRING wrapping the raw seed.
                    COctet seed;
                    if (unwrapOctetString(inner, seed)) {
                        pvt = _asym->createPrivateKey(seed);
                    }
                }

                if (!pvt) {
                    // EC's usual PKCS#8 form (e.g. `openssl req -newkey ec ...`): the inner blob
                    // is itself a SEC1 ECPrivateKey, not a raw scalar.
                    COctet native;
                    if (convertSec1ToNative(inner, native)) {
                        pvt = _asym->createPrivateKey(native);
                    }
                }

                if (!pvt) {
                    // DSA's usual PKCS#8 form: the inner blob is a bare INTEGER x, not the
                    // traditional {version, p, q, g, y, x} SEQUENCE.
                    COctet native;
                    if (convertPkcs8DsaInnerToNative(inner, native)) {
                        pvt = _asym->createPrivateKey(native);
                    }
                }
            }
        }

        if (!pvt) {
            return false;
        }

        return privateKey(pvt) == ERET_OK;
    }

    /* Imports the X.509 certificate from PEM-encoded raw data (a ".pem" file's contents). */
    ERetCode CCert::importPem(const COctet& data) {
        if (data.empty()) {
            return ERET_INVAL;
        }

        CString text(reinterpret_cast<const char*>(data.toPtr()), data.size());

        COctet certDer;
        bool haveCert = false;
        TArray<COctet> keyCandidates;

        size_t cursor = 0;
        CString label;
        COctet blockDer;
        while (findNextPemBlock(text, cursor, label, blockDer)) {
            if (!haveCert && label.compare("CERTIFICATE") == 0) {
                certDer = move(blockDer);
                haveCert = true;
            } else if (label.compare("CERTIFICATE") != 0) {
                keyCandidates.add(move(blockDer));
            }
        }

        if (!haveCert) {
            return ERET_BADREQ;
        }

        ERetCode rc = importDer(certDer);
        if (rc != ERET_OK) {
            return rc;
        }

        // Best-effort: the first candidate block that both parses under this certificate's own
        // algorithm and matches its public key wins (see tryAttachPrivateKey()'s own comment);
        // none of them matching just leaves privateKey() unset, same as importDer()'s own
        // unresolved-algorithm contract.
        for (const COctet& candidate : keyCandidates) {
            if (tryAttachPrivateKey(candidate)) {
                break;
            }
        }

        return ERET_OK;
    }

    /* Detects whether data is DER or PEM. */
    ECertFormat CCert::detectCertFormat(SReadOnlyByteSpan data) {
        static constexpr const char* PEM_MARKER = "-----BEGIN ";
        size_t markerLen = std::strlen(PEM_MARKER);

        size_t i = 0;
        while (i < data.size && (data.data[i] == ' ' || data.data[i] == '\t'
            || data.data[i] == '\r' || data.data[i] == '\n'))
        {
            ++i;
        }

        if (data.size - i >= markerLen && std::memcmp(data.data + i, PEM_MARKER, markerLen) == 0) {
            return ECERT_PEM;
        }

        return ECERT_DER;
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
            if (_keyAlgoIsDsa) {
                CBuffer blob;
                if (buildDsaPublicKeyBlob(_keyAlgoParams, _publicKey, blob)) {
                    _cachedPub = _asym->createPublicKey(blob.toSpan());
                }
            } else {
                _cachedPub = _asym->createPublicKey(_publicKey);
            }
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

        // --> Whether to hash first is decided by the issuer's key algorithm, never by
        // _sigHashAlgo == EHASH_UNKNOWN. That value is ambiguous: resolveSigAlgo() leaves it
        // untouched for an OID absent from SIG_ALGOS, which is indistinguishable from EdDSA's
        // legitimate "no separate hash" -- and reading it as EdDSA would hand the raw TBS bytes
        // to an ECDSA/DSA verify as though they were a digest, which truncates them to the
        // order's bit length and leaves the signature covering a prefix of the plaintext rather
        // than a hash of the message. OCSP's own verifySignature() had exactly that bug.
        crypto::EAsymmetrics keyAlgo = issuerKey->algorithm();
        if (keyAlgo == crypto::EASYM_ED25519 || keyAlgo == crypto::EASYM_ED448) {
            return ctx->verify(tbs, _signature.toSpan());
        }

        if (_sigHashAlgo == crypto::EHASH_UNKNOWN) {
            return ERET_NOTSUP;
        }

        crypto::IHasherPtr hasher = createHasher();
        if (!hasher) {
            return ERET_HASH_PIPE;
        }

        CBuffer digest;
        if (!digest.resize(hasher->byteWidth())
            || !hasher->push(tbs)
            || !hasher->finish(SByteSpan(digest.toPtr(), digest.size())))
        {
            return ERET_HASH_PIPE;
        }

        if (_sigIsRsaPss) {
            // --> verifyPss() takes a single hash algorithm and uses it for both the message
            // digest and MGF1's own mask generation, which is the only pairing RFC 8017
            // recommends and the only one any real issuer encodes. A certificate whose
            // maskGenAlgorithm genuinely names a different hash than hashAlgorithm -- or whose
            // trailerField isn't trailerFieldBC, the single value RFC 4055 defines and the only
            // one EMSA-PSS-VERIFY implements -- therefore cannot be checked here, and must fail
            // closed: verifying it with the wrong MGF1 hash would reject every valid signature,
            // which is indistinguishable from a forgery.
            if (_sigPssParams.mgfHashAlgo != _sigPssParams.hashAlgo || _sigPssParams.trailerField != 1) {
                return ERET_NOTSUP;
            }

            return ctx->verifyPss(
                digest.toSpan(), _sigHashAlgo, _sigPssParams.saltLength, _signature.toSpan()
            );
        }

        return ctx->verify(digest.toSpan(), _signature.toSpan());
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

    /* Appends one PEM block to text. */
    bool CCert::appendPemBlock(CString& text, const char* label, const COctet& der) {
        CString body;
        if (!CBase64::encode(body, der.toSpan(), true)) {
            return false;
        }

        text.append("-----BEGIN ").append(label).append("-----\n");
        text.append(body);
        text.append("-----END ").append(label).append("-----\n");
        return true;
    }

    /* Builds a standards-compliant SEC1 ECPrivateKey (RFC 5915) blob. */
    bool CCert::buildSec1PrivateKey(COctet& out) const {
        if (_privateKey.empty() || _publicKey.empty() || (_publicKey.size() % 2) == 0) {
            return false; // rawPublicKey() must be a SEC1 uncompressed point (0x04 || X || Y).
        }

        // Extract d from this library's own SEQUENCE { INTEGER 0, INTEGER d, OCTET STRING point }.
        CReader wrapper(_privateKey.toSpan(), EAENC_DER);
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

        size_t fieldLen = (_publicKey.size() - 1) / 2;

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

        if (!_keyAlgoParams.empty()) {
            // parameters [0] EXPLICIT OBJECT IDENTIFIER (namedCurve) -- this certificate's own,
            // already resolved by importDer().
            CBuffer oidTlv;
            if (!CDer::appendTlv(oidTlv, CTag::OBJ_ID, _keyAlgoParams.toSpan())
                || !CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), oidTlv.toSpan()))
            {
                return false;
            }
        }

        // publicKey [1] EXPLICIT BIT STRING (0 unused bits, content = the SEC1 uncompressed point).
        CBuffer bitStringContent;
        if (!bitStringContent.resize(1 + _publicKey.size())) {
            return false;
        }
        uint8_t* bitStringContentPtr = bitStringContent.toPtr();
        bitStringContentPtr[0] = 0x00;
        std::memcpy(bitStringContentPtr + 1, _publicKey.toPtr(), _publicKey.size());

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

    /* Builds a standards-compliant PKCS#8 PrivateKeyInfo (RFC 8410) blob. */
    bool CCert::buildPkcs8EddsaPrivateKey(COctet& out) const {
        if (_privateKey.empty()) {
            return false;
        }

        const char* oid = nullptr;
        for (const SKeyAlgo& entry : KEY_ALGOS) {
            if (_keyAlgo.compare(entry.name) == 0) {
                oid = entry.oid;
                break;
            }
        }
        if (!oid) {
            return false;
        }

        uint8_t oidContentBuf[32];
        size_t oidContentLen = 0;
        CString oidText(oid);
        if (!CEncoder::encodeOidString(TSpan<uint8_t>(oidContentBuf, sizeof(oidContentBuf)), oidText, oidContentLen)) {
            return false;
        }

        CBuffer body;
        uint8_t versionContent = 0x00;
        if (!CDer::appendTlv(body, CTag::INTEGER, SReadOnlyByteSpan(&versionContent, 1))) {
            return false;
        }

        // privateKeyAlgorithm AlgorithmIdentifier ::= SEQUENCE { OID } -- RFC 8410: no parameters.
        CBuffer algoIdContent;
        if (!CDer::appendTlv(algoIdContent, CTag::OBJ_ID, SReadOnlyByteSpan(oidContentBuf, oidContentLen))
            || !CDer::appendSequence(body, algoIdContent.toSpan()))
        {
            return false;
        }

        // privateKey OCTET STRING wrapping a separately DER-encoded CurvePrivateKey OCTET STRING
        // (RFC 8410 section 7's double-wrapping) around the raw seed.
        CBuffer innerTlv;
        if (!CDer::appendTlv(innerTlv, CTag::STRING_OCTET, _privateKey.toSpan())
            || !CDer::appendTlv(body, CTag::STRING_OCTET, innerTlv.toSpan()))
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

    /* Exports the certificate in PEM format, wrapping exportDer()'s own raw bytes as a
     * CERTIFICATE block. includePrivateKey additionally appends privateKey() as a genuinely
     * standard, interoperable block for every algorithm this library implements: "RSA PRIVATE
     * KEY" (PKCS#1, rawPrivateKey()'s own wire format directly) and "DSA PRIVATE KEY" (OpenSSL's
     * traditional format, likewise direct) need no conversion; "EC PRIVATE KEY" is built by
     * buildSec1PrivateKey() (SEC1/RFC 5915, since rawPrivateKey()'s own EC format isn't SEC1 --
     * see its doc comment) and "PRIVATE KEY" for Ed25519/Ed448/X25519 by
     * buildPkcs8EddsaPrivateKey() (PKCS#8/RFC 8410, since those algorithms have no traditional
     * PEM format of their own). If a certificate's algorithm can't be resolved to any of these
     * (this library doesn't implement it, or building the standard blob otherwise fails), the key
     * block is simply left out rather than writing out something non-standard. */
    ERetCode CCert::exportPem(COctet& output, bool includePrivateKey) const {
        COctet der;
        ERetCode rc = exportDer(der);
        if (rc != ERET_OK) {
            return rc;
        }

        CString text;
        if (!appendPemBlock(text, "CERTIFICATE", der)) {
            return ERET_NOMEM;
        }

        if (includePrivateKey && !_privateKey.empty()) {
            COctet keyDer;
            const char* label = nullptr;

            if (_keyAlgo.compare("RSA") == 0) {
                keyDer = _privateKey;
                label = "RSA PRIVATE KEY";
            } else if (_keyAlgo.compare("DSA") == 0) {
                keyDer = _privateKey;
                label = "DSA PRIVATE KEY";
            } else if (_keyAlgo.compare("EC") == 0 && buildSec1PrivateKey(keyDer)) {
                label = "EC PRIVATE KEY";
            } else if (buildPkcs8EddsaPrivateKey(keyDer)) {
                label = "PRIVATE KEY";
            }

            if (label && !appendPemBlock(text, label, keyDer)) {
                return ERET_NOMEM;
            }
        }

        output = COctet(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text.toPtr()), text.size()));
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

        // --- subjectPublicKeyInfo: resolve subjectKey's algorithm and, for DSA, split its
        // createPublicKey()-shaped serialize() back into X.509's split SPKI representation. ---
        crypto::EAsymmetrics subjWhich = subjectKey->algorithm();

        CString keyOid, ecCurveOid;
        bool keyIsDsa = false, keyIsEc = false;
        if (!CCert::resolveKeyAlgoForBuild(subjWhich, keyOid, keyIsDsa, keyIsEc, ecCurveOid)) {
            return ERET_NOTSUP; // --> subjectKey's algorithm has no SPKI OID this library knows.
        }

        COctet subjectKeyRaw;
        if (subjectKey->serialize(subjectKeyRaw) != ERET_OK) {
            return ERET_KEY_ERROR;
        }

        COctet spkiParams, spkiPublicKey;
        if (keyIsDsa) {
            if (!CCert::splitDsaPublicKeyBlob(subjectKeyRaw, spkiParams, spkiPublicKey)) {
                return ERET_KEY_FORMAT;
            }
        } else {
            spkiPublicKey = subjectKeyRaw;
        }

        // --- signature: resolve issuerKeyPair's algorithm + digestAlgo/rsaPss to a signature
        // OID + digest + AlgorithmIdentifier parameters. ---
        crypto::EAsymmetrics issuerWhich = issuerKeyPair.privateKey->algorithm();

        CString sigOid;
        crypto::EHashers sigHash = crypto::EHASH_UNKNOWN;
        COctet sigAlgoParams;
        if (!CCert::resolveSigAlgoForSigning(issuerWhich, digestAlgo, rsaPss, sigOid, sigHash, sigAlgoParams)) {
            return ERET_NOTSUP; // --> e.g. issuerKeyPair is X25519, or digestAlgo has no OID for it.
        }

        bool sigIsEddsa = (sigHash == crypto::EHASH_UNKNOWN);

        // AlgorithmIdentifier ::= SEQUENCE { OID, parameters ANY OPTIONAL } -- built once, since
        // TBSCertificate.signature and Certificate.signatureAlgorithm must be byte-identical.
        CBuffer sigAlgoIdTlv;
        {
            size_t needed = CEncoder::encodedOidStringSize(sigOid);
            if (!needed) {
                return ERET_UNKNOWN;
            }

            CBuffer oidContent;
            size_t written = 0;
            if (!oidContent.resize(needed) || !CEncoder::encodeOidString(oidContent.toSpan(), sigOid, written)) {
                return ERET_UNKNOWN;
            }

            CBuffer body;
            if (!CDer::appendTlv(body, CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), written))) {
                return ERET_UNKNOWN;
            }

            if (!sigAlgoParams.empty() && !CDer::appendRaw(body, sigAlgoParams.toSpan())) {
                return ERET_UNKNOWN;
            }
            // DSA/ECDSA/EdDSA signature AlgorithmIdentifiers carry no parameters at all.

            if (!CDer::appendSequence(sigAlgoIdTlv, body.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        // subjectPublicKeyInfo.algorithm AlgorithmIdentifier.
        CBuffer keyAlgoIdTlv;
        {
            size_t needed = CEncoder::encodedOidStringSize(keyOid);
            if (!needed) {
                return ERET_UNKNOWN;
            }

            CBuffer oidContent;
            size_t written = 0;
            if (!oidContent.resize(needed) || !CEncoder::encodeOidString(oidContent.toSpan(), keyOid, written)) {
                return ERET_UNKNOWN;
            }

            CBuffer body;
            if (!CDer::appendTlv(body, CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), written))) {
                return ERET_UNKNOWN;
            }

            if (keyIsEc) {
                size_t curveNeeded = CEncoder::encodedOidStringSize(ecCurveOid);
                CBuffer curveOidContent;
                size_t curveWritten = 0;
                if (!curveNeeded || !curveOidContent.resize(curveNeeded)
                    || !CEncoder::encodeOidString(curveOidContent.toSpan(), ecCurveOid, curveWritten))
                {
                    return ERET_UNKNOWN;
                }

                if (!CDer::appendTlv(body, CTag::OBJ_ID, SReadOnlyByteSpan(curveOidContent.toPtr(), curveWritten))) {
                    return ERET_UNKNOWN;
                }
            } else if (keyIsDsa) {
                if (!CDer::appendSequence(body, spkiParams.toSpan())) {
                    return ERET_UNKNOWN;
                }
            } else if (subjWhich == crypto::EASYM_RSA) {
                if (!CDer::appendTlv(body, CTag::NULL_, SReadOnlyByteSpan())) {
                    return ERET_UNKNOWN;
                }
            }
            // Ed25519/Ed448/X25519 carry no parameters at all (RFC 8410).

            if (!CDer::appendSequence(keyAlgoIdTlv, body.toSpan())) {
                return ERET_UNKNOWN;
            }
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
            CBuffer body;
            if (!CDer::appendRaw(body, keyAlgoIdTlv.toSpan())) {
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
                || !CDer::appendSequence(tbsBody, body.toSpan()))
            {
                return ERET_UNKNOWN;
            }
        }

        // extensions [3] EXPLICIT Extensions OPTIONAL (SEQUENCE OF Extension) -- omitted
        // entirely when empty, rather than encoded as an empty SEQUENCE.
        if (!extensions.empty()) {
            CBuffer extList;

            for (const IExtensionPtr& ext : extensions) {
                if (!ext) {
                    return ERET_INVAL;
                }

                CBuffer extnValue;
                if (!ext->encode(extnValue)) {
                    return ERET_UNKNOWN;
                }

                size_t needed = CEncoder::encodedOidStringSize(ext->oid());
                if (!needed) {
                    return ERET_UNKNOWN;
                }

                CBuffer oidContent;
                size_t written = 0;
                if (!oidContent.resize(needed) || !CEncoder::encodeOidString(oidContent.toSpan(), ext->oid(), written)) {
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

            CBuffer extListSeq;
            if (!CDer::appendSequence(extListSeq, extList.toSpan())
                || !CDer::appendTlv(tbsBody, CTag(EATAG_CONTEXT_SPECIFIC, 3, true), extListSeq.toSpan()))
            {
                return ERET_UNKNOWN;
            }
        }

        CBuffer tbsFull;
        if (!CDer::appendSequence(tbsFull, tbsBody.toSpan())) {
            return ERET_UNKNOWN;
        }

        // --- Sign the TBSCertificate: a digest for a hash-then-sign family, or the raw
        // TBSCertificate bytes directly for the self-hashing EdDSA schemes. ---
        crypto::IAsymmetricPtr issuerAsym = crypto::IAsymmetric::builtIn(issuerWhich);
        crypto::IAsymmetricContextPtr ctx = issuerAsym ? issuerAsym->createContext() : nullptr;
        if (!ctx) {
            return ERET_UNKNOWN;
        }

        ctx->keyPair(issuerKeyPair);

        COctet toSign;
        if (sigIsEddsa) {
            toSign = COctet(tbsFull.toSpan());
        } else {
            crypto::IHasherPtr hasher;
            if (crypto::IHasher::create(sigHash, hasher) != ERET_OK || !hasher) {
                return ERET_HASH_PIPE;
            }

            CBuffer digest;
            if (!digest.resize(hasher->byteWidth())
                || !hasher->push(tbsFull.toSpan())
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
        ERetCode signRc = (issuerWhich == crypto::EASYM_RSA && rsaPss)
            ? ctx->signPss(toSign.toSpan(), sigHash, toSign.size(), sigOut)
            : ctx->sign(toSign.toSpan(), sigOut);
        if (signRc != ERET_OK) {
            return signRc;
        }

        // --- Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }. ---
        CBuffer certBody;
        if (!CDer::appendRaw(certBody, tbsFull.toSpan()) || !CDer::appendRaw(certBody, sigAlgoIdTlv.toSpan())) {
            return ERET_UNKNOWN;
        }

        {
            CBuffer bitContent;
            size_t written = 0;
            if (!bitContent.resize(1 + sigOut.size)
                || !CEncoder::encodeBitString(bitContent.toSpan(), SReadOnlyByteSpan(sigOut.data, sigOut.size), 0, written))
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

} // namespace x509
} // namespace certpp
