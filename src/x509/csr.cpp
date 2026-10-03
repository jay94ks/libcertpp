#include <certpp/x509/csr.hpp>
#include <certpp/x509/chain/pem.hpp>
#include <certpp/asn1/reader.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/der.hpp>
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

    /* Reads the `attributes [0] IMPLICIT Attributes` field -- see its own doc comment in
     * csr.hpp. */
    bool CCertRequest::parseAttributes(
        CReader& attrs,
        TArray<SCertRequestAttribute>& outAttributes,
        std::vector<IExtensionPtr>& outExtensions
    ) {
        outAttributes.clear();
        outExtensions.clear();

        while (!attrs.atEnd()) {
            CReader attrSeq;
            if (!attrs.readSequence(attrSeq)) {
                return false;
            }

            CString attrOid;
            if (!attrSeq.readOidString(attrOid)) {
                return false;
            }

            // values SET OF ANY -- kept as the SET's own content octets, not unwrapped further
            // (see SCertRequestAttribute::values' own comment on why).
            CReader values;
            if (!attrSeq.readSet(values) || !attrSeq.atEnd()) {
                return false;
            }

            COctet valuesContent(values.remaining());

            // --> A repeated attribute type is rejected rather than kept twice: attributeOf()
            // answers with the first match while a caller walking attributes() sees both, and
            // two different answers to "what does this request ask for" is exactly the shape of
            // bug that lets a second extensionRequest smuggle past a policy check made against
            // the first. RFC 2986 gives no meaning to a repeat either.
            for (const SCertRequestAttribute& existing : outAttributes) {
                if (existing.oid.compare(attrOid) == 0) {
                    return false;
                }
            }

            bool isExtensionRequest = (attrOid.compare(OID_EXTENSION_REQUEST) == 0);

            if (!outAttributes.add(SCertRequestAttribute(attrOid, valuesContent))) {
                return false;
            }

            if (isExtensionRequest) {
                // extensionRequest's single value IS an Extensions SEQUENCE (RFC 2985 5.4.2),
                // which is the very shape CCert::parseExtensions() already walks for a
                // certificate's own [3] field -- so a requested SubjectAlternativeName comes
                // back as the same CSanExtension a certificate's would, rather than as a second
                // parallel decoding of the same bytes.
                //
                // Not best-effort, unlike parseExtensions() itself: a malformed Extensions value
                // here would leave extensions() silently empty, and "the request asked for
                // nothing" is a dangerously wrong answer to hand a CA. The SET must hold exactly
                // one value for the same reason.
                CReader valueReader(valuesContent.toSpan(), EAENC_DER);
                CTag valueTag;
                SReadOnlyByteSpan valueContent;
                if (!valueReader.readNextElement(valueTag, valueContent)
                    || valueTag != CTag::SEQ || !valueReader.atEnd())
                {
                    return false;
                }

                CCert::parseExtensions(valuesContent, outExtensions);
                if (outExtensions.empty()) {
                    return false; // --> an Extensions SEQUENCE that decoded to nothing usable.
                }
            }
        }

        return true;
    }

    /* Imports the certification request from DER-encoded raw data, verifying its
     * self-signature before reporting success. */
    ERetCode CCertRequest::importDer(const COctet& data) {
        reset();

        if (data.empty()) {
            return ERET_INVAL;
        }

        // --> Parsed into locals first and only committed at the end, the same shape
        // CCert::importDer() uses, so a failure partway through never leaves a half-populated
        // request behind.
        CDistinguishedName subject;
        CString signAlgoName;
        crypto::EHashers sigAlgoHash = crypto::EHASH_UNKNOWN;
        CCert::SSpkiFields spki;
        TArray<SCertRequestAttribute> attributes;
        std::vector<IExtensionPtr> extensions;

        CReader outer(data.toSpan(), EAENC_DER);
        CReader reqSeq;
        if (!outer.readSequence(reqSeq)) {
            return ERET_BADREQ;
        }

        // --> The CertificationRequest SEQUENCE must be the whole input, for the same reason
        // CCert::importDer() requires it: rawData()/exportDer() hand back whatever was passed
        // in, so accepting a trailing suffix would re-emit non-DER bytes to the next consumer
        // and give one request unlimited distinct encodings.
        if (!outer.atEnd()) {
            return ERET_BADREQ;
        }

        CReader criSeq;
        if (!reqSeq.readSequence(criSeq)) {
            return ERET_BADREQ;
        }

        // version INTEGER { v1(0) } -- not OPTIONAL and not DEFAULTed, unlike
        // TBSCertificate.version, and v1 is the only value RFC 2986 defines.
        int64_t version = 0;
        if (!criSeq.readInteger(version) || version != 0) {
            return ERET_BADREQ;
        }

        // subject Name -- legitimately empty for a request that carries all of its identity in a
        // requested SubjectAlternativeName, so emptiness isn't checked here.
        if (!criSeq.readDistinguishedName(subject)) {
            return ERET_BADREQ;
        }

        // subjectPKInfo SubjectPublicKeyInfo
        {
            CReader spkiSeq;
            if (!criSeq.readSequence(spkiSeq) || !CCert::decodeSubjectPublicKeyInfo(spkiSeq, spki)) {
                return ERET_BADREQ;
            }
        }

        // attributes [0] IMPLICIT Attributes -- *not* OPTIONAL (RFC 2986 4.1), so a request that
        // omits the field entirely is malformed even with nothing to put in it; the empty case is
        // a present-but-empty SET. An IMPLICIT tag over a SET is always constructed, which
        // readConstructed() already requires.
        if (criSeq.atEnd()) {
            return ERET_BADREQ;
        }

        {
            CTag attrsTag;
            CReader attrs;
            if (!criSeq.readConstructed(attrsTag, attrs)
                || attrsTag.tagClass() != EATAG_CONTEXT_SPECIFIC || attrsTag.value() != 0)
            {
                return ERET_BADREQ;
            }

            if (!parseAttributes(attrs, attributes, extensions)) {
                return ERET_BADREQ;
            }
        }

        if (!criSeq.atEnd()) {
            return ERET_BADREQ; // --> CertificationRequestInfo has exactly these four fields.
        }

        // signatureAlgorithm AlgorithmIdentifier -- only one copy here, unlike a Certificate's
        // two, so there is no inner/outer agreement to check.
        CReader sigAlgoSeq;
        if (!reqSeq.readSequence(sigAlgoSeq)) {
            return ERET_BADREQ;
        }

        CString sigAlgoOid;
        if (!sigAlgoSeq.readOidString(sigAlgoOid)) {
            return ERET_BADREQ;
        }

        CCert::resolveSigAlgo(sigAlgoOid, sigAlgoHash, signAlgoName);

        // parameters ANY DEFINED BY algorithm OPTIONAL -- only id-RSASSA-PSS's carry anything a
        // verifier needs, exactly as in CCert::importDer(); the difference is that parameters
        // that don't parse are fatal here rather than best-effort, since this class refuses to
        // report success without a verified signature and an RSASSA-PSS whose parameters are
        // unreadable can never be verified.
        bool sigIsRsaPss = false;
        SRsaPssParams sigPssParams;

        if (sigAlgoOid.compare("1.2.840.113549.1.1.10") == 0) {
            CReader pssParams;

            if (sigAlgoSeq.atEnd()) {
                // --> No parameters field at all: RFC 4055 3.3 requires one, but an empty
                // RSASSA-PSS-params SEQUENCE (all four fields defaulted) is legal and means
                // exactly what sigPssParams already holds, so the two are treated alike.
                sigIsRsaPss = true;
            }
            else if (sigAlgoSeq.readSequence(pssParams)
                && CCert::parseRsaPssParams(pssParams, sigPssParams)
                && sigAlgoSeq.atEnd())
            {
                sigIsRsaPss = true;
            }

            if (!sigIsRsaPss) {
                return ERET_BADREQ;
            }

            sigAlgoHash = sigPssParams.hashAlgo;
        }

        // signature BIT STRING
        SReadOnlyByteSpan sigBits;
        uint8_t sigUnusedBits = 0;
        // --> A signature is a whole number of octets, so its BIT STRING carries no unused bits;
        // allowing any would give every signature up to eight encodings of the same bits.
        if (!reqSeq.readBitString(sigBits, sigUnusedBits) || sigUnusedBits != 0) {
            return ERET_BADREQ;
        }

        if (!reqSeq.atEnd()) {
            return ERET_BADREQ; // --> CertificationRequest has exactly these three fields.
        }

        crypto::IAsymmetricPtr asym;
        if (spki.resolved) {
            asym = crypto::IAsymmetric::builtIn(spki.which);
        }

        _rawData = data;
        _version = uint32_t(version);
        _subject = move(subject);
        _subject.toString(_subjectStr);
        _keyAlgo = move(spki.algoName);
        _keyAlgoParams = move(spki.algoParams);
        _publicKey = move(spki.publicKey);
        _keyAlgoIsDsa = spki.resolved && spki.which == crypto::EASYM_DSA;
        _signAlgo = move(signAlgoName);
        _sigHashAlgo = sigAlgoHash;
        _signature = COctet(sigBits);
        _sigIsRsaPss = sigIsRsaPss;
        _sigPssParams = sigPssParams;
        _asym = move(asym);
        _cachedPub.reset(); // --> Rebuilt lazily by publicKey() on first call.
        _attributes = move(attributes);
        _extensions = move(extensions);

        // --> The whole point of the exercise. A CSR's content is an unauthenticated claim right
        // up until this passes, so reporting ERET_OK without it would hand a caller a "parsed"
        // request that proves nothing -- and callers do not re-check what a successful import
        // appears to have already validated. State is committed first only because verify()
        // reads it; a failure wipes it straight back out.
        ERetCode verifyRc = verify();
        if (verifyRc != ERET_OK) {
            reset();
            return verifyRc;
        }

        return ERET_OK;
    }

    /* Imports the certification request from PEM-encoded raw data. */
    ERetCode CCertRequest::importPem(const COctet& data) {
        if (data.empty()) {
            return ERET_INVAL;
        }

        CString text(reinterpret_cast<const char*>(data.toPtr()), data.size());

        size_t cursor = 0;
        CString label;
        COctet blockDer;
        // --> PEM framing lives on CPemChainFormat, which owns all of it; a request is the same
        // envelope around different DER. A block that is present but unusable (malformed, or
        // password-encrypted) ends the scan with its own code rather than being skipped over.
        ERetCode scan = ERET_OK;
        while ((scan = CPemChainFormat::nextBlock(text, cursor, label, blockDer)) == ERET_OK) {
            // "CERTIFICATE REQUEST" is RFC 7468 7's own label; "NEW CERTIFICATE REQUEST" is the
            // older Netscape-era spelling that several tools (and Windows' certreq) still emit
            // for exactly the same DER.
            if (label.compare("CERTIFICATE REQUEST") == 0 || label.compare("NEW CERTIFICATE REQUEST") == 0) {
                return importDer(blockDer);
            }
        }

        // ERET_NOTFOUND means the file held no CERTIFICATE REQUEST block at all, which from this
        // entry point's perspective is the same bad input as a file that held nothing usable.
        return (scan == ERET_NOTFOUND) ? ERET_BADREQ : scan;
    }

    /* Imports the certification request from raw data in the specified format. */
    ERetCode CCertRequest::importFrom(const SReadOnlyByteSpan& data, ECertFormat format) {
        if (format == ECERT_AUTO) {
            format = CCert::detectCertFormat(data);
        }

        if (format == ECERT_DER) {
            return importDer(COctet(data));
        }

        if (format == ECERT_PEM) {
            return importPem(COctet(data));
        }

        return ERET_NOTIMPL;
    }

    /* Resets this certification request to an empty state. */
    void CCertRequest::reset() {
        _rawData.clear();
        _version = 0;
        _subject = CDistinguishedName();
        _subjectStr.clear();
        _keyAlgo.clear();
        _keyAlgoParams.clear();
        _publicKey.clear();
        _keyAlgoIsDsa = false;
        _signAlgo.clear();
        _sigHashAlgo = crypto::EHASH_UNKNOWN;
        _signature.clear();
        _sigIsRsaPss = false;
        _sigPssParams = SRsaPssParams();
        _asym.reset();
        _cachedPub.reset();
        _extensions.clear();
        _attributes.clear();
    }

    /* Lazily builds and caches the requested public key, via the same CCert::makePublicKey()
     * CCert::publicKey() itself goes through -- so DSA's split SubjectPublicKeyInfo
     * representation is reassembled identically in both. */
    crypto::IPublicKeyPtr CCertRequest::publicKey() const {
        if (!_cachedPub && _asym) {
            _cachedPub = CCert::makePublicKey(_asym, _keyAlgoIsDsa, _keyAlgoParams, _publicKey);
        }

        return _cachedPub;
    }

    /* Returns the CertificationRequestInfo's complete TLV, the bytes the signature covers. */
    SReadOnlyByteSpan CCertRequest::certificationRequestInfo() const {
        if (_rawData.empty()) {
            return SReadOnlyByteSpan(nullptr, 0);
        }

        // --> CertificationRequest ::= SEQUENCE { certificationRequestInfo, signatureAlgorithm,
        // signature }. What gets signed is the first element's whole TLV, header included, so
        // the length comes from readEncodedValue()'s own bytesRead rather than from pointer
        // arithmetic over the content span -- see CCert::tbsCertificate()'s own comment on why
        // that distinction matters. Re-walked from _rawData on demand, the same way.
        SReadOnlyByteSpan outer = _rawData.toSpan();

        CTag tag;
        SReadOnlyByteSpan outerContent;
        size_t outerRead = 0;
        if (!CDecoder::readEncodedValue(outer, EAENC_DER, tag, outerContent, outerRead)
            || tag != CTag::SEQ || outerContent.empty())
        {
            return SReadOnlyByteSpan(nullptr, 0);
        }

        SReadOnlyByteSpan criContent;
        size_t criRead = 0;
        if (!CDecoder::readEncodedValue(outerContent, EAENC_DER, tag, criContent, criRead)
            || tag != CTag::SEQ)
        {
            return SReadOnlyByteSpan(nullptr, 0);
        }

        return SReadOnlyByteSpan(outerContent.data, criRead);
    }

    /* Verifies this request's self-signature against the very public key it carries. */
    ERetCode CCertRequest::verify() const {
        if (empty() || _signature.empty()) {
            return ERET_INVAL;
        }

        SReadOnlyByteSpan cri = certificationRequestInfo();
        if (cri.empty()) {
            return ERET_INVAL;
        }

        crypto::IPublicKeyPtr pub = publicKey();
        if (!pub) {
            return ERET_KEY_EMPTY;
        }

        crypto::IAsymmetricContextPtr ctx = _asym ? _asym->createContext() : nullptr;
        if (!ctx) {
            return ERET_NOTSUP;
        }

        // --> No private key: a verify-only context, bound to the one key the request carries.
        crypto::IPrivateKeyPtr noPrivateKey;
        ctx->keyPair(pub, noPrivateKey);

        return CCert::verifySignedBlob(
            ctx, pub->algorithm(), cri, _signature.toSpan(),
            _sigHashAlgo, _sigIsRsaPss, _sigPssParams
        );
    }

    /* Looks up one attribute's raw values content by its type OID. */
    ERetCode CCertRequest::attributeOf(const char* oid, COctet& out) const {
        if (!oid) {
            return ERET_INVAL;
        }

        for (const SCertRequestAttribute& attr : _attributes) {
            if (attr.oid.compare(oid) == 0) {
                out = attr.values;
                return ERET_OK;
            }
        }

        return ERET_INVAL;
    }

    /* Looks up one requested extension by its OID, from the extensionRequest attribute
     * importDer() decoded. */
    ERetCode CCertRequest::extensionOf(const char* oid, IExtensionPtr& out) const {
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
    ERetCode CCertRequest::extensionOf(const wchar_t* oid, IExtensionPtr& out) const {
        if (!oid) {
            return ERET_INVAL;
        }

        CString narrowOid = CWideString(oid).convertTo<char>();
        return extensionOf(narrowOid.toPtr(), out);
    }

    /* Two requests are equal iff they're byte-identical DER encodings. */
    bool CCertRequest::equals(const CCertRequest& other) const {
        return _rawData.toSpan().sequencialEqual(other._rawData.toSpan());
    }

    /* Exports the request in DER format -- the exact raw bytes imported or built. */
    ERetCode CCertRequest::exportDer(COctet& output) const {
        if (empty()) {
            return ERET_INVAL;
        }

        output = _rawData;
        return ERET_OK;
    }

    /* Exports the request as a PEM "CERTIFICATE REQUEST" block. */
    ERetCode CCertRequest::exportPem(COctet& output) const {
        COctet der;
        ERetCode rc = exportDer(der);
        if (rc != ERET_OK) {
            return rc;
        }

        CString text;
        if (!CPemChainFormat::appendBlock(text, "CERTIFICATE REQUEST", der)) {
            return ERET_NOMEM;
        }

        output = COctet(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(text.toPtr()), text.size()));
        return ERET_OK;
    }

    /* Exports the request in the specified format. */
    ERetCode CCertRequest::exportAs(COctet& output, ECertFormat format) const {
        if (format == ECERT_DER) {
            return exportDer(output);
        }

        if (format == ECERT_PEM) {
            return exportPem(output);
        }

        return ERET_NOTSUP; // --> ECERT_AUTO isn't a meaningful export format.
    }

    /* X.690 11.6: the elements of a DER SET OF appear in ascending order of their own complete
     * encodings, compared as octet strings -- so where one is a prefix of the other, the shorter
     * sorts first. Used to order a certification request's Attributes, which are a SET OF and
     * not a SEQUENCE OF. */
    static bool attributeEncodingLess(const COctet& left, const COctet& right) {
        size_t common = (left.size() < right.size()) ? left.size() : right.size();
        if (common) {
            int cmp = std::memcmp(left.toPtr(), right.toPtr(), common);
            if (cmp != 0) {
                return cmp < 0;
            }
        }

        return left.size() < right.size();
    }

    /* Builds and self-signs a certification request from this builder's fields, handing the
     * result to CCertRequest::importDer() -- which verifies the signature it just produced, so
     * `out` is populated exactly the way an externally-produced request would be. */
    ERetCode CCertRequestBuilder::build(CCertRequest& out) const {
        out = CCertRequest();

        if (subject.empty() || subjectKeyPair.empty()) {
            return ERET_INVAL;
        }

        // --> The two halves must genuinely be one pair. Without this a caller could hand over
        // someone else's public key with their own private key and get a request that asks the
        // CA to certify a key nobody in the exchange can prove possession of -- which is the
        // single thing a CSR exists to rule out, and which no amount of valid signing would
        // catch, since the signature would verify against the *private* key's own public half
        // rather than the one embedded in subjectPKInfo.
        {
            crypto::IPublicKeyPtr derived = subjectKeyPair.privateKey->publicKey();
            if (!derived || derived->compare(subjectKeyPair.publicKey) != 0) {
                return ERET_KEY_ERROR;
            }
        }

        crypto::EAsymmetrics which = subjectKeyPair.privateKey->algorithm();

        CString sigOid;
        crypto::EHashers sigHash = crypto::EHASH_UNKNOWN;
        COctet sigAlgoParams;
        if (!CCert::resolveSigAlgoForSigning(which, digestAlgo, rsaPss, sigOid, sigHash, sigAlgoParams)) {
            return ERET_NOTSUP; // --> e.g. an X25519 key, or digestAlgo has no OID for its family.
        }

        // --- Assemble CertificationRequestInfo. ---
        CBuffer criBody;

        // version INTEGER { v1(0) } -- the only version RFC 2986 defines, and not DEFAULTed, so
        // it is always written out.
        static constexpr uint8_t VERSION_V1_CONTENT[] = { 0x00 };
        if (!CDer::appendTlv(criBody, CTag::INTEGER, SReadOnlyByteSpan(VERSION_V1_CONTENT, sizeof(VERSION_V1_CONTENT)))) {
            return ERET_UNKNOWN;
        }

        // subject Name.
        if (!CCert::encodeName(subject, criBody)) {
            return ERET_UNKNOWN;
        }

        // subjectPKInfo SubjectPublicKeyInfo -- byte-for-byte the same encoder a certificate's
        // own SPKI goes through.
        {
            ERetCode rc = CCert::encodeSubjectPublicKeyInfo(subjectKeyPair.publicKey, criBody);
            if (rc != ERET_OK) {
                return rc;
            }
        }

        // --- attributes [0] IMPLICIT Attributes (a SET OF Attribute). ---
        //
        // Encoded unconditionally, even with nothing to put in it: the field is not OPTIONAL
        // (RFC 2986 4.1), so a request without attributes carries a present-but-empty SET
        // ("A0 00") rather than nothing at all. Omitting it produces a request that several
        // strict parsers -- including this library's own importDer() -- reject outright, and
        // that other tools accept while quietly covering different bytes with the signature.
        {
            TArray<COctet> attrTlvs;

            auto appendAttribute = [&attrTlvs](const CString& oid, SReadOnlyByteSpan valuesContent) -> bool {
                size_t needed = CEncoder::encodedOidStringSize(oid);
                if (!needed) {
                    return false;
                }

                CBuffer oidContent;
                size_t written = 0;
                if (!oidContent.resize(needed) || !CEncoder::encodeOidString(oidContent.toSpan(), oid, written)) {
                    return false;
                }

                // Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET OF ANY }
                CBuffer attrBody;
                if (!CDer::appendTlv(attrBody, CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), written))
                    || !CDer::appendTlv(attrBody, CTag::SET_OF, valuesContent))
                {
                    return false;
                }

                CBuffer attrTlv;
                if (!CDer::appendSequence(attrTlv, attrBody.toSpan())) {
                    return false;
                }

                return attrTlvs.add(COctet(attrTlv.toSpan()));
            };

            if (!extensions.empty()) {
                for (const SCertRequestAttribute& attr : attributes) {
                    if (attr.oid.compare(CCertRequest::OID_EXTENSION_REQUEST) == 0) {
                        // --> Two extensionRequest attributes would be two different answers to
                        // "what is being asked for", and importDer() rejects the repeat anyway.
                        return ERET_INVAL;
                    }
                }

                CBuffer extListSeq;
                ERetCode rc = CCert::encodeExtensions(extensions, extListSeq);
                if (rc != ERET_OK) {
                    return rc;
                }

                // extensionRequest's values SET holds exactly one element: the whole Extensions
                // SEQUENCE (RFC 2985 5.4.2).
                if (!appendAttribute(CString(CCertRequest::OID_EXTENSION_REQUEST), extListSeq.toSpan())) {
                    return ERET_UNKNOWN;
                }
            }

            for (const SCertRequestAttribute& attr : attributes) {
                if (!appendAttribute(attr.oid, attr.values.toSpan())) {
                    return ERET_INVAL; // --> e.g. an OID string that isn't dotted-decimal.
                }
            }

            // DER orders a SET OF by its elements' own encodings (X.690 11.6). An insertion sort
            // over what is realistically a handful of attributes; a build that skipped this
            // would still round-trip through this library (nothing here re-checks SET ordering)
            // and still be non-DER on the wire.
            for (size_t i = 1; i < attrTlvs.size(); ++i) {
                COctet key = attrTlvs[i];
                size_t j = i;
                while (j > 0 && attributeEncodingLess(key, attrTlvs[j - 1])) {
                    attrTlvs[j] = attrTlvs[j - 1];
                    --j;
                }
                attrTlvs[j] = move(key);
            }

            CBuffer attrsContent;
            for (const COctet& attrTlv : attrTlvs) {
                if (!CDer::appendRaw(attrsContent, attrTlv.toSpan())) {
                    return ERET_UNKNOWN;
                }
            }

            if (!CDer::appendTlv(criBody, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), attrsContent.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        CBuffer criFull;
        if (!CDer::appendSequence(criFull, criBody.toSpan())) {
            return ERET_UNKNOWN;
        }

        // --- Self-sign the CertificationRequestInfo, proving possession of the requested key. ---
        COctet signature;
        {
            ERetCode rc = CCert::signTbs(subjectKeyPair, criFull.toSpan(), sigHash, rsaPss, signature);
            if (rc != ERET_OK) {
                return rc;
            }
        }

        // --- CertificationRequest ::= SEQUENCE { certificationRequestInfo, signatureAlgorithm,
        // signature }. ---
        CBuffer reqBody;
        if (!CDer::appendRaw(reqBody, criFull.toSpan())
            || !CCert::encodeAlgorithmIdentifier(sigOid, sigAlgoParams, reqBody))
        {
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

            if (!CDer::appendTlv(reqBody, CTag::STRING_BIT, SReadOnlyByteSpan(bitContent.toPtr(), written))) {
                return ERET_UNKNOWN;
            }
        }

        CBuffer reqFull;
        if (!CDer::appendSequence(reqFull, reqBody.toSpan())) {
            return ERET_UNKNOWN;
        }

        return out.importDer(COctet(reqFull.toSpan()));
    }

} // namespace x509
} // namespace certpp
