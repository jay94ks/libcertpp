#include <certpp/x509/crl.hpp>
#include <certpp/asn1/reader.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/io/buffer.hpp>
#include "crlreason.hpp"

namespace certpp {
namespace x509 {

    using asn1::CReader;
    using asn1::CDecoder;
    using asn1::CEncoder;
    using asn1::CDer;
    using asn1::CTag;
    using asn1::EAENC_DER;
    using asn1::EATAG_CONTEXT_SPECIFIC;

    /* Parses rawData as one complete "revokedCertificates" entry TLV (SEQUENCE { userCertificate
     * CertificateSerialNumber, revocationDate Time, crlEntryExtensions Extensions OPTIONAL }),
     * the same "whole TLV in, whole object out" contract CCert::importDer() follows. Only the
     * reasonCode (id-ce-cRLReason) crlEntryExtensions entry is interpreted; any other extension
     * present is silently skipped. */
    ERetCode CCrlRevokationInfo::decode(const COctet& rawData, CCrlRevokationInfo& info) {
        if (rawData.empty()) {
            return ERET_INVAL;
        }

        CReader outer(rawData.toSpan(), EAENC_DER);
        CReader entrySeq;
        if (!outer.readSequence(entrySeq)) {
            return ERET_BADREQ;
        }

        // userCertificate CertificateSerialNumber (INTEGER) -- kept as its raw two's-complement
        // big-endian content, the same raw content bytes CCert::serialNumber() itself stores.
        CTag tag;
        SReadOnlyByteSpan content;
        if (!entrySeq.readNextElement(tag, content) || tag != CTag::INTEGER) {
            return ERET_BADREQ;
        }
        COctet serialNumber(content);

        // revocationDate Time
        SDateTime timestamp;
        if (!CCert::readTime(entrySeq, timestamp)) {
            return ERET_BADREQ;
        }

        // crlEntryExtensions Extensions OPTIONAL (SEQUENCE OF Extension -- unlike
        // TBSCertificate's own extensions, this isn't wrapped in a further [n] EXPLICIT tag).
        ECrlReasons reason = ECRLR_NONE;
        if (!entrySeq.atEnd()) {
            CReader extList;
            if (entrySeq.readSequence(extList)) {
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
                    extSeq.readBoolean(critical); // OPTIONAL DEFAULT FALSE -- not otherwise used

                    COctet extnValue;
                    if (!extSeq.readOctetString(extnValue)) {
                        continue;
                    }

                    if (extnOid.compare(OID_REASON_CODE) == 0) {
                        SReadOnlyByteSpan reasonCursor = extnValue.toSpan();
                        CTag reasonTag;
                        SReadOnlyByteSpan reasonContent;
                        uint32_t reasonValue = 0;
                        if (CDecoder::readNextElement(reasonCursor, EAENC_DER, reasonTag, reasonContent)
                            && reasonTag == CTag::ENUMERATED
                            && CDecoder::decodeEnumerated(reasonContent, reasonValue))
                        {
                            reason = CrlReasonCodec::toFlag(reasonValue);
                        }
                    }
                }
            }
        }

        info._rawData = rawData;
        info._serialNumber = move(serialNumber);
        info._timestamp = timestamp;
        info._reason = reason;
        return ERET_OK;
    }

    /* Rebuilds this entry's DER bytes from its own current fields -- the inverse of decode().
     * Used both by CCrlWriter::add() (to turn a freshly-set-up entry into canonical, decode()d
     * form) and available for a caller that wants to re-serialize a previously-decoded entry. */
    ERetCode CCrlRevokationInfo::encode(COctet& rawData) const {
        if (_serialNumber.empty() || _timestamp.isZero()) {
            return ERET_INVAL;
        }

        CBuffer body;
        if (!CDer::appendTlv(body, CTag::INTEGER, _serialNumber.toSpan())) {
            return ERET_UNKNOWN;
        }

        if (!CCert::encodeTime(_timestamp, body)) {
            return ERET_INVAL; // --> _timestamp.isUtc wasn't set -- see encodeTime()'s own contract.
        }

        if (_reason != ECRLR_NONE) {
            uint32_t reasonValue = 0;
            if (CrlReasonCodec::toEnumValue(_reason, reasonValue)) {
                uint8_t enumBuf[5];
                size_t enumWritten = 0;
                if (!CEncoder::encodeEnumerated(SByteSpan(enumBuf, sizeof(enumBuf)), reasonValue, enumWritten)) {
                    return ERET_UNKNOWN;
                }

                CBuffer reasonTlv;
                if (!CDer::appendTlv(reasonTlv, CTag::ENUMERATED, SReadOnlyByteSpan(enumBuf, enumWritten))) {
                    return ERET_UNKNOWN;
                }

                size_t oidNeeded = CEncoder::encodedOidStringSize(CString(OID_REASON_CODE));
                if (!oidNeeded) {
                    return ERET_UNKNOWN;
                }

                CBuffer oidContent;
                size_t oidWritten = 0;
                if (!oidContent.resize(oidNeeded)
                    || !CEncoder::encodeOidString(oidContent.toSpan(), CString(OID_REASON_CODE), oidWritten))
                {
                    return ERET_UNKNOWN;
                }

                // Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE (omitted),
                // extnValue OCTET STRING }.
                CBuffer extBody;
                if (!CDer::appendTlv(extBody, CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), oidWritten))
                    || !CDer::appendTlv(extBody, CTag::STRING_OCTET, reasonTlv.toSpan()))
                {
                    return ERET_UNKNOWN;
                }

                CBuffer oneExtensionTlv;
                if (!CDer::appendSequence(oneExtensionTlv, extBody.toSpan())) {
                    return ERET_UNKNOWN;
                }

                // crlEntryExtensions ::= Extensions ::= SEQUENCE OF Extension (just this one).
                CBuffer extensionsTlv;
                if (!CDer::appendSequence(extensionsTlv, oneExtensionTlv.toSpan())) {
                    return ERET_UNKNOWN;
                }

                if (!CDer::appendRaw(body, extensionsTlv.toSpan())) {
                    return ERET_UNKNOWN;
                }
            }
            // --> A reason with no ENUMERATED mapping can't happen given ECrlReasons' own
            // values (every flag CCrlWriter::add() can be given maps to one), but if it ever
            // did, crlEntryExtensions is OPTIONAL, so simply omitting it is correct.
        }

        CBuffer full;
        if (!CDer::appendSequence(full, body.toSpan())) {
            return ERET_UNKNOWN;
        }

        rawData = COctet(full.toSpan());
        return ERET_OK;
    }

    /* True (ERET_OK) iff this entry's own userCertificate matches cert's serial number. */
    ERetCode CCrlRevokationInfo::isFor(const CCert& cert) const {
        if (empty() || cert.empty()) {
            return ERET_INVAL;
        }

        return _serialNumber.toSpan().sequencialEqual(cert.serialNumber().toSpan()) ? ERET_OK : ERET_INVAL;
    }

    /* Loads a CRL (CertificateList, RFC 5280 5.1) from raw DER data. signatureAlgorithm/
     * signatureValue are read past (required by the grammar) but not retained -- this class
     * exposes no signature-verification API, only the parsed revocation data. */
    ERetCode CCrlReader::decode(const COctet& rawData) {
        if (rawData.empty()) {
            return ERET_INVAL;
        }

        // --> Parsed into locals first, committed to *this only once the whole structural parse
        // succeeds -- the same "never leave *this half-populated on failure" discipline
        // CCert::importDer() follows.
        TArray<CCrlRevokationInfo> revokations;
        uint32_t version = 0;
        CDistinguishedName issuer;
        SDateTime thisUpdate, nextUpdate;

        CReader outer(rawData.toSpan(), EAENC_DER);
        CReader certListSeq;
        if (!outer.readSequence(certListSeq)) {
            return ERET_BADREQ;
        }

        CReader tbsSeq;
        if (!certListSeq.readSequence(tbsSeq)) {
            return ERET_BADREQ;
        }

        // version Version OPTIONAL -- a plain (not context-tagged) INTEGER, unlike
        // TBSCertificate's own [0] EXPLICIT version; a present value can only legitimately be 1
        // (v2), since DER omits a default (v1/0) value entirely, but whatever's actually there
        // is still accepted rather than rejected.
        int64_t versionValue = 0;
        if (tbsSeq.readInteger(versionValue) && versionValue >= 0) {
            version = uint32_t(versionValue);
        }

        // signature AlgorithmIdentifier -- TBSCertList's own copy, required by the grammar to
        // match CertificateList.signatureAlgorithm (read further down); not separately retained.
        CReader tbsSigAlgoSeq;
        if (!tbsSeq.readSequence(tbsSigAlgoSeq)) {
            return ERET_BADREQ;
        }

        // issuer Name
        if (!tbsSeq.readDistinguishedName(issuer)) {
            return ERET_BADREQ;
        }

        // thisUpdate Time
        if (!CCert::readTime(tbsSeq, thisUpdate)) {
            return ERET_BADREQ;
        }

        // nextUpdate Time OPTIONAL -- best-effort; absent simply leaves nextUpdate at its zero
        // default (readTime()'s own read*Time() calls roll the cursor back on failure).
        CCert::readTime(tbsSeq, nextUpdate);

        // revokedCertificates SEQUENCE OF SEQUENCE {...} OPTIONAL, then crlExtensions [0]
        // EXPLICIT Extensions OPTIONAL -- neither is required to be present; crlExtensions isn't
        // exposed by this class (no CRL-level extensions field), so it's read past and discarded
        // if present.
        if (!tbsSeq.atEnd()) {
            CTag tag;
            SReadOnlyByteSpan content;
            if (!tbsSeq.readNextElement(tag, content)) {
                return ERET_BADREQ;
            }

            if (tag == CTag::SEQ) {
                CReader entriesSeq(content, EAENC_DER);

                while (!entriesSeq.atEnd()) {
                    // The full entry TLV (tag+length+content) is what CCrlRevokationInfo::decode()
                    // expects -- captured by snapshotting the cursor before the read, the same
                    // technique used wherever this codebase needs a sub-element's raw bytes
                    // rather than just its decoded content.
                    SReadOnlyByteSpan beforeEntry = entriesSeq.remaining();

                    CTag entryTag;
                    SReadOnlyByteSpan entryContent;
                    if (!entriesSeq.readNextElement(entryTag, entryContent)) {
                        break;
                    }

                    if (entryTag != CTag::SEQ) {
                        continue; // --> malformed entry; skip and keep scanning, best-effort
                    }

                    SReadOnlyByteSpan fullEntryTlv(
                        beforeEntry.data, size_t(entryContent.data + entryContent.size - beforeEntry.data)
                    );

                    CCrlRevokationInfo info;
                    if (CCrlRevokationInfo::decode(COctet(fullEntryTlv), info) == ERET_OK) {
                        revokations.add(move(info));
                    }
                }

                // crlExtensions [0] EXPLICIT Extensions OPTIONAL, if still present after
                // revokedCertificates -- not exposed, discarded.
                if (!tbsSeq.atEnd()) {
                    tbsSeq.readNextElement(tag, content);
                }
            }
            // --> Otherwise tag was already crlExtensions [0] itself (revokedCertificates
            // absent) -- already consumed above, discarded; nothing further to do.
        }

        // CertificateList.signatureAlgorithm AlgorithmIdentifier -- read past (must match
        // tbsCertList's own copy above) but not retained, same as tbsSigAlgoSeq.
        CReader sigAlgoSeq;
        if (!certListSeq.readSequence(sigAlgoSeq)) {
            return ERET_BADREQ;
        }

        // signatureValue BIT STRING -- read past but not retained (see this method's own
        // top-of-function comment on why).
        SReadOnlyByteSpan sigBits;
        uint8_t sigUnusedBits = 0;
        if (!certListSeq.readBitString(sigBits, sigUnusedBits)) {
            return ERET_BADREQ;
        }

        _rawData = rawData;
        _revokations = move(revokations);
        _version = version;
        _issuer = move(issuer);
        _thisUpdate = thisUpdate;
        _nextUpdate = nextUpdate;
        return ERET_OK;
    }

    /* Returns this reader's own already-decoded raw CRL bytes -- CCrlReader exposes no mutators
     * for version()/issuer()/thisUpdate()/nextUpdate() (only decode() populates them), so there's
     * never a "rebuild from current state" to do beyond handing back what decode() itself stored
     * (the same bytes rawData() already exposes directly); this just adds the empty/not-yet-
     * decoded failure case decode()'s own callers expect from an ERetCode-returning method. */
    ERetCode CCrlReader::encode(COctet& rawData) const {
        if (_rawData.empty()) {
            return ERET_INVAL;
        }

        rawData = _rawData;
        return ERET_OK;
    }

    /* Finds the revocation entry for cert, if any. ERET_INVAL (not ERET_OK) when no entry
     * matches -- the same not-found convention CCert::extensionOf() uses. */
    ERetCode CCrlReader::find(const CCert& cert, CCrlRevokationInfo& out) const {
        if (cert.empty()) {
            return ERET_INVAL;
        }

        for (const CCrlRevokationInfo& info : _revokations) {
            if (info.isFor(cert) == ERET_OK) {
                out = info;
                return ERET_OK;
            }
        }

        return ERET_INVAL;
    }

    /* Checks cert against this CRL's revocation list. ERET_OK means cert is NOT revoked (the
     * check passed, cleanly mirroring ERET_OK's usual "no problem" meaning); ERET_ALREADY means
     * cert IS revoked (already in the revoked state) -- there's no dedicated "revoked" ERetCode,
     * so this is the closest existing fit; any other returned code is a genuine error, not a
     * revocation verdict either way. */
    ERetCode CCrlReader::check(const CCert& cert) const {
        CCrlRevokationInfo info;
        ERetCode rc = find(cert, info);

        if (rc == ERET_OK) {
            return ERET_ALREADY; // --> found: cert is revoked.
        }
        if (rc == ERET_INVAL && !cert.empty()) {
            return ERET_OK; // --> not found: cert isn't revoked.
        }

        return rc; // --> cert itself was empty/invalid -- a real error, not a revocation verdict.
    }

    /* Adds (or, if cert is already listed, replaces) a revocation entry. Builds the entry's DER
     * bytes via CCrlRevokationInfo::encode() and re-parses them via decode() rather than poking
     * _rawData directly, so every entry this writer ever holds is canonical, decode()-validated
     * data -- exactly what build() later re-embeds verbatim via CCrlRevokationInfo::rawData(). */
    ERetCode CCrlWriter::add(const CCert& cert, const SDateTime& when, ECrlReasons reason) {
        if (cert.empty() || cert.serialNumber().empty() || when.isZero()) {
            return ERET_INVAL;
        }

        CCrlRevokationInfo info;
        info._serialNumber = cert.serialNumber();
        info._timestamp = when;
        info._reason = reason;

        COctet rawEntry;
        ERetCode rc = info.encode(rawEntry);
        if (rc != ERET_OK) {
            return rc;
        }

        CCrlRevokationInfo canonical;
        rc = CCrlRevokationInfo::decode(rawEntry, canonical);
        if (rc != ERET_OK) {
            return rc;
        }

        for (size_t i = 0; i < _revokations.size(); ++i) {
            if (_revokations[i].isFor(cert) == ERET_OK) {
                _revokations[i] = move(canonical);
                return ERET_OK;
            }
        }

        return _revokations.add(move(canonical)) ? ERET_OK : ERET_NOMEM;
    }

    /* Removes cert's revocation entry, if present. */
    ERetCode CCrlWriter::remove(const CCert& cert) {
        if (cert.empty()) {
            return ERET_INVAL;
        }

        for (size_t i = 0; i < _revokations.size(); ++i) {
            if (_revokations[i].isFor(cert) == ERET_OK) {
                return _revokations.remove(i) ? ERET_OK : ERET_UNKNOWN;
            }
        }

        return ERET_INVAL; // --> not found, matching find()'s own not-found convention
    }

    /* Builds and signs a CertificateList (RFC 5280 5.1) from this writer's current state, signed
     * with issuer's attached private key. */
    ERetCode CCrlWriter::build(const CCert& issuer, COctet& out) {
        out = COctet();

        if (issuer.empty() || _thisUpdate.isZero() || _version > 1) {
            return ERET_INVAL;
        }

        // The issuer Name to embed: this writer's own _issuer if explicitly set (must then match
        // issuer's own subject -- see issuer()'s own doc comment), otherwise derived from it.
        CDistinguishedName effectiveIssuer = _issuer;
        if (effectiveIssuer.empty()) {
            effectiveIssuer = issuer.subject();
        } else if (effectiveIssuer != issuer.subject()) {
            return ERET_INVAL;
        }
        if (effectiveIssuer.empty()) {
            return ERET_INVAL;
        }

        crypto::IPrivateKeyPtr issuerPriv = issuer.privateKey();
        if (!issuerPriv) {
            return ERET_KEY_EMPTY;
        }

        // --- signature: resolve issuer's algorithm to a signature OID + digest, exactly like
        // CCertBuilder::build() (always SHA-256, no PSS -- this writer has no digestAlgo/rsaPss
        // fields of its own). ---
        crypto::EAsymmetrics issuerWhich = issuerPriv->algorithm();

        CString sigOid;
        crypto::EHashers sigHash = crypto::EHASH_UNKNOWN;
        COctet sigAlgoParams;
        if (!CCert::resolveSigAlgoForSigning(issuerWhich, crypto::EHASH_UNKNOWN, false, sigOid, sigHash, sigAlgoParams)) {
            return ERET_NOTSUP; // --> e.g. issuer's key is X25519, which can't sign at all.
        }

        bool sigIsEddsa = (sigHash == crypto::EHASH_UNKNOWN);

        // AlgorithmIdentifier ::= SEQUENCE { OID, parameters ANY OPTIONAL } -- built once, since
        // TBSCertList.signature and CertificateList.signatureAlgorithm must be byte-identical.
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

            if (!CDer::appendSequence(sigAlgoIdTlv, body.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        // The effective version to encode: v1 (field omitted) unless any entry carries
        // crlEntryExtensions (a non-NONE reason), which requires v2(1) per the grammar -- or the
        // writer's own version() was already set to 1.
        bool needsV2 = false;
        for (const CCrlRevokationInfo& info : _revokations) {
            if (info.reason() != ECRLR_NONE) {
                needsV2 = true;
                break;
            }
        }
        uint32_t effectiveVersion = needsV2 ? 1u : _version;

        // --- Assemble TBSCertList. ---
        CBuffer tbsBody;

        if (effectiveVersion != 0) {
            uint8_t verBuf[9];
            size_t written = 0;
            if (!CEncoder::encodeInteger(SByteSpan(verBuf, sizeof(verBuf)), int64_t(effectiveVersion), written)) {
                return ERET_UNKNOWN;
            }
            if (!CDer::appendTlv(tbsBody, CTag::INTEGER, SReadOnlyByteSpan(verBuf, written))) {
                return ERET_UNKNOWN;
            }
        }

        // signature AlgorithmIdentifier -- TBSCertList's own copy of sigAlgoIdTlv.
        if (!CDer::appendRaw(tbsBody, sigAlgoIdTlv.toSpan())) {
            return ERET_UNKNOWN;
        }

        // issuer Name.
        if (!CCert::encodeName(effectiveIssuer, tbsBody)) {
            return ERET_UNKNOWN;
        }

        // thisUpdate Time.
        if (!CCert::encodeTime(_thisUpdate, tbsBody)) {
            return ERET_INVAL; // --> _thisUpdate.isUtc wasn't set -- see encodeTime()'s own contract.
        }

        // nextUpdate Time OPTIONAL.
        if (!_nextUpdate.isZero() && !CCert::encodeTime(_nextUpdate, tbsBody)) {
            return ERET_INVAL;
        }

        // revokedCertificates SEQUENCE OF SEQUENCE {...} OPTIONAL -- each entry's already-encoded
        // TLV (CCrlRevokationInfo::rawData(), guaranteed non-empty by add()) is spliced in as-is.
        if (!_revokations.empty()) {
            CBuffer entriesBody;
            for (const CCrlRevokationInfo& info : _revokations) {
                if (info.rawData().empty() || !CDer::appendRaw(entriesBody, info.rawData().toSpan())) {
                    return ERET_UNKNOWN;
                }
            }

            CBuffer entriesSeq;
            if (!CDer::appendSequence(entriesSeq, entriesBody.toSpan())) {
                return ERET_UNKNOWN;
            }
            if (!CDer::appendRaw(tbsBody, entriesSeq.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        // crlExtensions [0] EXPLICIT Extensions OPTIONAL -- never emitted: this writer has no
        // CRL-level extensions field (e.g. CRLNumber, AuthorityKeyIdentifier) of its own.

        CBuffer tbsFull;
        if (!CDer::appendSequence(tbsFull, tbsBody.toSpan())) {
            return ERET_UNKNOWN;
        }

        // --- Sign the TBSCertList: a digest for a hash-then-sign family, or the raw TBSCertList
        // bytes directly for the self-hashing EdDSA schemes -- same shape as
        // CCertBuilder::build(). ---
        crypto::IAsymmetricContextPtr ctx = issuer.createAsymmetricContext();
        if (!ctx) {
            return ERET_UNKNOWN;
        }

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
        ERetCode signRc = ctx->sign(toSign.toSpan(), sigOut);
        if (signRc != ERET_OK) {
            return signRc;
        }

        // --- CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }. ---
        CBuffer certListBody;
        if (!CDer::appendRaw(certListBody, tbsFull.toSpan()) || !CDer::appendRaw(certListBody, sigAlgoIdTlv.toSpan())) {
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

            if (!CDer::appendTlv(certListBody, CTag::STRING_BIT, SReadOnlyByteSpan(bitContent.toPtr(), written))) {
                return ERET_UNKNOWN;
            }
        }

        CBuffer certListFull;
        if (!CDer::appendSequence(certListFull, certListBody.toSpan())) {
            return ERET_UNKNOWN;
        }

        out = COctet(certListFull.toSpan());
        _version = effectiveVersion; // --> reflect the actually-encoded version back.
        return ERET_OK;
    }

} // namespace x509
} // namespace certpp
