#include <certpp/x509/ocsp.hpp>
#include <certpp/x509/exts/aki.hpp>
#include <certpp/x509/generalname.hpp>
#include <certpp/asn1/reader.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/io/buffer.hpp>
#include <certpp/crypto/rng.hpp>
#include "crlreason.hpp"
#include "ocspcodec.hpp"

namespace certpp {
namespace x509 {

    using asn1::CReader;
    using asn1::CDecoder;
    using asn1::CEncoder;
    using asn1::CDer;
    using asn1::CTag;
    using asn1::EAENC_DER;
    using asn1::EATAG_CONTEXT_SPECIFIC;

    // ------------------------------------------------------------------------------------------
    // COcspCertId
    // ------------------------------------------------------------------------------------------

    /* CertID.hashAlgorithm's OID <-> EHashers -- see this method's own doc comment in ocsp.hpp. */
    bool COcspCertId::hashAlgoToOid(crypto::EHashers hash, CString& outOid, bool& outNeedsNull) {
        switch (hash) {
            case crypto::EHASH_SHA1:   outOid = "1.3.14.3.2.26";          outNeedsNull = true;  return true;
            case crypto::EHASH_SHA224: outOid = "2.16.840.1.101.3.4.2.4"; outNeedsNull = false; return true;
            case crypto::EHASH_SHA256: outOid = "2.16.840.1.101.3.4.2.1"; outNeedsNull = false; return true;
            case crypto::EHASH_SHA384: outOid = "2.16.840.1.101.3.4.2.2"; outNeedsNull = false; return true;
            case crypto::EHASH_SHA512: outOid = "2.16.840.1.101.3.4.2.3"; outNeedsNull = false; return true;
            default: return false;
        }
    }

    bool COcspCertId::oidToHashAlgo(const CString& oid, crypto::EHashers& outHash) {
        if (oid.compare("1.3.14.3.2.26") == 0)          { outHash = crypto::EHASH_SHA1;   return true; }
        if (oid.compare("2.16.840.1.101.3.4.2.4") == 0) { outHash = crypto::EHASH_SHA224; return true; }
        if (oid.compare("2.16.840.1.101.3.4.2.1") == 0) { outHash = crypto::EHASH_SHA256; return true; }
        if (oid.compare("2.16.840.1.101.3.4.2.2") == 0) { outHash = crypto::EHASH_SHA384; return true; }
        if (oid.compare("2.16.840.1.101.3.4.2.3") == 0) { outHash = crypto::EHASH_SHA512; return true; }
        return false;
    }

    /* AKI-shortcut make() -- see this method's own doc comment in ocsp.hpp. */
    ERetCode COcspCertId::make(const CCert& cert, COcspCertId& out) {
        if (cert.empty()) {
            return ERET_INVAL;
        }

        auto aki = cert.extension<CAkiExtension>();
        if (!aki || !aki->hasKeyIdentifier()) {
            return ERET_NOTSUP;
        }

        CBuffer issuerNameTlv;
        if (!CCert::encodeName(cert.issuer(), issuerNameTlv)) {
            return ERET_UNKNOWN;
        }

        crypto::IHasherPtr hasher;
        if (crypto::IHasher::create(crypto::EHASH_SHA1, hasher) != ERET_OK || !hasher) {
            return ERET_UNKNOWN;
        }

        uint8_t digest[20];
        if (!hasher->push(issuerNameTlv.toSpan()) || !hasher->finish(SByteSpan(digest, sizeof(digest)))) {
            return ERET_HASH_PIPE;
        }

        out = COcspCertId(
            cert.serialNumber(), aki->keyIdentifier(), COctet(SReadOnlyByteSpan(digest, sizeof(digest))),
            crypto::EHASH_SHA1
        );
        return ERET_OK;
    }

    /* Fully general make() -- see this method's own doc comment in ocsp.hpp. */
    ERetCode COcspCertId::make(const CCert& cert, const CCert& issuer, crypto::EHashers hashAlgo, COcspCertId& out) {
        if (cert.empty() || issuer.empty()) {
            return ERET_INVAL;
        }

        crypto::IHasherPtr hasher;
        if (crypto::IHasher::create(hashAlgo, hasher) != ERET_OK || !hasher) {
            return ERET_NOTSUP;
        }

        CBuffer issuerNameTlv;
        if (!CCert::encodeName(issuer.subject(), issuerNameTlv)) {
            return ERET_UNKNOWN;
        }

        size_t hLen = hasher->byteWidth();

        CBuffer nameHash;
        nameHash.resize(hLen);
        hasher->reset();
        if (!hasher->push(issuerNameTlv.toSpan()) || !hasher->finish(nameHash.toSpan())) {
            return ERET_HASH_PIPE;
        }

        CBuffer keyHash;
        keyHash.resize(hLen);
        hasher->reset();
        if (!hasher->push(issuer.rawPublicKey().toSpan()) || !hasher->finish(keyHash.toSpan())) {
            return ERET_HASH_PIPE;
        }

        out = COcspCertId(
            cert.serialNumber(),
            COctet(keyHash.toSpan()),
            COctet(nameHash.toSpan()),
            hashAlgo
        );
        return ERET_OK;
    }

    /* Decodes a complete CertID SEQUENCE TLV (RFC 6960 4.1.1). */
    ERetCode COcspCertId::decode(const COctet& rawData, COcspCertId& out) {
        if (rawData.empty()) {
            return ERET_INVAL;
        }

        CReader outer(rawData.toSpan(), EAENC_DER);
        CReader certIdSeq;
        if (!outer.readSequence(certIdSeq)) {
            return ERET_BADREQ;
        }

        // --> The CertID SEQUENCE must be the whole input, not merely its prefix; see
        // CCert::importDer() for why trailing bytes are not a harmless leniency.
        if (!outer.atEnd()) {
            return ERET_BADREQ;
        }

        CReader algIdSeq;
        if (!certIdSeq.readSequence(algIdSeq)) {
            return ERET_BADREQ;
        }

        CString hashOid;
        if (!algIdSeq.readOidString(hashOid)) {
            return ERET_BADREQ;
        }
        // parameters ANY OPTIONAL -- not read; AlgorithmIdentifier is the last field of algIdSeq
        // regardless, so leaving it unconsumed is harmless.

        crypto::EHashers hashAlgo;
        if (!oidToHashAlgo(hashOid, hashAlgo)) {
            return ERET_NOTSUP;
        }

        COctet issuerNameHash, issuerKeyHash;
        if (!certIdSeq.readOctetString(issuerNameHash) || !certIdSeq.readOctetString(issuerKeyHash)) {
            return ERET_BADREQ;
        }

        CTag tag;
        SReadOnlyByteSpan content;
        if (!certIdSeq.readNextElement(tag, content) || tag != CTag::INTEGER) {
            return ERET_BADREQ;
        }

        out = COcspCertId(COctet(content), issuerKeyHash, issuerNameHash, hashAlgo);
        return ERET_OK;
    }

    /* Encodes this certificate ID as a complete CertID SEQUENCE TLV (RFC 6960 4.1.1). */
    ERetCode COcspCertId::encode(COctet& rawData) const {
        if (empty()) {
            return ERET_INVAL;
        }

        CString hashOid;
        bool needsNull = false;
        if (!hashAlgoToOid(_hashAlgo, hashOid, needsNull)) {
            return ERET_NOTSUP;
        }

        CBuffer algIdTlv;
        {
            size_t needed = CEncoder::encodedOidStringSize(hashOid);
            if (!needed) {
                return ERET_UNKNOWN;
            }

            CBuffer oidContent;
            size_t written = 0;
            if (!oidContent.resize(needed) || !CEncoder::encodeOidString(oidContent.toSpan(), hashOid, written)) {
                return ERET_UNKNOWN;
            }

            CBuffer body;
            if (!CDer::appendTlv(body, CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), written))) {
                return ERET_UNKNOWN;
            }
            if (needsNull && !CDer::appendTlv(body, CTag::NULL_, SReadOnlyByteSpan())) {
                return ERET_UNKNOWN;
            }
            if (!CDer::appendSequence(algIdTlv, body.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        CBuffer body;
        if (!CDer::appendRaw(body, algIdTlv.toSpan())
            || !CDer::appendTlv(body, CTag::STRING_OCTET, _issuerNameHash.toSpan())
            || !CDer::appendTlv(body, CTag::STRING_OCTET, _issuerKeyHash.toSpan())
            || !CDer::appendTlv(body, CTag::INTEGER, _serialNumber.toSpan()))
        {
            return ERET_UNKNOWN;
        }

        CBuffer full;
        if (!CDer::appendSequence(full, body.toSpan())) {
            return ERET_UNKNOWN;
        }

        rawData = COctet(full.toSpan());
        return ERET_OK;
    }

    /* Field-by-field equality. */
    bool COcspCertId::equals(const COcspCertId& other) const {
        if (empty() || other.empty()) {
            return false;
        }

        return _hashAlgo == other._hashAlgo
            && _serialNumber.toSpan().sequencialEqual(other._serialNumber.toSpan())
            && _issuerKeyHash.toSpan().sequencialEqual(other._issuerKeyHash.toSpan())
            && _issuerNameHash.toSpan().sequencialEqual(other._issuerNameHash.toSpan());
    }

    /* Matches cert by serial number always; additionally cross-checks the issuer hashes when
     * this CertID uses SHA-1 (by re-deriving them from cert's own AuthorityKeyIdentifier via the
     * same convention make(cert, out) uses) -- for any other hash algorithm, or a cert with no
     * usable AuthorityKeyIdentifier, there's no way to independently re-derive the issuer hash
     * from cert alone, so the serial-number match is the best available signal. */
    bool COcspCertId::isFor(const CCert& cert) const {
        if (empty() || cert.empty()) {
            return false;
        }

        if (!_serialNumber.toSpan().sequencialEqual(cert.serialNumber().toSpan())) {
            return false;
        }

        if (_hashAlgo == crypto::EHASH_SHA1) {
            COcspCertId candidate;
            if (make(cert, candidate) == ERET_OK) {
                return _issuerNameHash.toSpan().sequencialEqual(candidate._issuerNameHash.toSpan())
                    && _issuerKeyHash.toSpan().sequencialEqual(candidate._issuerKeyHash.toSpan());
            }
        }

        return true;
    }

    // ------------------------------------------------------------------------------------------
    // COcspEntry
    // ------------------------------------------------------------------------------------------

    /* Decodes a complete SingleResponse SEQUENCE TLV (RFC 6960 4.2.1). */
    ERetCode COcspEntry::decode(const COctet& rawData, COcspEntry& out) {
        if (rawData.empty()) {
            return ERET_INVAL;
        }

        CReader outer(rawData.toSpan(), EAENC_DER);
        CReader entrySeq;
        if (!outer.readSequence(entrySeq)) {
            return ERET_BADREQ;
        }

        // --> The SingleResponse SEQUENCE must be the whole input, not merely its prefix; see
        // CCert::importDer() for why trailing bytes are not a harmless leniency.
        if (!outer.atEnd()) {
            return ERET_BADREQ;
        }

        // certID CertID -- the full TLV is what COcspCertId::decode() expects.
        SReadOnlyByteSpan beforeCertId = entrySeq.remaining();
        CTag certIdTag;
        SReadOnlyByteSpan certIdContent;
        if (!entrySeq.readNextElement(certIdTag, certIdContent) || certIdTag != CTag::SEQ) {
            return ERET_BADREQ;
        }
        SReadOnlyByteSpan certIdTlv(
            beforeCertId.data, size_t(certIdContent.data + certIdContent.size - beforeCertId.data)
        );

        COcspCertId certId;
        if (COcspCertId::decode(COctet(certIdTlv), certId) != ERET_OK) {
            return ERET_BADREQ;
        }

        // certStatus CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo,
        // unknown [2] IMPLICIT NULL }.
        CTag statusTag;
        SReadOnlyByteSpan statusContent;
        if (!entrySeq.readNextElement(statusTag, statusContent)) {
            return ERET_BADREQ;
        }

        EOcspEntryStatus status = EOCSPENT_UNKNOWN;
        ECrlReasons reason = ECRLR_NONE;
        SDateTime revocationTime;

        if (statusTag == CTag(EATAG_CONTEXT_SPECIFIC, 0, false)) {
            status = EOCSPENT_GOOD;
        } else if (statusTag == CTag(EATAG_CONTEXT_SPECIFIC, 1, true)) {
            status = EOCSPENT_REVOKED;

            CReader revokedInfo(statusContent, EAENC_DER);
            if (!revokedInfo.readGeneralizedTime(revocationTime)) {
                return ERET_BADREQ;
            }

            if (!revokedInfo.atEnd()) {
                CTag reasonWrapTag;
                SReadOnlyByteSpan reasonWrapContent;
                if (revokedInfo.readNextElement(reasonWrapTag, reasonWrapContent)
                    && reasonWrapTag == CTag(EATAG_CONTEXT_SPECIFIC, 0, true))
                {
                    SReadOnlyByteSpan reasonCursor = reasonWrapContent;
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
        } else if (statusTag == CTag(EATAG_CONTEXT_SPECIFIC, 2, false)) {
            status = EOCSPENT_UNKNOWN;
        } else {
            return ERET_BADREQ;
        }

        SDateTime thisUpdate, nextUpdate;
        if (!entrySeq.readGeneralizedTime(thisUpdate)) {
            return ERET_BADREQ;
        }

        if (!entrySeq.atEnd()) {
            CTag nextTag;
            SReadOnlyByteSpan nextContent;
            if (entrySeq.readNextElement(nextTag, nextContent) && nextTag == CTag(EATAG_CONTEXT_SPECIFIC, 0, true)) {
                CReader nextReader(nextContent, EAENC_DER);
                nextReader.readGeneralizedTime(nextUpdate);
            }
            // singleExtensions [1] EXPLICIT OPTIONAL, if present after that -- not retained.
        }

        out = COcspEntry(certId, status, reason, thisUpdate, nextUpdate, revocationTime);
        return ERET_OK;
    }

    /* Encodes this entry as a complete SingleResponse SEQUENCE TLV (RFC 6960 4.2.1). */
    ERetCode COcspEntry::encode(COctet& rawData) const {
        if (_certId.empty() || _thisUpdate.isZero()) {
            return ERET_INVAL;
        }
        if (_status == EOCSPENT_REVOKED && _revocationTime.isZero()) {
            return ERET_INVAL;
        }

        COctet certIdTlv;
        if (_certId.encode(certIdTlv) != ERET_OK) {
            return ERET_UNKNOWN;
        }

        CBuffer body;
        if (!CDer::appendRaw(body, certIdTlv.toSpan())) {
            return ERET_UNKNOWN;
        }

        if (_status == EOCSPENT_GOOD) {
            if (!CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 0, false), SReadOnlyByteSpan())) {
                return ERET_UNKNOWN;
            }
        } else if (_status == EOCSPENT_REVOKED) {
            CBuffer revokedInfo;
            if (!OcspCodec::encodeGeneralizedTime(_revocationTime, revokedInfo)) {
                return ERET_INVAL;
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

                    if (!CDer::appendTlv(revokedInfo, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), reasonTlv.toSpan())) {
                        return ERET_UNKNOWN;
                    }
                }
            }

            if (!CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 1, true), revokedInfo.toSpan())) {
                return ERET_UNKNOWN;
            }
        } else {
            if (!CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 2, false), SReadOnlyByteSpan())) {
                return ERET_UNKNOWN;
            }
        }

        if (!OcspCodec::encodeGeneralizedTime(_thisUpdate, body)) {
            return ERET_INVAL;
        }

        if (!_nextUpdate.isZero()) {
            CBuffer nextUpdateTlv;
            if (!OcspCodec::encodeGeneralizedTime(_nextUpdate, nextUpdateTlv)) {
                return ERET_INVAL;
            }
            if (!CDer::appendTlv(body, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), nextUpdateTlv.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        // singleExtensions [1] EXPLICIT OPTIONAL -- never emitted (not used by this class).

        CBuffer full;
        if (!CDer::appendSequence(full, body.toSpan())) {
            return ERET_UNKNOWN;
        }

        rawData = COctet(full.toSpan());
        return ERET_OK;
    }

    // ------------------------------------------------------------------------------------------
    // COcspRequest
    // ------------------------------------------------------------------------------------------

    /* Decodes OCSPRequest (RFC 6960 4.1.1). version is read past but not retained;
     * requestorName is kept only when it's a directoryName (see requestorName()'s own doc
     * comment); optionalSignature, if present, is read into _tbsRequestRaw/_sigHashAlgo/
     * _signatureValue for verifySignature()'s own later use, but isn't verified here (this
     * method has no certificate to verify against). */
    ERetCode COcspRequest::decode(const CBuffer& data) {
        if (data.empty()) {
            return ERET_INVAL;
        }

        TArray<COcspCertId> certIds;
        COctet nonceBytes;
        CDistinguishedName requestorName;

        CReader outer(data.toSpan(), EAENC_DER);
        CReader reqSeq;
        if (!outer.readSequence(reqSeq)) {
            return ERET_BADREQ;
        }

        // --> The OCSPRequest SEQUENCE must be the whole input, not merely its prefix; see
        // CCert::importDer() for why trailing bytes are not a harmless leniency.
        if (!outer.atEnd()) {
            return ERET_BADREQ;
        }

        SReadOnlyByteSpan beforeTbs = reqSeq.remaining();
        CTag tbsOuterTag;
        SReadOnlyByteSpan tbsOuterContent;
        if (!reqSeq.readNextElement(tbsOuterTag, tbsOuterContent) || tbsOuterTag != CTag::SEQ) {
            return ERET_BADREQ;
        }
        SReadOnlyByteSpan tbsFullTlv(
            beforeTbs.data, size_t(tbsOuterContent.data + tbsOuterContent.size - beforeTbs.data)
        );

        CReader tbsSeq(tbsOuterContent, EAENC_DER);

        CTag tag;
        SReadOnlyByteSpan content;
        if (!tbsSeq.readNextElement(tag, content)) {
            return ERET_BADREQ; // requestList is mandatory -- something must be here
        }

        if (tag == CTag(EATAG_CONTEXT_SPECIFIC, 0, true)) { // version -- skip
            if (!tbsSeq.readNextElement(tag, content)) {
                return ERET_BADREQ;
            }
        }

        if (tag == CTag(EATAG_CONTEXT_SPECIFIC, 1, true)) { // requestorName [1] EXPLICIT GeneralName
            CTag gnTag;
            SReadOnlyByteSpan gnContent;
            SReadOnlyByteSpan gnCursor = content;
            if (CDecoder::readNextElement(gnCursor, EAENC_DER, gnTag, gnContent)) {
                CGeneralName gn;
                if (CGeneralName::decode(gnContent, gnTag.value(), gnTag.isConstructed(), gn) && gn.type() == EGNAME_DIRECTORY) {
                    requestorName = gn.directoryName();
                }
            }
            if (!tbsSeq.readNextElement(tag, content)) {
                return ERET_BADREQ;
            }
        }

        if (tag != CTag::SEQ) {
            return ERET_BADREQ; // requestList itself must be a plain SEQUENCE OF Request
        }

        CReader requestListSeq(content, EAENC_DER);
        while (!requestListSeq.atEnd()) {
            CReader reqEntrySeq;
            if (!requestListSeq.readSequence(reqEntrySeq)) {
                break;
            }

            SReadOnlyByteSpan beforeCertId = reqEntrySeq.remaining();
            CTag certIdTag;
            SReadOnlyByteSpan certIdContent;
            if (!reqEntrySeq.readNextElement(certIdTag, certIdContent) || certIdTag != CTag::SEQ) {
                continue; // --> malformed Request entry; skip and keep scanning, best-effort
            }

            SReadOnlyByteSpan certIdTlv(
                beforeCertId.data, size_t(certIdContent.data + certIdContent.size - beforeCertId.data)
            );

            COcspCertId certId;
            if (COcspCertId::decode(COctet(certIdTlv), certId) == ERET_OK) {
                certIds.add(move(certId));
            }
            // singleRequestExtensions [0] EXPLICIT OPTIONAL, if present -- not retained.
        }

        // requestExtensions [2] EXPLICIT Extensions OPTIONAL -- scan for the Nonce.
        if (!tbsSeq.atEnd()) {
            CTag extTag;
            SReadOnlyByteSpan extContent;
            if (tbsSeq.readNextElement(extTag, extContent) && extTag == CTag(EATAG_CONTEXT_SPECIFIC, 2, true)) {
                CReader extListOuter(extContent, EAENC_DER);
                CReader extList;
                if (extListOuter.readSequence(extList)) {
                    OcspCodec::scanForNonce(extList, nonceBytes);
                }
            }
        }

        // optionalSignature [0] EXPLICIT Signature OPTIONAL.
        crypto::EHashers sigHash = crypto::EHASH_UNKNOWN;
        COctet signatureValue;

        if (!reqSeq.atEnd()) {
            CTag sigOuterTag;
            SReadOnlyByteSpan sigOuterContent;
            if (reqSeq.readNextElement(sigOuterTag, sigOuterContent) && sigOuterTag == CTag(EATAG_CONTEXT_SPECIFIC, 0, true)) {
                CReader sigWrapper(sigOuterContent, EAENC_DER);
                CReader sigSeq;
                if (sigWrapper.readSequence(sigSeq)) {
                    CReader sigAlgoSeq;
                    if (sigSeq.readSequence(sigAlgoSeq)) {
                        CString sigAlgoOid;
                        if (sigAlgoSeq.readOidString(sigAlgoOid)) {
                            CString sigAlgoName;
                            CCert::resolveSigAlgo(sigAlgoOid, sigHash, sigAlgoName);
                        }
                    }

                    SReadOnlyByteSpan sigBits;
                    uint8_t sigUnused = 0;
                    // --> sigUnused must be 0: a signature is a whole number of octets.
                    if (sigSeq.readBitString(sigBits, sigUnused) && sigUnused == 0) {
                        signatureValue = COctet(sigBits);
                    }
                    // certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL -- not read; it's the
                    // last field regardless.
                }
            }
        }

        _rawData = COctet(data.toSpan());
        _certIds = move(certIds);
        _nonceBytes = move(nonceBytes);
        _requestorName = move(requestorName);
        _tbsRequestRaw = COctet(tbsFullTlv);
        _sigHashAlgo = sigHash;
        _signatureValue = move(signatureValue);
        return ERET_OK;
    }

    ERetCode COcspRequest::verifySignature(const CCert& requestorCert) const {
        if (_tbsRequestRaw.empty() || _signatureValue.empty()) {
            return ERET_INVAL;
        }

        crypto::IAsymmetricContextPtr ctx = requestorCert.createAsymmetricContext();
        if (!ctx) {
            return ERET_UNKNOWN;
        }

        // --> Decided by the verifying key, not by _sigHashAlgo == EHASH_UNKNOWN -- see
        // COcspResponse::verifySignature() for why that test was unsafe here.
        crypto::IPublicKeyPtr requestorKey = requestorCert.publicKey();
        crypto::EAsymmetrics keyAlgo = requestorKey ? requestorKey->algorithm() : crypto::EASYM_UNKNOWN;

        if (CCert::signsMessageDirectly(keyAlgo)) {
            // self-hashing (EdDSA, ML-DSA) -- the raw tbsRequest bytes are the message itself.
            return ctx->verify(_tbsRequestRaw.toSpan(), _signatureValue.toSpan());
        }

        if (_sigHashAlgo == crypto::EHASH_UNKNOWN) {
            return ERET_NOTSUP; // --> signature algorithm this library can't identify
        }

        crypto::IHasherPtr hasher;
        if (crypto::IHasher::create(_sigHashAlgo, hasher) != ERET_OK || !hasher) {
            return ERET_HASH_PIPE;
        }

        CBuffer digest;
        if (!digest.resize(hasher->byteWidth())
            || !hasher->push(_tbsRequestRaw.toSpan())
            || !hasher->finish(SByteSpan(digest.toPtr(), digest.size())))
        {
            return ERET_HASH_PIPE;
        }

        return ctx->verify(digest.toSpan(), _signatureValue.toSpan());
    }

    // ------------------------------------------------------------------------------------------
    // COcspRequestBuilder
    // ------------------------------------------------------------------------------------------

    ERetCode COcspRequestBuilder::add(const CCert& cert) {
        COcspCertId built;
        ERetCode rc = COcspCertId::make(cert, built);
        if (rc != ERET_OK) {
            return rc;
        }

        return _certIds.add(move(built)) ? ERET_OK : ERET_NOMEM;
    }

    ERetCode COcspRequestBuilder::add(const CCert& cert, const CCert& issuer, crypto::EHashers hashAlgo) {
        COcspCertId built;
        ERetCode rc = COcspCertId::make(cert, issuer, hashAlgo, built);
        if (rc != ERET_OK) {
            return rc;
        }

        return _certIds.add(move(built)) ? ERET_OK : ERET_NOMEM;
    }

    ERetCode COcspRequestBuilder::remove(const CCert& cert) {
        if (cert.empty()) {
            return ERET_INVAL;
        }

        for (size_t i = 0; i < _certIds.size(); ++i) {
            if (_certIds[i].isFor(cert)) {
                return _certIds.remove(i) ? ERET_OK : ERET_UNKNOWN;
            }
        }

        return ERET_INVAL;
    }

    ERetCode COcspRequestBuilder::generateNonce(size_t size) {
        if (size == 0) {
            return ERET_INVAL;
        }

        CBuffer buf;
        buf.resize(size);

        ERetCode rc = crypto::CRng::fill(buf.toSpan());
        if (rc != ERET_OK) {
            return rc;
        }

        _nonceBytes = COctet(buf.toSpan());
        return ERET_OK;
    }

    /* Builds (and, if requestorCert() is set, signs) OCSPRequest (RFC 6960 4.1.1). */
    ERetCode COcspRequestBuilder::build(COctet& out) const {
        out = COctet();

        if (_certIds.empty()) {
            return ERET_INVAL;
        }

        CBuffer requestListBody;
        for (const COcspCertId& certId : _certIds) {
            COctet certIdTlv;
            if (certId.encode(certIdTlv) != ERET_OK) {
                return ERET_UNKNOWN;
            }

            CBuffer reqBody;
            if (!CDer::appendRaw(reqBody, certIdTlv.toSpan())) {
                return ERET_UNKNOWN;
            }

            CBuffer reqTlv;
            if (!CDer::appendSequence(reqTlv, reqBody.toSpan())) {
                return ERET_UNKNOWN;
            }

            if (!CDer::appendRaw(requestListBody, reqTlv.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        CBuffer requestListTlv;
        if (!CDer::appendSequence(requestListTlv, requestListBody.toSpan())) {
            return ERET_UNKNOWN;
        }

        CBuffer tbsBody;

        // requestorName [1] EXPLICIT GeneralName OPTIONAL -- directoryName, from requestorCert's
        // own subject().
        if (!_requestorCert.empty()) {
            CGeneralName gn(_requestorCert.subject());
            CBuffer generalNameTlv;
            if (!gn.encode(generalNameTlv)) {
                return ERET_UNKNOWN;
            }
            if (!CDer::appendTlv(tbsBody, CTag(EATAG_CONTEXT_SPECIFIC, 1, true), generalNameTlv.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        if (!CDer::appendRaw(tbsBody, requestListTlv.toSpan())) {
            return ERET_UNKNOWN;
        }

        if (!_nonceBytes.empty()) {
            CBuffer nonceExtnValue;
            if (!OcspCodec::buildNonceExtnValue(_nonceBytes.toSpan(), nonceExtnValue)) {
                return ERET_UNKNOWN;
            }

            CBuffer extListTlv;
            if (!OcspCodec::appendSingleExtensionList(extListTlv, OcspCodec::OID_NONCE, nonceExtnValue.toSpan())) {
                return ERET_UNKNOWN;
            }

            if (!CDer::appendTlv(tbsBody, CTag(EATAG_CONTEXT_SPECIFIC, 2, true), extListTlv.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        CBuffer tbsTlv;
        if (!CDer::appendSequence(tbsTlv, tbsBody.toSpan())) {
            return ERET_UNKNOWN;
        }

        CBuffer reqFullBody;
        if (!CDer::appendRaw(reqFullBody, tbsTlv.toSpan())) {
            return ERET_UNKNOWN;
        }

        // optionalSignature [0] EXPLICIT Signature OPTIONAL.
        if (!_requestorCert.empty()) {
            crypto::IPrivateKeyPtr priv = _requestorCert.privateKey();
            if (!priv) {
                return ERET_KEY_EMPTY;
            }

            crypto::EAsymmetrics which = priv->algorithm();

            CString sigOid;
            crypto::EHashers sigHash = crypto::EHASH_UNKNOWN;
            COctet sigAlgoParams;
            if (!CCert::resolveSigAlgoForSigning(which, crypto::EHASH_UNKNOWN, false, sigOid, sigHash, sigAlgoParams)) {
                return ERET_NOTSUP;
            }

            bool sigIsSelfHashing = (sigHash == crypto::EHASH_UNKNOWN);

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

            crypto::IAsymmetricContextPtr ctx = _requestorCert.createAsymmetricContext();
            if (!ctx) {
                return ERET_UNKNOWN;
            }

            COctet toSign;
            if (sigIsSelfHashing) {
                toSign = COctet(tbsTlv.toSpan());
            } else {
                crypto::IHasherPtr hasher;
                if (crypto::IHasher::create(sigHash, hasher) != ERET_OK || !hasher) {
                    return ERET_HASH_PIPE;
                }

                CBuffer digest;
                if (!digest.resize(hasher->byteWidth())
                    || !hasher->push(tbsTlv.toSpan())
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

            // Signature ::= SEQUENCE { signatureAlgorithm, signature, certs [0] OPTIONAL }
            CBuffer sigBody;
            if (!CDer::appendRaw(sigBody, sigAlgoIdTlv.toSpan())) {
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
                if (!CDer::appendTlv(sigBody, CTag::STRING_BIT, SReadOnlyByteSpan(bitContent.toPtr(), written))) {
                    return ERET_UNKNOWN;
                }
            }
            // certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL -- never emitted.

            CBuffer sigTlv;
            if (!CDer::appendSequence(sigTlv, sigBody.toSpan())) {
                return ERET_UNKNOWN;
            }

            if (!CDer::appendTlv(reqFullBody, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), sigTlv.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        CBuffer reqFull;
        if (!CDer::appendSequence(reqFull, reqFullBody.toSpan())) {
            return ERET_UNKNOWN;
        }

        out = COctet(reqFull.toSpan());
        return ERET_OK;
    }

    // ------------------------------------------------------------------------------------------
    // COcspResponse
    // ------------------------------------------------------------------------------------------

    void COcspResponse::clear() {
        _rawData.clear();
        _status = EOCSP_INTERNAL;
        _version = 0;
        _responderName = CDistinguishedName();
        _producedAt = SDateTime();
        _entries.clear();
        _nonceBytes.clear();
        _tbsResponseDataRaw.clear();
        _sigHashAlgo = crypto::EHASH_UNKNOWN;
        _signatureValue.clear();
    }

    ERetCode COcspResponse::find(const CCert& cert, COcspEntry& out) const {
        if (cert.empty()) {
            return ERET_INVAL;
        }

        for (const COcspEntry& entry : _entries) {
            if (entry.isFor(cert)) {
                out = entry;
                return ERET_OK;
            }
        }

        return ERET_INVAL;
    }

    ERetCode COcspResponse::check(const CCert& cert) const {
        COcspEntry entry;
        ERetCode rc = find(cert, entry);
        if (rc != ERET_OK) {
            return rc; // --> ERET_INVAL: not found, or cert itself empty/invalid
        }

        switch (entry.status()) {
            case EOCSPENT_GOOD:    return ERET_OK;
            case EOCSPENT_REVOKED: return ERET_ALREADY;
            default:               return ERET_NOTSUP; // --> EOCSPENT_UNKNOWN
        }
    }

    ERetCode COcspResponse::verifySignature(const CCert& responderCert) const {
        if (_status != EOCSP_OK || _tbsResponseDataRaw.empty() || _signatureValue.empty()) {
            return ERET_INVAL;
        }

        crypto::IAsymmetricContextPtr ctx = responderCert.createAsymmetricContext();
        if (!ctx) {
            return ERET_UNKNOWN;
        }

        // --> Whether to hash first is decided by the key that will actually do the verifying,
        // not by _sigHashAlgo == EHASH_UNKNOWN. That value is ambiguous: resolveSigAlgo() leaves
        // it untouched for the SHA-3 family, anything malformed, or any other OID absent from
        // SIG_ALGOS -- and for id-RSASSA-PSS, whose digest lives in its AlgorithmIdentifier
        // parameters, which only CCert::importDer() reads (this responder never does). All of
        // that is indistinguishable from EdDSA's legitimate "no separate hash". Reading it as EdDSA handed the raw tbsResponseData to an ECDSA/DSA verify as
        // though it were a digest -- which truncates it to the order's bit length, so the
        // signature covered a prefix of the plaintext instead of a collision-resistant hash of
        // the whole message. An unrecognized algorithm must fail closed instead.
        crypto::IPublicKeyPtr responderKey = responderCert.publicKey();
        crypto::EAsymmetrics keyAlgo = responderKey ? responderKey->algorithm() : crypto::EASYM_UNKNOWN;
        if (CCert::signsMessageDirectly(keyAlgo)) {
            // self-hashing (EdDSA, ML-DSA) -- the raw tbsResponseData bytes are the message
            // itself.
            return ctx->verify(_tbsResponseDataRaw.toSpan(), _signatureValue.toSpan());
        }

        if (_sigHashAlgo == crypto::EHASH_UNKNOWN) {
            return ERET_NOTSUP; // --> signature algorithm this library can't identify
        }

        crypto::IHasherPtr hasher;
        if (crypto::IHasher::create(_sigHashAlgo, hasher) != ERET_OK || !hasher) {
            return ERET_HASH_PIPE;
        }

        CBuffer digest;
        if (!digest.resize(hasher->byteWidth())
            || !hasher->push(_tbsResponseDataRaw.toSpan())
            || !hasher->finish(SByteSpan(digest.toPtr(), digest.size())))
        {
            return ERET_HASH_PIPE;
        }

        return ctx->verify(digest.toSpan(), _signatureValue.toSpan());
    }

    // ------------------------------------------------------------------------------------------
    // COcspResponseBuilder
    // ------------------------------------------------------------------------------------------

    ERetCode COcspResponseBuilder::add(const COcspEntry& entry) {
        if (entry.empty()) {
            return ERET_INVAL;
        }

        for (size_t i = 0; i < _entries.size(); ++i) {
            if (_entries[i].certId().equals(entry.certId())) {
                _entries[i] = entry;
                return ERET_OK;
            }
        }

        return _entries.add(entry) ? ERET_OK : ERET_NOMEM;
    }

    ERetCode COcspResponseBuilder::add(
        const CCert& cert, const CCert& issuer, EOcspEntryStatus status, const SDateTime& thisUpdate,
        const SDateTime& nextUpdate, ECrlReasons reason, const SDateTime& revocationTime, crypto::EHashers hashAlgo
    ) {
        if (cert.empty() || issuer.empty() || thisUpdate.isZero()) {
            return ERET_INVAL;
        }
        if (status == EOCSPENT_REVOKED && revocationTime.isZero()) {
            return ERET_INVAL;
        }

        COcspCertId certId;
        ERetCode rc = COcspCertId::make(cert, issuer, hashAlgo, certId);
        if (rc != ERET_OK) {
            return rc;
        }

        return add(COcspEntry(certId, status, reason, thisUpdate, nextUpdate, revocationTime));
    }

    ERetCode COcspResponseBuilder::remove(const CCert& cert) {
        if (cert.empty()) {
            return ERET_INVAL;
        }

        for (size_t i = 0; i < _entries.size(); ++i) {
            if (_entries[i].isFor(cert)) {
                return _entries.remove(i) ? ERET_OK : ERET_UNKNOWN;
            }
        }

        return ERET_INVAL;
    }

    /* Builds and signs a response -- see its own doc comment in ocsp.hpp for the
     * EOCSP_OK-vs-anything-else split. */
    ERetCode COcspResponseBuilder::build(const CCert& responder, COctet& out) const {
        out = COctet();

        if (_status != EOCSP_OK) {
            uint8_t statusBuf[5];
            size_t written = 0;
            if (!CEncoder::encodeEnumerated(SByteSpan(statusBuf, sizeof(statusBuf)), uint32_t(_status), written)) {
                return ERET_UNKNOWN;
            }

            CBuffer body;
            if (!CDer::appendTlv(body, CTag::ENUMERATED, SReadOnlyByteSpan(statusBuf, written))) {
                return ERET_UNKNOWN;
            }

            CBuffer full;
            if (!CDer::appendSequence(full, body.toSpan())) {
                return ERET_UNKNOWN;
            }

            out = COctet(full.toSpan());
            return ERET_OK;
        }

        if (responder.empty() || _producedAt.isZero() || _entries.empty()) {
            return ERET_INVAL;
        }

        CDistinguishedName effectiveResponderName = _responderName;
        if (effectiveResponderName.empty()) {
            effectiveResponderName = responder.subject();
        }
        if (effectiveResponderName.empty()) {
            return ERET_INVAL;
        }

        crypto::IPrivateKeyPtr responderPriv = responder.privateKey();
        if (!responderPriv) {
            return ERET_KEY_EMPTY;
        }

        crypto::EAsymmetrics responderWhich = responderPriv->algorithm();

        CString sigOid;
        crypto::EHashers sigHash = crypto::EHASH_UNKNOWN;
        COctet sigAlgoParams;
        if (!CCert::resolveSigAlgoForSigning(responderWhich, crypto::EHASH_UNKNOWN, false, sigOid, sigHash, sigAlgoParams)) {
            return ERET_NOTSUP;
        }

        bool sigIsSelfHashing = (sigHash == crypto::EHASH_UNKNOWN);

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

        // responderID ::= CHOICE { byName [1] Name, ... } -- byName only.
        CBuffer responderIdTlv;
        {
            CBuffer nameTlv;
            if (!CCert::encodeName(effectiveResponderName, nameTlv)) {
                return ERET_UNKNOWN;
            }
            if (!CDer::appendTlv(responderIdTlv, CTag(EATAG_CONTEXT_SPECIFIC, 1, true), nameTlv.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        CBuffer responseDataBody;
        // version [0] EXPLICIT DEFAULT v1 -- omitted (only v1 is ever produced).
        if (!CDer::appendRaw(responseDataBody, responderIdTlv.toSpan())) {
            return ERET_UNKNOWN;
        }
        if (!OcspCodec::encodeGeneralizedTime(_producedAt, responseDataBody)) {
            return ERET_INVAL;
        }

        CBuffer responsesBody;
        for (const COcspEntry& entry : _entries) {
            COctet entryTlv;
            ERetCode rc = entry.encode(entryTlv);
            if (rc != ERET_OK) {
                return rc;
            }
            if (!CDer::appendRaw(responsesBody, entryTlv.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        CBuffer responsesTlv;
        if (!CDer::appendSequence(responsesTlv, responsesBody.toSpan())) {
            return ERET_UNKNOWN;
        }
        if (!CDer::appendRaw(responseDataBody, responsesTlv.toSpan())) {
            return ERET_UNKNOWN;
        }

        if (!_nonceBytes.empty()) {
            CBuffer nonceExtnValue;
            if (!OcspCodec::buildNonceExtnValue(_nonceBytes.toSpan(), nonceExtnValue)) {
                return ERET_UNKNOWN;
            }

            CBuffer extListTlv;
            if (!OcspCodec::appendSingleExtensionList(extListTlv, OcspCodec::OID_NONCE, nonceExtnValue.toSpan())) {
                return ERET_UNKNOWN;
            }

            if (!CDer::appendTlv(responseDataBody, CTag(EATAG_CONTEXT_SPECIFIC, 1, true), extListTlv.toSpan())) {
                return ERET_UNKNOWN;
            }
        }

        CBuffer responseDataTlv;
        if (!CDer::appendSequence(responseDataTlv, responseDataBody.toSpan())) {
            return ERET_UNKNOWN;
        }

        // --- Sign tbsResponseData. ---
        crypto::IAsymmetricContextPtr ctx = responder.createAsymmetricContext();
        if (!ctx) {
            return ERET_UNKNOWN;
        }

        COctet toSign;
        if (sigIsSelfHashing) {
            toSign = COctet(responseDataTlv.toSpan());
        } else {
            crypto::IHasherPtr hasher;
            if (crypto::IHasher::create(sigHash, hasher) != ERET_OK || !hasher) {
                return ERET_HASH_PIPE;
            }

            CBuffer digest;
            if (!digest.resize(hasher->byteWidth())
                || !hasher->push(responseDataTlv.toSpan())
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

        // BasicOCSPResponse ::= SEQUENCE { tbsResponseData, signatureAlgorithm, signature, certs? }
        CBuffer basicBody;
        if (!CDer::appendRaw(basicBody, responseDataTlv.toSpan()) || !CDer::appendRaw(basicBody, sigAlgoIdTlv.toSpan())) {
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
            if (!CDer::appendTlv(basicBody, CTag::STRING_BIT, SReadOnlyByteSpan(bitContent.toPtr(), written))) {
                return ERET_UNKNOWN;
            }
        }

        CBuffer basicTlv;
        if (!CDer::appendSequence(basicTlv, basicBody.toSpan())) {
            return ERET_UNKNOWN;
        }

        // ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
        CBuffer responseBytesBody;
        {
            size_t oidNeeded = CEncoder::encodedOidStringSize(CString(OcspCodec::OID_BASIC_RESPONSE));
            if (!oidNeeded) {
                return ERET_UNKNOWN;
            }

            CBuffer oidContent;
            size_t oidWritten = 0;
            if (!oidContent.resize(oidNeeded)
                || !CEncoder::encodeOidString(oidContent.toSpan(), CString(OcspCodec::OID_BASIC_RESPONSE), oidWritten))
            {
                return ERET_UNKNOWN;
            }

            if (!CDer::appendTlv(responseBytesBody, CTag::OBJ_ID, SReadOnlyByteSpan(oidContent.toPtr(), oidWritten))
                || !CDer::appendTlv(responseBytesBody, CTag::STRING_OCTET, basicTlv.toSpan()))
            {
                return ERET_UNKNOWN;
            }
        }

        CBuffer responseBytesTlv;
        if (!CDer::appendSequence(responseBytesTlv, responseBytesBody.toSpan())) {
            return ERET_UNKNOWN;
        }

        // OCSPResponse ::= SEQUENCE { responseStatus, responseBytes [0] EXPLICIT }
        CBuffer respBody;
        {
            uint8_t statusBuf[5];
            size_t written = 0;
            if (!CEncoder::encodeEnumerated(SByteSpan(statusBuf, sizeof(statusBuf)), uint32_t(EOCSP_OK), written)) {
                return ERET_UNKNOWN;
            }
            if (!CDer::appendTlv(respBody, CTag::ENUMERATED, SReadOnlyByteSpan(statusBuf, written))) {
                return ERET_UNKNOWN;
            }
        }
        if (!CDer::appendTlv(respBody, CTag(EATAG_CONTEXT_SPECIFIC, 0, true), responseBytesTlv.toSpan())) {
            return ERET_UNKNOWN;
        }

        CBuffer respFull;
        if (!CDer::appendSequence(respFull, respBody.toSpan())) {
            return ERET_UNKNOWN;
        }

        out = COctet(respFull.toSpan());
        return ERET_OK;
    }

    /* Decodes OCSPResponse (RFC 6960 4.2.1) -- see this method's own doc comment in ocsp.hpp. */
    ERetCode COcspResponse::decode(const COctet& rawData) {
        if (rawData.empty()) {
            return ERET_INVAL;
        }

        CReader outer(rawData.toSpan(), EAENC_DER);
        CReader respSeq;
        if (!outer.readSequence(respSeq)) {
            return ERET_BADREQ;
        }

        // --> The OCSPResponse SEQUENCE must be the whole input, not merely its prefix; see
        // CCert::importDer() for why trailing bytes are not a harmless leniency.
        if (!outer.atEnd()) {
            return ERET_BADREQ;
        }

        uint32_t statusValue = 0;
        if (!respSeq.readEnumerated(statusValue)) {
            return ERET_BADREQ;
        }

        EOcspStatus status = EOcspStatus(statusValue);

        if (status != EOCSP_OK) {
            clear();
            _rawData = rawData;
            _status = status;
            return ERET_OK;
        }

        CTag tag;
        SReadOnlyByteSpan content;
        if (!respSeq.readNextElement(tag, content) || tag != CTag(EATAG_CONTEXT_SPECIFIC, 0, true)) {
            return ERET_BADREQ;
        }

        CReader responseBytesOuter(content, EAENC_DER);
        CReader rbSeq;
        if (!responseBytesOuter.readSequence(rbSeq)) {
            return ERET_BADREQ;
        }

        CString responseTypeOid;
        if (!rbSeq.readOidString(responseTypeOid)) {
            return ERET_BADREQ;
        }
        if (responseTypeOid.compare(OcspCodec::OID_BASIC_RESPONSE) != 0) {
            return ERET_NOTSUP;
        }

        COctet basicResponseDer;
        if (!rbSeq.readOctetString(basicResponseDer)) {
            return ERET_BADREQ;
        }

        CReader basicOuter(basicResponseDer.toSpan(), EAENC_DER);
        CReader basicSeq;
        if (!basicOuter.readSequence(basicSeq)) {
            return ERET_BADREQ;
        }

        SReadOnlyByteSpan beforeTbs = basicSeq.remaining();
        CTag tbsTag;
        SReadOnlyByteSpan tbsContent;
        if (!basicSeq.readNextElement(tbsTag, tbsContent) || tbsTag != CTag::SEQ) {
            return ERET_BADREQ;
        }
        SReadOnlyByteSpan tbsFullTlv(beforeTbs.data, size_t(tbsContent.data + tbsContent.size - beforeTbs.data));

        CReader tbsSeq(tbsContent, EAENC_DER);

        uint32_t version = 0;
        CDistinguishedName responderName;
        SDateTime producedAt;
        TArray<COcspEntry> entries;
        COctet nonceBytes;

        CTag rdTag;
        SReadOnlyByteSpan rdContent;
        if (!tbsSeq.readNextElement(rdTag, rdContent)) {
            return ERET_BADREQ;
        }

        if (rdTag == CTag(EATAG_CONTEXT_SPECIFIC, 0, true)) { // version -- optional
            CReader verReader(rdContent, EAENC_DER);
            int64_t v = 0;
            if (verReader.readInteger(v) && v >= 0) {
                version = uint32_t(v);
            }
            if (!tbsSeq.readNextElement(rdTag, rdContent)) {
                return ERET_BADREQ;
            }
        }

        // responderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash } -- byKey not decoded.
        if (rdTag == CTag(EATAG_CONTEXT_SPECIFIC, 1, true)) {
            CReader nameReader(rdContent, EAENC_DER);
            if (!nameReader.readDistinguishedName(responderName)) {
                return ERET_BADREQ;
            }
        }

        if (!tbsSeq.readGeneralizedTime(producedAt)) {
            return ERET_BADREQ;
        }

        CReader responsesSeq;
        if (!tbsSeq.readSequence(responsesSeq)) {
            return ERET_BADREQ;
        }

        while (!responsesSeq.atEnd()) {
            SReadOnlyByteSpan beforeEntry = responsesSeq.remaining();
            CTag entryTag;
            SReadOnlyByteSpan entryContent;
            if (!responsesSeq.readNextElement(entryTag, entryContent)) {
                break;
            }
            if (entryTag != CTag::SEQ) {
                continue;
            }

            SReadOnlyByteSpan entryTlv(beforeEntry.data, size_t(entryContent.data + entryContent.size - beforeEntry.data));
            COcspEntry entry;
            if (COcspEntry::decode(COctet(entryTlv), entry) == ERET_OK) {
                entries.add(move(entry));
            }
        }

        if (!tbsSeq.atEnd()) {
            CTag extTag;
            SReadOnlyByteSpan extContent;
            if (tbsSeq.readNextElement(extTag, extContent) && extTag == CTag(EATAG_CONTEXT_SPECIFIC, 1, true)) {
                CReader extListOuter(extContent, EAENC_DER);
                CReader extList;
                if (extListOuter.readSequence(extList)) {
                    OcspCodec::scanForNonce(extList, nonceBytes);
                }
            }
        }

        CReader sigAlgoSeq;
        if (!basicSeq.readSequence(sigAlgoSeq)) {
            return ERET_BADREQ;
        }

        CString sigAlgoOid;
        if (!sigAlgoSeq.readOidString(sigAlgoOid)) {
            return ERET_BADREQ;
        }

        crypto::EHashers sigHash = crypto::EHASH_UNKNOWN;
        CString sigAlgoName;
        CCert::resolveSigAlgo(sigAlgoOid, sigHash, sigAlgoName);

        SReadOnlyByteSpan sigBits;
        uint8_t sigUnused = 0;
        // --> sigUnused must be 0: a signature is a whole number of octets. See
        // CCert::importDer() for why leaving it unchecked mattered.
        if (!basicSeq.readBitString(sigBits, sigUnused) || sigUnused != 0) {
            return ERET_BADREQ;
        }

        // certs [0] EXPLICIT OPTIONAL -- not read; it's the last field regardless.

        _rawData = rawData;
        _status = EOCSP_OK;
        _version = version;
        _responderName = move(responderName);
        _producedAt = producedAt;
        _entries = move(entries);
        _nonceBytes = move(nonceBytes);
        _tbsResponseDataRaw = COctet(tbsFullTlv);
        _sigHashAlgo = sigHash;
        _signatureValue = COctet(sigBits);

        return ERET_OK;
    }

} // namespace x509
} // namespace certpp
