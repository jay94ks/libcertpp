#include <certpp/x509/kemspki.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/asn1/encoder.hpp>
#include <certpp/asn1/reader.hpp>
#include <certpp/oid.hpp>

namespace certpp {
namespace x509 {

    namespace {
        using namespace asn1;

        bool oidFor(crypto::EKems which, COid& oid) {
            switch (which) {
                case crypto::EKEM_MLKEM512:  oid = COid::MLKEM512;  return true;
                case crypto::EKEM_MLKEM768:  oid = COid::MLKEM768;  return true;
                case crypto::EKEM_MLKEM1024: oid = COid::MLKEM1024; return true;
                default: return false;
            }
        }

        bool algorithmFor(const COid& oid, crypto::EKems& which) {
            if (oid == COid(COid::MLKEM512))  { which = crypto::EKEM_MLKEM512;  return true; }
            if (oid == COid(COid::MLKEM768))  { which = crypto::EKEM_MLKEM768;  return true; }
            if (oid == COid(COid::MLKEM1024)) { which = crypto::EKEM_MLKEM1024; return true; }
            return false;
        }

        bool appendOid(CBuffer& out, const COid& oid) {
            const size_t needed = CEncoder::encodedOidSize(oid.raw());
            CBuffer content;
            size_t written = 0;
            return needed && content.resize(needed)
                && CEncoder::encodeOid(content.toSpan(), oid.raw(), written)
                && CDer::appendTlv(out, CTag::OBJ_ID,
                    SReadOnlyByteSpan(content.toPtr(), written));
        }
    }

    ERetCode CKemSubjectPublicKeyInfo::encode(
        const crypto::IKemPublicKeyPtr& key, CBuffer& out
    ) {
        out.clear();
        if (!key) {
            return ERET_KEY_EMPTY;
        }

        COid oid;
        if (!oidFor(key->algorithm(), oid)) {
            return ERET_NOTSUP;
        }

        COctet raw;
        const ERetCode serialized = key->serialize(raw);
        if (serialized != ERET_OK) {
            return serialized;
        }

        CBuffer algorithmBody, algorithmIdentifier, body;
        if (!appendOid(algorithmBody, oid)
            || !CDer::appendSequence(algorithmIdentifier, algorithmBody.toSpan())
            || !CDer::appendRaw(body, algorithmIdentifier.toSpan())) {
            return ERET_NOMEM;
        }

        CBuffer bitContent;
        size_t written = 0;
        if (!bitContent.resize(raw.size() + 1)
            || !CEncoder::encodeBitString(bitContent.toSpan(), raw.toSpan(), 0, written)
            || !CDer::appendTlv(body, CTag::STRING_BIT,
                SReadOnlyByteSpan(bitContent.toPtr(), written))
            || !CDer::appendSequence(out, body.toSpan())) {
            out.clear();
            return ERET_NOMEM;
        }

        return ERET_OK;
    }

    ERetCode CKemSubjectPublicKeyInfo::decode(
        SReadOnlyByteSpan der, crypto::EKems& outAlgorithm,
        crypto::IKemPublicKeyPtr& outKey
    ) {
        outAlgorithm = crypto::EKEM_UNKNOWN;
        outKey.reset();

        asn1::CReader outer(der, asn1::EAENC_DER), spki, algorithm;
        if (!outer.readSequence(spki) || !outer.atEnd()
            || !spki.readSequence(algorithm)) {
            return ERET_KEY_FORMAT;
        }

        SRawOid rawOid;
        if (!algorithm.readOid(rawOid) || !algorithm.atEnd()
            || !algorithmFor(COid(rawOid), outAlgorithm)) {
            outAlgorithm = crypto::EKEM_UNKNOWN;
            return ERET_NOTSUP;
        }

        SReadOnlyByteSpan publicKey;
        uint8_t unusedBits = 0;
        if (!spki.readBitString(publicKey, unusedBits) || unusedBits != 0 || !spki.atEnd()) {
            outAlgorithm = crypto::EKEM_UNKNOWN;
            return ERET_KEY_FORMAT;
        }

        crypto::IKemPtr kem = crypto::IKem::builtIn(outAlgorithm);
        if (!kem || !(outKey = kem->createPublicKey(publicKey))) {
            outAlgorithm = crypto::EKEM_UNKNOWN;
            return ERET_KEY_FORMAT;
        }

        return ERET_OK;
    }

} // namespace x509
} // namespace certpp
