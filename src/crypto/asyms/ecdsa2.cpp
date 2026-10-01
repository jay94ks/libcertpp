#include <certpp/crypto/asyms/ecdsa2.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/asn1/decoder.hpp>
#include <certpp/io/buffer.hpp>
#include <cstring>
#include <memory>
#include <utility>

namespace certpp {
namespace crypto {

    namespace {

        using asn1::CDer;

        class Ec2PublicKey : public IPublicKey {
        private:
            // A value, not a pointer/reference -- see EcPublicKey::_curve's comment in
            // ecdsa.cpp for why (a generated key can outlive the CEcdsa2 it came from).
            CEc2Curve _curve;
            SEc2Point _q;

            /* Lexicographic byte comparison of two same-field (hence same-width) GF(2^m)
             * elements' fixed-width encodings -- CGf2m has no compare() (a field has no natural
             * ordering), but IKeyBase::compare() only needs *some* deterministic total order, not
             * a meaningful one. Kept here (private to the one class that needs it) rather than
             * promoted to CGf2m, since giving that class a public compare()-shaped method (even
             * one honestly disclaiming mathematical meaning) cuts against its own documented
             * "no ordering" design stance for this single call site. */
            static int32_t compareGf2m(const CGf2m& a, const CGf2m& b) {
                TArray<uint8_t> aBytes, bBytes;
                a.toBigEndian(aBytes);
                b.toBigEndian(bBytes);
                return int32_t(std::memcmp(aBytes.begin(), bBytes.begin(), aBytes.size()));
            }

        public:
            Ec2PublicKey(const CEc2Curve& curve, SEc2Point q, EAsymmetrics which)
                : _curve(curve), _q(std::move(q))
            {
                algorithm(which);
            }

            SKeySize keySize() const override {
                return _curve.field->m;
            }

            ERetCode serialize(COctet& out) const override {
                TArray<uint8_t> bytes;
                if (!_curve.encodePoint(_q, bytes)) {
                    return ERET_KEY_PARAM; // q's own coordinates don't fit the curve's field width
                }

                out = COctet(SReadOnlyByteSpan(bytes.begin(), bytes.size()));
                return ERET_OK;
            }

            int32_t compare(const IKeyBasePtr& other) const override {
                if (!other) {
                    return 1;
                }

                auto o = std::dynamic_pointer_cast<Ec2PublicKey>(other);
                if (!o) {
                    auto otherAsym = std::dynamic_pointer_cast<IAsymmetricKeyBase>(other);
                    return otherAsym ? (int32_t(keySize()) - int32_t(otherAsym->keySize())) : 1;
                }

                if (_q.infinity != o->_q.infinity) {
                    return _q.infinity ? -1 : 1;
                }
                if (_q.infinity) {
                    return 0;
                }

                int32_t d = compareGf2m(_q.x, o->_q.x);
                return d ? d : compareGf2m(_q.y, o->_q.y);
            }

            const SEc2Point& q() const { return _q; }
            const CEc2Curve& curve() const { return _curve; }
        };

        class Ec2PrivateKey : public IPrivateKey {
        private:
            CEc2Curve _curve; // owned by value -- see Ec2PublicKey::_curve's comment
            CBigNum _d;
            IPublicKeyPtr _publicKey;

        public:
            Ec2PrivateKey(const CEc2Curve& curve, CBigNum d, IPublicKeyPtr publicKey, EAsymmetrics which)
                : _curve(curve), _d(std::move(d)), _publicKey(std::move(publicKey))
            {
                algorithm(which);
            }

            SKeySize keySize() const override {
                return _curve.field->m;
            }

            ERetCode serialize(COctet& out) const override {
                auto pub = std::dynamic_pointer_cast<Ec2PublicKey>(_publicKey);
                if (!pub) {
                    return ERET_KEY_ERROR; // this key's own linked public key is missing/wrong type
                }

                TArray<uint8_t> pubBytes;
                if (!_curve.encodePoint(pub->q(), pubBytes)) {
                    return ERET_KEY_PARAM; // pub's own coordinates don't fit the curve's field width
                }

                CBuffer inner;
                bool ok = CDer::appendBigInteger(inner, CBigNum(uint64_t(0)))
                    && CDer::appendBigInteger(inner, _d)
                    && CDer::appendTlv(inner, asn1::CTag(asn1::EAUTAG_STRING_OCTET, false),
                        SReadOnlyByteSpan(pubBytes.begin(), pubBytes.size()));

                if (!ok) {
                    return ERET_UNKNOWN;
                }

                CBuffer der;
                if (!CDer::appendSequence(der, inner.toSpan())) {
                    return ERET_UNKNOWN;
                }

                out = COctet(der.toSpan());
                return ERET_OK;
            }

            int32_t compare(const IKeyBasePtr& other) const override {
                if (!other) {
                    return 1;
                }

                auto o = std::dynamic_pointer_cast<Ec2PrivateKey>(other);
                if (!o) {
                    auto otherAsym = std::dynamic_pointer_cast<IAsymmetricKeyBase>(other);
                    return otherAsym ? (int32_t(keySize()) - int32_t(otherAsym->keySize())) : 1;
                }

                return _d.compare(o->_d);
            }

            IPublicKeyPtr publicKey() const override {
                return _publicKey;
            }

            const CBigNum& d() const { return _d; }
            const CEc2Curve& curve() const { return _curve; }
        };

        class Ec2Context : public IAsymmetricContext {
        protected:
            void onReset() override {
                auto priv = std::dynamic_pointer_cast<Ec2PrivateKey>(privateKey());
                if (priv) {
                    size_t orderBytes = (priv->curve().n.bitLength() + 7) / 8;
                    sizeOfSign(CDer::maxSignatureSize(orderBytes));
                    sizeOfDigest(orderBytes);
                    return;
                }

                auto pub = std::dynamic_pointer_cast<Ec2PublicKey>(publicKey());
                if (pub) {
                    size_t orderBytes = (pub->curve().n.bitLength() + 7) / 8;
                    sizeOfSign(CDer::maxSignatureSize(orderBytes));
                    sizeOfDigest(orderBytes);
                }
            }

        public:
            ERetCode sign(const SReadOnlyByteSpan& digest, SByteSpan& out) override {
                if (!privateKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto priv = std::dynamic_pointer_cast<Ec2PrivateKey>(privateKey());
                if (!priv) {
                    return ERET_KEY_FORMAT;
                }

                const CEc2Curve& curve = priv->curve();
                const CBigNum& n = curve.n;
                const CBigNum& d = priv->d();

                CBigNum z = CBigNum::fromBigEndianTruncated(digest, n.bitLength());

                CBigNum nMinus1(n);
                nMinus1.sub(CBigNum(uint64_t(1)));

                CBigNum r, s;
                for (int attempt = 0; attempt < 1000; ++attempt) {
                    CBigNum k;
                    if (!CBigNum::randomBelow(nMinus1, k)) {
                        return ERET_UNKNOWN;
                    }
                    k.add(CBigNum(uint64_t(1))); // k in [1, n-1]

                    SEc2Point kg = curve.scalarMulBase(k);
                    if (kg.infinity) {
                        continue;
                    }

                    r = kg.x.toInteger();
                    r.mod(n);
                    if (r.isZero()) {
                        continue;
                    }

                    CBigNum kInv;
                    if (!CBigNum::modInverse(k, n, kInv)) {
                        continue;
                    }

                    CBigNum dr(d);
                    dr.mulMod(r, n);

                    CBigNum sum(z);
                    sum.add(dr);
                    sum.mod(n);

                    kInv.mulMod(sum, n);
                    s = std::move(kInv);

                    if (!s.isZero()) {
                        break;
                    }
                }

                if (r.isZero() || s.isZero()) {
                    return ERET_UNKNOWN;
                }

                CBuffer inner;
                if (!CDer::appendBigInteger(inner, r) || !CDer::appendBigInteger(inner, s)) {
                    return ERET_UNKNOWN;
                }

                CBuffer der;
                if (!CDer::appendSequence(der, inner.toSpan())) {
                    return ERET_UNKNOWN;
                }

                if (out.size < der.size()) {
                    return ERET_NOSPC;
                }

                std::memcpy(out.data, der.toPtr(), der.size());
                out = SByteSpan(out.data, der.size());

                return ERET_OK;
            }

            ERetCode verify(const SReadOnlyByteSpan& digest, const SReadOnlyByteSpan& signature) override {
                if (!publicKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto pub = std::dynamic_pointer_cast<Ec2PublicKey>(publicKey());
                if (!pub) {
                    return ERET_KEY_FORMAT;
                }

                const CEc2Curve& curve = pub->curve();
                const CBigNum& n = curve.n;

                TReadOnlySpan<uint8_t> content;
                if (!CDer::readOuterSequence(signature, content)) {
                    return ERET_BADREQ;
                }

                CBigNum r, s;
                if (!CDer::readBigInteger(content, r) || !CDer::readBigInteger(content, s) || !content.empty()) {
                    return ERET_BADREQ;
                }

                if (r.isZero() || r >= n || s.isZero() || s >= n) {
                    return ERET_BADREQ;
                }

                CBigNum w;
                if (!CBigNum::modInverse(s, n, w)) {
                    return ERET_BADREQ;
                }

                CBigNum z = CBigNum::fromBigEndianTruncated(digest, n.bitLength());

                z.mulMod(w, n);
                CBigNum u1 = std::move(z);

                CBigNum u2(r);
                u2.mulMod(w, n);

                SEc2Point p1 = curve.scalarMulBase(u1);
                SEc2Point p2 = curve.scalarMul(pub->q(), u2);
                SEc2Point sum = curve.add(p1, p2);

                if (sum.infinity) {
                    return ERET_BADREQ;
                }

                CBigNum v = sum.x.toInteger();
                v.mod(n);
                return v == r ? ERET_OK : ERET_BADREQ;
            }

            ERetCode createEncrypter(IAsymmetricTransformerPtr&) override {
                return ERET_NOTSUP;
            }

            ERetCode createDecrypter(IAsymmetricTransformerPtr&) override {
                return ERET_NOTSUP;
            }
        };

    } // namespace

    CEcdsa2::CEcdsa2(EEc2KnownCurves which) : _which(CEc2Curve::identify(which)) {
        CEc2Curve::knownCurves(which, _curve);

        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(_curve.field->m));
        keySizes(specs);
    }

    ERetCode CEcdsa2::generateKeyPair(SKeySize keySize, SKeyPair& out) {
        out = SKeyPair();

        if (keySize != _curve.field->m) {
            return ERET_KEY_SIZE;
        }

        CBigNum nMinus1(_curve.n);
        nMinus1.sub(CBigNum(uint64_t(1)));

        CBigNum d;
        if (!CBigNum::randomBelow(nMinus1, d)) {
            return ERET_UNKNOWN;
        }
        d.add(CBigNum(uint64_t(1))); // d in [1, n-1]

        SEc2Point q = _curve.scalarMulBase(d);
        if (q.infinity) {
            return ERET_AGAIN; // same degenerate-candidate condition checkPrivateKey() checks
        }

        auto pub = std::make_shared<Ec2PublicKey>(_curve, q, _which);
        auto priv = std::make_shared<Ec2PrivateKey>(_curve, d, pub, _which);

        if (checkPrivateKey(priv) != ERET_OK) {
            return ERET_AGAIN;
        }

        out = SKeyPair(pub, priv);
        return ERET_OK;
    }

    ERetCode CEcdsa2::checkPrivateKey(const IPrivateKeyPtr& key) const {
        auto priv = std::dynamic_pointer_cast<Ec2PrivateKey>(key);
        if (!priv) {
            return ERET_KEY_FORMAT;
        }

        const CEc2Curve& curve = priv->curve();
        const CBigNum& d = priv->d();
        const CBigNum& n = curve.n;

        // Private scalar range: d in [1, n-1].
        if (d.isZero() || d >= n) {
            return ERET_KEY_PARAM;
        }

        auto pub = std::dynamic_pointer_cast<Ec2PublicKey>(priv->publicKey());
        if (!pub) {
            return ERET_KEY_ERROR;
        }

        const SEc2Point& q = pub->q();

        // 1. Point at infinity.
        if (q.infinity) {
            return ERET_KEY_PARAM;
        }

        // 2. Field range: unlike CBigNum, CGf2m::fromBigEndian() already rejects any bit at or
        // above field.m at construction time, so a coordinate's *value* can't be out of range --
        // the meaningful check here is that it's tied to the curve's own field singleton at all
        // (guards against a coordinate from a mismatched/foreign field slipping through).
        if (q.x.field() != curve.field || q.y.field() != curve.field) {
            return ERET_KEY_PARAM;
        }

        // 3. Curve equation.
        if (!curve.isOnCurve(q)) {
            return ERET_KEY_PARAM;
        }

        // 4. Correct (order-n) subgroup: n*Q must be the point at infinity. Always true for a
        // point honestly computed as d*G on this library's cofactor-1 curves, but this also
        // re-validates a key parsed from untrusted storage via createPrivateKey().
        SEc2Point check = curve.scalarMul(q, n);
        if (!check.infinity) {
            return ERET_KEY_PARAM;
        }

        // 5. Q must actually be d*G -- the four checks above only establish that Q is *some*
        // legitimate point on the curve, not that it's *this key's* point; without this, a
        // private scalar could be paired with an unrelated (but otherwise well-formed) public
        // point and still pass every check above.
        if (!curve.scalarMulBase(d).equals(q)) {
            return ERET_KEY_ERROR;
        }

        return ERET_OK;
    }

    IPublicKeyPtr CEcdsa2::createPublicKey(const SReadOnlyByteSpan& keyData) const {
        SEc2Point q;
        if (!_curve.decodePoint(keyData, q) || q.infinity) {
            return nullptr;
        }

        return std::make_shared<Ec2PublicKey>(_curve, q, _which);
    }

    IPrivateKeyPtr CEcdsa2::createPrivateKey(const SReadOnlyByteSpan& keyData) const {
        TReadOnlySpan<uint8_t> content;
        if (!CDer::readOuterSequence(keyData, content)) {
            return nullptr;
        }

        CBigNum version;
        if (!CDer::readBigInteger(content, version) || version != CBigNum(uint64_t(0))) {
            return nullptr;
        }

        CBigNum d;
        if (!CDer::readBigInteger(content, d)) {
            return nullptr;
        }

        asn1::CTag tag;
        TReadOnlySpan<uint8_t> pubContent;
        if (!asn1::CDecoder::readNextElement(content, asn1::EAENC_DER, tag, pubContent)) {
            return nullptr;
        }

        if (!tag.equals(asn1::CTag(asn1::EAUTAG_STRING_OCTET, false)) || !content.empty()) {
            return nullptr;
        }

        SEc2Point q;
        if (!_curve.decodePoint(pubContent, q)) {
            return nullptr;
        }

        auto pub = std::make_shared<Ec2PublicKey>(_curve, q, _which);
        return std::make_shared<Ec2PrivateKey>(_curve, d, pub, _which);
    }

    IAsymmetricContextPtr CEcdsa2::createContext() const {
        return std::make_shared<Ec2Context>();
    }

} // namespace crypto
} // namespace certpp
