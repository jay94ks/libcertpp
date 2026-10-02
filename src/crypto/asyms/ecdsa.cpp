#include <certpp/crypto/asyms/ecdsa.hpp>
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

        class EcPublicKey : public IPublicKey {
        private:
            // A value, not a pointer/reference: the curve this key was created from may be a
            // per-instance CEcCurve member of some IAsymmetric object (e.g. CEcdsa::_curve)
            // rather than a program-lifetime static, so a key must own an independent copy to
            // stay valid after that object is destroyed.
            CEcCurve _curve;
            SEcPoint _q;

        public:
            EcPublicKey(const CEcCurve& curve, SEcPoint q, EAsymmetrics which)
                : _curve(curve), _q(std::move(q))
            {
                algorithm(which);
            }

            SKeySize keySize() const override {
                return _curve.p.bitLength();
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

                auto o = std::dynamic_pointer_cast<EcPublicKey>(other);
                if (!o) {
                    auto otherAsym = std::dynamic_pointer_cast<IAsymmetricKeyBase>(other);
                    return otherAsym ? (int32_t(keySize()) - int32_t(otherAsym->keySize())) : 1;
                }

                if (_q.infinity != o->_q.infinity) {
                    return _q.infinity ? -1 : 1;
                }

                int32_t d = _q.x.compare(o->_q.x);
                return d ? d : _q.y.compare(o->_q.y);
            }

            const SEcPoint& q() const { return _q; }
            const CEcCurve& curve() const { return _curve; }
        };

        class EcPrivateKey : public IPrivateKey {
        private:
            CEcCurve _curve; // owned by value -- see EcPublicKey::_curve's comment
            CBigNum _d;
            IPublicKeyPtr _publicKey;

        public:
            EcPrivateKey(const CEcCurve& curve, CBigNum d, IPublicKeyPtr publicKey, EAsymmetrics which)
                : _curve(curve), _d(std::move(d)), _publicKey(std::move(publicKey))
            {
                algorithm(which);
            }

            SKeySize keySize() const override {
                return _curve.p.bitLength();
            }

            ERetCode serialize(COctet& out) const override {
                auto pub = std::dynamic_pointer_cast<EcPublicKey>(_publicKey);
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

                auto o = std::dynamic_pointer_cast<EcPrivateKey>(other);
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
            const CEcCurve& curve() const { return _curve; }
        };

        class EcContext : public IAsymmetricContext {
        protected:
            void onReset() override {
                auto priv = std::dynamic_pointer_cast<EcPrivateKey>(privateKey());
                if (priv) {
                    size_t orderBytes = (priv->curve().n.bitLength() + 7) / 8;
                    sizeOfSign(CDer::maxSignatureSize(orderBytes));
                    sizeOfDigest(orderBytes);
                    return;
                }

                auto pub = std::dynamic_pointer_cast<EcPublicKey>(publicKey());
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

                auto priv = std::dynamic_pointer_cast<EcPrivateKey>(privateKey());
                if (!priv) {
                    return ERET_KEY_FORMAT;
                }

                const CEcCurve& curve = priv->curve();
                const CBigNum& n = curve.n;
                const CBigNum& d = priv->d();

                CBigNum z = CBigNum::fromBigEndianTruncated(digest, n.bitLength());

                CBigNum nMinus1(n);
                nMinus1.sub(CBigNum(uint64_t(1)));

                // --> k, and dr alongside it, are the two values here whose exposure is
                // catastrophic rather than merely unwanted: k yields d outright from a published
                // signature (d = (s*k - z) / r mod n), and dr yields it directly (d = dr / r mod
                // n). So both are cleared on every path out of the loop, including the retry
                // paths -- which take a zero r or a non-invertible k and so are unreachable short
                // of a broken CSPRNG, but cost three lines to cover properly.
                CBigNum r, s;
                for (int attempt = 0; attempt < 1000; ++attempt) {
                    CBigNum k;
                    if (!CBigNum::randomBelow(nMinus1, k)) {
                        return ERET_UNKNOWN;
                    }
                    k.add(CBigNum(uint64_t(1))); // k in [1, n-1]

                    SEcPoint kg = curve.scalarMulBase(k);
                    if (kg.infinity) {
                        k.secureClear();
                        continue;
                    }

                    kg.x.mod(n);
                    r = std::move(kg.x);
                    if (r.isZero()) {
                        k.secureClear();
                        continue;
                    }

                    CBigNum kInv;
                    if (!CBigNum::modInverse(k, n, kInv)) {
                        k.secureClear();
                        continue;
                    }

                    CBigNum dr(d);
                    dr.mulMod(r, n);

                    CBigNum sum(z);
                    sum.add(dr);
                    sum.mod(n);

                    kInv.mulMod(sum, n);
                    s = std::move(kInv);

                    k.secureClear();
                    dr.secureClear();
                    sum.secureClear();

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

                auto pub = std::dynamic_pointer_cast<EcPublicKey>(publicKey());
                if (!pub) {
                    return ERET_KEY_FORMAT;
                }

                const CEcCurve& curve = pub->curve();
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

                SEcPoint p1 = curve.scalarMulBase(u1);
                SEcPoint p2 = curve.scalarMul(pub->q(), u2);
                SEcPoint sum = curve.add(p1, p2);

                if (sum.infinity) {
                    return ERET_BADREQ;
                }

                sum.x.mod(n);
                return sum.x == r ? ERET_OK : ERET_BADREQ;
            }

            ERetCode createEncrypter(IAsymmetricTransformerPtr&) override {
                return ERET_NOTSUP;
            }

            ERetCode createDecrypter(IAsymmetricTransformerPtr&) override {
                return ERET_NOTSUP;
            }
        };

    } // namespace

    CEcdsa::CEcdsa(EEcKnownCurves which) : _which(CEcCurve::identify(which)) {
        CEcCurve::knownCurves(which, _curve);

        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(_curve.p.bitLength()));
        keySizes(specs);
    }

    ERetCode CEcdsa::generateKeyPair(SKeySize keySize, SKeyPair& out) {
        out = SKeyPair();

        if (keySize != _curve.p.bitLength()) {
            return ERET_KEY_SIZE;
        }

        CBigNum nMinus1(_curve.n);
        nMinus1.sub(CBigNum(uint64_t(1)));

        CBigNum d;
        if (!CBigNum::randomBelow(nMinus1, d)) {
            return ERET_UNKNOWN;
        }
        d.add(CBigNum(uint64_t(1))); // d in [1, n-1]

        SEcPoint q = _curve.scalarMulBase(d);
        if (q.infinity) {
            return ERET_AGAIN; // same degenerate-candidate condition checkPrivateKey() checks
        }

        auto pub = std::make_shared<EcPublicKey>(_curve, q, _which);
        auto priv = std::make_shared<EcPrivateKey>(_curve, d, pub, _which);

        if (checkPrivateKey(priv) != ERET_OK) {
            return ERET_AGAIN;
        }

        out = SKeyPair(pub, priv);
        return ERET_OK;
    }

    ERetCode CEcdsa::checkPrivateKey(const IPrivateKeyPtr& key) const {
        auto priv = std::dynamic_pointer_cast<EcPrivateKey>(key);
        if (!priv) {
            return ERET_KEY_FORMAT;
        }

        const CEcCurve& curve = priv->curve();
        const CBigNum& d = priv->d();
        const CBigNum& n = curve.n;

        // Private scalar range: d in [1, n-1].
        if (d.isZero() || d >= n) {
            return ERET_KEY_PARAM;
        }

        auto pub = std::dynamic_pointer_cast<EcPublicKey>(priv->publicKey());
        if (!pub) {
            return ERET_KEY_ERROR;
        }

        const SEcPoint& q = pub->q();

        // 1. Point at infinity.
        if (q.infinity) {
            return ERET_KEY_PARAM;
        }

        // 2. Field range: 0 <= x, y < p.
        if (q.x >= curve.p || q.y >= curve.p) {
            return ERET_KEY_PARAM;
        }

        // 3. Curve equation.
        if (!curve.isOnCurve(q)) {
            return ERET_KEY_PARAM;
        }

        // 4. Correct (order-n) subgroup: n*Q must be the point at infinity. Always true for a
        // point honestly computed as d*G on this library's cofactor-1 curves, but this also
        // re-validates a key parsed from untrusted storage via createPrivateKey().
        SEcPoint check = curve.scalarMul(q, n);
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

    IPublicKeyPtr CEcdsa::createPublicKey(const SReadOnlyByteSpan& keyData) const {
        SEcPoint q;
        if (!_curve.decodePoint(keyData, q) || q.infinity) {
            return nullptr;
        }

        return std::make_shared<EcPublicKey>(_curve, q, _which);
    }

    IPrivateKeyPtr CEcdsa::createPrivateKey(const SReadOnlyByteSpan& keyData) const {
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

        SEcPoint q;
        if (!_curve.decodePoint(pubContent, q)) {
            return nullptr;
        }

        auto pub = std::make_shared<EcPublicKey>(_curve, q, _which);
        return std::make_shared<EcPrivateKey>(_curve, d, pub, _which);
    }

    IAsymmetricContextPtr CEcdsa::createContext() const {
        return std::make_shared<EcContext>();
    }

} // namespace crypto
} // namespace certpp
