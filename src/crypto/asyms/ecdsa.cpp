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

            /* ECDH (RFC 5903 / SP 800-56A section 5.7.1.2) over the bound private key's curve.
             *
             * --> NOT constant-time, and the shape of this library's prime-curve arithmetic is
             * why, not an oversight here. CEcCurve::scalarMul() is a branch-free-*shaped* ladder
             * -- it always performs both an addition and a doubling per bit -- but it iterates
             * k.bitLength() times (so the iteration count leaks the scalar's top bit position),
             * dispatches each step through CBigNum::condSwap(), which is a plain
             * `if (swap) std::swap(a, b)` on a bit of the private scalar, and runs on CBigNum,
             * which trims leading zero limbs so every operation's cost depends on its operands.
             * For an online handshake with ephemeral keys -- an IKEv2 exchange, say -- that is a
             * real timing side channel, not a theoretical one. X25519 has a fixed-width,
             * branch-free field (crypto/asyms/fe25519.hpp) for exactly this reason; the prime
             * curves have no equivalent yet, and giving them one is a larger job than adding this
             * operation. Prefer X25519 where the protocol allows a choice. */
            ERetCode deriveSharedSecret(const IPublicKeyPtr& peerPublicKey, SByteSpan& out) override {
                if (!privateKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto priv = std::dynamic_pointer_cast<EcPrivateKey>(privateKey());
                if (!priv) {
                    return ERET_KEY_FORMAT;
                }

                if (!peerPublicKey) {
                    return ERET_KEY_EMPTY;
                }

                auto peer = std::dynamic_pointer_cast<EcPublicKey>(peerPublicKey);
                if (!peer) {
                    return ERET_KEY_FORMAT; // peerPublicKey wasn't created by this algorithm
                }

                const CEcCurve& curve = priv->curve();
                const SEcPoint& q = peer->q();

                // Peer-key validation, re-run here against *our own* curve rather than trusted
                // from whatever curve the peer's EcPublicKey happens to carry. This is the
                // defence against an invalid-curve attack: a point taken from a different,
                // weaker curve, fed in so that the resulting d*Q lands in a small-order group
                // and leaks d a few bits at a time. A point from another curve fails check 3
                // below against ours (or check 2, if its coordinates are simply too wide), so
                // the attack never reaches scalarMul(). createPublicKey() already validates on
                // decode, but a key reaching us as an IPublicKeyPtr need not have come from
                // there, and the cost of repeating three field operations is nothing next to the
                // scalar multiplication that follows.

                // 1. Point at infinity -- d*infinity is infinity, i.e. no secret at all.
                if (q.infinity) {
                    return ERET_KEY_PARAM;
                }

                // 2. Field range: 0 <= x, y < p. CBigNum is an unsigned magnitude, so a negative
                // coordinate isn't representable and only the upper bound needs testing; a
                // non-canonical x or y >= p would otherwise pass check 3, since isOnCurve()
                // works mod p.
                if (q.x >= curve.p || q.y >= curve.p) {
                    return ERET_KEY_PARAM;
                }

                // 3. Curve equation. Of the three, this is the one that actually stops an
                // invalid-curve point: checks 1 and 2 are defence in depth, since no SEC1
                // encoding reaching createPublicKey() can produce either an infinite point or an
                // out-of-range coordinate, and an in-range point from another curve is caught
                // here rather than there (confirmed by disabling each check in turn -- removing
                // this one lets a secp256k1 point through and yields a "shared secret"; removing
                // either of the others changes nothing observable).
                if (!curve.isOnCurve(q)) {
                    return ERET_KEY_PARAM;
                }

                // 4. There is deliberately NO small-subgroup check (an n*Q == infinity test, nor
                // a cofactor multiplication) -- because CEcCurve::decodePoint() already made it,
                // unconditionally, and every EcPublicKey reaching here was built either by
                // createPublicKey() (which goes through decodePoint()) or by generateKeyPair()
                // (whose Q is d*G and so is in the subgroup by construction). Repeating it would
                // cost a second scalar multiplication to re-derive a fact already established.
                //
                // Note that "the curves are cofactor 1, so the only orders are 1 and n" is NOT
                // the reason, though it was when this was written and the comment used to say
                // so. ECURVE_GOST256A and ECURVE_GOST512C have cofactor 4 and do contain points
                // of small order -- any root of x^3 + a*x + b with y = 0 has order 2 -- so on
                // those curves the test is doing real work; it is just doing it at the decode
                // boundary rather than here. Compare X25519
                // (crypto/asyms/x25519.cpp's validatePublicValue(), check 3, cofactor 8), which
                // has no equivalent decode-time check and must therefore test explicitly.
                // Absent, not forgotten -- and absent for a reason that survives the GOST
                // curves' arrival.

                const size_t flen = curve.fieldByteLen();
                if (out.size < flen) {
                    return ERET_NOSPC;
                }

                SEcPoint shared = curve.scalarMul(q, priv->d());

                // Unreachable for a d in [1, n-1] against a point of order n (the two checked
                // conditions above), but a d outside that range -- a key built by
                // createPrivateKey() from untrusted bytes and never put through
                // checkPrivateKey() -- can still land here, and must not yield a "secret".
                if (shared.infinity) {
                    return ERET_BADREQ;
                }

                // RFC 5903 section 7: the shared secret is the x-coordinate of the common value
                // alone -- not the full point, not a hash of it -- left-padded with zeros to the
                // field width ("enforced, if necessary, by prepending the value with zeros").
                // toBigEndian() over a fixed-width span does exactly that padding; it can only
                // fail if x needed more than flen bytes, which scalarMul() reducing mod p rules
                // out (p is flen bytes wide by definition of fieldByteLen()).
                if (!shared.x.toBigEndian(SByteSpan(out.data, flen))) {
                    return ERET_UNKNOWN;
                }

                out = SByteSpan(out.data, flen);

                // Both halves of the common value are secret-derived; the caller only gets x, so
                // neither should be left in the heap limbs this SEcPoint is about to free.
                shared.x.secureClear();
                shared.y.secureClear();

                return ERET_OK;
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
