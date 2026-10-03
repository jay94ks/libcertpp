#include <certpp/crypto/asyms/gost3410.hpp>
#include <certpp/io/buffer.hpp>
#include <cstring>
#include <memory>
#include <utility>

namespace certpp {
namespace crypto {

    namespace {

        /* The nominal half-width, in bytes, of one r/s/coordinate for a parameter set whose
         * subgroup order is q: 32 for the 256-bit sets, 64 for the 512-bit ones. RFC 7091
         * section 5.2 constrains q to 2^254 < q < 2^256 or 2^508 < q < 2^512, so the two
         * families are told apart by a single comparison -- and the nominal width is what
         * RFC 9215 sections 2.3/2.4 fix the serialized sizes to, which is not quite the same
         * as ceil(bitLength(q) / 8) for a set like ECURVE_GOST512C whose q is 510 bits. */
        size_t halfLenOf(const CBigNum& q) {
            return q.bitLength() > 256 ? 64 : 32;
        }

        /* RFC 7091 step 2/step 3: e = alpha mod q, where alpha is the integer whose binary
         * representation is the hash vector H, and e = 0 is replaced by 1.
         *
         * RFC 6986 numbers a vector's bits from the right, and Streebog256/Streebog512 emit
         * their digest with that same byte position 0 first, so "the integer whose binary
         * representation is H" reads the digest LITTLE-endian. This is the single step where
         * copying ECDSA (fromBigEndianTruncated) would produce signatures that verify against
         * themselves and against nothing else. */
        CBigNum digestToE(const SReadOnlyByteSpan& digest, const CBigNum& q) {
            CBigNum e = CBigNum::fromLittleEndian(digest);
            e.mod(q);

            if (e.isZero()) {
                return CBigNum(uint64_t(1));
            }

            return e;
        }

        class GostPublicKey : public IPublicKey {
        private:
            // A value, not a pointer/reference: the curve this key was created from is a
            // per-instance CEcCurve member of a CGost3410 object rather than a program-lifetime
            // static, so a key must own an independent copy to stay valid after that object is
            // destroyed. (Same reasoning as EcPublicKey in ecdsa.cpp.)
            CEcCurve _curve;
            SEcPoint _q;
            size_t _halfLen;

        public:
            GostPublicKey(const CEcCurve& curve, SEcPoint q, size_t halfLen, EAsymmetrics which)
                : _curve(curve), _q(std::move(q)), _halfLen(halfLen)
            {
                algorithm(which);
            }

            SKeySize keySize() const override {
                return _halfLen * 8;
            }

            ERetCode serialize(COctet& out) const override {
                if (_q.infinity) {
                    return ERET_KEY_PARAM; // the point at infinity has no coordinates to emit
                }

                // --> RFC 9215 section 2.4: x || y, each little-endian and zero-padded to the
                // parameter set's half-width. Little-endian here, big-endian in a signature --
                // that asymmetry is GOST's, not a mistake.
                CBuffer blob;
                if (!blob.resize(_halfLen * 2)) {
                    return ERET_NOMEM;
                }
                std::memset(blob.toPtr(), 0, blob.size());

                uint8_t* bytes = blob.toPtr();
                if (!_q.x.toLittleEndian(SByteSpan(bytes, _halfLen))
                    || !_q.y.toLittleEndian(SByteSpan(bytes + _halfLen, _halfLen))) {
                    return ERET_KEY_PARAM; // a coordinate wider than the parameter set allows
                }

                out = COctet(blob.toSpan());
                return ERET_OK;
            }

            int32_t compare(const IKeyBasePtr& other) const override {
                if (!other) {
                    return 1;
                }

                auto o = std::dynamic_pointer_cast<GostPublicKey>(other);
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
            size_t halfLen() const { return _halfLen; }
        };

        class GostPrivateKey : public IPrivateKey {
        private:
            CEcCurve _curve; // owned by value -- see GostPublicKey::_curve's comment
            CBigNum _d;
            IPublicKeyPtr _publicKey;
            size_t _halfLen;

        public:
            GostPrivateKey(
                const CEcCurve& curve, CBigNum d, IPublicKeyPtr publicKey, size_t halfLen,
                EAsymmetrics which
            )
                : _curve(curve), _d(std::move(d)), _publicKey(std::move(publicKey)),
                  _halfLen(halfLen)
            {
                algorithm(which);
            }

            SKeySize keySize() const override {
                return _halfLen * 8;
            }

            ERetCode serialize(COctet& out) const override {
                // --> d alone, little-endian, matching the public key's coordinate order. The
                // public point is re-derived as d*P on import, so there is nothing else to
                // store; RFC 9215 doesn't define a private key encoding to match here.
                CBuffer blob;
                if (!blob.resize(_halfLen)) {
                    return ERET_NOMEM;
                }
                std::memset(blob.toPtr(), 0, blob.size());

                if (!_d.toLittleEndian(SByteSpan(blob.toPtr(), blob.size()))) {
                    return ERET_KEY_PARAM; // d wider than the parameter set allows
                }

                out = COctet(blob.toSpan());
                return ERET_OK;
            }

            int32_t compare(const IKeyBasePtr& other) const override {
                if (!other) {
                    return 1;
                }

                auto o = std::dynamic_pointer_cast<GostPrivateKey>(other);
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
            size_t halfLen() const { return _halfLen; }
        };

        class GostContext : public IAsymmetricContext {
        protected:
            void onReset() override {
                auto priv = std::dynamic_pointer_cast<GostPrivateKey>(privateKey());
                if (priv) {
                    sizeOfSign(priv->halfLen() * 2);
                    sizeOfDigest(priv->halfLen());
                    return;
                }

                auto pub = std::dynamic_pointer_cast<GostPublicKey>(publicKey());
                if (pub) {
                    sizeOfSign(pub->halfLen() * 2);
                    sizeOfDigest(pub->halfLen());
                }
            }

        public:
            ERetCode sign(const SReadOnlyByteSpan& digest, SByteSpan& out) override {
                if (!privateKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto priv = std::dynamic_pointer_cast<GostPrivateKey>(privateKey());
                if (!priv) {
                    return ERET_KEY_FORMAT;
                }

                const CEcCurve& curve = priv->curve();
                const CBigNum& q = curve.n;
                const CBigNum& d = priv->d();
                const size_t halfLen = priv->halfLen();

                if (out.size < halfLen * 2) {
                    return ERET_NOSPC;
                }

                const CBigNum e = digestToE(digest, q);

                CBigNum qMinus1(q);
                qMinus1.sub(CBigNum(uint64_t(1)));

                // --> k, r*d, and the k*e intermediate are the values here whose exposure is
                // catastrophic rather than merely unwanted: k yields d outright from a
                // published signature (d = (s - k*e) / r mod q), r*d yields it directly
                // (d = r*d / r mod q), and k*e yields k given the public e. So all three are
                // cleared on every path out of the loop, including the retry paths -- which
                // take a zero r or a zero s and so are unreachable short of a broken CSPRNG,
                // but cost three lines to cover properly.
                CBigNum r, s;
                for (int attempt = 0; attempt < 1000; ++attempt) {
                    CBigNum k;
                    if (!CBigNum::randomBelow(qMinus1, k)) {
                        return ERET_UNKNOWN;
                    }
                    k.add(CBigNum(uint64_t(1))); // k in [1, q-1], per RFC 7091 step 3

                    // --> Step 4: C = k*P, r = x_C mod q.
                    SEcPoint c = curve.scalarMulBase(k);
                    if (c.infinity) {
                        k.secureClear();
                        continue;
                    }

                    c.x.mod(q);
                    r = std::move(c.x);
                    if (r.isZero()) {
                        k.secureClear();
                        continue;
                    }

                    // --> Step 5: s = (r*d + k*e) mod q. No inversion of k anywhere: this is
                    // the point where GOST R 34.10 and ECDSA part company.
                    CBigNum rd(r);
                    rd.mulMod(d, q);

                    CBigNum sum(k);
                    sum.mulMod(e, q);
                    sum.add(rd);
                    sum.mod(q);
                    s = sum;

                    k.secureClear();
                    rd.secureClear();
                    sum.secureClear();

                    if (!s.isZero()) {
                        break;
                    }
                }

                if (r.isZero() || s.isZero()) {
                    return ERET_UNKNOWN;
                }

                // --> Step 6, as RFC 9215 section 2.3 serializes it: s first, then r, each
                // big-endian and zero-padded to the parameter set's half-width.
                if (!s.toBigEndian(SByteSpan(out.data, halfLen))
                    || !r.toBigEndian(SByteSpan(out.data + halfLen, halfLen))) {
                    return ERET_UNKNOWN;
                }

                out = SByteSpan(out.data, halfLen * 2);
                return ERET_OK;
            }

            ERetCode verify(const SReadOnlyByteSpan& digest, const SReadOnlyByteSpan& signature) override {
                if (!publicKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto pub = std::dynamic_pointer_cast<GostPublicKey>(publicKey());
                if (!pub) {
                    return ERET_KEY_FORMAT;
                }

                const CEcCurve& curve = pub->curve();
                const CBigNum& q = curve.n;
                const size_t halfLen = pub->halfLen();

                if (signature.size != halfLen * 2) {
                    return ERET_BADREQ;
                }

                // --> s || r, each big-endian (RFC 9215 section 2.3).
                CBigNum s = CBigNum::fromBigEndian(SReadOnlyByteSpan(signature.data, halfLen));
                CBigNum r = CBigNum::fromBigEndian(
                    SReadOnlyByteSpan(signature.data + halfLen, halfLen));

                // --> Step 1: 0 < r < q, 0 < s < q.
                if (r.isZero() || r >= q || s.isZero() || s >= q) {
                    return ERET_BADREQ;
                }

                const CBigNum e = digestToE(digest, q);

                // --> Step 4: v = e^-1 mod q. ECDSA inverts s here instead.
                CBigNum v;
                if (!CBigNum::modInverse(e, q, v)) {
                    return ERET_BADREQ;
                }

                // --> Step 5: z1 = s*v mod q, z2 = -r*v mod q.
                CBigNum z1(s);
                z1.mulMod(v, q);

                CBigNum z2(r);
                z2.mulMod(v, q);
                z2.modNeg(q);

                // --> Step 6/7: C = z1*P + z2*Q, accept if x_C mod q == r.
                SEcPoint p1 = curve.scalarMulBase(z1);
                SEcPoint p2 = curve.scalarMul(pub->q(), z2);
                SEcPoint c = curve.add(p1, p2);

                if (c.infinity) {
                    return ERET_BADREQ;
                }

                c.x.mod(q);
                return c.x == r ? ERET_OK : ERET_BADREQ;
            }

            ERetCode createEncrypter(IAsymmetricTransformerPtr&) override {
                return ERET_NOTSUP;
            }

            ERetCode createDecrypter(IAsymmetricTransformerPtr&) override {
                return ERET_NOTSUP;
            }
        };

    } // namespace

    /* Constructs an instance over one of the GOST parameter sets. */
    CGost3410::CGost3410(EEcKnownCurves which) : _which(CEcCurve::identify(which)) {
        CEcCurve::knownCurves(which, _curve);
        _halfLen = halfLenOf(_curve.n);

        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(_halfLen * 8));
        keySizes(specs);
    }

    /* Generates a new key pair. */
    ERetCode CGost3410::generateKeyPair(SKeySize keySize, SKeyPair& out) {
        out = SKeyPair();

        if (keySize != _halfLen * 8) {
            return ERET_KEY_SIZE;
        }

        CBigNum qMinus1(_curve.n);
        qMinus1.sub(CBigNum(uint64_t(1)));

        CBigNum d;
        if (!CBigNum::randomBelow(qMinus1, d)) {
            return ERET_UNKNOWN;
        }
        d.add(CBigNum(uint64_t(1))); // d in [1, q-1], per RFC 7091 section 5.2

        SEcPoint q = _curve.scalarMulBase(d);
        if (q.infinity) {
            return ERET_AGAIN; // same degenerate-candidate condition checkPrivateKey() checks
        }

        auto pub = std::make_shared<GostPublicKey>(_curve, q, _halfLen, _which);
        auto priv = std::make_shared<GostPrivateKey>(_curve, d, pub, _halfLen, _which);

        if (checkPrivateKey(priv) != ERET_OK) {
            return ERET_AGAIN;
        }

        out = SKeyPair(pub, priv);
        return ERET_OK;
    }

    /* Validates a private key's structure. */
    ERetCode CGost3410::checkPrivateKey(const IPrivateKeyPtr& key) const {
        auto priv = std::dynamic_pointer_cast<GostPrivateKey>(key);
        if (!priv) {
            return ERET_KEY_FORMAT;
        }

        const CEcCurve& curve = priv->curve();
        const CBigNum& d = priv->d();
        const CBigNum& q = curve.n;

        // Signature key range: 0 < d < q (RFC 7091 section 5.2).
        if (d.isZero() || d >= q) {
            return ERET_KEY_PARAM;
        }

        auto pub = std::dynamic_pointer_cast<GostPublicKey>(priv->publicKey());
        if (!pub) {
            return ERET_KEY_ERROR;
        }

        const SEcPoint& point = pub->q();

        // 1. The zero point.
        if (point.infinity) {
            return ERET_KEY_PARAM;
        }

        // 2. Field range: 0 <= x, y < p.
        if (point.x >= curve.p || point.y >= curve.p) {
            return ERET_KEY_PARAM;
        }

        // 3. Curve equation.
        if (!curve.isOnCurve(point)) {
            return ERET_KEY_PARAM;
        }

        // 4. Correct (order-q) subgroup: q*Q must be the zero point. Unlike the cofactor-1
        // curves CEcdsa runs over, this is a real check for ECURVE_GOST256A/ECURVE_GOST512C,
        // whose cofactor is 4 -- a point can satisfy every check above and still sit outside
        // the order-q subgroup.
        if (!curve.scalarMul(point, q).infinity) {
            return ERET_KEY_PARAM;
        }

        // 5. Q must actually be d*P -- the four checks above only establish that Q is *some*
        // legitimate point, not that it's *this key's* point.
        if (!curve.scalarMulBase(d).equals(point)) {
            return ERET_KEY_ERROR;
        }

        return ERET_OK;
    }

    /* Parses public key material into a usable public key. */
    IPublicKeyPtr CGost3410::createPublicKey(const SReadOnlyByteSpan& keyData) const {
        if (keyData.size != _halfLen * 2 || !keyData.data) {
            return nullptr;
        }

        // --> x || y, each little-endian (RFC 9215 section 2.4).
        SEcPoint point(
            CBigNum::fromLittleEndian(SReadOnlyByteSpan(keyData.data, _halfLen)),
            CBigNum::fromLittleEndian(SReadOnlyByteSpan(keyData.data + _halfLen, _halfLen)));

        if (point.x >= _curve.p || point.y >= _curve.p) {
            return nullptr;
        }

        if (!_curve.isOnCurve(point)) {
            return nullptr;
        }

        // --> Order-q subgroup, which is a genuine check on the cofactor-4 parameter sets --
        // see checkPrivateKey()'s step 4.
        if (!_curve.scalarMul(point, _curve.n).infinity) {
            return nullptr;
        }

        return std::make_shared<GostPublicKey>(_curve, std::move(point), _halfLen, _which);
    }

    /* Parses private key material into a usable private key. */
    IPrivateKeyPtr CGost3410::createPrivateKey(const SReadOnlyByteSpan& keyData) const {
        if (keyData.size != _halfLen || !keyData.data) {
            return nullptr;
        }

        CBigNum d = CBigNum::fromLittleEndian(keyData);
        if (d.isZero() || d >= _curve.n) {
            return nullptr;
        }

        // --> Re-derive the public point rather than carrying it in the blob: it's a single
        // scalar multiplication, and it makes a mismatched (d, Q) pair impossible to import.
        SEcPoint point = _curve.scalarMulBase(d);
        if (point.infinity) {
            return nullptr;
        }

        auto pub = std::make_shared<GostPublicKey>(_curve, std::move(point), _halfLen, _which);
        return std::make_shared<GostPrivateKey>(_curve, std::move(d), pub, _halfLen, _which);
    }

    /* Creates a context for this algorithm's operations. */
    IAsymmetricContextPtr CGost3410::createContext() const {
        return std::make_shared<GostContext>();
    }

} // namespace crypto
} // namespace certpp
