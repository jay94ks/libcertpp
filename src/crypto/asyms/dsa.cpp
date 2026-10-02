#include <certpp/crypto/asyms/dsa.hpp>
#include <certpp/utils/bignum.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/io/buffer.hpp>
#include <cstring>
#include <memory>
#include <utility>

namespace certpp {
namespace crypto {

    /* Maps a DSA modulus size (L, in bits) to its FIPS 186-4 subgroup order (N, in bits).
     * Returns 0 for any L not among the three approved sizes this library supports. */
    size_t DSA::subgroupBitsFor(SKeySize keySizeL) {
        switch (keySizeL) {
            case 1024: return 160;
            case 2048: return 256;
            case 3072: return 256;
            default: return 0;
        }
    }

    /* Generates FIPS 186-4-style domain parameters: q (an N-bit prime), p (an L-bit prime
     * with q | (p - 1)), and g (a generator of the order-q subgroup of Z*p). Uses the
     * simplified "probable primes" construction (FIPS 186-4 A.1.1.2, minus the seed/counter
     * bookkeeping needed to later *re-verify* a parameter set's provenance, which nothing in
     * this library needs): draw a random L-bit X, then set p = X - (X mod 2q) + 1, which is
     * always congruent to 1 (mod 2q) -- i.e. odd and a multiple of q above 1 -- and, since 2q is
     * negligibly small next to 2^(L-1) for every (L, N) pair this library supports, almost
     * always still exactly L bits long (unlike naively building p as k*q + 1 for a freshly
     * random k, which lets the product's bit length wander across a ~4x range and wastes
     * the large majority of attempts on the wrong size before ever reaching a primality
     * test). */
    bool DSA::generateDomainParams(size_t bitsL, size_t bitsN, CBigNum& p, CBigNum& q, CBigNum& g) {
        if (!CBigNum::generatePrime(bitsN, q)) {
            return false;
        }

            CBigNum twoQ(q);
            twoQ.shl(1);

            CBigNum lowerBound(uint64_t(1));
            lowerBound.shl(bitsL - 1); // 2^(L-1)

            constexpr size_t MAX_ATTEMPTS = 100000;
            for (size_t attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
                CBigNum x;
                if (!CBigNum::random(bitsL, x)) {
                    return false;
                }
                x.setBit(bitsL - 1); // force into [2^(L-1), 2^L)

                CBigNum c(x);
                c.mod(twoQ);

                x.sub(c);
                x.add(CBigNum(uint64_t(1)));
                CBigNum candidate = std::move(x);

                if (candidate < lowerBound || candidate.bitLength() != bitsL) {
                    continue;
                }

                if (!candidate.isProbablePrime()) {
                    continue;
                }

                p = candidate;

                // (p - 1) is always exactly divisible by q by construction.
                CBigNum pMinus1(p);
                pMinus1.sub(CBigNum(uint64_t(1)));

                CBigNum quotient, remainder;
                pMinus1.divMod(q, quotient, remainder);

                for (uint64_t h = 2; h < 1000; ++h) {
                    CBigNum candidateG = CBigNum::modExp(CBigNum(h), quotient, p);
                    if (candidateG != CBigNum(uint64_t(1))) {
                        g = candidateG;
                        return true;
                    }
                }

                // Astronomically unlikely (no generator found among h in [2, 999]); try a
                // fresh p instead of failing outright.
            }

            return false;
        }

    namespace {

        using asn1::CDer;

        class DsaPublicKey : public IPublicKey {
        private:
            CBigNum _p, _q, _g, _y;

        public:
            DsaPublicKey(CBigNum p, CBigNum q, CBigNum g, CBigNum y)
                : _p(std::move(p)), _q(std::move(q)), _g(std::move(g)), _y(std::move(y))
            {
                algorithm(EASYM_DSA);
            }

            SKeySize keySize() const override {
                return _p.bitLength();
            }

            ERetCode serialize(COctet& out) const override {
                CBuffer inner;
                bool ok = CDer::appendBigInteger(inner, _p)
                    && CDer::appendBigInteger(inner, _q)
                    && CDer::appendBigInteger(inner, _g)
                    && CDer::appendBigInteger(inner, _y);

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

                auto o = std::dynamic_pointer_cast<DsaPublicKey>(other);
                if (!o) {
                    auto otherAsym = std::dynamic_pointer_cast<IAsymmetricKeyBase>(other);
                    return otherAsym ? (int32_t(keySize()) - int32_t(otherAsym->keySize())) : 1;
                }

                int32_t d = _p.compare(o->_p);
                return d ? d : _y.compare(o->_y);
            }

            const CBigNum& p() const { return _p; }
            const CBigNum& q() const { return _q; }
            const CBigNum& g() const { return _g; }
            const CBigNum& y() const { return _y; }
        };

        class DsaPrivateKey : public IPrivateKey {
        private:
            CBigNum _p, _q, _g, _y, _x;
            IPublicKeyPtr _publicKey;
            mutable TArray<CBigNum> _gTable; // --> lazy g^0..g^15 mod p window table, see fixedBaseModExpG().

        public:
            DsaPrivateKey(CBigNum p, CBigNum q, CBigNum g, CBigNum y, CBigNum x, IPublicKeyPtr publicKey)
                : _p(std::move(p)), _q(std::move(q)), _g(std::move(g)), _y(std::move(y)),
                  _x(std::move(x)), _publicKey(std::move(publicKey))
            {
                algorithm(EASYM_DSA);
            }

            SKeySize keySize() const override {
                return _p.bitLength();
            }

            ERetCode serialize(COctet& out) const override {
                CBuffer inner;
                bool ok = CDer::appendBigInteger(inner, CBigNum(uint64_t(0)))
                    && CDer::appendBigInteger(inner, _p)
                    && CDer::appendBigInteger(inner, _q)
                    && CDer::appendBigInteger(inner, _g)
                    && CDer::appendBigInteger(inner, _y)
                    && CDer::appendBigInteger(inner, _x);

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

                auto o = std::dynamic_pointer_cast<DsaPrivateKey>(other);
                if (!o) {
                    auto otherAsym = std::dynamic_pointer_cast<IAsymmetricKeyBase>(other);
                    return otherAsym ? (int32_t(keySize()) - int32_t(otherAsym->keySize())) : 1;
                }

                int32_t d = _p.compare(o->_p);
                return d ? d : _x.compare(o->_x);
            }

            IPublicKeyPtr publicKey() const override {
                return _publicKey;
            }

            const CBigNum& p() const { return _p; }
            const CBigNum& q() const { return _q; }
            const CBigNum& g() const { return _g; }
            const CBigNum& y() const { return _y; }
            const CBigNum& x() const { return _x; }

            /* Left-to-right windowed exponentiation over a lazily-built, per-instance-cached
             * table of g^0..g^15 mod p -- the same "16-entry window" shape
             * CEcCurve::scalarMulBase() already uses for fixed-base EC signing (see its own doc
             * comment), adapted from point addition/doubling to modular multiplication/squaring:
             * every sign() call's g^k mod p becomes bitLength/4 squarings plus exactly one
             * window multiplication per 4 bits, instead of a plain square-and-multiply's
             * ~bitLength/2 average multiplications -- and since the table is keyed only on this
             * key's own fixed (g, p), it's built once and amortizes across every sign() call
             * this key ever makes, not just the current one. */
            CBigNum fixedBaseModExpG(const CBigNum& k) const {
                constexpr size_t WINDOW = 4;
                constexpr size_t TABLE_SIZE = size_t(1) << WINDOW; // 16

                if (_gTable.size() != TABLE_SIZE) {
                    TArray<CBigNum> table;
                    table.resize(TABLE_SIZE);

                    table[0] = CBigNum(uint64_t(1));
                    for (size_t i = 1; i < TABLE_SIZE; ++i) {
                        table[i] = table[i - 1];
                        table[i].mulMod(_g, _p);
                    }

                    _gTable = std::move(table);
                }

                if (k.isZero()) {
                    return CBigNum(uint64_t(1));
                }

                size_t bits = k.bitLength();
                size_t numWindows = (bits + WINDOW - 1) / WINDOW;

                CBigNum result(uint64_t(1));
                for (size_t w = numWindows; w-- > 0; ) {
                    for (size_t i = 0; i < WINDOW; ++i) {
                        result.mulMod(result, _p);
                    }

                    size_t base = w * WINDOW;
                    size_t windowValue = 0;
                    for (size_t b = 0; b < WINDOW; ++b) {
                        if (k.testBit(base + b)) {
                            windowValue |= (size_t(1) << b);
                        }
                    }

                    result.mulMod(_gTable[windowValue], _p);
                }

                return result;
            }
        };

        class DsaContext : public IAsymmetricContext {
        protected:
            void onReset() override {
                auto priv = std::dynamic_pointer_cast<DsaPrivateKey>(privateKey());
                if (priv) {
                    size_t qBytes = (priv->q().bitLength() + 7) / 8;
                    sizeOfSign(CDer::maxSignatureSize(qBytes));
                    sizeOfDigest(qBytes);
                    return;
                }

                auto pub = std::dynamic_pointer_cast<DsaPublicKey>(publicKey());
                if (pub) {
                    size_t qBytes = (pub->q().bitLength() + 7) / 8;
                    sizeOfSign(CDer::maxSignatureSize(qBytes));
                    sizeOfDigest(qBytes);
                }
            }

        public:
            ERetCode sign(const SReadOnlyByteSpan& digest, SByteSpan& out) override {
                if (!privateKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto priv = std::dynamic_pointer_cast<DsaPrivateKey>(privateKey());
                if (!priv) {
                    return ERET_KEY_FORMAT;
                }

                const CBigNum& q = priv->q();
                const CBigNum& x = priv->x();

                CBigNum z = CBigNum::fromBigEndianTruncated(digest, q.bitLength());

                CBigNum qMinus1(q);
                qMinus1.sub(CBigNum(uint64_t(1)));

                CBigNum r, s;
                for (int attempt = 0; attempt < 1000; ++attempt) {
                    CBigNum k;
                    if (!CBigNum::randomBelow(qMinus1, k)) {
                        return ERET_UNKNOWN;
                    }
                    k.add(CBigNum(uint64_t(1))); // k in [1, q-1]

                    r = priv->fixedBaseModExpG(k);
                    r.mod(q);
                    if (r.isZero()) {
                        continue;
                    }

                    CBigNum kInv;
                    if (!CBigNum::modInverse(k, q, kInv)) {
                        continue;
                    }

                    CBigNum xr(x);
                    xr.mulMod(r, q);

                    CBigNum sum(z);
                    sum.add(xr);
                    sum.mod(q);

                    kInv.mulMod(sum, q);
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

                auto pub = std::dynamic_pointer_cast<DsaPublicKey>(publicKey());
                if (!pub) {
                    return ERET_KEY_FORMAT;
                }

                const CBigNum& p = pub->p();
                const CBigNum& q = pub->q();
                const CBigNum& g = pub->g();
                const CBigNum& y = pub->y();

                TReadOnlySpan<uint8_t> content;
                if (!CDer::readOuterSequence(signature, content)) {
                    return ERET_BADREQ;
                }

                CBigNum r, s;
                if (!CDer::readBigInteger(content, r) || !CDer::readBigInteger(content, s) || !content.empty()) {
                    return ERET_BADREQ;
                }

                if (r.isZero() || r >= q || s.isZero() || s >= q) {
                    return ERET_BADREQ;
                }

                CBigNum w;
                if (!CBigNum::modInverse(s, q, w)) {
                    return ERET_BADREQ;
                }

                CBigNum z = CBigNum::fromBigEndianTruncated(digest, q.bitLength());

                z.mulMod(w, q);
                CBigNum u1 = std::move(z);

                CBigNum u2(r);
                u2.mulMod(w, q);

                CBigNum v = CBigNum::modExp(g, u1, p);
                v.mulMod(CBigNum::modExp(y, u2, p), p);
                v.mod(q);

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

    DSA::DSA() {
        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(1024));
        specs.add(SKeySizeSpec(2048));
        specs.add(SKeySizeSpec(3072));
        keySizes(specs);
    }

    ERetCode DSA::generateKeyPair(SKeySize keySize, SKeyPair& out) {
        out = SKeyPair();

        size_t bitsN = subgroupBitsFor(keySize);
        if (!bitsN) {
            return ERET_KEY_SIZE;
        }

        CBigNum p, q, g;
        if (!generateDomainParams(keySize, bitsN, p, q, g)) {
            return ERET_UNKNOWN;
        }

        CBigNum qMinus1(q);
        qMinus1.sub(CBigNum(uint64_t(1)));

        CBigNum x;
        if (!CBigNum::randomBelow(qMinus1, x)) {
            return ERET_UNKNOWN;
        }
        x.add(CBigNum(uint64_t(1))); // x in [1, q-1]

        CBigNum y = CBigNum::modExp(g, x, p);

        auto pub = std::make_shared<DsaPublicKey>(p, q, g, y);
        auto priv = std::make_shared<DsaPrivateKey>(p, q, g, y, x, pub);

        if (checkPrivateKey(priv) != ERET_OK) {
            return ERET_AGAIN;
        }

        out = SKeyPair(pub, priv);
        return ERET_OK;
    }

    ERetCode DSA::checkPrivateKey(const IPrivateKeyPtr& key) const {
        auto priv = std::dynamic_pointer_cast<DsaPrivateKey>(key);
        if (!priv) {
            return ERET_KEY_FORMAT;
        }

        auto pub = std::dynamic_pointer_cast<DsaPublicKey>(priv->publicKey());
        if (!pub) {
            return ERET_KEY_ERROR; // this key's own linked public key is missing/wrong type
        }

        const CBigNum& p = priv->p();
        const CBigNum& q = priv->q();
        const CBigNum& g = priv->g();
        const CBigNum& y = priv->y();
        const CBigNum& x = priv->x();
        CBigNum one(uint64_t(1));

        // The linked public key must be consistent with this private key's own domain
        // parameters and y.
        if (pub->p() != p || pub->q() != q || pub->g() != g || pub->y() != y) {
            return ERET_KEY_ERROR;
        }

        // p, q must be (probable) primes.
        if (!p.isProbablePrime() || !q.isProbablePrime()) {
            return ERET_KEY_PARAM;
        }

        // q must divide (p - 1).
        CBigNum pMinus1(p);
        pMinus1.sub(one);

        CBigNum quotient, remainder;
        pMinus1.divMod(q, quotient, remainder);
        if (!remainder.isZero()) {
            return ERET_KEY_PARAM;
        }

        // g must be in [2, p-1] and have order q (g^q mod p == 1).
        CBigNum two(uint64_t(2));
        if (g < two || g >= p) {
            return ERET_KEY_PARAM;
        }

        CBigNum gq = CBigNum::modExp(g, q, p);
        if (gq != one) {
            return ERET_KEY_PARAM;
        }

        // x must be in [1, q-1].
        if (x.isZero() || x >= q) {
            return ERET_KEY_PARAM;
        }

        // y must equal g^x mod p.
        CBigNum expectedY = CBigNum::modExp(g, x, p);
        if (expectedY != y) {
            return ERET_KEY_PARAM;
        }

        return ERET_OK;
    }

    IPublicKeyPtr DSA::createPublicKey(const SReadOnlyByteSpan& keyData) const {
        TReadOnlySpan<uint8_t> content;
        if (!CDer::readOuterSequence(keyData, content)) {
            return nullptr;
        }

        CBigNum p, q, g, y;
        bool ok = CDer::readBigInteger(content, p)
            && CDer::readBigInteger(content, q)
            && CDer::readBigInteger(content, g)
            && CDer::readBigInteger(content, y);

        if (!ok || !content.empty() || p.isZero() || q.isZero() || g.isZero()) {
            return nullptr;
        }

        return std::make_shared<DsaPublicKey>(p, q, g, y);
    }

    IPrivateKeyPtr DSA::createPrivateKey(const SReadOnlyByteSpan& keyData) const {
        TReadOnlySpan<uint8_t> content;
        if (!CDer::readOuterSequence(keyData, content)) {
            return nullptr;
        }

        CBigNum version, p, q, g, y, x;
        bool ok = CDer::readBigInteger(content, version)
            && CDer::readBigInteger(content, p)
            && CDer::readBigInteger(content, q)
            && CDer::readBigInteger(content, g)
            && CDer::readBigInteger(content, y)
            && CDer::readBigInteger(content, x);

        if (!ok || !content.empty() || version != CBigNum(uint64_t(0))) {
            return nullptr;
        }

        auto pub = std::make_shared<DsaPublicKey>(p, q, g, y);
        return std::make_shared<DsaPrivateKey>(p, q, g, y, x, pub);
    }

    IAsymmetricContextPtr DSA::createContext() const {
        return std::make_shared<DsaContext>();
    }

} // namespace crypto
} // namespace certpp
