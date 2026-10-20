#include <certpp/crypto/asyms/dsa.hpp>
#include <certpp/crypto/rng.hpp>
#include <certpp/utils/bignum.hpp>
#include <certpp/utils/montgomery.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/io/buffer.hpp>
#include <certpp/utils/secure.hpp>
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
     * this library needs): draw a random L-bit starting value X, set the first candidate to
     * X - (X mod 2q) + 1, then walk a bounded number of candidates by adding 2q. Every candidate
     * is therefore odd and congruent to 1 (mod q). Since 2q is negligibly small next to 2^(L-1)
     * for every supported (L, N) pair, the bounded progression remains exactly L bits except at
     * the upper edge, where generation simply draws another starting value. */
    bool DSA::generateDomainParams(
        const IRng& rng, size_t bitsL, size_t bitsN, CBigNum& p, CBigNum& q, CBigNum& g,
        CMontgomery& montgomery
    ) {
        if (!CBigNum::generatePrime(rng, bitsN, q)) {
            return false;
        }

        CBigNum twoQ(q);
        twoQ.shl(1);

        // Walking one bounded p == 1 (mod 2q) progression lets the big-number helper reuse
        // each candidate's small-prime residues as well as avoiding a fresh division by 2q.
        // It retains the same 20 Miller--Rabin rounds used by ordinary prime generation.
        if (!CBigNum::generatePrimeCongruentOne(rng, bitsL, twoQ, p)) {
            return false;
        }

        // (p - 1) is exactly divisible by q by construction.
        CBigNum pMinus1(p);
        pMinus1.sub(CBigNum(uint64_t(1)));

        CBigNum quotient, remainder;
        pMinus1.divMod(q, quotient, remainder);

        montgomery = CMontgomery(p);
        if (!montgomery.isValid()) {
            return false;
        }
        for (uint64_t h = 2; h < 1000; ++h) {
            CBigNum candidateG = montgomery.modExp(CBigNum(h), quotient);
            if (candidateG != CBigNum(uint64_t(1))) {
                g = candidateG;
                return true;
            }
        }

        // Astronomically unlikely (no generator found among h in [2, 999]).
        return false;
    }

    namespace {

        using asn1::CDer;

        /* A position-dependent fixed-base table for DSA exponents of up to 256 bits. Each four-bit
         * row stores base^(digit * 16^row) in Montgomery form, so a bound context can evaluate a
         * new exponent with at most 64 multiplications and no squarings. Signing scans every
         * non-zero row entry before using the selected value; verification exponents are public
         * and may index the same representation directly. */
        class DsaFixedBaseTable {
        private:
            static constexpr size_t WINDOW_BITS = 4;
            static constexpr size_t ENTRIES = (size_t(1) << WINDOW_BITS) - 1;

            TArray<CBigNum> _powers;
            size_t _rows = 0;

        public:
            void clear() {
                _powers.resize(0);
                _rows = 0;
            }

            bool prepare(
                const CMontgomery& montgomery, const CBigNum& base, size_t exponentBits
            ) {
                clear();
                if (!montgomery.isValid() || exponentBits == 0) {
                    return false;
                }

                const size_t rows = (exponentBits + WINDOW_BITS - 1) / WINDOW_BITS;
                if (!_powers.resize(rows * ENTRIES)) {
                    return false;
                }

                CBigNum rowBase = montgomery.toMont(base);
                for (size_t row = 0; row < rows; ++row) {
                    CBigNum multiple(rowBase);
                    for (size_t digit = 1; digit <= ENTRIES; ++digit) {
                        _powers[row * ENTRIES + digit - 1] = multiple;
                        if (digit != ENTRIES) {
                            montgomery.mul(multiple, rowBase);
                        }
                    }
                    for (size_t bit = 0; bit < WINDOW_BITS; ++bit) {
                        montgomery.mul(rowBase, rowBase);
                    }
                }
                _rows = rows;
                return true;
            }

            bool valid() const {
                return _rows != 0 && _powers.size() == _rows * ENTRIES;
            }

            CBigNum evaluateMontgomery(
                const CMontgomery& montgomery, const CBigNum& exponent, bool secret
            ) const {
                if (!valid()) {
                    return CBigNum();
                }

                CBigNum result(montgomery.one());
                for (size_t row = 0; row < _rows; ++row) {
                    size_t digit = 0;
                    for (size_t bit = 0; bit < WINDOW_BITS; ++bit) {
                        digit |= size_t(exponent.testBit(row * WINDOW_BITS + bit)) << bit;
                    }

                    if (!secret) {
                        if (digit != 0) {
                            montgomery.mul(result, _powers[row * ENTRIES + digit - 1]);
                        }
                        continue;
                    }

                    const size_t tableDigit = digit | size_t(digit == 0);
                    CBigNum selected(_powers[row * ENTRIES]);
                    for (size_t candidateDigit = 2; candidateDigit <= ENTRIES; ++candidateDigit) {
                        CBigNum candidate(_powers[
                            row * ENTRIES + candidateDigit - 1]);
                        CBigNum::condSwap(candidateDigit == tableDigit, selected, candidate);
                    }
                    CBigNum product(result);
                    montgomery.mul(product, selected);
                    CBigNum::condSwap(digit != 0, result, product);
                }
                return result;
            }
        };

        class DsaPublicKey : public IPublicKey {
        private:
            CBigNum _p, _q, _g, _y;
            CMontgomery _montgomery;

        public:
            DsaPublicKey(CBigNum p, CBigNum q, CBigNum g, CBigNum y)
                : _p(std::move(p)), _q(std::move(q)), _g(std::move(g)), _y(std::move(y)),
                  _montgomery(_p)
            {
                algorithm(EASYM_DSA);
            }

            DsaPublicKey(
                CBigNum p, CBigNum q, CBigNum g, CBigNum y,
                const CMontgomery& montgomery)
                : _p(std::move(p)), _q(std::move(q)), _g(std::move(g)), _y(std::move(y)),
                  _montgomery(montgomery)
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
            const CMontgomery& montgomery() const { return _montgomery; }

            /* Fallback that computes g^u1 * y^u2 mod p with one shared squaring chain when a
             * context could not prepare its position-dependent tables. Both exponents are
             * public verification values, so selecting one of g/y/g*y from their bits does not
             * expose private key material. Keeping the accumulator and table in Montgomery form
             * avoids every division in the loop and converts only the final result back. */
            CBigNum jointModExp(const CBigNum& u1, const CBigNum& u2) const {
                if (!_montgomery.isValid()) {
                    CBigNum result = CBigNum::modExp(_g, u1, _p);
                    result.mulMod(CBigNum::modExp(_y, u2, _p), _p);
                    return result;
                }

                return _montgomery.modExpProduct(_g, u1, _y, u2);
            }
        };

        class DsaPrivateKey : public IPrivateKey {
        private:
            CBigNum _p, _q, _g, _y, _x;
            IPublicKeyPtr _publicKey;
            CMontgomery _montgomery;

        public:
            DsaPrivateKey(CBigNum p, CBigNum q, CBigNum g, CBigNum y, CBigNum x, IPublicKeyPtr publicKey)
                : _p(std::move(p)), _q(std::move(q)), _g(std::move(g)), _y(std::move(y)),
                  _x(std::move(x)), _publicKey(std::move(publicKey)), _montgomery(_p)
            {
                algorithm(EASYM_DSA);
            }

            DsaPrivateKey(
                CBigNum p, CBigNum q, CBigNum g, CBigNum y, CBigNum x,
                IPublicKeyPtr publicKey, const CMontgomery& montgomery)
                : _p(std::move(p)), _q(std::move(q)), _g(std::move(g)), _y(std::move(y)),
                  _x(std::move(x)), _publicKey(std::move(publicKey)),
                  _montgomery(montgomery)
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
            const CMontgomery& montgomery() const { return _montgomery; }

            /* Fallback that uses the key's cached Montgomery context when a context could not
             * prepare its position-dependent generator table. CBigNum storage and exponent-bit
             * branches mean this remains variable-time, matching the documented big-number
             * limit. */
            CBigNum fixedBaseModExpG(const CBigNum& k) const {
                return _montgomery.isValid()
                    ? _montgomery.modExp(_g, k)
                    : CBigNum::modExp(_g, k, _p);
            }
        };

        class DsaContext : public IAsymmetricContext {
        public:
            using IAsymmetricContext::IAsymmetricContext;

        private:
            DsaFixedBaseTable _generatorTable;
            DsaFixedBaseTable _publicTable;

        protected:
            void onReset() override {
                _generatorTable.clear();
                _publicTable.clear();
                auto priv = std::dynamic_pointer_cast<DsaPrivateKey>(privateKey());
                if (priv) {
                    size_t qBytes = (priv->q().bitLength() + 7) / 8;
                    sizeOfSign(CDer::maxSignatureSize(qBytes));
                    sizeOfDigest(qBytes);
                    _generatorTable.prepare(
                        priv->montgomery(), priv->g(), priv->q().bitLength());
                }

                auto pub = std::dynamic_pointer_cast<DsaPublicKey>(publicKey());
                if (!pub && priv) {
                    pub = std::dynamic_pointer_cast<DsaPublicKey>(priv->publicKey());
                }
                if (pub) {
                    size_t qBytes = (pub->q().bitLength() + 7) / 8;
                    sizeOfSign(CDer::maxSignatureSize(qBytes));
                    sizeOfDigest(qBytes);
                    if (!_generatorTable.valid()) {
                        _generatorTable.prepare(
                            pub->montgomery(), pub->g(), pub->q().bitLength());
                    }
                    _publicTable.prepare(
                        pub->montgomery(), pub->y(), pub->q().bitLength());
                }
            }

        public:
            ERetCode sign(const SReadOnlyByteSpan& digest, SByteSpan& out) override {
                const IRng& rng = randomGenerator();
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

                // --> k and xr each yield the private exponent x outright given the published
                // signature (x = (s*k - z) / r mod q, or x = xr / r mod q), so both are cleared
                // on every path out of the loop -- the retry paths included, unreachable though
                // they are short of a broken CSPRNG.
                CBigNum r, s;
                for (int attempt = 0; attempt < 1000; ++attempt) {
                    CBigNum k;
                    if (!CBigNum::randomBelow(rng, qMinus1, k)) {
                        return ERET_UNKNOWN;
                    }
                    k.add(CBigNum(uint64_t(1))); // k in [1, q-1]

                    if (_generatorTable.valid()) {
                        r = priv->montgomery().fromMont(
                            _generatorTable.evaluateMontgomery(
                                priv->montgomery(), k, true));
                    } else {
                        r = priv->fixedBaseModExpG(k);
                    }
                    r.mod(q);
                    if (r.isZero()) {
                        k.secureClear();
                        continue;
                    }

                    CBigNum kInv;
                    if (!CBigNum::modInverse(k, q, kInv)) {
                        k.secureClear();
                        continue;
                    }

                    CBigNum xr(x);
                    xr.mulMod(r, q);

                    CBigNum sum(z);
                    sum.add(xr);
                    sum.mod(q);

                    kInv.mulMod(sum, q);
                    s = std::move(kInv);

                    k.secureClear();
                    xr.secureClear();
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

                auto pub = std::dynamic_pointer_cast<DsaPublicKey>(publicKey());
                if (!pub) {
                    return ERET_KEY_FORMAT;
                }

                const CBigNum& p = pub->p();
                const CBigNum& q = pub->q();

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

                CBigNum v;
                if (_generatorTable.valid() && _publicTable.valid()) {
                    CBigNum first = _generatorTable.evaluateMontgomery(
                        pub->montgomery(), u1, false);
                    CBigNum second = _publicTable.evaluateMontgomery(
                        pub->montgomery(), u2, false);
                    pub->montgomery().mul(first, second);
                    v = pub->montgomery().fromMont(first);
                } else {
                    v = pub->jointModExp(u1, u2);
                }
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

    ERetCode DSA::generateKeyPair(const IRng& rng, SKeySize keySize, SKeyPair& out) {
        out = SKeyPair();

        size_t bitsN = subgroupBitsFor(keySize);
        if (!bitsN) {
            return ERET_KEY_SIZE;
        }

        CBigNum p, q, g;
        CMontgomery montgomery;
        if (!generateDomainParams(rng, keySize, bitsN, p, q, g, montgomery)) {
            return ERET_UNKNOWN;
        }

        CBigNum qMinus1(q);
        qMinus1.sub(CBigNum(uint64_t(1)));

        CBigNum x;
        if (!CBigNum::randomBelow(rng, qMinus1, x)) {
            return ERET_UNKNOWN;
        }
        x.add(CBigNum(uint64_t(1))); // x in [1, q-1]

        CBigNum y = montgomery.modExp(g, x);

        auto pub = std::make_shared<DsaPublicKey>(p, q, g, y, montgomery);
        auto priv = CSecure::make<DsaPrivateKey>(p, q, g, y, x, pub, montgomery);
        if (!priv) {
            return ERET_NOMEM;
        }

        // generateDomainParams() has just established p/q primality, q | (p - 1), and g's
        // order; x was sampled in range and y was computed from it above. Re-running the import
        // validator here would repeat forty Miller--Rabin rounds plus two exponentiations over
        // values produced by these same checked operations.
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

        const CMontgomery& montgomery = priv->montgomery();
        CBigNum gq = montgomery.isValid()
            ? montgomery.modExp(g, q) : CBigNum::modExp(g, q, p);
        if (gq != one) {
            return ERET_KEY_PARAM;
        }

        // x must be in [1, q-1].
        if (x.isZero() || x >= q) {
            return ERET_KEY_PARAM;
        }

        // y must equal g^x mod p.
        CBigNum expectedY = montgomery.isValid()
            ? montgomery.modExp(g, x) : CBigNum::modExp(g, x, p);
        if (expectedY != y) {
            return ERET_KEY_PARAM;
        }

        return ERET_OK;
    }

    ERetCode DSA::createPublicKey(
        IPublicKeyPtr& out, const SReadOnlyByteSpan& keyData
    ) const {
        out.reset();
        TReadOnlySpan<uint8_t> content;
        if (!CDer::readOuterSequence(keyData, content)) {
            return ERET_KEY_FORMAT;
        }

        CBigNum p, q, g, y;
        bool ok = CDer::readBigInteger(content, p)
            && CDer::readBigInteger(content, q)
            && CDer::readBigInteger(content, g)
            && CDer::readBigInteger(content, y);

        // --> y was the one of the four left unchecked; a zero public value is as unusable as a
        // zero modulus, and verify() would otherwise accept the key and fail obscurely later.
        if (!ok || !content.empty() || p.isZero() || q.isZero() || g.isZero() || y.isZero()) {
            return ERET_KEY_FORMAT;
        }
        try {
            out = std::make_shared<DsaPublicKey>(p, q, g, y);
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        return ERET_OK;
    }

    ERetCode DSA::createPrivateKey(
        IPrivateKeyPtr& out, const SReadOnlyByteSpan& keyData
    ) const {
        out.reset();
        TReadOnlySpan<uint8_t> content;
        if (!CDer::readOuterSequence(keyData, content)) {
            return ERET_KEY_FORMAT;
        }

        CBigNum version, p, q, g, y, x;
        bool ok = CDer::readBigInteger(content, version)
            && CDer::readBigInteger(content, p)
            && CDer::readBigInteger(content, q)
            && CDer::readBigInteger(content, g)
            && CDer::readBigInteger(content, y)
            && CDer::readBigInteger(content, x);

        // --> The same structural rejections createPublicKey() applies, plus the private scalar's
        // own FIPS 186-4 range (x in [1, q-1]). This deliberately stops short of checkPrivateKey()'s
        // full validation (primality of p/q, q | p-1, g's order, y == g^x) -- that stays a separate,
        // explicit call -- but a zero modulus or an out-of-range x isn't a weak key, it's one that
        // makes sign() divide by zero, so it has to be caught at the import boundary.
        if (!ok || !content.empty() || version != CBigNum(uint64_t(0))) {
            return ERET_KEY_FORMAT;
        }

        if (p.isZero() || q.isZero() || g.isZero() || x.isZero() || x >= q) {
            return ERET_KEY_PARAM;
        }
        try {
            auto pub = std::make_shared<DsaPublicKey>(p, q, g, y);
            out = CSecure::make<DsaPrivateKey>(p, q, g, y, x, pub);
            if (!out) return ERET_NOMEM;
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        return ERET_OK;
    }

    ERetCode DSA::createContext(
        IAsymmetricContextPtr& out, const std::shared_ptr<IRng>& rng
    ) const {
        out.reset();
        if (!rng) return ERET_BADREQ;
        try {
            out = std::make_shared<DsaContext>(rng);
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        return ERET_OK;
    }

} // namespace crypto
} // namespace certpp
