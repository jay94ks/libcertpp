#include <certpp/crypto/asyms/rsa.hpp>
#include <certpp/utils/secure.hpp>
#include <certpp/utils/bignum.hpp>
#include <certpp/crypto/rng.hpp>
#include <certpp/asn1/der.hpp>
#include <certpp/io/buffer.hpp>
#include <cstring>
#include <memory>
#include <utility>

namespace certpp {
namespace crypto {

    namespace {

        using asn1::CDer;

        class RsaPublicKey : public IPublicKey {
        private:
            CBigNum _n;
            CBigNum _e;

        public:
            RsaPublicKey(CBigNum n, CBigNum e) : _n(std::move(n)), _e(std::move(e)) {
                algorithm(EASYM_RSA);
            }

            SKeySize keySize() const override {
                return _n.bitLength();
            }

            ERetCode serialize(COctet& out) const override {
                CBuffer inner;
                if (!CDer::appendBigInteger(inner, _n) || !CDer::appendBigInteger(inner, _e)) {
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

                auto o = std::dynamic_pointer_cast<RsaPublicKey>(other);
                if (!o) {
                    auto otherAsym = std::dynamic_pointer_cast<IAsymmetricKeyBase>(other);
                    return otherAsym ? (int32_t(keySize()) - int32_t(otherAsym->keySize())) : 1;
                }

                int32_t d = _n.compare(o->_n);
                return d ? d : _e.compare(o->_e);
            }

            const CBigNum& n() const { return _n; }
            const CBigNum& e() const { return _e; }
        };

        class RsaPrivateKey : public IPrivateKey {
        private:
            CBigNum _n, _e, _d, _p, _q, _dp, _dq, _qInv;
            IPublicKeyPtr _publicKey;

        public:
            RsaPrivateKey(
                CBigNum n, CBigNum e, CBigNum d, CBigNum p, CBigNum q,
                CBigNum dp, CBigNum dq, CBigNum qInv, IPublicKeyPtr publicKey
            )
                : _n(std::move(n)), _e(std::move(e)), _d(std::move(d)), _p(std::move(p)),
                  _q(std::move(q)), _dp(std::move(dp)), _dq(std::move(dq)), _qInv(std::move(qInv)),
                  _publicKey(std::move(publicKey))
            {
                algorithm(EASYM_RSA);
            }

            SKeySize keySize() const override {
                return _n.bitLength();
            }

            ERetCode serialize(COctet& out) const override {
                CBuffer inner;
                bool ok = CDer::appendBigInteger(inner, CBigNum(uint64_t(0)))
                    && CDer::appendBigInteger(inner, _n)
                    && CDer::appendBigInteger(inner, _e)
                    && CDer::appendBigInteger(inner, _d)
                    && CDer::appendBigInteger(inner, _p)
                    && CDer::appendBigInteger(inner, _q)
                    && CDer::appendBigInteger(inner, _dp)
                    && CDer::appendBigInteger(inner, _dq)
                    && CDer::appendBigInteger(inner, _qInv);

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

                auto o = std::dynamic_pointer_cast<RsaPrivateKey>(other);
                if (!o) {
                    auto otherAsym = std::dynamic_pointer_cast<IAsymmetricKeyBase>(other);
                    return otherAsym ? (int32_t(keySize()) - int32_t(otherAsym->keySize())) : 1;
                }

                int32_t d = _n.compare(o->_n);
                return d ? d : _d.compare(o->_d);
            }

            IPublicKeyPtr publicKey() const override {
                return _publicKey;
            }

            const CBigNum& n() const { return _n; }
            const CBigNum& e() const { return _e; }
            const CBigNum& d() const { return _d; }
            const CBigNum& p() const { return _p; }
            const CBigNum& q() const { return _q; }
            const CBigNum& dp() const { return _dp; }
            const CBigNum& dq() const { return _dq; }
            const CBigNum& qInv() const { return _qInv; }
        };

        class RsaContext : public IAsymmetricContext, public std::enable_shared_from_this<RsaContext> {
        protected:
            void onReset() override {
                auto priv = std::dynamic_pointer_cast<RsaPrivateKey>(privateKey());
                if (priv) {
                    sizeOfSign((priv->n().bitLength() + 7) / 8);
                    return;
                }

                auto pub = std::dynamic_pointer_cast<RsaPublicKey>(publicKey());
                if (pub) {
                    sizeOfSign((pub->n().bitLength() + 7) / 8);
                }
            }

        private:
            /* Returns the DER-encoded DigestInfo AlgorithmIdentifier+NULL prefix (RFC 8017
             * Appendix B) for the hash algorithm whose digest is digestLen bytes long -- the only
             * way sign()/verify() have to identify the hash, since neither is passed a hash
             * algorithm indicator. Covers every hasher this library ships whose digest lengths
             * (16/20/28/32/48/64) happen to be pairwise distinct -- MD5/SHA-1/SHA-224/SHA-256/
             * SHA-384/SHA-512 (SHAKE256's output length is caller-configurable, so it has no
             * fixed slot here and isn't signable via this PKCS#1 v1.5 path). Returns an empty
             * span for any other length. */
            static SReadOnlyByteSpan digestInfoPrefixFor(size_t digestLen) {
                static const uint8_t MD5_PREFIX[] = {
                    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
                    0x05, 0x00, 0x04, 0x10
                };
                static const uint8_t SHA1_PREFIX[] = {
                    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                    0x14
                };
                static const uint8_t SHA224_PREFIX[] = {
                    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                    0x04, 0x05, 0x00, 0x04, 0x1c
                };
                static const uint8_t SHA256_PREFIX[] = {
                    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                    0x01, 0x05, 0x00, 0x04, 0x20
                };
                static const uint8_t SHA384_PREFIX[] = {
                    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                    0x02, 0x05, 0x00, 0x04, 0x30
                };
                static const uint8_t SHA512_PREFIX[] = {
                    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                    0x03, 0x05, 0x00, 0x04, 0x40
                };

                switch (digestLen) {
                    case 16: return SReadOnlyByteSpan(MD5_PREFIX, sizeof(MD5_PREFIX));
                    case 20: return SReadOnlyByteSpan(SHA1_PREFIX, sizeof(SHA1_PREFIX));
                    case 28: return SReadOnlyByteSpan(SHA224_PREFIX, sizeof(SHA224_PREFIX));
                    case 32: return SReadOnlyByteSpan(SHA256_PREFIX, sizeof(SHA256_PREFIX));
                    case 48: return SReadOnlyByteSpan(SHA384_PREFIX, sizeof(SHA384_PREFIX));
                    case 64: return SReadOnlyByteSpan(SHA512_PREFIX, sizeof(SHA512_PREFIX));
                    default: return SReadOnlyByteSpan();
                }
            }

            /* Builds the EMSA-PKCS1-v1_5 encoded message (RFC 8017 9.2): 0x00 0x01 0xFF...0xFF
             * 0x00 || DigestInfo(digest), padded to exactly keyBytes long. */
            static bool buildPkcs1v15EncodedMessage(size_t keyBytes, SReadOnlyByteSpan digest, CBuffer& out) {
                SReadOnlyByteSpan prefix = digestInfoPrefixFor(digest.size);
                if (prefix.empty()) {
                    return false;
                }

                size_t tLen = prefix.size + digest.size;
                if (keyBytes < tLen + 11) {
                    return false;
                }

                out.resize(keyBytes);
                uint8_t* p = out.toPtr();

                p[0] = 0x00;
                p[1] = 0x01;

                size_t padLen = keyBytes - tLen - 3;
                std::memset(p + 2, 0xFF, padLen);
                p[2 + padLen] = 0x00;

                size_t offset = 3 + padLen;
                std::memcpy(p + offset, prefix.data, prefix.size);

                offset += prefix.size;
                std::memcpy(p + offset, digest.data, digest.size);

                return true;
            }

            /* MGF1 (RFC 8017 Appendix B.2.1): fills out with a mask derived from seed, using
             * hasher (already reset by the caller) as the underlying hash function -- repeatedly
             * hashing seed || I2OSP(counter, 4) for counter = 0, 1, 2, ... and concatenating the
             * digests until out is full. hasher is reset before each iteration's use, so the
             * caller may pass any freshly-created or freshly-reset instance. */
            static bool mgf1(IHasher& hasher, SReadOnlyByteSpan seed, SByteSpan out) {
                size_t hLen = hasher.byteWidth();
                uint8_t digest[64]; // --> Large enough for every hasher this library ships (<= SHA-512).
                if (hLen > sizeof(digest)) {
                    return false;
                }

                size_t written = 0;
                for (uint32_t counter = 0; written < out.size; ++counter) {
                    uint8_t c[4] = {
                        uint8_t(counter >> 24), uint8_t(counter >> 16), uint8_t(counter >> 8), uint8_t(counter)
                    };

                    hasher.reset();
                    hasher.push(seed);
                    hasher.push(SReadOnlyByteSpan(c, sizeof(c)));

                    SByteSpan digestOut(digest, hLen);
                    if (!hasher.finish(digestOut)) {
                        return false;
                    }

                    size_t take = (out.size - written < hLen) ? (out.size - written) : hLen;
                    std::memcpy(out.data + written, digest, take);
                    written += take;
                }

                return true;
            }

            /* EMSA-PSS-ENCODE (RFC 8017 9.1.1): builds the emLen-byte encoded message EM (emLen =
             * ceil(emBits/8)) from mHash (an already-computed message digest) and a
             * caller-supplied salt, using hasher (already reset, or about to be) as both the
             * digest and MGF1's underlying hash. False on any of the encoding-error conditions
             * 9.1.1 itself defines (most commonly: modulus too small for hLen+sLen+2). */
            static bool emsaPssEncode(
                IHasher& hasher, SReadOnlyByteSpan mHash, size_t emBits, SReadOnlyByteSpan salt, CBuffer& outEm
            ) {
                size_t hLen = hasher.byteWidth();
                if (mHash.size != hLen) {
                    return false;
                }

                size_t emLen = (emBits + 7) / 8;
                size_t sLen = salt.size;
                if (emLen < hLen + sLen + 2) {
                    return false;
                }

                // M' = 8 zero octets || mHash || salt; H = Hash(M').
                uint8_t zeros[8] = { 0 };
                hasher.reset();
                hasher.push(SReadOnlyByteSpan(zeros, sizeof(zeros)));
                hasher.push(mHash);
                hasher.push(salt);

                CBuffer h(hLen);
                SByteSpan hOut(h.toPtr(), hLen);
                if (!hasher.finish(hOut)) {
                    return false;
                }

                // DB = PS (zeros) || 0x01 || salt, of length emLen - hLen - 1.
                size_t dbLen = emLen - hLen - 1;
                size_t psLen = dbLen - sLen - 1;

                CBuffer db(dbLen);
                uint8_t* dbPtr = db.toPtr();
                std::memset(dbPtr, 0x00, psLen);
                dbPtr[psLen] = 0x01;
                std::memcpy(dbPtr + psLen + 1, salt.data, sLen);

                CBuffer dbMask(dbLen);
                if (!mgf1(hasher, SReadOnlyByteSpan(h.toPtr(), hLen), SByteSpan(dbMask.toPtr(), dbLen))) {
                    return false;
                }

                const uint8_t* maskPtr = dbMask.toPtr();
                for (size_t i = 0; i < dbLen; ++i) {
                    dbPtr[i] = uint8_t(dbPtr[i] ^ maskPtr[i]);
                }

                // Zero the leftmost 8*emLen - emBits bits of the leftmost octet of maskedDB.
                size_t zeroBits = 8 * emLen - emBits;
                if (zeroBits > 0) {
                    dbPtr[0] = uint8_t(dbPtr[0] & (0xFF >> zeroBits));
                }

                outEm.resize(emLen);
                uint8_t* emPtr = outEm.toPtr();
                std::memcpy(emPtr, dbPtr, dbLen);
                std::memcpy(emPtr + dbLen, h.toPtr(), hLen);
                emPtr[emLen - 1] = 0xBC;

                return true;
            }

            /* EMSA-PSS-VERIFY (RFC 8017 9.1.2): checks whether em (emLen = ceil(emBits/8) bytes)
             * is a valid PSS encoding of mHash for a salt of length sLen, using hasher the same
             * way emsaPssEncode() does. */
            static bool emsaPssVerify(
                IHasher& hasher, SReadOnlyByteSpan mHash, SReadOnlyByteSpan em, size_t emBits, size_t sLen
            ) {
                size_t hLen = hasher.byteWidth();
                if (mHash.size != hLen) {
                    return false;
                }

                size_t emLen = (emBits + 7) / 8;
                if (em.size != emLen || emLen < hLen + sLen + 2) {
                    return false;
                }

                if (em.data[emLen - 1] != 0xBC) {
                    return false;
                }

                size_t dbLen = emLen - hLen - 1;
                SReadOnlyByteSpan maskedDb(em.data, dbLen);
                SReadOnlyByteSpan h(em.data + dbLen, hLen);

                size_t zeroBits = 8 * emLen - emBits;
                if (zeroBits > 0 && (maskedDb.data[0] & ~(0xFF >> zeroBits)) != 0) {
                    return false;
                }

                CBuffer db(dbLen);
                uint8_t* dbPtr = db.toPtr();
                if (!mgf1(hasher, h, SByteSpan(dbPtr, dbLen))) {
                    return false;
                }

                for (size_t i = 0; i < dbLen; ++i) {
                    dbPtr[i] = uint8_t(dbPtr[i] ^ maskedDb.data[i]);
                }
                if (zeroBits > 0) {
                    dbPtr[0] = uint8_t(dbPtr[0] & (0xFF >> zeroBits));
                }

                size_t psLen = dbLen - sLen - 1;
                for (size_t i = 0; i < psLen; ++i) {
                    if (dbPtr[i] != 0x00) {
                        return false;
                    }
                }
                if (dbPtr[psLen] != 0x01) {
                    return false;
                }

                SReadOnlyByteSpan salt(dbPtr + psLen + 1, sLen);

                uint8_t zeros[8] = { 0 };
                hasher.reset();
                hasher.push(SReadOnlyByteSpan(zeros, sizeof(zeros)));
                hasher.push(mHash);
                hasher.push(salt);

                CBuffer hPrime(hLen);
                SByteSpan hPrimeOut(hPrime.toPtr(), hLen);
                if (!hasher.finish(hPrimeOut)) {
                    return false;
                }

                if (hPrime.size() != h.size) {
                    return false;
                }
                if (std::memcmp(hPrime.toPtr(), h.data, hLen) != 0) {
                    return false;
                }

                return true;
            }

            /* Private-key exponentiation x^d mod n (RFC 8017 5.1.2), accelerated via CRT when
             * priv's p/q/dp/dq/qInv are all present: m1 = x^dp mod p, m2 = x^dq mod q, combined
             * by Garner's formula (h = qInv*(m1-m2) mod p; m = m2 + h*q) instead of one
             * full-modulus exponentiation -- each of the two exponentiations works over a
             * modulus/exponent roughly half the bit-length of n/d, for close to a 4x speedup over
             * plain modExp(x, d, n). The CRT result is checked against a full re-encrypt
             * (modExp(m, e, n) == x) before being trusted -- the standard countermeasure against a
             * Lenstra/Bellcore-style fault attack (a single bit error during either CRT branch
             * lets an attacker factor n from the faulty result), and it also makes this safe to
             * call on an imported private key whose CRT parameters were never run through
             * RSA::checkPrivateKey(): a mismatch (or a missing CRT parameter) just falls back to
             * the always-correct, if slower, plain exponentiation rather than ever returning a
             * wrong result. */
            static CBigNum privateExp(const RsaPrivateKey& priv, const CBigNum& x) {
                const CBigNum& p = priv.p();
                const CBigNum& q = priv.q();
                const CBigNum& dp = priv.dp();
                const CBigNum& dq = priv.dq();
                const CBigNum& qInv = priv.qInv();

                if (!p.isZero() && !q.isZero() && !dp.isZero() && !dq.isZero() && !qInv.isZero()) {
                    CBigNum m1 = CBigNum::modExp(x, dp, p);
                    CBigNum m2 = CBigNum::modExp(x, dq, q);

                    CBigNum h(m1);
                    h.modSub(m2, p);
                    h.mulMod(qInv, p);

                    CBigNum m(h);
                    m.mul(q);
                    m.add(m2);

                    const bool consistent = (CBigNum::modExp(m, priv.e(), priv.n()) == x);

                    // --> Each CRT intermediate hands over the factorization, not merely a hint
                    // of it: m1 is m mod p, so m - m1 is a multiple of p and gcd(m - m1, n) is p
                    // exactly. For signing, m is the published signature, which makes m1 and m2
                    // strictly more sensitive than the value being computed. They are cleared
                    // before either return, and so is m on the path where the re-encrypt check
                    // failed and it is a wrong value nobody wants.
                    m1.secureClear();
                    m2.secureClear();
                    h.secureClear();

                    if (consistent) {
                        return m;
                    }

                    m.secureClear();
                }

                return CBigNum::modExp(x, priv.d(), priv.n());
            }

        public:
            ERetCode sign(const SReadOnlyByteSpan& digest, SByteSpan& out) override {
                if (!privateKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto priv = std::dynamic_pointer_cast<RsaPrivateKey>(privateKey());
                if (!priv) {
                    return ERET_KEY_FORMAT;
                }

                size_t keyBytes = (priv->n().bitLength() + 7) / 8;
                if (out.size < keyBytes) {
                    return ERET_NOSPC;
                }

                CBuffer em;
                if (!buildPkcs1v15EncodedMessage(keyBytes, digest, em)) {
                    return ERET_NOTSUP;
                }

                CBigNum m = CBigNum::fromBigEndian(em.toSpan());
                CBigNum s = privateExp(*priv, m);

                if (!s.toBigEndian(SByteSpan(out.data, keyBytes))) {
                    return ERET_UNKNOWN;
                }
                out = SByteSpan(out.data, keyBytes);

                return ERET_OK;
            }

            ERetCode verify(const SReadOnlyByteSpan& digest, const SReadOnlyByteSpan& signature) override {
                if (!publicKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto pub = std::dynamic_pointer_cast<RsaPublicKey>(publicKey());
                if (!pub) {
                    return ERET_KEY_FORMAT;
                }

                size_t keyBytes = (pub->n().bitLength() + 7) / 8;
                if (signature.size != keyBytes) {
                    return ERET_BADREQ;
                }

                CBigNum s = CBigNum::fromBigEndian(signature);
                if (s >= pub->n()) {
                    return ERET_BADREQ;
                }

                CBigNum m = CBigNum::modExp(s, pub->e(), pub->n());

                CBuffer em(keyBytes);
                if (!m.toBigEndian(em.toSpan())) {
                    return ERET_BADREQ;
                }

                CBuffer expected;
                if (!buildPkcs1v15EncodedMessage(keyBytes, digest, expected)) {
                    return ERET_NOTSUP;
                }

                if (expected.size() != em.size()) {
                    return ERET_BADREQ;
                }

                if (std::memcmp(em.toPtr(), expected.toPtr(), em.size()) != 0) {
                    return ERET_BADREQ;
                }

                return ERET_OK;
            }

            ERetCode signPss(
                const SReadOnlyByteSpan& digest, EHashers hashAlg, size_t saltLen, SByteSpan& out
            ) override {
                if (!privateKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto priv = std::dynamic_pointer_cast<RsaPrivateKey>(privateKey());
                if (!priv) {
                    return ERET_KEY_FORMAT;
                }

                IHasherPtr hasher;
                if (IHasher::create(hashAlg, hasher) != ERET_OK || !hasher) {
                    return ERET_NOTSUP;
                }
                if (digest.size != hasher->byteWidth()) {
                    return ERET_BADREQ;
                }

                size_t modBits = priv->n().bitLength();
                size_t keyBytes = (modBits + 7) / 8;
                if (out.size < keyBytes) {
                    return ERET_NOSPC;
                }
                if (modBits == 0) {
                    return ERET_KEY_ERROR;
                }
                size_t emBits = modBits - 1;

                CBuffer salt(saltLen);
                if (saltLen > 0) {
                    ERetCode rc = CRng::fill(salt.toSpan());
                    if (rc != ERET_OK) {
                        return rc;
                    }
                }

                CBuffer em;
                if (!emsaPssEncode(*hasher, digest, emBits, salt.toSpan(), em)) {
                    return ERET_NOTSUP; // --> modulus too small for this hash/salt combination.
                }

                CBigNum m = CBigNum::fromBigEndian(em.toSpan());
                CBigNum s = privateExp(*priv, m);

                if (!s.toBigEndian(SByteSpan(out.data, keyBytes))) {
                    return ERET_UNKNOWN;
                }
                out = SByteSpan(out.data, keyBytes);

                return ERET_OK;
            }

            ERetCode verifyPss(
                const SReadOnlyByteSpan& digest, EHashers hashAlg, size_t saltLen,
                const SReadOnlyByteSpan& signature
            ) override {
                if (!publicKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto pub = std::dynamic_pointer_cast<RsaPublicKey>(publicKey());
                if (!pub) {
                    return ERET_KEY_FORMAT;
                }

                IHasherPtr hasher;
                if (IHasher::create(hashAlg, hasher) != ERET_OK || !hasher) {
                    return ERET_NOTSUP;
                }
                if (digest.size != hasher->byteWidth()) {
                    return ERET_BADREQ;
                }

                size_t modBits = pub->n().bitLength();
                size_t keyBytes = (modBits + 7) / 8;
                if (signature.size != keyBytes || modBits == 0) {
                    return ERET_BADREQ;
                }

                CBigNum s = CBigNum::fromBigEndian(signature);
                if (s >= pub->n()) {
                    return ERET_BADREQ;
                }

                CBigNum m = CBigNum::modExp(s, pub->e(), pub->n());

                size_t emBits = modBits - 1;
                size_t emLen = (emBits + 7) / 8;

                CBuffer em(emLen);
                if (!m.toBigEndian(em.toSpan())) {
                    return ERET_BADREQ;
                }

                if (!emsaPssVerify(*hasher, digest, em.toSpan(), emBits, saltLen)) {
                    return ERET_BADREQ;
                }

                return ERET_OK;
            }

            ERetCode encryptBlock(SReadOnlyByteSpan message, SByteSpan& output) {
                if (!publicKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto pub = std::dynamic_pointer_cast<RsaPublicKey>(publicKey());
                if (!pub) {
                    return ERET_KEY_FORMAT;
                }

                size_t keyBytes = (pub->n().bitLength() + 7) / 8;
                if (keyBytes < 11 || message.size > keyBytes - 11) {
                    return ERET_BADREQ;
                }
                if (output.size < keyBytes) {
                    return ERET_NOSPC;
                }

                CBuffer em(keyBytes);
                uint8_t* emPtr = em.toPtr();
                emPtr[0] = 0x00;
                emPtr[1] = 0x02;

                size_t padLen = keyBytes - message.size - 3;
                ERetCode padStatus = CRng::fillNonZero(SByteSpan(emPtr + 2, padLen));
                if (padStatus != ERET_OK) {
                    return padStatus;
                }

                emPtr[2 + padLen] = 0x00;
                std::memcpy(emPtr + 3 + padLen, message.data, message.size);

                CBigNum m = CBigNum::fromBigEndian(em.toSpan());
                CBigNum c = CBigNum::modExp(m, pub->e(), pub->n());

                if (!c.toBigEndian(SByteSpan(output.data, keyBytes))) {
                    return ERET_UNKNOWN;
                }
                output = SByteSpan(output.data, keyBytes);
                return ERET_OK;
            }

            ERetCode decryptBlock(SReadOnlyByteSpan ciphertext, SByteSpan& output) {
                if (!privateKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto priv = std::dynamic_pointer_cast<RsaPrivateKey>(privateKey());
                if (!priv) {
                    return ERET_KEY_FORMAT;
                }

                size_t keyBytes = (priv->n().bitLength() + 7) / 8;

                // --> keyBytes >= 11 is what makes an EME-PKCS1-v1_5 block well-formed at all
                // (two lead bytes, >= 8 padding bytes, a separator); encryptBlock() already
                // requires it. Without it here, a key small enough to give keyBytes < 2 -- which
                // only an imported key could -- would have the lead-byte read below run off the
                // end of em.
                if (keyBytes < 11 || ciphertext.size != keyBytes) {
                    return ERET_BADREQ;
                }

                CBigNum c = CBigNum::fromBigEndian(ciphertext);

                // --> RFC 8017 5.1.2 step 1: a ciphertext representative outside [0, n-1] is not
                // a valid input and must be rejected rather than exponentiated. Letting it
                // through is also a timing distinguisher: privateExp()'s re-encrypt check can
                // never match for c >= n, so every such call would quietly take the slow
                // full-modulus fallback path instead of the CRT one.
                if (c >= priv->n()) {
                    return ERET_BADREQ;
                }

                CBigNum m = privateExp(*priv, c);

                CBuffer em(keyBytes);
                if (!m.toBigEndian(em.toSpan())) {
                    return ERET_BADREQ;
                }

                // --> Constant-time EME-PKCS1-v1_5 unpadding (RFC 8017 7.2.2): the separator
                // search below scans every byte of EM unconditionally (always keyBytes-2
                // iterations, never stopping at the first 0x00) and never branches on the
                // decrypted content itself, combining every check into a single mask instead --
                // the same discipline CbcTransformer's PKCS#7 check already applies (see its own
                // doc comment). The original version's data-dependent-length scan plus
                // early-return branches on the lead bytes/separator position was the textbook
                // Bleichenbacher-oracle shape; every failure still reports the same ERET_BADREQ,
                // but previously the *time taken to reach it* leaked which check failed and
                // where.
                const uint8_t* emPtr = em.toPtr();

                uint8_t leadMismatch = uint8_t((emPtr[0] ^ 0x00) | (emPtr[1] ^ 0x02));
                uint8_t leadOk = uint8_t(-(uint8_t(leadMismatch == 0)));

                size_t sepIndex = 0;
                uint8_t sepFound = 0; // --> 0xFF once the first 0x00 past the lead bytes is seen.

                for (size_t idx = 2; idx < keyBytes; ++idx) {
                    uint8_t isZero = uint8_t(-(uint8_t(emPtr[idx] == 0)));
                    uint8_t takeIt = uint8_t(isZero & uint8_t(~sepFound)); // --> only the first.
                    size_t mask = size_t(0) - size_t(takeIt >> 7);
                    sepIndex = (sepIndex & ~mask) | (idx & mask);
                    sepFound = uint8_t(sepFound | isZero);
                }

                // RFC 8017 7.2.2 step 3 requires at least 8 padding (PS) bytes between the lead
                // bytes and the separator, i.e. the separator index must be >= 2 + 8.
                uint8_t lenOk = uint8_t(-(uint8_t(sepIndex >= 2 + 8)));
                uint8_t allOk = uint8_t(leadOk & sepFound & lenOk);

                if (allOk == 0) {
                    CSecure::zero(em.toSpan());
                    return ERET_BADREQ;
                }

                size_t msgStart = sepIndex + 1;
                size_t msgLen = keyBytes - msgStart;

                if (output.size < msgLen) {
                    CSecure::zero(em.toSpan());
                    return ERET_NOSPC;
                }

                std::memcpy(output.data, emPtr + msgStart, msgLen);
                output = SByteSpan(output.data, msgLen);

                // em held the full padded plaintext. The caller now has the message itself; the
                // padding around it is of no further use to anyone, here least of all.
                CSecure::zero(em.toSpan());

                return ERET_OK;
            }

            ERetCode createEncrypter(IAsymmetricTransformerPtr& out) override;
            ERetCode createDecrypter(IAsymmetricTransformerPtr& out) override;
        };

        class RsaTransformer : public IAsymmetricTransformer {
        private:
            bool _encrypting;
            size_t _inputBlockSize;     // --> encrypting: max plaintext/block (keyBytes-11); decrypting: keyBytes.
            CBuffer _buffer;

            /* Processes every complete _inputBlockSize chunk currently buffered, writing each
             * block's output in turn; the trailing remainder is kept buffered unless final is
             * true, in which case it's treated as this operation's last block (a non-empty
             * decrypt remainder is a truncated ciphertext, not a valid partial block). If a
             * block can't be processed because output is out of room, a non-final call defers
             * it to a later call instead of failing; consumed bytes are always spliced out of
             * _buffer -- even on error -- so a retry never reprocesses (and, for encryption,
             * never re-randomizes the padding of) an already-completed block. */
            ERetCode processBuffered(bool final, SByteSpan& output) {
                auto rsaCtx = std::dynamic_pointer_cast<RsaContext>(context());
                if (!rsaCtx) {
                    return ERET_KEY_FORMAT; // context() is never null; only its type can mismatch
                }

                size_t outWritten = 0;
                size_t consumed = 0;
                ERetCode result = ERET_OK;

                while (_inputBlockSize > 0 && _buffer.size() - consumed >= _inputBlockSize) {
                    SByteSpan blockOut(output.data + outWritten, output.size - outWritten);
                    SReadOnlyByteSpan block(_buffer.toPtr() + consumed, _inputBlockSize);

                    ERetCode rc = _encrypting
                        ? rsaCtx->encryptBlock(block, blockOut)
                        : rsaCtx->decryptBlock(block, blockOut);

                    if (rc == ERET_NOSPC && !final) {
                        break; // not enough room for this block yet -- defer to a later call
                    }
                    if (rc != ERET_OK) {
                        result = rc;
                        break;
                    }

                    outWritten += blockOut.size;
                    consumed += _inputBlockSize;
                }

                if (result == ERET_OK && final) {
                    size_t leftover = _buffer.size() - consumed;
                    if (leftover > 0) {
                        if (!_encrypting) {
                            result = ERET_BADREQ; // truncated ciphertext: blocks are always keyBytes
                        } else {
                            SByteSpan blockOut(output.data + outWritten, output.size - outWritten);
                            SReadOnlyByteSpan block(_buffer.toPtr() + consumed, leftover);

                            ERetCode rc = rsaCtx->encryptBlock(block, blockOut);
                            if (rc != ERET_OK) {
                                result = rc;
                            } else {
                                outWritten += blockOut.size;
                                consumed += leftover;
                            }
                        }
                    }
                }

                if (consumed > 0) {
                    CBuffer remainder(_buffer.size() - consumed);
                    std::memcpy(remainder.toPtr(), _buffer.toPtr() + consumed, remainder.size());
                    _buffer = std::move(remainder);
                }

                output = SByteSpan(output.data, outWritten);
                return result;
            }

        public:
            RsaTransformer(const IAsymmetricContextPtr& ctx, bool encrypting)
                : IAsymmetricTransformer(ctx), _encrypting(encrypting), _inputBlockSize(0)
            {
                auto rsaCtx = std::dynamic_pointer_cast<RsaContext>(ctx);
                if (rsaCtx) {
                    size_t keyBytes = rsaCtx->sizeOfSign();
                    blockSize(keyBytes);
                    _inputBlockSize = encrypting ? (keyBytes > 11 ? keyBytes - 11 : 0) : keyBytes;
                }
            }

            ERetCode transform(const SReadOnlyByteSpan& input, SByteSpan& output) override {
                size_t old = _buffer.size();
                size_t add = input.size;

                _buffer.resize(old + add);
                std::memcpy(_buffer.toPtr() + old, input.data, add);

                return processBuffered(false, output);
            }

            ERetCode transformFinal(SByteSpan& output) override {
                return processBuffered(true, output);
            }
        };

        ERetCode RsaContext::createEncrypter(IAsymmetricTransformerPtr& out) {
            if (!publicKey()) {
                return ERET_KEY_EMPTY;
            }

            out = std::make_shared<RsaTransformer>(shared_from_this(), true);
            return ERET_OK;
        }

        ERetCode RsaContext::createDecrypter(IAsymmetricTransformerPtr& out) {
            if (!privateKey()) {
                return ERET_KEY_EMPTY;
            }

            out = std::make_shared<RsaTransformer>(shared_from_this(), false);
            return ERET_OK;
        }

    } // namespace

    RSA::RSA() {
        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(512, 8192, 8));
        keySizes(specs);
    }

    ERetCode RSA::generateKeyPair(SKeySize keySize, SKeyPair& out) {
        out = SKeyPair();

        bool ok = false;
        for (size_t i = 0; i < keySizes().size(); ++i) {
            if (keySizes()[i].includes(keySize)) {
                ok = true;
                break;
            }
        }

        if (!ok) {
            return ERET_KEY_SIZE;
        }

        size_t halfBits = keySize / 2;
        CBigNum e(uint64_t(65537));
        CBigNum one(uint64_t(1));

        for (int attempt = 0; attempt < 100; ++attempt) {
            CBigNum p, q;
            if (!CBigNum::generatePrime(halfBits, p) || !CBigNum::generatePrime(halfBits, q)) {
                return ERET_UNKNOWN;
            }

            if (p == q) {
                continue;
            }

            CBigNum n(p);
            n.mul(q);

            CBigNum pMinus1(p);
            pMinus1.sub(one);

            CBigNum qMinus1(q);
            qMinus1.sub(one);

            CBigNum phi(pMinus1);
            phi.mul(qMinus1);

            if (CBigNum::gcd(e, phi) != one) {
                continue;
            }

            CBigNum d;
            if (!CBigNum::modInverse(e, phi, d)) {
                continue;
            }

            CBigNum dp(d);
            dp.mod(pMinus1);

            CBigNum dq(d);
            dq.mod(qMinus1);

            CBigNum qInv;
            if (!CBigNum::modInverse(q, p, qInv)) {
                continue;
            }

            auto pub = std::make_shared<RsaPublicKey>(n, e);
            auto priv = std::make_shared<RsaPrivateKey>(n, e, d, p, q, dp, dq, qInv, pub);

            if (checkPrivateKey(priv) != ERET_OK) {
                return ERET_AGAIN;
            }

            out = SKeyPair(pub, priv);
            return ERET_OK;
        }

        return ERET_UNKNOWN;
    }

    ERetCode RSA::checkPrivateKey(const IPrivateKeyPtr& key) const {
        auto priv = std::dynamic_pointer_cast<RsaPrivateKey>(key);
        if (!priv) {
            return ERET_KEY_FORMAT;
        }

        auto pub = std::dynamic_pointer_cast<RsaPublicKey>(priv->publicKey());
        if (!pub) {
            return ERET_KEY_ERROR; // this key's own linked public key is missing/wrong type
        }

        const CBigNum& n = priv->n();
        const CBigNum& e = priv->e();
        const CBigNum& d = priv->d();
        const CBigNum& p = priv->p();
        const CBigNum& q = priv->q();
        const CBigNum& dp = priv->dp();
        const CBigNum& dq = priv->dq();
        const CBigNum& qInv = priv->qInv();
        CBigNum one(uint64_t(1));

        // The linked public key must be consistent with this private key's own n/e.
        if (pub->n() != n || pub->e() != e) {
            return ERET_KEY_ERROR;
        }

        // p, q must be distinct probable primes.
        if (p == q || !p.isProbablePrime() || !q.isProbablePrime()) {
            return ERET_KEY_PARAM;
        }

        // n must equal p*q.
        CBigNum pq(p);
        pq.mul(q);
        if (pq != n) {
            return ERET_KEY_PARAM;
        }

        CBigNum pMinus1(p);
        pMinus1.sub(one);

        CBigNum qMinus1(q);
        qMinus1.sub(one);

        CBigNum phi(pMinus1);
        phi.mul(qMinus1);

        // e must be coprime to phi(n) -- otherwise no modular inverse (d) exists.
        if (CBigNum::gcd(e, phi) != one) {
            return ERET_KEY_PARAM;
        }

        // e*d must be congruent to 1 modulo both p-1 and q-1 -- equivalently, modulo
        // lambda(n) = lcm(p-1, q-1). RFC 8017 3.2 lets d be the inverse of e modulo either
        // lambda(n) or phi(n), and the two differ whenever gcd(p-1, q-1) > 2: OpenSSL (for
        // 2048 bits and up), BIND's dnssec-keygen and ldns all emit the lambda(n) value,
        // which is the smaller of the two. Comparing d against the phi(n) inverse rejected
        // every one of those keys as ERET_KEY_PARAM even though they sign and verify
        // correctly. lambda divides phi, so this congruence accepts both forms -- and still
        // rejects a d that is not an inverse at all.
        CBigNum ed(e);
        ed.mul(d);

        CBigNum edModP(ed);
        edModP.mod(pMinus1);

        CBigNum edModQ(ed);
        edModQ.mod(qMinus1);

        if (edModP != one || edModQ != one) {
            return ERET_KEY_PARAM;
        }

        // The CRT parameters (dp, dq, qInv) must be consistent with d, p, q.
        CBigNum expectedDp(d);
        expectedDp.mod(pMinus1);

        CBigNum expectedDq(d);
        expectedDq.mod(qMinus1);

        CBigNum expectedQInv;
        if (!CBigNum::modInverse(q, p, expectedQInv)) {
            return ERET_KEY_PARAM;
        }

        if (expectedDp != dp || expectedDq != dq || expectedQInv != qInv) {
            return ERET_KEY_PARAM;
        }

        return ERET_OK;
    }

    IPublicKeyPtr RSA::createPublicKey(const SReadOnlyByteSpan& keyData) const {
        TReadOnlySpan<uint8_t> content;
        if (!asn1::CDer::readOuterSequence(keyData, content)) {
            return nullptr;
        }

        CBigNum n, e;
        if (!asn1::CDer::readBigInteger(content, n) || !asn1::CDer::readBigInteger(content, e)) {
            return nullptr;
        }

        if (!content.empty() || n.isZero() || e.isZero()) {
            return nullptr;
        }

        return std::make_shared<RsaPublicKey>(n, e);
    }

    IPrivateKeyPtr RSA::createPrivateKey(const SReadOnlyByteSpan& keyData) const {
        TReadOnlySpan<uint8_t> content;
        if (!asn1::CDer::readOuterSequence(keyData, content)) {
            return nullptr;
        }

        CBigNum version, n, e, d, p, q, dp, dq, qInv;
        bool ok = asn1::CDer::readBigInteger(content, version)
            && asn1::CDer::readBigInteger(content, n)
            && asn1::CDer::readBigInteger(content, e)
            && asn1::CDer::readBigInteger(content, d)
            && asn1::CDer::readBigInteger(content, p)
            && asn1::CDer::readBigInteger(content, q)
            && asn1::CDer::readBigInteger(content, dp)
            && asn1::CDer::readBigInteger(content, dq)
            && asn1::CDer::readBigInteger(content, qInv);

        if (!ok || !content.empty() || version != CBigNum(uint64_t(0))) {
            return nullptr;
        }

        auto pub = std::make_shared<RsaPublicKey>(n, e);
        return std::make_shared<RsaPrivateKey>(n, e, d, p, q, dp, dq, qInv, pub);
    }

    IAsymmetricContextPtr RSA::createContext() const {
        return std::make_shared<RsaContext>();
    }

} // namespace crypto
} // namespace certpp
