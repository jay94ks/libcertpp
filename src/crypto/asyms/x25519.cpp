#include <certpp/crypto/asyms/x25519.hpp>
#include <certpp/utils/bignum.hpp>
#include <certpp/crypto/rng.hpp>
#include <cstring>
#include <utility>

namespace certpp {
namespace crypto {

    namespace {

        /* Everything specific to implementing Curve25519/X25519 (RFC 7748): the field prime,
         * scalar/u-coordinate decoding, and the Montgomery ladder itself -- bundled into one
         * class rather than left as file-scope free functions, mirroring Edwards25519
         * (ed25519.cpp), Edwards448 (ed448.cpp), and AesCore/DesCore/ChaCha20Core (crypto/syms/). */
        class Curve25519 {
        private:
            /* The Montgomery curve coefficient A = 486662 (RFC 7748 4.1); a24 = (A - 2) / 4 =
             * 121665, used directly in the ladder step (RFC 7748 5). */
            static const CBigNum& a24() {
                static const CBigNum v = CBigNum(uint64_t(121665));
                return v;
            }

        public:
            /* The Curve25519 field prime, 2^255 - 19 (RFC 7748 4.1) -- cheaper and safer to
             * derive than to transcribe as a 64-hex-digit literal (same reasoning as
             * ed25519.cpp). */
            static const CBigNum& fieldPrime() {
                static const CBigNum p = CBigNum(uint64_t(1)).shl(255).sub(CBigNum(uint64_t(19)));
                return p;
            }

            /* The Curve25519 base point's u-coordinate, u = 9 (RFC 7748 4.1) -- small enough to
             * not need deriving or cross-checking, unlike every other constant in this module. */
            static const CBigNum& basePointU() {
                static const CBigNum u = CBigNum(uint64_t(9));
                return u;
            }

            /* Applies RFC 7748 5's clamping to a raw 32-byte scalar, producing the CBigNum the
             * ladder actually multiplies by. Clamping is applied here, at every scalar-mult call
             * site, rather than once at key-creation time, so a private key's stored bytes always
             * round-trip exactly through serialize()/createPrivateKey() (RFC 7748 5's own
             * recommended split of responsibility between "decode scalar" and "the caller's
             * stored secret"). */
            static CBigNum decodeScalar(const uint8_t k[32]) {
                uint8_t clamped[32];
                std::memcpy(clamped, k, 32);

                clamped[0] &= 248;
                clamped[31] &= 127;
                clamped[31] |= 64;

                return CBigNum::fromLittleEndian(SReadOnlyByteSpan(clamped, 32));
            }

            /* Decodes a 32-byte little-endian u-coordinate per RFC 7748 5: the top bit is masked
             * (it's never set for a canonical Curve25519 value, but decodeUCoordinate must still
             * accept it per the RFC) and the result is reduced mod p -- non-canonical values are
             * REDUCED, not rejected, unlike Ed25519's point decode. This is a spec requirement,
             * not an inconsistency with ed25519.cpp's stricter decodePoint(). */
            static CBigNum decodeUCoordinate(const uint8_t u[32]) {
                uint8_t bytes[32];
                std::memcpy(bytes, u, 32);
                bytes[31] &= 0x7F;

                CBigNum result = CBigNum::fromLittleEndian(SReadOnlyByteSpan(bytes, 32));
                result.mod(fieldPrime());
                return result;
            }

            /* RFC 7748 5's X25519 function: the Montgomery ladder over the u-coordinate only, in
             * projective (X:Z) form so no per-step inversion is needed -- just one at the end. */
            static CBigNum x25519(const CBigNum& clampedScalar, const CBigNum& u) {
                const CBigNum& p = fieldPrime();

                CBigNum x1(u);
                CBigNum x2(uint64_t(1)), z2;
                CBigNum x3(u), z3(uint64_t(1));
                bool swap = false;

                for (size_t t = 255; t-- > 0; ) {
                    bool kt = clampedScalar.testBit(t);
                    swap ^= kt;
                    CBigNum::condSwap(swap, x2, x3);
                    CBigNum::condSwap(swap, z2, z3);
                    swap = kt;

                    CBigNum A(x2);
                    A.add(z2);
                    A.mod(p);

                    CBigNum AA(A);
                    AA.mulMod(A, p);

                    CBigNum B(x2);
                    B.modSub(z2, p);

                    CBigNum BB(B);
                    BB.mulMod(B, p);

                    CBigNum E(AA);
                    E.modSub(BB, p);

                    CBigNum C(x3);
                    C.add(z3);
                    C.mod(p);

                    CBigNum D(x3);
                    D.modSub(z3, p);

                    CBigNum DA(D);
                    DA.mulMod(A, p);

                    CBigNum CB(C);
                    CB.mulMod(B, p);

                    CBigNum newX3(DA);
                    newX3.add(CB);
                    newX3.mod(p);
                    newX3.mulMod(newX3, p);

                    CBigNum newZ3(DA);
                    newZ3.modSub(CB, p);
                    newZ3.mulMod(newZ3, p);
                    newZ3.mulMod(x1, p);

                    CBigNum newX2(AA);
                    newX2.mulMod(BB, p);

                    CBigNum newZ2(a24());
                    newZ2.mulMod(E, p);
                    newZ2.add(AA);
                    newZ2.mod(p);
                    newZ2.mulMod(E, p);

                    x2 = std::move(newX2);
                    z2 = std::move(newZ2);
                    x3 = std::move(newX3);
                    z3 = std::move(newZ3);
                }

                CBigNum::condSwap(swap, x2, x3);
                CBigNum::condSwap(swap, z2, z3);

                CBigNum z2Inv;
                if (!CBigNum::modInverse(z2, p, z2Inv)) {
                    return CBigNum();
                }

                x2.mulMod(z2Inv, p);
                return x2;
            }
        };

        class X25519PublicKey : public IPublicKey {
        private:
            uint8_t _encoded[32];

        public:
            explicit X25519PublicKey(const uint8_t encoded[32]) {
                algorithm(EASYM_X25519);
                std::memcpy(_encoded, encoded, 32);
            }

            SKeySize keySize() const override {
                return 256;
            }

            ERetCode serialize(COctet& out) const override {
                out = COctet(_encoded, 32);
                return ERET_OK;
            }

            int32_t compare(const IKeyBasePtr& other) const override {
                if (!other) {
                    return 1;
                }

                auto o = std::dynamic_pointer_cast<X25519PublicKey>(other);
                if (!o) {
                    auto otherAsym = std::dynamic_pointer_cast<IAsymmetricKeyBase>(other);
                    return otherAsym ? (int32_t(keySize()) - int32_t(otherAsym->keySize())) : 1;
                }

                return int32_t(std::memcmp(_encoded, o->_encoded, 32));
            }

            const uint8_t* encoded() const { return _encoded; }
        };

        class X25519PrivateKey : public IPrivateKey {
        private:
            uint8_t _raw[32];
            IPublicKeyPtr _publicKey;

        public:
            X25519PrivateKey(const uint8_t raw[32], IPublicKeyPtr publicKey) : _publicKey(std::move(publicKey)) {
                algorithm(EASYM_X25519);
                std::memcpy(_raw, raw, 32);
            }

            SKeySize keySize() const override {
                return 256;
            }

            ERetCode serialize(COctet& out) const override {
                out = COctet(_raw, 32);
                return ERET_OK;
            }

            int32_t compare(const IKeyBasePtr& other) const override {
                if (!other) {
                    return 1;
                }

                auto o = std::dynamic_pointer_cast<X25519PrivateKey>(other);
                if (!o) {
                    auto otherAsym = std::dynamic_pointer_cast<IAsymmetricKeyBase>(other);
                    return otherAsym ? (int32_t(keySize()) - int32_t(otherAsym->keySize())) : 1;
                }

                return int32_t(std::memcmp(_raw, o->_raw, 32));
            }

            IPublicKeyPtr publicKey() const override {
                return _publicKey;
            }

            const uint8_t* raw() const { return _raw; }
        };

    } // namespace

    /* Builds the matching public key for a 32-byte raw private key (shared by
     * generateKeyPair() and createPrivateKey()). */
    IPublicKeyPtr X25519::publicKeyFromRaw(const uint8_t raw[32]) {
        CBigNum scalar = Curve25519::decodeScalar(raw);
        CBigNum u = Curve25519::x25519(scalar, Curve25519::basePointU());

        uint8_t encoded[32];
        if (!u.toLittleEndian(SByteSpan(encoded, 32))) {
            return nullptr;
        }

        return std::make_shared<X25519PublicKey>(encoded);
    }

    namespace {

        class X25519Context : public IAsymmetricContext {
        protected:
            void onReset() override {
            }

        public:
            ERetCode deriveSharedSecret(const IPublicKeyPtr& peerPublicKey, SByteSpan& out) override {
                if (!privateKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto priv = std::dynamic_pointer_cast<X25519PrivateKey>(privateKey());
                if (!priv) {
                    return ERET_KEY_FORMAT;
                }

                if (!peerPublicKey) {
                    return ERET_KEY_EMPTY;
                }

                auto peer = std::dynamic_pointer_cast<X25519PublicKey>(peerPublicKey);
                if (!peer) {
                    return ERET_KEY_FORMAT; // peerPublicKey wasn't created by this algorithm
                }

                if (out.size < 32) {
                    return ERET_NOSPC;
                }

                CBigNum scalar = Curve25519::decodeScalar(priv->raw());
                CBigNum peerU = Curve25519::decodeUCoordinate(peer->encoded());
                CBigNum secretU = Curve25519::x25519(scalar, peerU);

                uint8_t secretBytes[32];
                if (!secretU.toLittleEndian(SByteSpan(secretBytes, 32))) {
                    return ERET_UNKNOWN;
                }

                // RFC 7748 6.1: reject an all-zero shared secret (the peer supplied a low-order
                // point, e.g. u = 0) rather than silently returning predictable output.
                bool allZero = true;
                for (size_t i = 0; i < 32 && allZero; ++i) {
                    allZero = secretBytes[i] == 0;
                }
                if (allZero) {
                    return ERET_BADREQ;
                }

                std::memcpy(out.data, secretBytes, 32);
                out = SByteSpan(out.data, 32);

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

    X25519::X25519() {
        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(256));
        keySizes(specs);
    }

    ERetCode X25519::generateKeyPair(SKeySize keySize, SKeyPair& out) {
        out = SKeyPair();

        if (keySize != 256) {
            return ERET_KEY_SIZE;
        }

        uint8_t raw[32];
        if (CRng::fill(SByteSpan(raw, 32)) != ERET_OK) {
            return ERET_UNKNOWN;
        }

        IPublicKeyPtr pub = publicKeyFromRaw(raw);
        if (!pub) {
            return ERET_UNKNOWN;
        }

        auto priv = std::make_shared<X25519PrivateKey>(raw, pub);

        if (checkPrivateKey(priv) != ERET_OK) {
            return ERET_AGAIN;
        }

        out = SKeyPair(pub, priv);
        return ERET_OK;
    }

    /* X25519 is a Montgomery curve, u-coordinate only (no y, no point-at-infinity
     * representation) and cofactor 8 (unlike CEcdsa/CEcdsa2/Ed25519/Ed448's cofactor-1 curves),
     * so ECDSA/EdDSA's four checks don't translate literally -- these are their RFC 7748-
     * appropriate analogues instead. There's also no "curve equation" check: by design, X25519
     * accepts u-coordinates from either edwards25519's Montgomery form OR its quadratic twist
     * (RFC 7748 4.1's "twist security" -- both have no small subgroups beyond the explicit
     * cofactor), so restricting to only the main curve would reject spec-valid inputs. */
    ERetCode X25519::checkPrivateKey(const IPrivateKeyPtr& key) const {
        auto priv = std::dynamic_pointer_cast<X25519PrivateKey>(key);
        if (!priv) {
            return ERET_KEY_FORMAT;
        }

        auto pub = std::dynamic_pointer_cast<X25519PublicKey>(priv->publicKey());
        if (!pub) {
            return ERET_KEY_ERROR; // this key's own linked public key is missing/wrong type
        }

        CBigNum scalar = Curve25519::decodeScalar(priv->raw());
        CBigNum u = Curve25519::x25519(scalar, Curve25519::basePointU());

        // The linked public key must be consistent with this private key's own raw scalar.
        uint8_t derivedEncoded[32];
        if (!u.toLittleEndian(SByteSpan(derivedEncoded, 32))
            || std::memcmp(derivedEncoded, pub->encoded(), 32) != 0)
        {
            return ERET_KEY_ERROR;
        }

        const CBigNum& p = Curve25519::fieldPrime();

        // 1. Field range: u must be canonically reduced (< p) -- always true for a value
        // produced by our own Curve25519::x25519(), but checked explicitly since this validates a stored/
        // imported key, not just a freshly generated one.
        if (u >= p) {
            return ERET_KEY_PARAM;
        }

        // 2. "Point at infinity" analogue: RFC 7748 6.1's own "reject an all-zero output" rule,
        // applied here to key generation instead of the ECDH shared secret.
        if (u.isZero()) {
            return ERET_KEY_PARAM;
        }

        // 3. "Correct subgroup" analogue: reject a public key of order dividing the cofactor (8)
        // -- a low-order/twist-torsion point -- computed directly rather than via a hardcoded
        // constant list: 8*u reduces to the identity (u = 0) exactly when u itself has order
        // dividing 8. Uses the raw (unclamped) scalar 8, since this multiplies a public value by
        // a small constant rather than performing an actual Diffie-Hellman step.
        CBigNum eightU = Curve25519::x25519(CBigNum(uint64_t(8)), u);
        if (eightU.isZero()) {
            return ERET_KEY_PARAM;
        }

        return ERET_OK;
    }

    IPublicKeyPtr X25519::createPublicKey(const SReadOnlyByteSpan& keyData) const {
        if (keyData.size != 32) {
            return nullptr;
        }

        return std::make_shared<X25519PublicKey>(keyData.data);
    }

    IPrivateKeyPtr X25519::createPrivateKey(const SReadOnlyByteSpan& keyData) const {
        if (keyData.size != 32) {
            return nullptr;
        }

        IPublicKeyPtr pub = publicKeyFromRaw(keyData.data);
        if (!pub) {
            return nullptr;
        }

        return std::make_shared<X25519PrivateKey>(keyData.data, pub);
    }

    IAsymmetricContextPtr X25519::createContext() const {
        return std::make_shared<X25519Context>();
    }

} // namespace crypto
} // namespace certpp
