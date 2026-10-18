#include <certpp/crypto/asyms/x25519.hpp>
#include <certpp/utils/secure.hpp>
#include "fe25519.hpp"
#include <certpp/crypto/rng.hpp>
#include <cstring>
#include <utility>

namespace certpp {
namespace crypto {

    namespace {

        /* Everything specific to implementing Curve25519/X25519 (RFC 7748): scalar clamping
         * and the Montgomery ladder, over Fe25519 rather than CBigNum.
         *
         * --> This used to run on CBigNum, and that was a timing side channel rather than a
         * theoretical one. CBigNum trims leading zero limbs, so the work every operation does
         * depends on the value it operates on; and CBigNum::condSwap is a plain branch, whose
         * condition in a Montgomery ladder *is* a bit of the private scalar -- leaking the key
         * one bit per iteration. Fe25519 is fixed-width with no data-dependent branching, which
         * is why it exists. Raised by a downstream consumer using X25519 for an online
         * handshake with ephemeral keys, where it genuinely matters.
         *
         * Nothing here touches CBigNum any more, so there is no path by which a secret scalar
         * reaches variable-time arithmetic. */
        class Curve25519 {
        public:
            /* The base point's u-coordinate, u = 9 (RFC 7748 4.1), little-endian. */
            static void basePointU(uint8_t out[32]) {
                std::memset(out, 0, 32);
                out[0] = 9;
            }

            /* Applies RFC 7748 5's clamping to a raw 32-byte scalar. Clamping happens at every
             * scalar-mult call site rather than once at key-creation time, so a private key's
             * stored bytes round-trip exactly through serialize()/createPrivateKey() -- RFC
             * 7748 5's own split between "decode scalar" and "the caller's stored secret". */
            static void clampScalar(const uint8_t raw[32], uint8_t out[32]) {
                std::memcpy(out, raw, 32);

                out[0] = uint8_t(out[0] & 248u);
                out[31] = uint8_t(out[31] & 127u);
                out[31] = uint8_t(out[31] | 64u);
            }

            /* RFC 7748 5's X25519 function: the Montgomery ladder over the u-coordinate only,
             * in projective (X:Z) form so no per-step inversion is needed -- just one at the
             * end. The scalar is used exactly as given; callers wanting RFC 7748's X25519 clamp
             * it first.
             *
             * Every iteration performs the same operations in the same order regardless of the
             * scalar bit: the conditional exchange is Fe25519::condSwap under a mask derived
             * arithmetically from the bit, never an `if`. */
            static void ladder(const uint8_t scalar[32], const uint8_t uBytes[32], uint8_t out[32]) {
                Fe25519::x25519Ladder(scalar, uBytes, out);
            }

            /* RFC 7748's X25519 function proper: clamp, then multiply. */
            static void scalarMult(const uint8_t rawScalar[32], const uint8_t uBytes[32], uint8_t out[32]) {
                uint8_t clamped[32];
                clampScalar(rawScalar, clamped);

                ladder(clamped, uBytes, out);

                CSecure::zero(SByteSpan(clamped, sizeof(clamped)));
            }

            /* Multiplies with a scalar already clamped when its key object was constructed. */
            static void scalarMultClamped(
                const uint8_t clamped[32], const uint8_t uBytes[32], uint8_t out[32]
            ) {
                ladder(clamped, uBytes, out);
            }
        };

        /* RFC 7748-appropriate validity checks on a u-coordinate derived from the standard base
         * point with a clamped scalar. Shared by checkPrivateKey() and generateKeyPair(): the
         * latter has already derived the value and would otherwise pay for a second ladder to
         * have it recomputed.
         *
         * X25519 is a Montgomery curve, u-coordinate only (no y, no point-at-infinity
         * representation) and cofactor 8 -- unlike CEcdsa/CEcdsa2/Ed25519/Ed448 cofactor-1
         * curves -- so ECDSA/EdDSA four checks do not translate literally. Clamping makes the
         * scalar a multiple of 8, which maps the base point into its prime-order subgroup. The
         * derived point therefore has order L unless it is the identity; an additional `8*u`
         * ladder cannot distinguish another bad case and only repeats a full 255-step ladder. */
        ERetCode validateDerivedPublicValue(const uint8_t encoded[32]) {
            // 1. Field range. Fe25519::toBytes() emits the canonical representative in [0, p),
            // so a value derived here cannot be out of range -- what used to be a u >= p test is
            // now a structural property of the encoding. Bit 255 is checked instead, being the
            // one thing a 32-byte encoding could still carry.
            if ((encoded[31] & 0x80u) != 0) {
                return ERET_KEY_PARAM;
            }

            // 2. "Point at infinity" analogue: RFC 7748 6.1 own "reject an all-zero output"
            // rule, applied here to key generation instead of the ECDH shared secret.
            uint8_t accumulator = 0;
            for (size_t i = 0; i < 32; ++i) {
                accumulator = uint8_t(accumulator | encoded[i]);
            }
            if (accumulator == 0) {
                return ERET_KEY_PARAM;
            }

            return ERET_OK;
        }

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
            uint8_t _clamped[32];
            IPublicKeyPtr _publicKey;

        public:
            X25519PrivateKey(const uint8_t raw[32], IPublicKeyPtr publicKey) : _publicKey(std::move(publicKey)) {
                algorithm(EASYM_X25519);
                std::memcpy(_raw, raw, 32);
                Curve25519::clampScalar(raw, _clamped);
            }

            ~X25519PrivateKey() override {
                CSecure::zero(SByteSpan(_raw, sizeof(_raw)));
                CSecure::zero(SByteSpan(_clamped, sizeof(_clamped)));
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
            const uint8_t* clamped() const { return _clamped; }
        };

    } // namespace

    /* Builds the matching public key for a 32-byte raw private key (shared by
     * generateKeyPair() and createPrivateKey()). */
    IPublicKeyPtr X25519::publicKeyFromRaw(const uint8_t raw[32]) {
        uint8_t base[32];
        Curve25519::basePointU(base);

        uint8_t encoded[32];
        Curve25519::scalarMult(raw, base, encoded);

        return std::make_shared<X25519PublicKey>(encoded);
    }

    namespace {

        class X25519Context : public IAsymmetricContext {
        private:
            std::shared_ptr<X25519PrivateKey> _private;
            IPublicKeyPtr _peerBase;
            std::shared_ptr<X25519PublicKey> _peer;

        protected:
            void onReset() override {
                _private = std::dynamic_pointer_cast<X25519PrivateKey>(privateKey());
                _peerBase.reset();
                _peer.reset();
            }

        public:
            ERetCode deriveSharedSecret(const IPublicKeyPtr& peerPublicKey, SByteSpan& out) override {
                if (!privateKey()) {
                    return ERET_KEY_EMPTY;
                }

                if (!_private) {
                    return ERET_KEY_FORMAT;
                }

                if (!peerPublicKey) {
                    return ERET_KEY_EMPTY;
                }

                // OpenSSL likewise validates and binds the peer once on its EVP_PKEY_CTX. Cache a
                // successful check for the same shared object rather than repeating RTTI on every
                // derive; a different object is always checked before replacing the cache.
                if (_peerBase != peerPublicKey) {
                    std::shared_ptr<X25519PublicKey> checked =
                        std::dynamic_pointer_cast<X25519PublicKey>(peerPublicKey);
                    if (!checked) {
                        return ERET_KEY_FORMAT; // peerPublicKey wasn't created by this algorithm
                    }
                    _peerBase = peerPublicKey;
                    _peer = std::move(checked);
                }

                if (out.size < 32) {
                    return ERET_NOSPC;
                }

                // Fe25519::fromBytes masks bit 255 and reduces, which is RFC 7748 5's rule for
                // a peer's u-coordinate: a non-canonical value is REDUCED, not rejected, unlike
                // Ed25519's stricter point decode. The private key already owns a clamped copy;
                // the secret bytes below are cleared once copied out.
                uint8_t secretBytes[32];
                Curve25519::scalarMultClamped(
                    _private->clamped(), _peer->encoded(), secretBytes);

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

                CSecure::zero(SByteSpan(secretBytes, sizeof(secretBytes)));

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

        uint8_t base[32];
        Curve25519::basePointU(base);

        // --> One derivation, not two. This used to derive the public key and then call
        // checkPrivateKey(), which derived it a second time purely to compare against the value
        // just computed. Validating the derived value directly runs exactly the same three
        // checks -- validateDerivedPublicValue() is the code checkPrivateKey() delegates to -- while
        // dropping a derivation whose only purpose was to compare a value against itself.
        uint8_t encoded[32];
        Curve25519::scalarMult(raw, base, encoded);

        if (validateDerivedPublicValue(encoded) != ERET_OK) {
            return ERET_AGAIN;
        }

        auto pub = std::make_shared<X25519PublicKey>(encoded);
        auto priv = std::make_shared<X25519PrivateKey>(raw, pub);

        CSecure::zero(SByteSpan(raw, sizeof(raw)));

        out = SKeyPair(pub, priv);
        return ERET_OK;
    }

    /* X25519 is a Montgomery curve, u-coordinate only (no y, no point-at-infinity
     * representation), so ECDSA/EdDSA's four affine-point checks do not translate literally.
     * Re-deriving from the standard base point checks that the linked public value belongs to
     * this private scalar; clamping has already cleared the base point's cofactor, and the
     * remaining all-zero check rejects the identity. */
    ERetCode X25519::checkPrivateKey(const IPrivateKeyPtr& key) const {
        auto priv = std::dynamic_pointer_cast<X25519PrivateKey>(key);
        if (!priv) {
            return ERET_KEY_FORMAT;
        }

        auto pub = std::dynamic_pointer_cast<X25519PublicKey>(priv->publicKey());
        if (!pub) {
            return ERET_KEY_ERROR; // this key's own linked public key is missing/wrong type
        }

        uint8_t base[32];
        Curve25519::basePointU(base);

        uint8_t derivedEncoded[32];
        Curve25519::scalarMult(priv->raw(), base, derivedEncoded);

        // The linked public key must be consistent with this private key's own raw scalar.
        if (std::memcmp(derivedEncoded, pub->encoded(), 32) != 0) {
            return ERET_KEY_ERROR;
        }

        return validateDerivedPublicValue(derivedEncoded);
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
