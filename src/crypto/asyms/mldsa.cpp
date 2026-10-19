#include <certpp/crypto/asyms/mldsa.hpp>
#include <certpp/crypto/rng.hpp>
#include <certpp/utils/secure.hpp>
#include <certpp/io/buffer.hpp>
#include "mldsascheme.hpp"
#include "mldsaparams.hpp"
#include <cstring>
#include <memory>
#include <utility>

namespace certpp {
namespace crypto {

    namespace {

        /* Maps an EAsymmetrics to the parameter set it names, and to the number keySizes()
         * reports for it. False for anything that is not one of ML-DSA's three sets. */
        bool paramsOf(EAsymmetrics which, MlDsaParams& outParams, SKeySize& outKeySize) {
            switch (which) {
                case EASYM_MLDSA44:
                    outParams = MlDsaParams::mlDsa44();
                    outKeySize = 44;
                    return true;

                case EASYM_MLDSA65:
                    outParams = MlDsaParams::mlDsa65();
                    outKeySize = 65;
                    return true;

                case EASYM_MLDSA87:
                    outParams = MlDsaParams::mlDsa87();
                    outKeySize = 87;
                    return true;

                default:
                    return false;
            }
        }

        class MlDsaPublicKey : public IPublicKey {
        private:
            COctet _key;
            SKeySize _keySize;

        public:
            MlDsaPublicKey(EAsymmetrics which, SKeySize keySize, COctet key)
                : _key(std::move(key)), _keySize(keySize)
            {
                algorithm(which);
            }

            SKeySize keySize() const override {
                return _keySize;
            }

            ERetCode serialize(COctet& out) const override {
                out = _key;
                return ERET_OK;
            }

            int32_t compare(const IKeyBasePtr& other) const override {
                if (!other) {
                    return 1;
                }

                auto o = std::dynamic_pointer_cast<MlDsaPublicKey>(other);
                if (!o) {
                    auto otherAsym = std::dynamic_pointer_cast<IAsymmetricKeyBase>(other);
                    return otherAsym ? (int32_t(keySize()) - int32_t(otherAsym->keySize())) : 1;
                }

                if (_key.size() != o->_key.size()) {
                    return _key.size() < o->_key.size() ? -1 : 1;
                }

                return int32_t(std::memcmp(_key.toPtr(), o->_key.toPtr(), _key.size()));
            }

            const COctet& bytes() const {
                return _key;
            }
        };

        class MlDsaPrivateKey : public IPrivateKey {
        private:
            CSecureOctet _key;
            IPublicKeyPtr _publicKey;
            SKeySize _keySize;

        public:
            MlDsaPrivateKey(
                EAsymmetrics which, SKeySize keySize, CSecureOctet key,
                IPublicKeyPtr publicKey
            )
                : _key(std::move(key)), _publicKey(std::move(publicKey)), _keySize(keySize)
            {
                algorithm(which);
            }

            SKeySize keySize() const override {
                return _keySize;
            }

            ERetCode serialize(COctet& out) const override {
                return out.store(_key.toPtr(), _key.size()) ? ERET_OK : ERET_NOMEM;
            }

            int32_t compare(const IKeyBasePtr& other) const override {
                if (!other) {
                    return 1;
                }

                auto o = std::dynamic_pointer_cast<MlDsaPrivateKey>(other);
                if (!o) {
                    auto otherAsym = std::dynamic_pointer_cast<IAsymmetricKeyBase>(other);
                    return otherAsym ? (int32_t(keySize()) - int32_t(otherAsym->keySize())) : 1;
                }

                if (_key.size() != o->_key.size()) {
                    return _key.size() < o->_key.size() ? -1 : 1;
                }

                return int32_t(std::memcmp(_key.toPtr(), o->_key.toPtr(), _key.size()));
            }

            IPublicKeyPtr publicKey() const override {
                return _publicKey;
            }

            const CSecureOctet& bytes() const {
                return _key;
            }
        };

        /* Builds the public key a private key corresponds to, by re-deriving it (a FIPS 204
         * private key carries tr = H(pk), but not pk itself). Null if the key is malformed, or
         * if its three parts contradict each other -- the re-derived pk not hashing to the
         * stored tr, or the stored t0 not being the one Power2Round produces. Either way the
         * encoding is internally inconsistent, and that is exactly the case an imported key has
         * to be rejected for rather than silently signed with. */
        IPublicKeyPtr derivePublicKey(
            EAsymmetrics which, const MlDsaParams& params, SKeySize keySize,
            const SReadOnlyByteSpan& sk
        ) {
            CBuffer pk;
            if (!pk.resize(params.publicKeyBytes())) {
                return nullptr;
            }

            bool matchesTr = false;
            if (!MlDsaScheme::publicKeyOf(
                    params, sk, SByteSpan(pk.toPtr(), pk.size()), matchesTr) || !matchesTr)
            {
                return nullptr;
            }

            return std::make_shared<MlDsaPublicKey>(which, keySize, COctet(pk.toSpan()));
        }

        class MlDsaContext : public IAsymmetricContext {
        public:
            using IAsymmetricContext::IAsymmetricContext;

        private:
            MlDsaParams _params;
            SKeySize _keySize;
            bool _ready;

        protected:
            void onReset() override {
                _ready = false;

                EAsymmetrics which = EASYM_UNKNOWN;
                if (publicKey()) {
                    which = publicKey()->algorithm();
                }
                else if (privateKey()) {
                    which = privateKey()->algorithm();
                }

                if (!paramsOf(which, _params, _keySize)) {
                    return;
                }

                _ready = true;
                sizeOfSign(_params.signatureBytes());

                // --> sizeOfDigest() stays 0 deliberately. There is no digest for a caller to
                // compute: ML-DSA hashes the message itself, and sign()/verify() below take the
                // message in the parameter the interface calls `digest`. Zero is how a caller
                // tells the two conventions apart.
            }

        public:
            explicit MlDsaContext(const std::shared_ptr<IRng>& rng)
                : IAsymmetricContext(rng), _params(MlDsaParams::mlDsa44()),
                  _keySize(0), _ready(false) { }

            ERetCode sign(const SReadOnlyByteSpan& message, SByteSpan& out) override {
                const IRng& rng = randomGenerator();
                if (!privateKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto priv = std::dynamic_pointer_cast<MlDsaPrivateKey>(privateKey());
                if (!priv || !_ready) {
                    return ERET_KEY_FORMAT;
                }

                const size_t needed = _params.signatureBytes();
                if (out.size < needed) {
                    return ERET_NOSPC;
                }

                // --> Hedged signing, FIPS 204's recommended default: a fresh 32-byte rnd per
                // signature, folded into rho'' alongside the key's own K. Deterministic signing
                // (rnd = 0) is also standard and is what the known-answer tests use, but it is
                // reached through MlDsaScheme directly rather than exposed here -- a caller who
                // does not specifically want it should not be able to select it by accident.
                uint8_t rnd[MlDsaScheme::RND_BYTES];
                if (rng.fillTo(SByteSpan(rnd, sizeof(rnd))) != ERET_OK) {
                    return ERET_UNKNOWN;
                }

                // Empty context string: FIPS 204 Algorithm 2 with ctx = "", which is what
                // RFC 9881's id-ml-dsa-* OIDs mean. See CMlDsa's own doc comment.
                const bool ok = MlDsaScheme::sign(
                    _params, priv->bytes().toSpan(), message, SReadOnlyByteSpan(nullptr, 0),
                    SReadOnlyByteSpan(rnd, sizeof(rnd)), SByteSpan(out.data, needed));

                CSecure::zero(SByteSpan(rnd, sizeof(rnd)));

                if (!ok) {
                    return ERET_UNKNOWN;
                }

                out = SByteSpan(out.data, needed);
                return ERET_OK;
            }

            ERetCode verify(
                const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& signature
            ) override {
                if (!publicKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto pub = std::dynamic_pointer_cast<MlDsaPublicKey>(publicKey());
                if (!pub || !_ready) {
                    return ERET_KEY_FORMAT;
                }

                if (signature.size != _params.signatureBytes()) {
                    return ERET_BADREQ;
                }

                return MlDsaScheme::verify(
                    _params, pub->bytes().toSpan(), message, SReadOnlyByteSpan(nullptr, 0),
                    signature) ? ERET_OK : ERET_BADREQ;
            }

            ERetCode createEncrypter(IAsymmetricTransformerPtr&) override {
                return ERET_NOTSUP;
            }

            ERetCode createDecrypter(IAsymmetricTransformerPtr&) override {
                return ERET_NOTSUP;
            }
        };

    } // namespace

    /* Whether an EAsymmetrics names one of ML-DSA's parameter sets. */
    bool CMlDsa::isMlDsa(EAsymmetrics which) {
        return which == EASYM_MLDSA44 || which == EASYM_MLDSA65 || which == EASYM_MLDSA87;
    }

    /* Constructs an ML-DSA instance for one parameter set. */
    CMlDsa::CMlDsa(EAsymmetrics which) : _which(EASYM_UNKNOWN) {
        MlDsaParams params = MlDsaParams::mlDsa44();
        SKeySize keySize = 0;

        if (!paramsOf(which, params, keySize)) {
            return; // --> keySizes() stays empty, so every operation below refuses.
        }

        _which = which;

        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(keySize));
        keySizes(specs);
    }

    /* Generates a new ML-DSA key pair from 32 fresh CSPRNG bytes. */
    ERetCode CMlDsa::generateKeyPair(const IRng& rng, SKeySize keySize, SKeyPair& out) {
        out = SKeyPair();

        MlDsaParams params = MlDsaParams::mlDsa44();
        SKeySize expected = 0;
        if (!paramsOf(_which, params, expected)) {
            return ERET_NOTSUP;
        }
        if (keySize != expected) {
            return ERET_KEY_SIZE;
        }

        uint8_t seed[MlDsaScheme::SEED_BYTES];
        if (rng.fillTo(SByteSpan(seed, sizeof(seed))) != ERET_OK) {
            return ERET_UNKNOWN;
        }

        CBuffer pk;
        CSecureBuffer sk;
        if (!pk.resize(params.publicKeyBytes()) || !sk.resize(params.privateKeyBytes())) {
            CSecure::zero(SByteSpan(seed, sizeof(seed)));
            return ERET_NOMEM;
        }

        const bool ok = MlDsaScheme::keyGenInternal(
            params, SReadOnlyByteSpan(seed, sizeof(seed)), SByteSpan(pk.toPtr(), pk.size()),
            SByteSpan(sk.toPtr(), sk.size()));

        // xi expands into rho, rho' and K, so it is every bit as sensitive as the private key it
        // produced and has no further use once keyGenInternal() has consumed it.
        CSecure::zero(SByteSpan(seed, sizeof(seed)));

        if (!ok) {
            return ERET_UNKNOWN;
        }

        auto pub = std::make_shared<MlDsaPublicKey>(_which, expected, COctet(pk.toSpan()));
        CSecureOctet protectedKey(sk.toSpan());
        sk.clear();
        if (protectedKey.size() != params.privateKeyBytes()) {
            return ERET_NOMEM;
        }
        auto priv = CSecure::make<MlDsaPrivateKey>(
            _which, expected, std::move(protectedKey), pub);

        if (!priv) {
            return ERET_NOMEM;
        }

        if (checkPrivateKey(priv) != ERET_OK) {
            return ERET_AGAIN;
        }

        out = SKeyPair(pub, priv);
        return ERET_OK;
    }

    /* Validates a private key's structure: its s1/s2 range, and that its linked public key is
     * the one its own rho/s1/s2 actually produce. */
    ERetCode CMlDsa::checkPrivateKey(const IPrivateKeyPtr& key) const {
        auto priv = std::dynamic_pointer_cast<MlDsaPrivateKey>(key);
        if (!priv) {
            return ERET_KEY_FORMAT;
        }

        MlDsaParams params = MlDsaParams::mlDsa44();
        SKeySize keySize = 0;
        if (!paramsOf(_which, params, keySize) || priv->algorithm() != _which) {
            return ERET_KEY_FORMAT; // --> a key from a different parameter set entirely
        }

        auto pub = std::dynamic_pointer_cast<MlDsaPublicKey>(priv->publicKey());
        if (!pub) {
            return ERET_KEY_ERROR;
        }

        // 1. The encoding itself, including skDecode()'s s1/s2 range check -- the one ML-DSA
        // decode that cannot guarantee its own range (2*eta + 1 is 5 or 9, neither a power of
        // two), and the reason FIPS 204 Algorithm 25 has an explicit rejection step.
        if (!MlDsaScheme::checkPrivateKey(params, priv->bytes().toSpan())) {
            return ERET_KEY_PARAM;
        }

        // 2. The linked public key must be the one this private key derives. The check above
        // only establishes that the bytes decode to legal vectors, not that they belong with the
        // public key they are paired with -- without this, a well-formed sk could be handed an
        // unrelated well-formed pk and every signature it produced would fail to verify, with
        // nothing diagnosing why.
        CBuffer derived;
        if (!derived.resize(params.publicKeyBytes())) {
            return ERET_NOMEM;
        }

        bool matchesTr = false;
        if (!MlDsaScheme::publicKeyOf(
                params, priv->bytes().toSpan(), SByteSpan(derived.toPtr(), derived.size()),
                matchesTr))
        {
            return ERET_KEY_PARAM;
        }

        // 3. tr is H(pk) by construction (FIPS 204 Algorithm 6), so a disagreement means the
        // private key's own three parts contradict each other.
        if (!matchesTr) {
            return ERET_KEY_ERROR;
        }

        if (pub->bytes().size() != derived.size()
            || std::memcmp(pub->bytes().toPtr(), derived.toPtr(), derived.size()) != 0)
        {
            return ERET_KEY_ERROR;
        }

        return ERET_OK;
    }

    /* Parses a pkEncode()-format public key. */
    ERetCode CMlDsa::createPublicKey(
        IPublicKeyPtr& out, const SReadOnlyByteSpan& keyData
    ) const {
        out.reset();
        MlDsaParams params = MlDsaParams::mlDsa44();
        SKeySize keySize = 0;
        if (!paramsOf(_which, params, keySize)) {
            return ERET_NOTSUP;
        }

        if (!MlDsaScheme::checkPublicKey(params, keyData)) {
            return keyData.size == params.publicKeyBytes() ? ERET_KEY_FORMAT : ERET_KEY_SIZE;
        }
        try {
            out = std::make_shared<MlDsaPublicKey>(_which, keySize, COctet(keyData));
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        return ERET_OK;
    }

    /* Parses an skEncode()-format private key, re-deriving its public half. */
    ERetCode CMlDsa::createPrivateKey(
        IPrivateKeyPtr& out, const SReadOnlyByteSpan& keyData
    ) const {
        out.reset();
        MlDsaParams params = MlDsaParams::mlDsa44();
        SKeySize keySize = 0;
        if (!paramsOf(_which, params, keySize)) {
            return ERET_NOTSUP;
        }

        if (!MlDsaScheme::checkPrivateKey(params, keyData)) {
            return keyData.size == params.privateKeyBytes() ? ERET_KEY_FORMAT : ERET_KEY_SIZE;
        }

        IPublicKeyPtr pub = derivePublicKey(_which, params, keySize, keyData);
        if (!pub) {
            return ERET_KEY_ERROR;
        }
        CSecureOctet protectedKey(keyData);
        if (protectedKey.size() != keyData.size) {
            return ERET_NOMEM;
        }
        try {
            out = CSecure::make<MlDsaPrivateKey>(
                _which, keySize, std::move(protectedKey), pub);
            if (!out) return ERET_NOMEM;
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        return ERET_OK;
    }

    /* Creates a key-less ML-DSA context. */
    ERetCode CMlDsa::createContext(
        IAsymmetricContextPtr& out, const std::shared_ptr<IRng>& rng
    ) const {
        out.reset();
        if (!rng) return ERET_BADREQ;
        try {
            out = std::make_shared<MlDsaContext>(rng);
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        return ERET_OK;
    }

} // namespace crypto
} // namespace certpp
