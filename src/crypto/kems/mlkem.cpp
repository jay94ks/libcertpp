#include <certpp/crypto/kems/mlkem.hpp>
#include <certpp/crypto/rng.hpp>
#include <certpp/io/buffer.hpp>
#include <certpp/utils/secure.hpp>
#include <cstring>
#include <utility>

namespace certpp {
namespace crypto {

    namespace {

        /* The SKeySize each parameter set accepts: the set's own number. See MLKEM's doc
         * comment for why that rather than a modulus width or a security strength. */
        SKeySize keySizeOf(EKems which) {
            switch (which) {
                case EKEM_MLKEM512:  return 512;
                case EKEM_MLKEM768:  return 768;
                case EKEM_MLKEM1024: return 1024;
                default:             return 0;
            }
        }

        /* An ML-KEM encapsulation key: FIPS 203's own encoding, 800/1184/1568 bytes, and nothing
         * wrapped around it. */
        class MlKemPublicKey : public IKemPublicKey {
        private:
            COctet _encoded;
            SMlKemParams _params;

        public:
            MlKemPublicKey(EKems which, const SMlKemParams& params, const SReadOnlyByteSpan& encoded)
                : _encoded(encoded), _params(params)
            {
                algorithm(which);
            }

            SKeySize keySize() const override {
                return keySizeOf(algorithm());
            }

            ERetCode serialize(COctet& out) const override {
                out = _encoded;
                return ERET_OK;
            }

            int32_t compare(const IKeyBasePtr& other) const override {
                if (!other) {
                    return 1;
                }

                auto o = std::dynamic_pointer_cast<MlKemPublicKey>(other);
                if (!o) {
                    auto otherKem = std::dynamic_pointer_cast<IKemKeyBase>(other);
                    return otherKem ? (int32_t(keySize()) - int32_t(otherKem->keySize())) : 1;
                }

                // A key of a different parameter set is a different length, so ordering by
                // length first keeps the comparison total without comparing across sets by
                // whatever their leading bytes happen to be.
                if (_encoded.size() != o->_encoded.size()) {
                    return _encoded.size() < o->_encoded.size() ? -1 : 1;
                }

                return int32_t(std::memcmp(_encoded.toPtr(), o->_encoded.toPtr(), _encoded.size()));
            }

            const SMlKemParams& params() const { return _params; }
            SReadOnlyByteSpan span() const { return _encoded.toSpan(); }
        };

        /* An ML-KEM decapsulation key: FIPS 203's dk_PKE || ek || H(ek) || z, 1632/2400/3168
         * bytes. It embeds its own encapsulation key, so publicKey() reads that out rather than
         * recomputing it -- and checkPrivateKey() verifies the embedded H(ek) agrees with it. */
        class MlKemPrivateKey : public IKemPrivateKey {
        private:
            COctet _encoded;
            SMlKemParams _params;
            IKemPublicKeyPtr _publicKey;

        public:
            MlKemPrivateKey(
                EKems which, const SMlKemParams& params, const SReadOnlyByteSpan& encoded,
                IKemPublicKeyPtr publicKey
            ) : _encoded(encoded), _params(params), _publicKey(std::move(publicKey)) {
                algorithm(which);
            }

            SKeySize keySize() const override {
                return keySizeOf(algorithm());
            }

            ERetCode serialize(COctet& out) const override {
                out = _encoded;
                return ERET_OK;
            }

            int32_t compare(const IKeyBasePtr& other) const override {
                if (!other) {
                    return 1;
                }

                auto o = std::dynamic_pointer_cast<MlKemPrivateKey>(other);
                if (!o) {
                    auto otherKem = std::dynamic_pointer_cast<IKemKeyBase>(other);
                    return otherKem ? (int32_t(keySize()) - int32_t(otherKem->keySize())) : 1;
                }

                if (_encoded.size() != o->_encoded.size()) {
                    return _encoded.size() < o->_encoded.size() ? -1 : 1;
                }

                return int32_t(std::memcmp(_encoded.toPtr(), o->_encoded.toPtr(), _encoded.size()));
            }

            IKemPublicKeyPtr publicKey() const override {
                return _publicKey;
            }

            const SMlKemParams& params() const { return _params; }
            SReadOnlyByteSpan span() const { return _encoded.toSpan(); }
        };

        class MlKemContext : public IKemContext {
        protected:
            /* Both sizes are fixed per parameter set, so they come from whichever key is bound.
             * Either half carries the parameter set, and a context bound to only one of them is
             * the normal case for encapsulation (the peer's public key alone). */
            void onReset() override {
                const SMlKemParams* params = nullptr;

                if (auto pub = std::dynamic_pointer_cast<MlKemPublicKey>(publicKey())) {
                    params = &pub->params();
                }
                else if (auto priv = std::dynamic_pointer_cast<MlKemPrivateKey>(privateKey())) {
                    params = &priv->params();
                }

                if (!params) {
                    return;
                }

                sizeOfCiphertext(params->ciphertextBytes());
                sizeOfSharedSecret(params->sharedSecretBytes());
            }

        public:
            ERetCode encapsulate(SByteSpan& ciphertext, SByteSpan& sharedSecret) override {
                if (!publicKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto pub = std::dynamic_pointer_cast<MlKemPublicKey>(publicKey());
                if (!pub) {
                    return ERET_KEY_FORMAT;
                }

                const SMlKemParams& params = pub->params();
                if (ciphertext.size < params.ciphertextBytes()
                    || sharedSecret.size < params.sharedSecretBytes())
                {
                    return ERET_NOSPC;
                }

                // The one place ML-KEM draws randomness. CMlKem::encapsulate() takes the message
                // as a parameter so it can be driven from a test vector; a reused message means a
                // reused shared secret, so nothing but fresh CSPRNG output belongs here.
                uint8_t message[32];
                if (CRng::fill(SByteSpan(message, sizeof(message))) != ERET_OK) {
                    return ERET_UNKNOWN;
                }

                const bool encapsulated = CMlKem::encapsulate(
                    params, pub->span(), SReadOnlyByteSpan(message, sizeof(message)),
                    SByteSpan(ciphertext.data, params.ciphertextBytes()),
                    SByteSpan(sharedSecret.data, params.sharedSecretBytes()));

                // The message determines the shared secret outright, so it is cleared either way
                // -- including on the failure path, where the caller gets nothing and so has no
                // reason for it to still be here.
                CSecure::zero(SByteSpan(message, sizeof(message)));

                if (!encapsulated) {
                    return ERET_UNKNOWN;
                }

                ciphertext = SByteSpan(ciphertext.data, params.ciphertextBytes());
                sharedSecret = SByteSpan(sharedSecret.data, params.sharedSecretBytes());

                return ERET_OK;
            }

            /* A ciphertext that fails ML-KEM's re-encryption check is *not* reported here: it
             * yields the implicit-rejection secret and ERET_OK, exactly as if it had decapsulated
             * normally. That is the Fujisaki-Okamoto requirement IKemContext::decapsulate()'s own
             * doc comment states, and the reason CMlKem::decapsulate() has no failure mode for a
             * bad ciphertext to pass up. The error codes below are all structural -- no key bound,
             * wrong key type, wrong lengths -- and none of them depends on the ciphertext's
             * contents. */
            ERetCode decapsulate(const SReadOnlyByteSpan& ciphertext, SByteSpan& sharedSecret) override {
                if (!privateKey()) {
                    return ERET_KEY_EMPTY;
                }

                auto priv = std::dynamic_pointer_cast<MlKemPrivateKey>(privateKey());
                if (!priv) {
                    return ERET_KEY_FORMAT;
                }

                const SMlKemParams& params = priv->params();
                if (ciphertext.size != params.ciphertextBytes() || !ciphertext.data) {
                    return ERET_BADREQ;
                }
                if (sharedSecret.size < params.sharedSecretBytes()) {
                    return ERET_NOSPC;
                }

                if (!CMlKem::decapsulate(
                        params, priv->span(), ciphertext,
                        SByteSpan(sharedSecret.data, params.sharedSecretBytes())))
                {
                    return ERET_UNKNOWN;
                }

                sharedSecret = SByteSpan(sharedSecret.data, params.sharedSecretBytes());
                return ERET_OK;
            }
        };

    } // namespace

    /* Maps an EKems value to the parameter set it names. */
    bool MLKEM::paramsOf(EKems which, SMlKemParams& out) {
        switch (which) {
            case EKEM_MLKEM512:
                out = SMlKemParams::mlKem512();
                return true;

            case EKEM_MLKEM768:
                out = SMlKemParams::mlKem768();
                return true;

            case EKEM_MLKEM1024:
                out = SMlKemParams::mlKem1024();
                return true;

            default:
                return false;
        }
    }

    /* Constructs an ML-KEM instance for one parameter set. */
    MLKEM::MLKEM(EKems which) : _params(SMlKemParams::mlKem768()), _which(EKEM_UNKNOWN) {
        if (!paramsOf(which, _params)) {
            // keySizes() stays empty, so generateKeyPair() rejects every size and the create*Key()
            // length checks never match. _params keeps a valid set only so that nothing downstream
            // has to cope with a half-built one.
            return;
        }

        _which = which;

        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(keySizeOf(which)));
        keySizes(specs);
    }

    /* Draws both FIPS 203 seeds from the CSPRNG and expands them into a key pair. */
    ERetCode MLKEM::generateKeyPair(SKeySize keySize, SKemKeyPair& out) {
        out = SKemKeyPair();

        if (_which == EKEM_UNKNOWN || keySize != keySizeOf(_which)) {
            return ERET_KEY_SIZE;
        }

        // d expands into the key material; z is retained inside the decapsulation key as the
        // implicit-rejection seed, and never leaves it.
        uint8_t seeds[64];
        if (CRng::fill(SByteSpan(seeds, sizeof(seeds))) != ERET_OK) {
            return ERET_UNKNOWN;
        }

        CBuffer ek(_params.ekBytes());
        CBuffer dk(_params.dkBytes());
        if (ek.size() != _params.ekBytes() || dk.size() != _params.dkBytes()) {
            return ERET_NOMEM;
        }

        const bool generated = CMlKem::generateKeyPair(
            _params, SReadOnlyByteSpan(seeds, 32), SReadOnlyByteSpan(seeds + 32, 32),
            ek.toSpan(), dk.toSpan());

        // d regenerates the entire key pair and z is the implicit-rejection secret; both have
        // served their purpose here, and z lives on inside dk where it belongs.
        CSecure::zero(SByteSpan(seeds, sizeof(seeds)));

        if (!generated) {
            return ERET_UNKNOWN;
        }

        auto pub = std::make_shared<MlKemPublicKey>(
            _which, _params, SReadOnlyByteSpan(ek.toPtr(), ek.size()));
        auto priv = std::make_shared<MlKemPrivateKey>(
            _which, _params, SReadOnlyByteSpan(dk.toPtr(), dk.size()), pub);

        if (checkPrivateKey(priv) != ERET_OK) {
            return ERET_AGAIN;
        }

        out = SKemKeyPair(pub, priv);
        return ERET_OK;
    }

    /* Checks a decapsulation key against FIPS 203 6.2: right length, embedded H(ek) agreeing with
     * the ek it carries, and that ek itself canonical. */
    ERetCode MLKEM::checkPrivateKey(const IKemPrivateKeyPtr& key) const {
        auto priv = std::dynamic_pointer_cast<MlKemPrivateKey>(key);
        if (!priv) {
            return ERET_KEY_FORMAT;
        }

        if (priv->algorithm() != _which) {
            return ERET_KEY_FORMAT; // a key of a different parameter set than this instance runs
        }

        auto pub = std::dynamic_pointer_cast<MlKemPublicKey>(priv->publicKey());
        if (!pub) {
            return ERET_KEY_ERROR; // this key's own linked public key is missing/wrong type
        }

        // 1. The decapsulation key must agree with itself: its embedded H(ek) has to match the
        // encapsulation key it carries. A key that disagrees here would make Decaps's
        // re-encryption comparison compare against the wrong thing.
        if (!CMlKem::checkDecapsulationKey(_params, priv->span())) {
            return ERET_KEY_PARAM;
        }

        // 2. The linked public key must be the one embedded at offset 384*k, not merely a
        // well-formed key of the same length.
        if (pub->span().size != _params.ekBytes()
            || std::memcmp(
                   priv->span().data + _params.dkPkeBytes(), pub->span().data,
                   _params.ekBytes()) != 0)
        {
            return ERET_KEY_ERROR;
        }

        // 3. And that encapsulation key has to be canonical -- every 12-bit segment below q.
        // ByteDecode at d=12 reduces mod q, so a non-canonical key decodes successfully into
        // something other than what its bytes say.
        if (!CMlKem::checkEncapsulationKey(_params, pub->span())) {
            return ERET_KEY_PARAM;
        }

        return ERET_OK;
    }

    /* Parses an encapsulation key, rejecting a non-canonical one. */
    IKemPublicKeyPtr MLKEM::createPublicKey(const SReadOnlyByteSpan& keyData) const {
        if (_which == EKEM_UNKNOWN || !CMlKem::checkEncapsulationKey(_params, keyData)) {
            return nullptr;
        }

        return std::make_shared<MlKemPublicKey>(_which, _params, keyData);
    }

    /* Parses a decapsulation key, rejecting one whose embedded H(ek) doesn't match. */
    IKemPrivateKeyPtr MLKEM::createPrivateKey(const SReadOnlyByteSpan& keyData) const {
        if (_which == EKEM_UNKNOWN || !CMlKem::checkDecapsulationKey(_params, keyData)) {
            return nullptr;
        }

        // The embedded encapsulation key is the public half, so there is nothing to recompute --
        // and it is checked for canonicality here rather than trusted, since this key came from
        // outside.
        const SReadOnlyByteSpan ek(keyData.data + _params.dkPkeBytes(), _params.ekBytes());
        if (!CMlKem::checkEncapsulationKey(_params, ek)) {
            return nullptr;
        }

        auto pub = std::make_shared<MlKemPublicKey>(_which, _params, ek);
        return std::make_shared<MlKemPrivateKey>(_which, _params, keyData, pub);
    }

    /* Creates a key-less context for this parameter set. */
    IKemContextPtr MLKEM::createContext() const {
        return std::make_shared<MlKemContext>();
    }

} // namespace crypto
} // namespace certpp
