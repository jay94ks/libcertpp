#include <certpp/crypto/syms/des3.hpp>
#include <certpp/crypto/rng.hpp>
#include "symkey.hpp"
#include "cbctransformer.hpp"
#include "descore.hpp"
#include <cstring>
#include <memory>

namespace certpp {
namespace crypto {

    namespace {

        constexpr size_t DES3_BLOCK_BYTES = 8;
        constexpr size_t DES_KEY_BYTES = 8;

        /* Encrypts/decrypts one 8-byte block via DES-EDE3 (FIPS 46-3): Encrypt(K3,
         * Decrypt(K2, Encrypt(K1, block))) to encrypt, or the mirror image to decrypt. Each
         * roundKeyTriple[i] is already oriented the way DesCore::processBlock needs it applied
         * for that step (forward for an Encrypt step, reversed for a Decrypt step) -- see
         * TripleDesContext::createEncrypter()/createDecrypter(), which build them accordingly. */
        class TripleDesCore {
        public:
            static void process(const uint8_t in[8], uint8_t out[8], const uint64_t (&keys)[3][16]) {
                uint8_t stage[8];
                DesCore::processBlock(in, stage, keys[0]);
                DesCore::processBlock(stage, stage, keys[1]);
                DesCore::processBlock(stage, out, keys[2]);
            }

            static void reverseSchedule(const uint64_t in[16], uint64_t out[16]) {
                for (int i = 0; i < 16; ++i) {
                    out[i] = in[15 - i];
                }
            }
        };

        class TripleDesContext : public ISymmetricContext, public std::enable_shared_from_this<TripleDesContext> {
        private:
            uint64_t _k1[16];
            uint64_t _k2[16];
            uint64_t _k3[16];
            bool _ready;

        protected:
            void onReset() override {
                _ready = false;

                auto k = std::dynamic_pointer_cast<SymRawKey>(key());
                if (!k) {
                    return;
                }

                size_t keyBytes = k->keyData().size();
                if (keyBytes != 16 && keyBytes != 24) {
                    return;
                }

                const uint8_t* raw = k->keyData().toPtr();
                DesCore::keySchedule(raw, _k1);
                DesCore::keySchedule(raw + DES_KEY_BYTES, _k2);
                DesCore::keySchedule(keyBytes == 24 ? raw + 2 * DES_KEY_BYTES : raw, _k3);

                _ready = true;
                sizeOfBlock(DES3_BLOCK_BYTES);
            }

        public:
            TripleDesContext() : _k1{}, _k2{}, _k3{}, _ready(false) {
            }

            ERetCode createEncrypter(ISymmetricTransformerPtr& out) override {
                if (!_ready) {
                    return ERET_KEY_EMPTY;
                }
                if (iv().size() != DES3_BLOCK_BYTES) {
                    return ERET_KEY_PARAM;
                }

                uint64_t keys[3][16];
                std::memcpy(keys[0], _k1, sizeof(keys[0]));
                TripleDesCore::reverseSchedule(_k2, keys[1]);
                std::memcpy(keys[2], _k3, sizeof(keys[2]));

                out = std::make_shared<CbcTransformer>(
                    shared_from_this(), true, DES3_BLOCK_BYTES, iv().toSpan(), padding(),
                    [keys](const uint8_t* in, uint8_t* o) {
                        TripleDesCore::process(in, o, keys);
                    }
                );
                return ERET_OK;
            }

            ERetCode createDecrypter(ISymmetricTransformerPtr& out) override {
                if (!_ready) {
                    return ERET_KEY_EMPTY;
                }
                if (iv().size() != DES3_BLOCK_BYTES) {
                    return ERET_KEY_PARAM;
                }

                uint64_t keys[3][16];
                TripleDesCore::reverseSchedule(_k3, keys[0]);
                std::memcpy(keys[1], _k2, sizeof(keys[1]));
                TripleDesCore::reverseSchedule(_k1, keys[2]);

                out = std::make_shared<CbcTransformer>(
                    shared_from_this(), false, DES3_BLOCK_BYTES, iv().toSpan(), padding(),
                    [keys](const uint8_t* in, uint8_t* o) {
                        TripleDesCore::process(in, o, keys);
                    }
                );
                return ERET_OK;
            }
        };

    } // namespace

    TripleDES::TripleDES() {
        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(128, 192, 64));
        keySizes(specs);
    }

    ERetCode TripleDES::generateKey(ISymmetricKeyPtr& out, const SKeySizeSpec& keySize) const {
        SKeySize bits = keySize.empty() ? 192 : keySize.minSize;

        bool valid = false;
        for (const auto& spec : keySizes()) {
            if (spec.includes(bits)) {
                valid = true;
                break;
            }
        }
        if (!valid) {
            return ERET_KEY_SIZE;
        }

        CBuffer raw(bits / 8);

        ERetCode rc = CRng::fill(raw.toSpan());
        if (rc != ERET_OK) {
            return rc;
        }

        out = createKey(raw.toSpan());
        return out ? ERET_OK : ERET_KEY_SIZE;
    }

    ISymmetricKeyPtr TripleDES::createKey(const SReadOnlyByteSpan& keyData) const {
        if (keyData.size != 16 && keyData.size != 24) {
            return nullptr;
        }

        return std::make_shared<SymRawKey>(ESYM_3DES, COctet(keyData));
    }

    ERetCode TripleDES::generateIV(const ISymmetricKeyPtr& key, CBuffer& out) const {
        if (!key || key->algorithm() != ESYM_3DES) {
            return ERET_KEY_FORMAT;
        }

        out.resize(DES3_BLOCK_BYTES);
        return CRng::fill(out.toSpan());
    }

    ISymmetricContextPtr TripleDES::createContext(const ISymmetricKeyPtr& key) const {
        auto ctx = std::make_shared<TripleDesContext>();
        ctx->key(key, CBuffer());
        return ctx;
    }

} // namespace crypto
} // namespace certpp
