#include <certpp/crypto/syms/des.hpp>
#include <certpp/crypto/rng.hpp>
#include "symkey.hpp"
#include "cbctransformer.hpp"
#include "descore.hpp"
#include <cstring>
#include <memory>

namespace certpp {
namespace crypto {

    namespace {

        constexpr size_t DES_BLOCK_BYTES = 8;
        constexpr size_t DES_KEY_BYTES = 8;

        class DesContext : public ISymmetricContext, public std::enable_shared_from_this<DesContext> {
        private:
            uint64_t _roundKeys[16];
            bool _ready;

        protected:
            void onReset() override {
                _ready = false;

                auto k = std::dynamic_pointer_cast<SymRawKey>(key());
                if (!k || k->keyData().size() != DES_KEY_BYTES) {
                    return;
                }

                DesCore::keySchedule(k->keyData().toPtr(), _roundKeys);
                _ready = true;
                sizeOfBlock(DES_BLOCK_BYTES);
            }

        public:
            DesContext() : _roundKeys{}, _ready(false) {
            }

            ERetCode createEncrypter(ISymmetricTransformerPtr& out) override {
                if (!_ready) {
                    return ERET_KEY_EMPTY;
                }
                if (iv().size() != DES_BLOCK_BYTES) {
                    return ERET_KEY_PARAM;
                }

                uint64_t keys[16];
                std::memcpy(keys, _roundKeys, sizeof(keys));

                out = std::make_shared<CbcTransformer>(
                    shared_from_this(), true, DES_BLOCK_BYTES, iv().toSpan(),
                    [keys](const uint8_t* in, uint8_t* o) {
                        DesCore::processBlock(in, o, keys);
                    }
                );
                return ERET_OK;
            }

            ERetCode createDecrypter(ISymmetricTransformerPtr& out) override {
                if (!_ready) {
                    return ERET_KEY_EMPTY;
                }
                if (iv().size() != DES_BLOCK_BYTES) {
                    return ERET_KEY_PARAM;
                }

                uint64_t keys[16];
                for (int i = 0; i < 16; ++i) {
                    keys[i] = _roundKeys[15 - i]; // --> decrypt applies the schedule in reverse.
                }

                out = std::make_shared<CbcTransformer>(
                    shared_from_this(), false, DES_BLOCK_BYTES, iv().toSpan(),
                    [keys](const uint8_t* in, uint8_t* o) {
                        DesCore::processBlock(in, o, keys);
                    }
                );
                return ERET_OK;
            }
        };

    } // namespace

    DES::DES() {
        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(64));
        keySizes(specs);
    }

    ERetCode DES::generateKey(ISymmetricKeyPtr& out, const SKeySizeSpec& keySize) const {
        SKeySize bits = keySize.empty() ? 64 : keySize.minSize;
        if (bits != 64) {
            return ERET_KEY_SIZE;
        }

        CBuffer raw(DES_KEY_BYTES);

        ERetCode rc = CRng::fill(raw.toSpan());
        if (rc != ERET_OK) {
            return rc;
        }

        out = createKey(raw.toSpan());
        return out ? ERET_OK : ERET_KEY_SIZE;
    }

    ISymmetricKeyPtr DES::createKey(const SReadOnlyByteSpan& keyData) const {
        if (keyData.size != DES_KEY_BYTES) {
            return nullptr;
        }

        return std::make_shared<SymRawKey>(ESYM_DES, COctet(keyData));
    }

    ERetCode DES::generateIV(const ISymmetricKeyPtr& key, CBuffer& out) const {
        if (!key || key->algorithm() != ESYM_DES) {
            return ERET_KEY_FORMAT;
        }

        out.resize(DES_BLOCK_BYTES);
        return CRng::fill(out.toSpan());
    }

    ISymmetricContextPtr DES::createContext(const ISymmetricKeyPtr& key) const {
        auto ctx = std::make_shared<DesContext>();
        ctx->key(key, CBuffer());
        return ctx;
    }

} // namespace crypto
} // namespace certpp
