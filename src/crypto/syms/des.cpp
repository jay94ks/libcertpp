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
            DesCore::RoundKey _roundKeys[16];
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

                DesCore::RoundKey keys[16];
                std::memcpy(keys, _roundKeys, sizeof(keys));

                out = std::make_shared<CbcTransformer>(
                    shared_from_this(), true, DES_BLOCK_BYTES, iv().toSpan(), padding(),
                    [keys](const uint8_t* in, uint8_t* o) {
                        DesCore::processBlock(in, o, keys);
                    },
                    [keys](const uint8_t* in, uint8_t* o, size_t blocks, uint8_t* chain) {
                        DesCore::encryptCbcBulk(in, o, blocks, chain, keys);
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

                DesCore::RoundKey keys[16];
                for (int i = 0; i < 16; ++i) {
                    keys[i] = _roundKeys[15 - i]; // --> decrypt applies the schedule in reverse.
                }

                out = std::make_shared<CbcTransformer>(
                    shared_from_this(), false, DES_BLOCK_BYTES, iv().toSpan(), padding(),
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

    ERetCode DES::generateKey(
        const IRng& rng, ISymmetricKeyPtr& out, const SKeySizeSpec& keySize
    ) const {
        out.reset();
        SKeySize bits = keySize.empty() ? 64 : keySize.minSize;
        if (bits != 64) {
            return ERET_KEY_SIZE;
        }

        CBuffer raw(DES_KEY_BYTES);

        ERetCode rc = rng.fillTo(raw.toSpan());
        if (rc != ERET_OK) {
            return rc;
        }

        return createKey(out, raw.toSpan());
    }

    ERetCode DES::createKey(
        ISymmetricKeyPtr& out, const SReadOnlyByteSpan& keyData
    ) const {
        out.reset();
        if (keyData.size != DES_KEY_BYTES) {
            return ERET_KEY_SIZE;
        }
        try {
            out = std::make_shared<SymRawKey>(ESYM_DES, COctet(keyData));
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        return ERET_OK;
    }

    ERetCode DES::generateIV(const IRng& rng, const ISymmetricKeyPtr& key, CBuffer& out) const {
        if (!key || key->algorithm() != ESYM_DES) {
            return ERET_KEY_FORMAT;
        }

        out.resize(DES_BLOCK_BYTES);
        return rng.fillTo(out.toSpan());
    }

    ERetCode DES::createContext(
        ISymmetricContextPtr& out, const ISymmetricKeyPtr& key
    ) const {
        out.reset();
        try {
            out = std::make_shared<DesContext>();
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        out->key(key, CBuffer());
        return ERET_OK;
    }

} // namespace crypto
} // namespace certpp
