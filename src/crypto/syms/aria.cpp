#include <certpp/crypto/syms/aria.hpp>
#include <certpp/crypto/rng.hpp>

#include "symkey.hpp"
#include "cbctransformer.hpp"
#include "ariacore.hpp"

#include <cstring>
#include <memory>

namespace certpp {
namespace crypto {

    namespace {

        constexpr size_t ARIA_BLOCK_BYTES = AriaCore::BLOCK_BYTES;

        class AriaContext : public ISymmetricContext, public std::enable_shared_from_this<AriaContext> {
        private:
            TArray<uint8_t> _roundKeys;
            uint32_t _nr;

        protected:
            void onReset() override {
                _roundKeys.clear();
                _nr = 0;

                auto k = std::dynamic_pointer_cast<SymRawKey>(key());
                if (!k) {
                    return;
                }

                const size_t keyBytes = k->keyData().size();
                if (!AriaCore::expandKey(k->keyData().toPtr(), keyBytes, _roundKeys, _nr)) {
                    return;
                }

                sizeOfBlock(ARIA_BLOCK_BYTES);
            }

        public:
            AriaContext() : _nr(0) {
            }

            ERetCode createEncrypter(ISymmetricTransformerPtr& out) override {
                if (_nr == 0) {
                    return ERET_KEY_EMPTY;
                }
                if (iv().size() != ARIA_BLOCK_BYTES) {
                    return ERET_KEY_PARAM;
                }

                // --> captured by the lambda below, kept alive with it.
                auto roundKeys = _roundKeys;
                const uint32_t nr = _nr;

                out = std::make_shared<CbcTransformer>(
                    shared_from_this(), true, ARIA_BLOCK_BYTES, iv().toSpan(), padding(),
                    [roundKeys, nr](const uint8_t* in, uint8_t* o) {
                        AriaCore::encryptBlock(in, o, roundKeys.begin(), nr);
                    }
                );
                return ERET_OK;
            }

            ERetCode createDecrypter(ISymmetricTransformerPtr& out) override {
                if (_nr == 0) {
                    return ERET_KEY_EMPTY;
                }
                if (iv().size() != ARIA_BLOCK_BYTES) {
                    return ERET_KEY_PARAM;
                }

                auto roundKeys = _roundKeys;
                const uint32_t nr = _nr;

                // Note: decryptBlock() derives the decryption round keys from the encryption
                // schedule per call. That is one diffusion-layer pass per interior key, on
                // top of the rounds themselves -- roughly 15% overhead on this cipher. A
                // caller doing bulk work would want to cache the decrypted schedule; the
                // single-block entry point here matches AesCore's shape and keeps the
                // interface the same for every block cipher in this library.
                out = std::make_shared<CbcTransformer>(
                    shared_from_this(), false, ARIA_BLOCK_BYTES, iv().toSpan(), padding(),
                    [roundKeys, nr](const uint8_t* in, uint8_t* o) {
                        AriaCore::decryptBlock(in, o, roundKeys.begin(), nr);
                    }
                );
                return ERET_OK;
            }
        };

    } // namespace

    ARIA::ARIA() {
        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(128, 256, 64));
        keySizes(specs);
    }

    ERetCode ARIA::generateKey(ISymmetricKeyPtr& out, const SKeySizeSpec& keySize) const {
        // Default to the largest key, as AES::generateKey() does -- a caller that does not
        // say which it wants is better served by 256 bits than by 128.
        SKeySize bits = keySize.empty() ? 256 : keySize.minSize;

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

        const ERetCode rc = CRng::fill(raw.toSpan());
        if (rc != ERET_OK) {
            return rc;
        }

        out = createKey(raw.toSpan());
        return out ? ERET_OK : ERET_KEY_SIZE;
    }

    ISymmetricKeyPtr ARIA::createKey(const SReadOnlyByteSpan& keyData) const {
        if (keyData.size != 16 && keyData.size != 24 && keyData.size != 32) {
            return nullptr;
        }

        return std::make_shared<SymRawKey>(ESYM_ARIA, COctet(keyData));
    }

    ERetCode ARIA::generateIV(const ISymmetricKeyPtr& key, CBuffer& out) const {
        if (!key || key->algorithm() != ESYM_ARIA) {
            return ERET_KEY_FORMAT;
        }

        out.resize(ARIA_BLOCK_BYTES);
        return CRng::fill(out.toSpan());
    }

    ISymmetricContextPtr ARIA::createContext(const ISymmetricKeyPtr& key) const {
        auto ctx = std::make_shared<AriaContext>();
        ctx->key(key, CBuffer());
        return ctx;
    }

} // namespace crypto
} // namespace certpp
