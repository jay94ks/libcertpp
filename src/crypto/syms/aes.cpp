#include <certpp/crypto/syms/aes.hpp>
#include <certpp/crypto/rng.hpp>
#include "symkey.hpp"
#include "cbctransformer.hpp"
#include "aescore.hpp"
#include <cstring>
#include <memory>

namespace certpp {
namespace crypto {

    namespace {

        constexpr size_t AES_BLOCK_BYTES = AesCore::BLOCK_BYTES;

        class AesContext : public ISymmetricContext, public std::enable_shared_from_this<AesContext> {
        private:
            TSecureArray<uint8_t> _roundKeys;
            uint32_t _nr;

        protected:
            void onReset() override {
                _roundKeys.clear();
                _nr = 0;

                auto k = std::dynamic_pointer_cast<SymRawKey>(key());
                if (!k) {
                    return;
                }

                size_t keyBytes = k->keyData().size();
                if (!AesCore::expandKey(k->keyData().toPtr(), keyBytes, _roundKeys, _nr)) {
                    return;
                }

                sizeOfBlock(AES_BLOCK_BYTES);
            }

        public:
            AesContext() : _nr(0) {
            }

            ERetCode createEncrypter(ISymmetricTransformerPtr& out) override {
                if (_nr == 0) {
                    return ERET_KEY_EMPTY;
                }
                if (iv().size() != AES_BLOCK_BYTES) {
                    return ERET_KEY_PARAM;
                }

                auto roundKeys = _roundKeys; // --> captured by the lambda below, kept alive with it.
                uint32_t nr = _nr;

                // --> The bulk path, where this CPU has AES-NI: AesCore::encryptCbcBulk()
                // keeps the chaining value in a register across a whole run of blocks, which
                // is worth ~1.8x at 64 KiB because the per-block path writes the chain out
                // and reads it back for every block. It produces identical output -- checked
                // by tests/crypto/syms/aes.cpp against the portable block function, and kept
                // that way by construction here.
                CbcTransformer::BulkBlockFn bulk = nullptr;
                if (AesCore::hasAesNi()) {
                    bulk = [roundKeys, nr](
                        const uint8_t* in, uint8_t* out, size_t blocks, uint8_t* chain
                    ) {
                        AesCore::encryptCbcBulk(in, out, blocks, chain,
                                                roundKeys.begin(), nr);
                    };
                }

                out = std::make_shared<CbcTransformer>(
                    shared_from_this(), true, AES_BLOCK_BYTES, iv().toSpan(), padding(),
                    [roundKeys, nr](const uint8_t* in, uint8_t* o) {
                        AesCore::encryptBlock(in, o, roundKeys.begin(), nr);
                    },
                    bulk
                );
                return ERET_OK;
            }

            ERetCode createDecrypter(ISymmetricTransformerPtr& out) override {
                if (_nr == 0) {
                    return ERET_KEY_EMPTY;
                }
                if (iv().size() != AES_BLOCK_BYTES) {
                    return ERET_KEY_PARAM;
                }

                auto roundKeys = _roundKeys;
                uint32_t nr = _nr;

                out = std::make_shared<CbcTransformer>(
                    shared_from_this(), false, AES_BLOCK_BYTES, iv().toSpan(), padding(),
                    [roundKeys, nr](const uint8_t* in, uint8_t* o) {
                        AesCore::decryptBlock(in, o, roundKeys.begin(), nr);
                    }
                );
                return ERET_OK;
            }
        };

    } // namespace

    AES::AES() {
        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(128, 256, 64));
        keySizes(specs);
    }

    ERetCode AES::generateKey(
        const IRng& rng, ISymmetricKeyPtr& out, const SKeySizeSpec& keySize
    ) const {
        out.reset();
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

        CSecureBuffer raw(bits / 8);
        if (raw.size() != bits / 8) {
            return ERET_NOMEM;
        }

        ERetCode rc = rng.fillTo(raw.toSpan());
        if (rc != ERET_OK) {
            return rc;
        }

        return createKey(out, raw.toSpan());
    }

    ERetCode AES::createKey(
        ISymmetricKeyPtr& out, const SReadOnlyByteSpan& keyData
    ) const {
        out.reset();
        if (keyData.size != 16 && keyData.size != 24 && keyData.size != 32) {
            return ERET_KEY_SIZE;
        }
        try {
            out = std::make_shared<SymRawKey>(ESYM_AES, keyData);
            if (out->keySize() != keyData.size) {
                out.reset();
                return ERET_NOMEM;
            }
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        return ERET_OK;
    }

    ERetCode AES::generateIV(const IRng& rng, const ISymmetricKeyPtr& key, CBuffer& out) const {
        if (!key || key->algorithm() != ESYM_AES) {
            return ERET_KEY_FORMAT;
        }

        out.resize(AES_BLOCK_BYTES);
        return rng.fillTo(out.toSpan());
    }

    ERetCode AES::createContext(
        ISymmetricContextPtr& out, const ISymmetricKeyPtr& key
    ) const {
        out.reset();
        try {
            out = std::make_shared<AesContext>();
        } catch (const std::bad_alloc&) {
            return ERET_NOMEM;
        }
        out->key(key, CBuffer());
        return ERET_OK;
    }

} // namespace crypto
} // namespace certpp
