#include <certpp/crypto/syms/chacha20.hpp>
#include <certpp/crypto/rng.hpp>
#include "symkey.hpp"
#include "chacha20core.hpp"
#include <cstring>
#include <memory>

namespace certpp {
namespace crypto {

    namespace {

        // Mirrors of ChaCha20Core's own constants, so this file reads as the ISymmetric
        // wrapper it is rather than reaching through the core for every length.
        constexpr size_t CHACHA20_KEY_BYTES = ChaCha20Core::KEY_BYTES;
        constexpr size_t CHACHA20_NONCE_BYTES = ChaCha20Core::NONCE_BYTES;
        constexpr size_t CHACHA20_BLOCK_BYTES = ChaCha20Core::BLOCK_BYTES;

        /* XORs input with the ChaCha20 keystream -- the same operation encrypts and decrypts, so
         * this one class backs both createEncrypter() and createDecrypter(). The block counter
         * always starts at 0 and increments as each 64-byte keystream block is exhausted; no
         * padding or block-alignment is needed since this is a pure stream cipher. */
        class ChaCha20Transformer : public ISymmetricTransformer {
        private:
            uint8_t _key[CHACHA20_KEY_BYTES];
            uint8_t _nonce[CHACHA20_NONCE_BYTES];
            uint32_t _counter;
            uint8_t _keystream[CHACHA20_BLOCK_BYTES];
            size_t _keystreamPos; // --> CHACHA20_BLOCK_BYTES once the current block is exhausted.

        public:
            ChaCha20Transformer(
                const ISymmetricContextPtr& ctx, const uint8_t key[CHACHA20_KEY_BYTES],
                const uint8_t nonce[CHACHA20_NONCE_BYTES]
            )
                : ISymmetricTransformer(ctx), _counter(0), _keystreamPos(CHACHA20_BLOCK_BYTES)
            {
                std::memcpy(_key, key, CHACHA20_KEY_BYTES);
                std::memcpy(_nonce, nonce, CHACHA20_NONCE_BYTES);
            }

            ERetCode transform(const SReadOnlyByteSpan& input, SByteSpan& output) override {
                if (output.size < input.size) {
                    return ERET_NOSPC;
                }

                for (size_t i = 0; i < input.size; ++i) {
                    if (_keystreamPos == CHACHA20_BLOCK_BYTES) {
                        ChaCha20Core::block(_key, _counter, _nonce, _keystream);
                        ++_counter;
                        _keystreamPos = 0;
                    }

                    output.data[i] = static_cast<uint8_t>(input.data[i] ^ _keystream[_keystreamPos++]);
                }

                output = SByteSpan(output.data, input.size);
                return ERET_OK;
            }

            ERetCode transformFinal(SByteSpan& output) override {
                output = SByteSpan(output.data, 0); // --> nothing buffered; a stream cipher pads nothing.
                return ERET_OK;
            }
        };

        class ChaCha20Context : public ISymmetricContext, public std::enable_shared_from_this<ChaCha20Context> {
        private:
            bool _ready;

        protected:
            void onReset() override {
                _ready = false;

                auto k = std::dynamic_pointer_cast<SymRawKey>(key());
                if (!k || k->keyData().size() != CHACHA20_KEY_BYTES) {
                    return;
                }

                _ready = true;
                sizeOfBlock(CHACHA20_BLOCK_BYTES);
            }

        public:
            ChaCha20Context() : _ready(false) {
            }

            ERetCode createEncrypter(ISymmetricTransformerPtr& out) override {
                if (!_ready) {
                    return ERET_KEY_EMPTY;
                }
                if (iv().size() != CHACHA20_NONCE_BYTES) {
                    return ERET_KEY_PARAM;
                }

                auto k = std::dynamic_pointer_cast<SymRawKey>(key());
                out = std::make_shared<ChaCha20Transformer>(
                    shared_from_this(), k->keyData().toPtr(), iv().toPtr()
                );
                return ERET_OK;
            }

            ERetCode createDecrypter(ISymmetricTransformerPtr& out) override {
                // --> ChaCha20 encryption and decryption are the identical XOR-with-keystream
                // operation, so decrypting just needs another instance of the same transformer.
                return createEncrypter(out);
            }
        };

    } // namespace

    ChaCha20::ChaCha20() {
        TArray<SKeySizeSpec> specs;
        specs.add(SKeySizeSpec(256));
        keySizes(specs);
    }

    ERetCode ChaCha20::generateKey(ISymmetricKeyPtr& out, const SKeySizeSpec& keySize) const {
        SKeySize bits = keySize.empty() ? 256 : keySize.minSize;
        if (bits != 256) {
            return ERET_KEY_SIZE;
        }

        CBuffer raw(CHACHA20_KEY_BYTES);

        ERetCode rc = CRng::fill(raw.toSpan());
        if (rc != ERET_OK) {
            return rc;
        }

        out = createKey(raw.toSpan());
        return out ? ERET_OK : ERET_KEY_SIZE;
    }

    ISymmetricKeyPtr ChaCha20::createKey(const SReadOnlyByteSpan& keyData) const {
        if (keyData.size != CHACHA20_KEY_BYTES) {
            return nullptr;
        }

        return std::make_shared<SymRawKey>(ESYM_CHACHA20, COctet(keyData));
    }

    ERetCode ChaCha20::generateIV(const ISymmetricKeyPtr& key, CBuffer& out) const {
        if (!key || key->algorithm() != ESYM_CHACHA20) {
            return ERET_KEY_FORMAT;
        }

        out.resize(CHACHA20_NONCE_BYTES);
        return CRng::fill(out.toSpan());
    }

    ISymmetricContextPtr ChaCha20::createContext(const ISymmetricKeyPtr& key) const {
        auto ctx = std::make_shared<ChaCha20Context>();
        ctx->key(key, CBuffer());
        return ctx;
    }

} // namespace crypto
} // namespace certpp
