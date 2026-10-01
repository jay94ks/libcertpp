#include <certpp/crypto/syms/chacha20.hpp>
#include <certpp/crypto/rng.hpp>
#include "symkey.hpp"
#include <cstring>
#include <memory>

namespace certpp {
namespace crypto {

    namespace {

        constexpr size_t CHACHA20_KEY_BYTES = 32;
        constexpr size_t CHACHA20_NONCE_BYTES = 12;
        constexpr size_t CHACHA20_BLOCK_BYTES = 64;

        /* ChaCha20 (RFC 8439 2.3) block core: expands a 256-bit key, 96-bit nonce, and 32-bit
         * block counter into one 64-byte keystream block. Used only from this file. */
        class ChaCha20Core {
        private:
            static inline uint32_t rotl32(uint32_t x, int n) {
                return (x << n) | (x >> (32 - n));
            }

            static inline uint32_t loadLE32(const uint8_t* p) {
                return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8)
                    | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
            }

            static inline void storeLE32(uint8_t* p, uint32_t v) {
                p[0] = static_cast<uint8_t>(v);
                p[1] = static_cast<uint8_t>(v >> 8);
                p[2] = static_cast<uint8_t>(v >> 16);
                p[3] = static_cast<uint8_t>(v >> 24);
            }

            static inline void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
                a += b; d ^= a; d = rotl32(d, 16);
                c += d; b ^= c; b = rotl32(b, 12);
                a += b; d ^= a; d = rotl32(d, 8);
                c += d; b ^= c; b = rotl32(b, 7);
            }

        public:
            static void block(
                const uint8_t key[CHACHA20_KEY_BYTES], uint32_t counter,
                const uint8_t nonce[CHACHA20_NONCE_BYTES], uint8_t out[CHACHA20_BLOCK_BYTES]
            ) {
                uint32_t state[16];
                state[0] = 0x61707865u;
                state[1] = 0x3320646eu;
                state[2] = 0x79622d32u;
                state[3] = 0x6b206574u;

                for (int i = 0; i < 8; ++i) {
                    state[4 + i] = loadLE32(key + 4 * i);
                }

                state[12] = counter;
                for (int i = 0; i < 3; ++i) {
                    state[13 + i] = loadLE32(nonce + 4 * i);
                }

                uint32_t working[16];
                std::memcpy(working, state, sizeof(working));

                for (int i = 0; i < 10; ++i) {
                    quarterRound(working[0], working[4], working[8], working[12]);
                    quarterRound(working[1], working[5], working[9], working[13]);
                    quarterRound(working[2], working[6], working[10], working[14]);
                    quarterRound(working[3], working[7], working[11], working[15]);

                    quarterRound(working[0], working[5], working[10], working[15]);
                    quarterRound(working[1], working[6], working[11], working[12]);
                    quarterRound(working[2], working[7], working[8], working[13]);
                    quarterRound(working[3], working[4], working[9], working[14]);
                }

                for (int i = 0; i < 16; ++i) {
                    storeLE32(out + 4 * i, working[i] + state[i]);
                }
            }
        };

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
