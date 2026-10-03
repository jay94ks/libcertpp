#include "chacha20core.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

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

    } // namespace

    /* One ChaCha20 keystream block (RFC 8439 2.3). */
    void ChaCha20Core::block(
        const uint8_t key[KEY_BYTES], uint32_t counter,
        const uint8_t nonce[NONCE_BYTES], uint8_t out[BLOCK_BYTES]
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

} // namespace crypto
} // namespace certpp
