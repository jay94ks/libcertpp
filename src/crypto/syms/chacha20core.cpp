#include "chacha20core.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

        inline uint32_t rotl32(uint32_t x, int n) {
            return (x << n) | (x >> (32 - n));
        }

        /* Unaligned 32-bit access through memcpy: the caller's buffer carries no alignment
         * guarantee, and every compiler folds this to a single load or store. */
        inline uint32_t loadWord(const uint8_t* p) {
            uint32_t v;
            std::memcpy(&v, p, sizeof(v));
            return v;
        }

        inline void storeWord(uint8_t* p, uint32_t v) {
            std::memcpy(p, &v, sizeof(v));
        }

        /* Explicitly little-endian, for the state words and the keystream block, where the byte
         * order is part of the algorithm rather than host-defined. */
        inline uint32_t loadLE32(const uint8_t* p) {
            return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
                 | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
        }

        inline void storeLE32(uint8_t* p, uint32_t v) {
            p[0] = uint8_t(v);
            p[1] = uint8_t(v >> 8);
            p[2] = uint8_t(v >> 16);
            p[3] = uint8_t(v >> 24);
        }

        inline void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
            a += b; d ^= a; d = rotl32(d, 16);
            c += d; b ^= c; b = rotl32(b, 12);
            a += b; d ^= a; d = rotl32(d, 8);
            c += d; b ^= c; b = rotl32(b, 7);
        }

        /* The twenty rounds, from a prepared state plus a counter, leaving the result in
         * `working` *without* the final feed-forward addition -- one caller wants the sum XORed
         * straight into a buffer and the other wants it stored, so they add it themselves. */
        inline void rounds(
            const ChaCha20Core::SState& state, uint32_t counter, uint32_t working[16]
        ) {
            std::memcpy(working, state.words, sizeof(uint32_t) * 16);
            working[12] = counter;

            for (int i = 0; i < 10; ++i) {
                // Columns, then diagonals -- RFC 8439 2.3's double round.
                quarterRound(working[0], working[4], working[8], working[12]);
                quarterRound(working[1], working[5], working[9], working[13]);
                quarterRound(working[2], working[6], working[10], working[14]);
                quarterRound(working[3], working[7], working[11], working[15]);

                quarterRound(working[0], working[5], working[10], working[15]);
                quarterRound(working[1], working[6], working[11], working[12]);
                quarterRound(working[2], working[7], working[8], working[13]);
                quarterRound(working[3], working[4], working[9], working[14]);
            }
        }

    } // namespace

    /* Prepares a state from a key and nonce. */
    void ChaCha20Core::initState(
        SState& out, const uint8_t key[KEY_BYTES], const uint8_t nonce[NONCE_BYTES]
    ) {
        out.words[0] = 0x61707865u;
        out.words[1] = 0x3320646eu;
        out.words[2] = 0x79622d32u;
        out.words[3] = 0x6b206574u;

        for (size_t i = 0; i < 8; ++i) {
            out.words[4 + i] = loadLE32(key + 4 * i);
        }

        out.words[12] = 0;   // the counter, filled in per block

        for (size_t i = 0; i < 3; ++i) {
            out.words[13 + i] = loadLE32(nonce + 4 * i);
        }
    }

    /* One keystream block from a prepared state. */
    void ChaCha20Core::block(const SState& state, uint32_t counter, uint8_t out[BLOCK_BYTES]) {
        uint32_t working[16];
        rounds(state, counter, working);

        for (size_t i = 0; i < 16; ++i) {
            const uint32_t original = (i == 12) ? counter : state.words[i];
            storeLE32(out + 4 * i, working[i] + original);
        }
    }

    /* XORs the keystream over the input, 32 bits at a time for whole blocks. */
    void ChaCha20Core::xorStream(
        const SState& state, uint32_t initialCounter,
        const uint8_t* in, uint8_t* out, size_t length
    ) {
        uint32_t counter = initialCounter;
        size_t offset = 0;

        while (length - offset >= BLOCK_BYTES) {
            uint32_t working[16];
            rounds(state, counter, working);

            // --> Word-wise, which is the whole point of this function. The previous version
            // XORed a byte at a time, so one 64-byte block cost 64 loads, 64 XORs and 64 stores
            // instead of 16 of each -- at 64 KiB, roughly 48 thousand redundant operations.
            for (size_t i = 0; i < 16; ++i) {
                const uint32_t original = (i == 12) ? counter : state.words[i];
                const uint32_t keyWord = working[i] + original;
                storeWord(out + offset + 4 * i, loadWord(in + offset + 4 * i) ^ keyWord);
            }

            offset += BLOCK_BYTES;
            ++counter;
        }

        if (offset < length) {
            // The trailing partial block, byte by byte: there is no whole word left, and reading
            // past the caller's buffer to get one is not an option.
            uint8_t keystream[BLOCK_BYTES];
            block(state, counter, keystream);

            const size_t rest = length - offset;
            for (size_t i = 0; i < rest; ++i) {
                out[offset + i] = uint8_t(in[offset + i] ^ keystream[i]);
            }

            // Keystream bytes are as sensitive as the plaintext they cover.
            std::memset(keystream, 0, sizeof(keystream));
        }
    }

    /* One keystream block, preparing the state for this call alone. */
    void ChaCha20Core::block(
        const uint8_t key[KEY_BYTES], uint32_t counter,
        const uint8_t nonce[NONCE_BYTES], uint8_t out[BLOCK_BYTES]
    ) {
        SState state;
        initState(state, key, nonce);
        block(state, counter, out);
    }

} // namespace crypto
} // namespace certpp
