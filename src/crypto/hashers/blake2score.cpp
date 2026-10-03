#include "blake2score.hpp"
#include <cstring>

namespace certpp {
namespace crypto {

    namespace {

        /* BLAKE2s shares SHA-256's initialization vector (RFC 7693 2.6). */
        constexpr uint32_t IV[8] = {
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
        };

        /* The message-word permutation (RFC 7693 2.7, table SIGMA). Ten rows for BLAKE2s's ten
         * rounds -- BLAKE2b uses the first ten of its own twelve. Transposing or swapping rows
         * here yields a perfectly deterministic hash that matches no other implementation, so it
         * is transcribed row-for-row from the RFC and pinned by the known-answer tests. */
        constexpr uint8_t SIGMA[10][16] = {
            {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
            { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
            { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
            {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
            {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
            {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
            { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
            { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
            {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
            { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
        };

        inline uint32_t rotr(uint32_t value, uint32_t count) {
            return (value >> count) | (value << (32 - count));
        }

        /* The G mixing function (RFC 7693 3.1), over four words of the working vector. The four
         * rotation distances -- 16, 12, 8, 7 -- are BLAKE2s's; BLAKE2b uses 32, 24, 16, 63. */
        inline void mixG(
            uint32_t* v, size_t a, size_t b, size_t c, size_t d, uint32_t x, uint32_t y
        ) {
            v[a] = v[a] + v[b] + x;
            v[d] = rotr(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = rotr(v[b] ^ v[c], 12);
            v[a] = v[a] + v[b] + y;
            v[d] = rotr(v[d] ^ v[a], 8);
            v[c] = v[c] + v[d];
            v[b] = rotr(v[b] ^ v[c], 7);
        }

    } // namespace

    /* Runs the compression function F over one block. */
    void Blake2sCore::compress(
        uint32_t state[8], const uint8_t block[BLOCK_BYTES], uint64_t counter, bool last
    ) {
        // --> BLAKE2s reads its message words little-endian, unlike the big-endian SHA-2 family.
        uint32_t m[16];
        for (size_t i = 0; i < 16; ++i) {
            m[i] = uint32_t(block[i * 4 + 0])
                 | (uint32_t(block[i * 4 + 1]) << 8)
                 | (uint32_t(block[i * 4 + 2]) << 16)
                 | (uint32_t(block[i * 4 + 3]) << 24);
        }

        uint32_t v[16];
        std::memcpy(v, state, sizeof(uint32_t) * 8);
        std::memcpy(v + 8, IV, sizeof(IV));

        v[12] ^= uint32_t(counter);
        v[13] ^= uint32_t(counter >> 32);

        if (last) {
            // --> f[0], the finalization flag. Omitting it makes every digest wrong in a way no
            // amount of internal consistency reveals.
            v[14] ^= 0xFFFFFFFFu;
        }

        // --> Ten rounds for BLAKE2s (twelve for BLAKE2b). The first four G calls are the column
        // step, the last four the diagonal step.
        for (size_t round = 0; round < 10; ++round) {
            const uint8_t* s = SIGMA[round];

            mixG(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
            mixG(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
            mixG(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
            mixG(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
            mixG(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
            mixG(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            mixG(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
            mixG(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
        }

        for (size_t i = 0; i < 8; ++i) {
            state[i] ^= v[i] ^ v[i + 8];
        }
    }

    /* Initializes a context from the parameter block, seeding the key block when keyed. */
    void Blake2sCore::init(
        uint32_t state[8], uint8_t buffer[BLOCK_BYTES], size_t& bufferLen, uint64_t& counter,
        size_t digestBytes, const SReadOnlyByteSpan& key
    ) {
        const size_t keyBytes = key.data ? key.size : 0;

        std::memcpy(state, IV, sizeof(IV));

        // RFC 7693 2.8/3.2: the first state word carries the parameter block's first four bytes
        // -- digest length, key length, fanout, depth -- little-endian, so fanout = depth = 1 is
        // 0x01010000 and the two lengths occupy the low two bytes. Getting the two lengths'
        // positions the wrong way round still hashes, just not BLAKE2s.
        state[0] ^= 0x01010000u ^ uint32_t(keyBytes << 8) ^ uint32_t(digestBytes);

        std::memset(buffer, 0, BLOCK_BYTES);
        counter = 0;

        if (keyBytes == 0) {
            bufferLen = 0;
            return;
        }

        // The key is absorbed as a whole zero-padded first block, and it counts towards t. Note
        // this leaves the block *buffered*: for an empty message it is also the final block.
        std::memcpy(buffer, key.data, keyBytes);
        bufferLen = BLOCK_BYTES;
    }

    /* Absorbs input, holding back whatever might turn out to be the final block. */
    size_t Blake2sCore::absorb(
        uint32_t state[8], uint8_t buffer[BLOCK_BYTES], size_t& bufferLen, uint64_t& counter,
        const SReadOnlyByteSpan& buf
    ) {
        if (buf.size == 0 || !buf.data) {
            return 0;
        }

        const uint8_t* data = buf.data;
        size_t remaining = buf.size;
        const size_t fill = BLOCK_BYTES - bufferLen;

        // --> Strictly greater: a block is compressed only once there is at least one byte after
        // it, because the last block is the one that gets the f[0] flag. With `>=` here, a message
        // whose length is a multiple of 64 would flag the wrong block.
        if (remaining > fill) {
            std::memcpy(buffer + bufferLen, data, fill);
            data += fill;
            remaining -= fill;

            bufferLen = 0;
            counter += BLOCK_BYTES;
            compress(state, buffer, counter, false);

            while (remaining > BLOCK_BYTES) {
                counter += BLOCK_BYTES;
                compress(state, data, counter, false);
                data += BLOCK_BYTES;
                remaining -= BLOCK_BYTES;
            }
        }

        std::memcpy(buffer + bufferLen, data, remaining);
        bufferLen += remaining;

        return buf.size;
    }

    /* Pads and compresses the final block on a copy, then writes the little-endian digest. */
    void Blake2sCore::digest(
        const uint32_t state[8], const uint8_t buffer[BLOCK_BYTES], size_t bufferLen,
        uint64_t counter, uint8_t* out, size_t digestBytes
    ) {
        uint32_t h[8];
        std::memcpy(h, state, sizeof(h));

        uint8_t block[BLOCK_BYTES];
        std::memcpy(block, buffer, bufferLen);
        std::memset(block + bufferLen, 0, BLOCK_BYTES - bufferLen);

        compress(h, block, counter + bufferLen, true);

        uint8_t full[MAX_DIGEST_BYTES];
        for (size_t i = 0; i < 8; ++i) {
            // --> The digest words go out little-endian, matching the message packing.
            full[i * 4 + 0] = uint8_t(h[i]);
            full[i * 4 + 1] = uint8_t(h[i] >> 8);
            full[i * 4 + 2] = uint8_t(h[i] >> 16);
            full[i * 4 + 3] = uint8_t(h[i] >> 24);
        }

        std::memcpy(out, full, digestBytes);
    }

} // namespace crypto
} // namespace certpp
