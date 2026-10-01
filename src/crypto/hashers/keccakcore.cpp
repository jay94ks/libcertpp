#include "keccakcore.hpp"

namespace certpp {
namespace crypto {

    /* Applies the Keccak-f[1600] permutation (24 rounds of theta/rho/pi/chi/iota) to a 1600-bit
     * state, given as 25 64-bit lanes, lane(x, y) at a[x + 5*y]. */
    void KeccakCore::f1600(uint64_t a[25]) {
        /* Keccak-f[1600]'s 24 round constants (FIPS 202 3.2.5), applied to lane (0, 0) at the
         * end of each round. */
        static constexpr uint64_t ROUND_CONSTANTS[24] = {
            0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808Aull, 0x8000000080008000ull,
            0x000000000000808Bull, 0x0000000080000001ull, 0x8000000080008081ull, 0x8000000000008009ull,
            0x000000000000008Aull, 0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000Aull,
            0x000000008000808Bull, 0x800000000000008Bull, 0x8000000000008089ull, 0x8000000000008003ull,
            0x8000000000008002ull, 0x8000000000000080ull, 0x000000000000800Aull, 0x800000008000000Aull,
            0x8000000080008081ull, 0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull
        };

        /* Keccak-f[1600]'s per-lane rotation offsets (FIPS 202 3.2.2), indexed [y][x] (note the
         * order: this literal reads naturally row-by-row as "all r[x][0] for x=0..4", "all
         * r[x][1] for x=0..4", etc. -- i.e. row i is the y=i slice) with lane(x, y) at flat
         * index x + 5*y. */
        static constexpr int ROTATION_OFFSETS[5][5] = {
            {  0,  1, 62, 28, 27 },
            { 36, 44,  6, 55, 20 },
            {  3, 10, 43, 25, 39 },
            { 41, 45, 15, 21,  8 },
            { 18,  2, 61, 56, 14 }
        };

        for (size_t round = 0; round < 24; ++round) {
            // Theta
            uint64_t c[5];
            for (size_t x = 0; x < 5; ++x) {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }

            uint64_t d[5];
            for (size_t x = 0; x < 5; ++x) {
                d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
            }

            for (size_t x = 0; x < 5; ++x) {
                for (size_t y = 0; y < 5; ++y) {
                    a[x + 5 * y] ^= d[x];
                }
            }

            // Rho + Pi: b[y][2x+3y mod 5] = rotl(a[x][y], r[x][y])
            uint64_t b[25];
            for (size_t x = 0; x < 5; ++x) {
                for (size_t y = 0; y < 5; ++y) {
                    size_t newX = y;
                    size_t newY = (2 * x + 3 * y) % 5;
                    b[newX + 5 * newY] = rotl64(a[x + 5 * y], ROTATION_OFFSETS[y][x]);
                }
            }

            // Chi
            for (size_t x = 0; x < 5; ++x) {
                for (size_t y = 0; y < 5; ++y) {
                    a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
                }
            }

            // Iota
            a[0] ^= ROUND_CONSTANTS[round];
        }
    }

    void KeccakCore::permute(uint8_t state[STATE_BYTES]) {
        uint64_t lanes[25];
        for (size_t i = 0; i < 25; ++i) {
            uint64_t lane = 0;
            for (size_t b = 0; b < 8; ++b) {
                lane |= uint64_t(state[i * 8 + b]) << (8 * b);
            }
            lanes[i] = lane;
        }

        f1600(lanes);

        for (size_t i = 0; i < 25; ++i) {
            for (size_t b = 0; b < 8; ++b) {
                state[i * 8 + b] = uint8_t(lanes[i] >> (8 * b));
            }
        }
    }

    void KeccakCore::absorbBlock(uint8_t state[STATE_BYTES], const uint8_t* src, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            state[i] ^= src[i];
        }

        permute(state);
    }

} // namespace crypto
} // namespace certpp
