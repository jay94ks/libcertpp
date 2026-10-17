#include "descore.hpp"

namespace certpp {
namespace crypto {

    const uint8_t DesCore::IP[64] = {
        58, 50, 42, 34, 26, 18, 10,  2,
        60, 52, 44, 36, 28, 20, 12,  4,
        62, 54, 46, 38, 30, 22, 14,  6,
        64, 56, 48, 40, 32, 24, 16,  8,
        57, 49, 41, 33, 25, 17,  9,  1,
        59, 51, 43, 35, 27, 19, 11,  3,
        61, 53, 45, 37, 29, 21, 13,  5,
        63, 55, 47, 39, 31, 23, 15,  7,
    };

    const uint8_t DesCore::FP[64] = {
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25,
    };

    const uint8_t DesCore::PBOX[32] = {
        16,  7, 20, 21,
        29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25,
    };

    const uint8_t DesCore::PC1[56] = {
        57, 49, 41, 33, 25, 17,  9,
         1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
         7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4,
    };

    const uint8_t DesCore::PC2[48] = {
        14, 17, 11, 24,  1,  5,
         3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32,
    };

    const uint8_t DesCore::SHIFTS[16] = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
    };

    const uint8_t DesCore::SBOX[8][64] = {
        { // S1
            14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
             0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
             4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
            15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
        },
        { // S2
            15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
             3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
             0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
            13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
        },
        { // S3
            10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
            13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
            13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
             1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
        },
        { // S4
             7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
            13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
            10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
             3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
        },
        { // S5
             2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
            14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
             4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
            11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
        },
        { // S6
            12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
            10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
             9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
             4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
        },
        { // S7
             4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
            13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
             1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
             6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
        },
        { // S8
            13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
             1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
             7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
             2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11,
        },
    };

    uint64_t DesCore::permute(uint64_t input, const uint8_t* table, size_t tableLen, size_t inputBits) {
        uint64_t output = 0;
        for (size_t i = 0; i < tableLen; ++i) {
            size_t shift = inputBits - table[i];
            output = (output << 1) | ((input >> shift) & 1ULL);
        }
        return output;
    }

    const DesCore::SpBoxes& DesCore::spBoxes() {
        static const SpBoxes boxes = [] {
            SpBoxes result{};
            for (size_t box = 0; box < 8; ++box) {
                for (uint32_t input = 0; input < 64; ++input) {
                    const uint8_t row = static_cast<uint8_t>(
                        ((input & 0x20u) >> 4) | (input & 0x01u));
                    const uint8_t column = static_cast<uint8_t>((input >> 1) & 0x0fu);
                    const uint32_t substituted =
                        uint32_t(SBOX[box][row * 16 + column]) << (28 - 4 * box);
                    result.values[box][input] = static_cast<uint32_t>(
                        permute(substituted, PBOX, 32, 32));
                }
            }
            return result;
        }();
        return boxes;
    }

    const DesCore::BlockPermutations& DesCore::blockPermutations() {
        static const BlockPermutations tables = [] {
            BlockPermutations result{};
            for (size_t byte = 0; byte < 8; ++byte) {
                const size_t shift = (7 - byte) * 8;
                for (uint64_t value = 0; value < 256; ++value) {
                    const uint64_t placed = value << shift;
                    result.initial[byte][value] = permute(placed, IP, 64, 64);
                    result.final[byte][value] = permute(placed, FP, 64, 64);
                }
            }
            return result;
        }();
        return tables;
    }

    uint64_t DesCore::permuteBlock(uint64_t input, const uint64_t table[8][256]) {
        return table[0][(input >> 56) & 0xffu]
            | table[1][(input >> 48) & 0xffu]
            | table[2][(input >> 40) & 0xffu]
            | table[3][(input >> 32) & 0xffu]
            | table[4][(input >> 24) & 0xffu]
            | table[5][(input >> 16) & 0xffu]
            | table[6][(input >> 8) & 0xffu]
            | table[7][input & 0xffu];
    }

    uint32_t DesCore::feistel(uint32_t r, const RoundKey& roundKey, const SpBoxes& boxes) {
        const uint32_t rotated = (r << 7) | (r >> 25);
        const uint32_t even = rotated ^ roundKey.even;
        const uint32_t odd = ((r << 3) | (r >> 29)) ^ roundKey.odd;
        return boxes.values[0][(even >> 2) & 0x3fu]
            | boxes.values[6][(even >> 10) & 0x3fu]
            | boxes.values[4][(even >> 18) & 0x3fu]
            | boxes.values[2][(even >> 26) & 0x3fu]
            | boxes.values[7][(odd >> 2) & 0x3fu]
            | boxes.values[5][(odd >> 10) & 0x3fu]
            | boxes.values[3][(odd >> 18) & 0x3fu]
            | boxes.values[1][(odd >> 26) & 0x3fu];
    }

    uint64_t DesCore::loadBlock(const uint8_t in[8]) {
        uint64_t value = 0;
        for (size_t i = 0; i < 8; ++i) {
            value = (value << 8) | in[i];
        }
        return value;
    }

    void DesCore::storeBlock(uint64_t value, uint8_t out[8]) {
        for (int i = 7; i >= 0; --i) {
            out[i] = static_cast<uint8_t>(value);
            value >>= 8;
        }
    }

#if defined(__clang__) || (defined(__GNUC__) && !defined(_MSC_VER))
    __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
    __forceinline
#endif
    uint64_t DesCore::processPermuted(
        uint64_t input, const RoundKey roundKeys[16], const SpBoxes& boxes
    ) {
        uint32_t l = static_cast<uint32_t>(input >> 32);
        uint32_t r = static_cast<uint32_t>(input);

#if defined(__clang__)
#pragma clang loop unroll(full)
#elif defined(__GNUC__) && !defined(_MSC_VER)
#pragma GCC unroll 16
#endif
        for (int round = 0; round < 16; ++round) {
            const uint32_t next = l ^ feistel(r, roundKeys[round], boxes);
            l = r;
            r = next;
        }

        return (uint64_t(r) << 32) | l;
    }

    void DesCore::keySchedule(const uint8_t key[8], RoundKey roundKeys[16]) {
        uint64_t k64 = 0;
        for (int i = 0; i < 8; ++i) {
            k64 = (k64 << 8) | key[i];
        }

        uint64_t k56 = permute(k64, PC1, 56, 64);
        uint32_t c = static_cast<uint32_t>((k56 >> 28) & 0x0FFFFFFFu);
        uint32_t d = static_cast<uint32_t>(k56 & 0x0FFFFFFFu);

        for (int round = 0; round < 16; ++round) {
            uint8_t shift = SHIFTS[round];
            c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFFu;
            d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFFu;

            uint64_t cd = (static_cast<uint64_t>(c) << 28) | d;
            const uint64_t roundKey = permute(cd, PC2, 48, 56);
            const uint32_t k0 = static_cast<uint32_t>((roundKey >> 42) & 0x3fu);
            const uint32_t k1 = static_cast<uint32_t>((roundKey >> 36) & 0x3fu);
            const uint32_t k2 = static_cast<uint32_t>((roundKey >> 30) & 0x3fu);
            const uint32_t k3 = static_cast<uint32_t>((roundKey >> 24) & 0x3fu);
            const uint32_t k4 = static_cast<uint32_t>((roundKey >> 18) & 0x3fu);
            const uint32_t k5 = static_cast<uint32_t>((roundKey >> 12) & 0x3fu);
            const uint32_t k6 = static_cast<uint32_t>((roundKey >> 6) & 0x3fu);
            const uint32_t k7 = static_cast<uint32_t>(roundKey & 0x3fu);
            roundKeys[round].even = (k0 << 2) | (k6 << 10) | (k4 << 18) | (k2 << 26);
            roundKeys[round].odd = (k7 << 2) | (k5 << 10) | (k3 << 18) | (k1 << 26);
        }
    }

    void DesCore::processBlock(const uint8_t in[8], uint8_t out[8], const RoundKey roundKeys[16]) {
        const uint64_t block = loadBlock(in);
        const BlockPermutations& permutations = blockPermutations();
        const SpBoxes& boxes = spBoxes();
        const uint64_t afterIp = permuteBlock(block, permutations.initial);
        const uint64_t preOutput = processPermuted(afterIp, roundKeys, boxes);
        storeBlock(permuteBlock(preOutput, permutations.final), out);
    }

    void DesCore::processTripleBlock(
        const uint8_t in[8], uint8_t out[8], const RoundKey roundKeys[3][16]
    ) {
        const BlockPermutations& permutations = blockPermutations();
        const SpBoxes& boxes = spBoxes();
        uint64_t value = permuteBlock(loadBlock(in), permutations.initial);
        value = processPermuted(value, roundKeys[0], boxes);
        value = processPermuted(value, roundKeys[1], boxes);
        value = processPermuted(value, roundKeys[2], boxes);
        storeBlock(permuteBlock(value, permutations.final), out);
    }

    void DesCore::encryptCbcBulk(
        const uint8_t* in, uint8_t* out, size_t blocks, uint8_t chain[8],
        const RoundKey roundKeys[16]
    ) {
        const BlockPermutations& permutations = blockPermutations();
        const SpBoxes& boxes = spBoxes();
        uint64_t chaining = loadBlock(chain);

        for (size_t block = 0; block < blocks; ++block) {
            uint64_t value = loadBlock(in + block * 8) ^ chaining;
            value = permuteBlock(value, permutations.initial);
            value = processPermuted(value, roundKeys, boxes);
            chaining = permuteBlock(value, permutations.final);
            storeBlock(chaining, out + block * 8);
        }

        storeBlock(chaining, chain);
    }

    void DesCore::encryptTripleCbcBulk(
        const uint8_t* in, uint8_t* out, size_t blocks, uint8_t chain[8],
        const RoundKey roundKeys[3][16]
    ) {
        const BlockPermutations& permutations = blockPermutations();
        const SpBoxes& boxes = spBoxes();
        uint64_t chaining = loadBlock(chain);

        for (size_t block = 0; block < blocks; ++block) {
            uint64_t value = permuteBlock(
                loadBlock(in + block * 8) ^ chaining, permutations.initial);
            value = processPermuted(value, roundKeys[0], boxes);
            value = processPermuted(value, roundKeys[1], boxes);
            value = processPermuted(value, roundKeys[2], boxes);
            chaining = permuteBlock(value, permutations.final);
            storeBlock(chaining, out + block * 8);
        }

        storeBlock(chaining, chain);
    }

} // namespace crypto
} // namespace certpp
